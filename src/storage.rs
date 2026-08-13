use crate::Result;

/// Abstracción del medio de almacenamiento. Toma `&self` también en las
/// escrituras porque el escritor es único y los lectores son concurrentes: la
/// exclusión mutua la impone `WriteTxn`, no el tipo. `FileStorage` lo cumple
/// con `pread`/`pwrite`, que no mueven un cursor compartido y por tanto no
/// necesitan `&mut`.
pub trait Storage: Send + Sync {
    /// Llena `buf` desde `offset`. Falla con `UnexpectedEof` si no hay bytes
    /// suficientes: una lectura corta significa fichero truncado, y devolver
    /// un buffer a medio llenar escondería la corrupción.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Escribe `buf` en `offset`, extendiendo el medio si hace falta.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Fuerza a disco lo escrito hasta ahora.
    fn sync(&self) -> Result<()>;

    fn len(&self) -> Result<u64>;

    /// Recorta el medio a `len` bytes y devuelve la cola al sistema de
    /// ficheros. Es la única operación del trait que hace DESAPARECER bytes
    /// ya escritos, y por eso su contrato es más estrecho que el del resto:
    ///
    /// - **Nunca extiende.** Si `len` es mayor o igual que la longitud
    ///   actual, el medio se queda exactamente como estaba y la llamada
    ///   devuelve `Ok(())`. `File::set_len` de la biblioteca estándar SÍ
    ///   extiende con ceros, así que `FileStorage` lo comprueba antes de
    ///   llamarla: una implementación que extendiera por accidente
    ///   convertiría un error de cálculo del llamante en un fichero más
    ///   grande, en silencio, justo en la operación que existe para hacerlo
    ///   más pequeño.
    /// - **No promete durabilidad por sí sola.** Como cualquier escritura,
    ///   necesita un `sync()` posterior para que el nuevo tamaño sobreviva
    ///   a un corte de corriente. Quien llama decide el orden; el motor lo
    ///   fija en `Db::reclaim_tail` (`tx.rs`): la meta con el `n_pages`
    ///   reducido se escribe y se sincroniza ANTES de recortar, nunca al
    ///   revés, para que ninguna meta que pueda sobrevivir a un corte
    ///   referencie una página más allá del final del fichero.
    /// - **Parcial no existe.** Un corte durante un recorte deja el tamaño
    ///   viejo o el nuevo, nunca uno intermedio: un `Storage` que no pueda
    ///   ofrecer eso debe devolver `Err` en vez de recortar a medias (ver
    ///   `FaultStorage`, que por eso modela un "desgarro" de recorte como
    ///   un fallo total).
    ///
    /// El único llamador dentro del motor es `Db::reclaim_tail`, siempre
    /// con el candado de escritor tomado y con un `len` múltiplo del tamaño
    /// de página.
    fn truncate(&self, len: u64) -> Result<()>;
}

#[cfg(feature = "std")]
pub use imp_std::{Fault, FaultStorage, FileStorage, MemStorage};

#[cfg(feature = "std")]
mod imp_std {
    use super::Storage;
    use crate::{Error, IoError, Result};
    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    /// Cualquier `Arc<S>` sobre un medio es, a su vez, un medio (tarea 20):
    /// un arnés de pruebas necesita conservar un asa (`Arc::clone`) tras
    /// entregarle la propiedad a `Db::create`/`open`, que exige
    /// `Box<dyn Storage>` — sin este `impl`, cada módulo de pruebas del
    /// crate ha venido definiendo su propio envoltorio local de una línea
    /// (`ArcStorage`, `ArcPowerLoss`, `ArcRecording`, …) solo para volver a
    /// implementar exactamente estos cuatro métodos delegando en `Arc`. Es
    /// completamente genérico — no depende de `FaultStorage` ni de ningún
    /// otro tipo concreto — y no colisiona con las reglas de huérfanos:
    /// `Storage` es un trait de este crate, así que puede implementarse
    /// para cualquier tipo, incluido uno ajeno como `Arc`.
    impl<S: Storage + ?Sized> Storage for Arc<S> {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            (**self).read_at(offset, buf)
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            (**self).write_at(offset, buf)
        }

        fn sync(&self) -> Result<()> {
            (**self).sync()
        }

        fn len(&self) -> Result<u64> {
            (**self).len()
        }

        fn truncate(&self, len: u64) -> Result<()> {
            (**self).truncate(len)
        }
    }

    fn map_io(e: std::io::Error) -> Error {
        use std::io::ErrorKind as K;
        Error::Io(match e.kind() {
            K::NotFound => IoError::NotFound,
            K::PermissionDenied => IoError::PermissionDenied,
            K::UnexpectedEof => IoError::UnexpectedEof,
            K::WriteZero => IoError::WriteZero,
            _ => IoError::Other(e.raw_os_error().unwrap_or(0)),
        })
    }

    pub struct MemStorage {
        data: Mutex<Vec<u8>>,
        reads: std::sync::atomic::AtomicU64,
    }

    impl MemStorage {
        pub fn new() -> Self {
            Self { data: Mutex::new(Vec::new()), reads: std::sync::atomic::AtomicU64::new(0) }
        }

        /// Copia del contenido completo. Solo para pruebas.
        pub fn snapshot(&self) -> Vec<u8> {
            self.data.lock().unwrap().clone()
        }

        /// Restaura el contenido completo. Solo para pruebas.
        pub fn restore(&self, bytes: Vec<u8>) {
            *self.data.lock().unwrap() = bytes;
        }

        /// Número de llamadas a `read_at` desde la creación o el último
        /// `reset_read_count`. Solo para pruebas: mide el coste de apertura
        /// contando lecturas, no tiempo.
        pub fn read_count(&self) -> u64 {
            self.reads.load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn reset_read_count(&self) {
            self.reads.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl Storage for MemStorage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let data = self.data.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                return Err(Error::Io(IoError::UnexpectedEof));
            }
            buf.copy_from_slice(&data[start..end]);
            Ok(())
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            let mut data = self.data.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&self) -> Result<()> {
            Ok(())
        }

        fn len(&self) -> Result<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }

        /// `shrink_to_fit` además de `truncate`: sin él, `Vec::truncate`
        /// baja la longitud pero conserva la CAPACIDAD, así que el medio en
        /// memoria seguiría ocupando la RAM del pico histórico y las
        /// pruebas de recuperación de espacio medirían una devolución que
        /// no ha ocurrido. Es el equivalente en memoria de devolverle los
        /// bloques al sistema de ficheros, que es de lo que trata esta
        /// operación.
        fn truncate(&self, len: u64) -> Result<()> {
            let mut data = self.data.lock().unwrap();
            let len = len as usize;
            if len < data.len() {
                data.truncate(len);
                data.shrink_to_fit();
            }
            Ok(())
        }
    }

    /// Fallo a inyectar en una escritura concreta (tarea 20). El número de
    /// escritura es un ORDINAL GLOBAL de 1 en adelante — la primera llamada
    /// a `write_at` de este medio, desde que se creó, es la 1 — para que
    /// pueda anclarse a un punto exacto de la secuencia física completa
    /// (arranque + `seed` + la transacción bajo prueba), no solo a la
    /// transacción actual.
    #[derive(Debug, Clone, Copy)]
    pub enum Fault {
        /// Falla la escritura número `n` y todas las siguientes: simula un
        /// corte de corriente. Ninguna de esas escrituras llega al medio —
        /// ver el comentario de `write_at` sobre por qué eso es exactamente
        /// lo que hace falta modelar: una vez la máquina muere, no ejecuta
        /// ni una línea más.
        AbortAt(u64),
        /// En la escritura número `write`, deposita solo los primeros
        /// `bytes` bytes en el medio y falla a partir de ahí (esa misma
        /// escritura incluida): simula una escritura desgarrada, que es lo
        /// que de verdad hace un disco al perder la corriente a mitad de un
        /// sector — algo de la escritura SÍ llega al plato, el resto no.
        ///
        /// **Digno de registrar, no de corregir** (ronda de revisión de la
        /// tarea 20): si `bytes` es mayor o igual que el contenido ÚTIL de
        /// lo que se estaba escribiendo — para una ranura de meta,
        /// `meta::META_SIZE` = 152, el resto de la página ya es relleno a
        /// cero en ambos lados — el desgarro no desgarra NADA de contenido
        /// real: lo que llega al plato es indistinguible de una escritura
        /// completa. `write_at` sigue devolviendo `Err` de todos modos (así
        /// lo define esta variante: "falla a partir de ahí", sin excepción
        /// para el caso en que ya no quede nada útil por desgarrar), así
        /// que el resultado observable es que el COMMIT QUEDA DURADERO DE
        /// VERDAD aunque `WriteTxn::commit` devuelva `Err` — correcto (los
        /// bytes llegaron), pero sorprendente para quien solo mire el
        /// `Result`. Ver
        /// `a_torn_write_of_the_meta_page_with_a_prefix_at_or_above_meta_size_lands_a_full_commit_anyway`
        /// en `tests/faults.rs`, que documenta y fija este caso por
        /// separado en vez de dejarlo como una sorpresa sin probar.
        TearAt { write: u64, bytes: usize },
    }

    /// Envuelve `MemStorage` con la capacidad de fallar una escritura
    /// concreta, o desgarrarla, bajo demanda (tarea 20).
    ///
    /// **Deliberadamente más simple que `crypto::tests::PowerLossStorage`**
    /// (tarea 17/18, con sus rondas de endurecimiento documentadas junto a
    /// ese tipo): aquel arnés modela cifrado — necesita saber cuáles de las
    /// escrituras son ranuras de meta o de cabecera para poder revertir
    /// SOLO esas al último `sync()`, porque su pregunta es "¿puede un nonce
    /// reutilizarse tras un corte?" y para responderla hace falta distinguir
    /// qué sobrevive sin sincronizar. La pregunta de esta tarea es otra: "al
    /// abortar en la escritura N, sea cual sea, ¿el contenido tras reabrir
    /// es EXACTAMENTE el del último commit confirmado?" — eso no depende de
    /// clasificar cada escritura por tipo, solo de poder fallar (o
    /// desgarrar) la escritura N-ésima de la secuencia completa, sin
    /// importar qué sea. Por eso esta variante no revierte nada por su
    /// cuenta ni distingue meta de dato: toda escritura anterior al fallo
    /// queda depositada sin condición (el propio `write_at` de
    /// `MemStorage` no tiene búfer de sistema operativo que perder), y es la
    /// prueba — no el medio — quien decide, sabiendo dónde cae la meta en
    /// la secuencia, qué punto de corte ejercita el diseño de dos ranuras.
    /// Dos arneses con la misma forma general (envolver un medio, fallar
    /// bajo demanda) pero preguntas distintas, no una duplicación accidental.
    pub struct FaultStorage {
        inner: MemStorage,
        writes: AtomicU64,
        fault: Mutex<Option<Fault>>,
    }

    impl FaultStorage {
        pub fn new(inner: MemStorage, fault: Option<Fault>) -> Self {
            Self { inner, writes: AtomicU64::new(0), fault: Mutex::new(fault) }
        }

        /// Ordinal de la última escritura emitida contra este medio, desde
        /// su creación — incluidas las que el fallo armado hizo fracasar (o
        /// desgarró). Es la cifra que la prueba usa tanto para medir cuántas
        /// escrituras hace una transacción de referencia como para anclar
        /// `Fault::AbortAt`/`Fault::TearAt` a una escritura concreta de la
        /// siguiente.
        pub fn write_count(&self) -> u64 {
            self.writes.load(Ordering::SeqCst)
        }

        pub fn set_fault(&self, fault: Option<Fault>) {
            *self.fault.lock().unwrap() = fault;
        }
    }

    impl Storage for FaultStorage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            // Ordinal 1-based de ESTA escritura: `fetch_add` devuelve el
            // valor ANTES de sumar, así que `+ 1` da el número de esta
            // llamada en la secuencia completa. Se calcula siempre, incluso
            // si acaba fallando — así `write_count()` refleja escrituras
            // INTENTADAS, que es exactamente lo que mide una corrida de
            // referencia sin fallo armado (ahí ninguna falla, así que
            // intentadas == exitosas).
            let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            let fault = *self.fault.lock().unwrap();
            match fault {
                Some(Fault::AbortAt(k)) if n >= k => Err(Error::Io(IoError::WriteZero)),
                Some(Fault::TearAt { write, bytes }) if n == write => {
                    // Parte de la escritura SÍ llega al plato: es justo lo
                    // que hace un disco real cuando pierde la corriente a
                    // mitad de un sector. `bytes` se recorta a `buf.len()`
                    // para que un valor de prueba absurdamente grande no
                    // entre en pánico por slicing fuera de rango.
                    let bytes = bytes.min(buf.len());
                    self.inner.write_at(offset, &buf[..bytes])?;
                    Err(Error::Io(IoError::WriteZero))
                }
                // Misma semántica que `AbortAt`, aplicada a partir de la
                // escritura desgarrada (excluida, ya gestionada arriba): la
                // máquina murió ahí, así que nada posterior llega tampoco.
                Some(Fault::TearAt { write, .. }) if n > write => Err(Error::Io(IoError::WriteZero)),
                _ => self.inner.write_at(offset, buf),
            }
        }

        fn sync(&self) -> Result<()> {
            // Deliberado, no un olvido (ver el brief): lo que esta prueba
            // ejercita es la pérdida de ESCRITURAS, no la de
            // sincronizaciones — `sync` de un medio real puede fallar,
            // pero ese es un fallo de E/S distinto, no un corte de
            // corriente, y mezclar los dos aquí solo complicaría el modelo
            // sin acercarlo más a lo que esta tarea pregunta.
            self.inner.sync()
        }

        fn len(&self) -> Result<u64> {
            self.inner.len()
        }

        /// **El recorte consume un ordinal de la MISMA secuencia que las
        /// escrituras**, y no es un detalle de implementación: es lo que
        /// deja apuntar un `Fault::AbortAt` a un recorte concreto igual que
        /// a cualquier otra operación física, sin que la prueba tenga que
        /// saber cuál de las dos cosas es la operación número N. Un
        /// `Db::reclaim_tail` emite escrituras (lista de libres, dos
        /// ranuras de meta) y UN recorte al final, y el barrido de
        /// `tests/faults.rs` los recorre todos por ordinal sin distinguir
        /// tipos — exactamente el mismo criterio con el que este arnés trata
        /// ya la escritura de la meta.
        ///
        /// Un `TearAt` sobre un recorte falla ENTERO, sin recortar nada: el
        /// tamaño de un fichero cambia o no cambia, no hay estado
        /// intermedio que desgarrar (ver el contrato de `Storage::truncate`).
        fn truncate(&self, len: u64) -> Result<()> {
            let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            let fault = *self.fault.lock().unwrap();
            match fault {
                Some(Fault::AbortAt(k)) if n >= k => Err(Error::Io(IoError::WriteZero)),
                Some(Fault::TearAt { write, .. }) if n >= write => {
                    Err(Error::Io(IoError::WriteZero))
                }
                _ => self.inner.truncate(len),
            }
        }
    }

    /// Ficheros que ESTE proceso tiene abiertos ahora mismo, por ruta
    /// canonicalizada.
    ///
    /// Existe porque `Db` no tiene ningún estado compartido entre asas: dos
    /// `Db` sobre el mismo fichero traen cada uno su `write_lock`, así que
    /// el escritor único deja de ser único — y dos escritores
    /// copy-on-write sobre un mismo fichero es corrupción, con cifrado o
    /// sin él. Ese daño sigue siendo motivo de sobra para este rechazo.
    ///
    /// **Lo que YA NO es (cambio de diseño a nonces aleatorios).** Hasta
    /// ese cambio había un segundo daño, peor: cada asa traía su propio
    /// contador de nonce, y los dos arrancaban en el mismo `write_counter`
    /// de la meta, así que las dos asas repartían LOS MISMOS nonces bajo la
    /// misma clave de datos y sus textos cifrados se anulaban al XOR —
    /// pérdida total de la confidencialidad, no un árbol corrupto. Hoy cada
    /// apertura sortea su propio prefijo aleatorio de 16 bytes
    /// (`crypto::NonceStream`), así que dos asas no pueden compartir un
    /// nonce ni aunque este rechazo no existiera. Comprobado en
    /// `two_opens_of_the_same_file_draw_different_prefixes` (`crypto.rs`),
    /// que es la misma propiedad sin depender de este guardián — y por eso
    /// vale también para dos PROCESOS, donde no hay guardián posible.
    ///
    /// **Solo cubre este proceso, y es todo lo que se puede cubrir aquí**
    /// (ver la sección 3.4 de la especificación, corregida en esta misma
    /// ronda): `flock(2)` no es alcanzable — `std` no lo expone, `libc`/
    /// `rustix` exigen `unsafe` (prohibido en todo el crate por
    /// `[lints.rust] unsafe_code = "forbid"`) y `fs4`/`fs2` serían una
    /// dependencia de runtime; un fichero `.lock` al lado sí sería posible
    /// con cero dependencias, pero renuncia justo a la ventaja sobre LMDB
    /// que la sección 3.4 reclama dos párrafos antes. Quien reparta un
    /// fichero entre varios PROCESOS tiene que excluirlos por su cuenta.
    ///
    /// `BTreeSet` y no `HashSet`: es `const`-construible, así que el
    /// registro es un `static` sin `OnceLock` ni inicialización perezosa, y
    /// se ahorra el estado del hasher aleatorio. Con un puñado de bases
    /// abiertas por proceso, la diferencia entre O(log n) y O(1) en una
    /// operación que ocurre dos veces por apertura no se mide.
    static OPEN_FILES: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

    /// El envenenamiento se ignora a propósito. La sección crítica es un
    /// `insert` o un `remove` y nada más — ni código del llamante ni
    /// asignaciones que puedan entrar en pánico a mitad — así que un
    /// `BTreeSet` envenenado es un `BTreeSet` íntegro. Propagarlo con
    /// `unwrap()` convertiría un pánico ajeno en "esta base ya no se puede
    /// abrir NI CERRAR en lo que queda de proceso", y en `Drop` sería un
    /// pánico durante un pánico, es decir un abort.
    fn open_files() -> MutexGuard<'static, BTreeSet<PathBuf>> {
        OPEN_FILES.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserva viva de una ruta en `OPEN_FILES`. Toda la garantía de
    /// liberación está en el `Drop` de este tipo, no en los caminos de
    /// error de nadie: una entrada fugada dejaría el fichero imposible de
    /// abrir durante el resto de la vida del proceso, que es peor que el
    /// fallo que esto corrige.
    struct PathGuard {
        path: PathBuf,
    }

    impl PathGuard {
        /// Comprueba y reserva bajo el MISMO candado: `insert` devuelve
        /// `false` si ya estaba, así que no hay ventana entre mirar y
        /// apuntarse por la que dos hilos puedan colarse a la vez.
        fn acquire(path: PathBuf) -> Result<Self> {
            if !open_files().insert(path.clone()) {
                return Err(Error::AlreadyOpen);
            }
            Ok(Self { path })
        }
    }

    impl Drop for PathGuard {
        fn drop(&mut self) {
            open_files().remove(&self.path);
        }
    }

    pub struct FileStorage {
        file: File,
        /// Nunca se lee: su único valor es el `Drop`, que devuelve la ruta
        /// al registro. Vive DENTRO de `FileStorage` para que la liberación
        /// no dependa de que nadie se acuerde de nada: el asa muere cuando
        /// muere el `Box<dyn Storage>` que la posee, y eso ocurre igual si
        /// `Db::open` devuelve `Ok` y el `Db` se suelta más tarde que si
        /// falla a medias (`BadFormat`, `VersionTooNew`, `Corrupt`, la
        /// clave equivocada de una base cifrada…) y el `Box` que recibió
        /// por valor se destruye al retornar el `Err`.
        _registry: PathGuard,
    }

    impl FileStorage {
        /// Abre `path` para lectura y escritura, creándolo si no existe, y
        /// lo reserva en el registro de este proceso: una SEGUNDA apertura
        /// del mismo fichero mientras la primera siga viva falla con
        /// `Error::AlreadyOpen` en vez de entregar un asa independiente.
        ///
        /// Esta comprobación vive aquí, y no en `Db::create`/`Db::open`,
        /// porque aquí es donde hay una RUTA: aquellos reciben un
        /// `Box<dyn Storage>` ya construido y no pueden saber qué fichero
        /// —si es que hay alguno— hay detrás. Ponerla aquí, además, cubre a
        /// cualquiera que abra el mismo fichero para algo que no sea un
        /// `Db`, y deja `MemStorage`/`FaultStorage` intactos: no tienen
        /// ruta, dos de ellos son dos bases distintas.
        pub fn open(path: &Path) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .map_err(map_io)?;
            // Canonicaliza DESPUÉS de abrir, no antes: `canonicalize` exige
            // que la ruta exista ya, y `create(true)` de arriba es
            // justamente lo que la crea la primera vez. Resuelve enlaces
            // simbólicos, `.` y `..`, y devuelve una ruta absoluta, así que
            // `base.inro` y `/tmp/x/base.inro` chocan como deben en vez de
            // pasar por dos ficheros distintos.
            let canonical = path.canonicalize().map_err(map_io)?;
            let registry = PathGuard::acquire(canonical)?;
            Ok(Self { file, _registry: registry })
        }
    }

    impl Storage for FileStorage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            read_exact_at(&self.file, offset, buf)
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            write_all_at(&self.file, offset, buf)
        }

        fn sync(&self) -> Result<()> {
            self.file.sync_all().map_err(map_io)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.file.metadata().map_err(map_io)?.len())
        }

        /// La comprobación previa NO es defensiva de más: `File::set_len`
        /// con un `len` mayor que el actual EXTIENDE el fichero con ceros
        /// (así lo define `std`), que es justo lo contrario de lo que esta
        /// operación promete — ver el contrato en el trait. Con ella,
        /// `truncate` es monótona: solo puede dejar el fichero igual o más
        /// pequeño, pase lo que pase por encima.
        fn truncate(&self, len: u64) -> Result<()> {
            if len >= self.len()? {
                return Ok(());
            }
            self.file.set_len(len).map_err(map_io)
        }
    }

    #[cfg(unix)]
    fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset).map_err(map_io)
    }

    #[cfg(unix)]
    fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset).map_err(map_io)
    }

    #[cfg(windows)]
    fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match file.seek_read(buf, offset).map_err(map_io)? {
                0 => return Err(Error::Io(IoError::UnexpectedEof)),
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn write_all_at(file: &File, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match file.seek_write(buf, offset).map_err(map_io)? {
                0 => return Err(Error::Io(IoError::WriteZero)),
                n => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::{Error, IoError};

    fn exercise<S: Storage>(s: &S) {
        s.write_at(0, b"hola").unwrap();
        s.write_at(4, b"mundo").unwrap();
        let mut buf = [0u8; 9];
        s.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"holamundo");
        assert_eq!(s.len().unwrap(), 9);
    }

    #[test]
    fn mem_storage_reads_back_what_it_wrote() {
        exercise(&MemStorage::new());
    }

    #[test]
    fn writing_past_the_end_grows_the_backing_store() {
        let s = MemStorage::new();
        s.write_at(100, b"x").unwrap();
        assert_eq!(s.len().unwrap(), 101);
        let mut buf = [0xffu8; 1];
        s.read_at(50, &mut buf).unwrap();
        assert_eq!(buf[0], 0, "el hueco se rellena con ceros");
    }

    #[test]
    fn reading_past_the_end_is_an_error() {
        let s = MemStorage::new();
        s.write_at(0, b"ab").unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(s.read_at(0, &mut buf), Err(Error::Io(IoError::UnexpectedEof)));
    }

    // ---- Registro de ficheros abiertos (ver `OPEN_FILES`) ----

    use crate::{Db, Options};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Ruta temporal única por prueba: las pruebas del mismo binario corren
    /// en paralelo y el registro es GLOBAL AL PROCESO, así que dos que
    /// compartieran fichero se refutarían entre ellas.
    fn temp_path(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let name = format!("inro-open-{tag}-{}-{n}.inro", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn opening_the_same_file_twice_in_one_process_is_refused() {
        let path = temp_path("doble");
        let first = FileStorage::open(&path).unwrap();
        assert_eq!(
            FileStorage::open(&path).err(),
            Some(Error::AlreadyOpen),
            "dos asas sobre un fichero son dos `write_lock`: el escritor unico deja de serlo"
        );
        drop(first);

        // El mismo caso por el camino que de verdad lo destapó: con un `Db`
        // vivo sobre el fichero, no hay forma de construir el medio para un
        // segundo `Db`, así que tampoco hay dos contadores de nonce.
        let db = Db::create(Box::new(FileStorage::open(&path).unwrap()), Options::default()).unwrap();
        assert_eq!(FileStorage::open(&path).err(), Some(Error::AlreadyOpen));
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// El mismo rechazo sobre una base CIFRADA. Era el caso que de verdad
    /// dolía —dos asas repartiendo los mismos nonces bajo la misma clave de
    /// datos— y desde el cambio a nonces aleatorios ya no lo es: lo que
    /// esta prueba fija ahora es que el rechazo siga ahí, porque la
    /// corrupción del árbol por dos escritores concurrentes no depende del
    /// cifrado y no se ha ido a ninguna parte. Ver el comentario de
    /// `Error::AlreadyOpen`.
    #[cfg(feature = "encryption")]
    #[test]
    fn an_encrypted_database_refuses_the_second_handle_too() {
        use crate::crypto::{Algorithm, Encryption};
        let path = temp_path("cifrada");
        let opts = Options {
            encryption: Some(Encryption { key: [7u8; 32], algorithm: Algorithm::XChaCha20Poly1305 }),
            ..Options::default()
        };
        let db = Db::create(Box::new(FileStorage::open(&path).unwrap()), opts).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(1, b"k", b"v").unwrap();
        tx.commit().unwrap();
        assert_eq!(FileStorage::open(&path).err(), Some(Error::AlreadyOpen));
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn closing_the_database_returns_its_path_to_the_registry() {
        let path = temp_path("suelta");
        let db = Db::create(Box::new(FileStorage::open(&path).unwrap()), Options::default()).unwrap();
        drop(db);
        let db = Db::open(Box::new(FileStorage::open(&path).unwrap()), Options::default()).unwrap();
        drop(db);
        // Una tercera vez: descarta que la liberación funcione una sola vez.
        drop(FileStorage::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// El caso que convertiría la corrección en algo PEOR que el fallo: si
    /// una apertura que falla DESPUÉS de reservar la ruta no la devolviera,
    /// el fichero quedaría imposible de abrir durante el resto de la vida
    /// del proceso.
    #[test]
    fn an_open_that_fails_after_registering_the_path_still_releases_it() {
        let path = temp_path("fallida");
        // Un fichero que no es una base inro: `FileStorage::open` reserva
        // la ruta y `Db::open` falla más tarde, con el `Box<dyn Storage>`
        // que recibió por valor destruyéndose al retornar el `Err`.
        std::fs::write(&path, vec![0xabu8; 4096]).unwrap();
        // `.err()`, no `unwrap_err()`: `Db` no implementa `Debug` (ni debe
        // — ver `Encryption`, que redacta su clave precisamente para no
        // acabar en un `{:?}`).
        let first = Db::open(Box::new(FileStorage::open(&path).unwrap()), Options::default())
            .err()
            .expect("un fichero de basura no puede abrirse como base");
        assert_ne!(first, Error::AlreadyOpen, "debe fallar por el contenido, no por el registro");

        let second = Db::open(Box::new(FileStorage::open(&path).unwrap()), Options::default())
            .err()
            .expect("sigue siendo basura");
        assert_eq!(second, first, "el mismo fallo, no `AlreadyOpen`: la ruta se liberó");

        // Y una apertura REHUSADA tampoco deja rastro: la reserva es de
        // quien la consiguió, y sigue siéndolo hasta que la suelta.
        let held = FileStorage::open(&path).unwrap();
        assert_eq!(FileStorage::open(&path).err(), Some(Error::AlreadyOpen));
        drop(held);
        drop(FileStorage::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// Sin canonicalizar, `dir/base.inro` y `/abs/dir/base.inro` serían dos
    /// entradas distintas del registro para un mismo fichero — es decir, el
    /// fallo intacto para quien abra por rutas escritas de dos formas.
    #[test]
    fn a_relative_and_an_absolute_path_to_the_same_file_collide() {
        // Bajo el directorio de trabajo, que es lo único que hace
        // significativa una ruta RELATIVA. `target/` ya lo produce la propia
        // compilación, así que no ensucia el árbol de fuentes.
        let dir = std::path::Path::new("target").join("inro-open-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let relative = dir.join(format!("relativa-{}.inro", std::process::id()));
        let absolute = std::env::current_dir().unwrap().join(&relative);
        let _ = std::fs::remove_file(&absolute);
        assert!(relative.is_relative() && absolute.is_absolute());

        let held = FileStorage::open(&relative).unwrap();
        assert_eq!(FileStorage::open(&absolute).err(), Some(Error::AlreadyOpen));
        drop(held);

        // Y en el otro sentido, para que no dependa de cuál se abrió antes.
        let held = FileStorage::open(&absolute).unwrap();
        assert_eq!(FileStorage::open(&relative).err(), Some(Error::AlreadyOpen));
        drop(held);
        let _ = std::fs::remove_file(&absolute);
    }

    #[test]
    fn distinct_files_stay_independently_openable() {
        let a = temp_path("distinta-a");
        let b = temp_path("distinta-b");
        let sa = FileStorage::open(&a).unwrap();
        let sb = FileStorage::open(&b).unwrap();
        exercise(&sa);
        exercise(&sb);
        drop((sa, sb));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    /// El registro es de RUTAS: `MemStorage` no tiene ninguna, y dos medios
    /// en memoria son dos bases distintas, no dos asas de la misma.
    #[test]
    fn the_registry_leaves_mem_storage_alone() {
        let uno = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let dos = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        for db in [&uno, &dos] {
            let mut tx = db.begin_write().unwrap();
            tx.put(1, b"k", b"v").unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(uno.begin_read().get(1, b"k").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(dos.begin_read().get(1, b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }
}
