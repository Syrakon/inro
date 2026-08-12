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
}

#[cfg(feature = "std")]
pub use imp_std::{Fault, FaultStorage, FileStorage, MemStorage};

#[cfg(feature = "std")]
mod imp_std {
    use super::Storage;
    use crate::{Error, IoError, Result};
    use std::fs::{File, OpenOptions};
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

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
    }

    pub struct FileStorage {
        file: File,
    }

    impl FileStorage {
        pub fn open(path: &Path) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .map_err(map_io)?;
            Ok(Self { file })
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
}
