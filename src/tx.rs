use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use std::sync::{Mutex, MutexGuard, RwLock};
use std::time::Instant;

use crate::freelist::Freelist;
use crate::header::{Geometry, FORMAT_MAJOR, MAX_PAGE_SIZE, MIN_PAGE_SIZE, FLAG_ENCRYPTED};
use crate::index::{index_key, primary_of, IndexDef, CATALOG_NS, INDEX_NS_BASE};
use crate::meta::{Meta, MetaSlot};
use crate::pager::Pager;
use crate::{Error, PageNo, Result, Storage, TxnId};

// Reexportado para que el resto del crate (y las pruebas de `crypto.rs`,
// que lo importan como `crate::tx::Encryption`) puedan nombrarlo sin
// conocer que en realidad vive en `crypto`. `Encryption` es un tipo simple
// (ver su comentario en `crypto.rs`), así que reexportarlo aquí sin
// condicionarlo a la feature `encryption` no compila nada de más — el
// reexport PÚBLICO desde la raíz del crate (`lib.rs`) sí está tras esa
// feature, que es el sitio que de verdad importa para "quien no cifra no
// puede ni nombrar el tipo desde fuera".
pub use crate::crypto::Encryption;

/// Política de sincronización a disco.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sync {
    /// Un `fsync` de páginas y otro de meta por commit. Pérdida máxima en un
    /// corte: el commit en vuelo.
    Commit,
    /// Agrupa sincronizaciones. Pérdida máxima: los commits de la última
    /// ventana. Pensado para IoT, donde sincronizar cada escritura desgasta la
    /// memoria flash. Nunca corrompe: el dato vivo no se sobrescribe.
    Interval(Duration),
    /// Sin `fsync`. Solo para pruebas y bancos.
    Never,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub page_size: u32,
    pub sync: Sync,
    pub cache_pages: usize,
    /// Clave maestra y algoritmo para el cifrado por página (tarea 17).
    /// `None` (el valor por defecto): base sin cifrar, formato idéntico al
    /// de antes de esta tarea. Con la feature `encryption` desactivada, el
    /// tipo `Encryption` no es alcanzable fuera del crate (ver `lib.rs`),
    /// así que en la práctica solo puede llegar aquí `None` — `Db::create`/
    /// `open` fallan alto con `Error::BadFormat` si alguna vez no fuera
    /// así (ver su comentario), en vez de cifrar en silencio con una
    /// implementación que no está compilada.
    pub encryption: Option<Encryption>,
}

impl Default for Options {
    fn default() -> Self {
        Self { page_size: 512, sync: Sync::Commit, cache_pages: 32, encryption: None }
    }
}

pub struct Db {
    pager: Pager,
    committed: RwLock<(Meta, MetaSlot)>,
    write_lock: Mutex<Option<WriterState>>,
    readers: Mutex<BTreeMap<TxnId, u32>>,
    sync: Sync,
    last_sync: Mutex<Instant>,
    /// Índices registrados en este proceso (tarea 16). Vacío hasta que el
    /// llamante invoca `define_index`; nunca se relee solo de disco — cada
    /// apertura debe volver a registrar sus índices, porque el extractor es
    /// código del llamante y no vive en el fichero.
    indexes: Mutex<Vec<IndexDef>>,
}

/// Estado que sobrevive entre transacciones de escritura: la lista de libres
/// no se relee de disco en cada una.
struct WriterState {
    freelist: Freelist,
    /// Contador de nonce VIVO (tarea 17, segunda ronda de revisión posterior
    /// a la primera entrega). Estado de la BASE, no de una transacción —
    /// vive aquí, no en `WriteTxn`, precisamente para que sobreviva a un
    /// aborto sin comprometerse: `WriteTxn::Drop` restaura `freelist` desde
    /// `pre_freelist`, pero NUNCA toca esto. Es justo esa propiedad —
    /// nunca retrocede, ni siquiera cuando una transacción se descarta sin
    /// `commit` — la que cierra el hallazgo BLOCKER de la segunda ronda: un
    /// aborto no puede volver a repartir un contador que una transacción
    /// muerta ya usó para sellar páginas reales en disco, porque nada
    /// rebobina este campo.
    live_counter: u64,
    /// Techo hasta el que `live_counter` puede crecer sin que haga falta
    /// otra escritura DURADERA. Solo avanza en dos momentos, los dos
    /// demostrablemente duraderos:
    /// - al abrir la base (`Db::assemble`), desde el `write_counter` de la
    ///   meta ganadora;
    /// - al extender la reserva (`Db::extend_counter_ceiling`), que
    ///   sincroniza de forma INCONDICIONAL, sin importar la política de
    ///   `Sync` configurada.
    ///
    /// Un commit normal SÍ escribe un `write_counter` más alto en la META
    /// que ya iba a escribir de todos modos (barato: viaja con una
    /// escritura que ya iba a pasar) — pero esa escritura NO actualiza este
    /// campo, porque bajo `Sync::Interval`/`Never` puede no haberse hecho
    /// durable todavía. Tratarla como si lo fuera sería reabrir exactamente
    /// el hueco HIGH que encontró la segunda ronda de revisión: el único
    /// avance de `counter_ceiling` en el que se puede confiar es el que ya
    /// se demostró en disco.
    counter_ceiling: u64,
}

/// Página de la meta B: debe caer en un sector físico de 4 KB distinto al de
/// la meta A, que vive en la página 1. Con páginas de 4 KB o más, la página 2
/// ya está en otro sector.
fn meta_b_page(page_size: u32) -> PageNo {
    core::cmp::max(2, 4096 / page_size)
}

impl Db {
    pub fn create(storage: Box<dyn Storage>, opts: Options) -> Result<Self> {
        if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&opts.page_size)
            || !opts.page_size.is_power_of_two()
        {
            return Err(Error::BadFormat);
        }
        let meta_b = meta_b_page(opts.page_size);
        // Fijo en la creación (ver `header::FLAG_ENCRYPTED`): activar el
        // cifrado más tarde exigiría reescribir todas las páginas ya
        // existentes, así que la decisión se toma aquí y no se revisita.
        let flags = if opts.encryption.is_some() { FLAG_ENCRYPTED } else { 0 };
        let geometry = Geometry {
            page_size: opts.page_size,
            format_major: FORMAT_MAJOR,
            format_minor: 0,
            flags,
            db_id: db_id(),
            created_unix: now_unix(),
            meta_a_page: 1,
            meta_b_page: meta_b,
        };
        geometry.write(storage.as_ref())?;

        let mut meta = Meta {
            txn_id: 1,
            root: 0,
            catalog_root: 0,
            freelist_head: 0,
            freelist_tail: 0,
            n_pages: meta_b + 1,
            page_size_log2: opts.page_size.trailing_zeros() as u8,
            format_major: FORMAT_MAJOR,
            flags,
            wrapped_key: None,
            // Techo inicial pre-sembrado a `COUNTER_RESERVE` para una base
            // cifrada (tarea 17, segunda ronda de revisión posterior a la
            // primera entrega) — no 0. Esta escritura YA se sincroniza sin
            // condiciones dos líneas más abajo (`storage.sync()?`, ya
            // existía antes de esta ronda), así que sembrar el techo aquí
            // es gratis: cubre de inmediato la primera `COUNTER_RESERVE` de
            // contadores sin que la primera escritura cifrada de la base
            // tenga que pagar una extensión aparte. `live_counter` arranca
            // en 0 por separado, más abajo, al construir `WriterState` — a
            // diferencia de `Db::open`, aquí no hay ninguna sesión previa
            // cuyo progreso haya que proteger, así que no hace falta
            // arrancar el contador vivo en el techo también.
            write_counter: if opts.encryption.is_some() { COUNTER_RESERVE } else { 0 },
        };
        // Genera la clave de datos y la envuelve con la maestra ANTES de
        // guardar la meta: `meta.wrapped_key` tiene que estar ya poblado
        // para que las dos ranuras se escriban con él.
        let encryption = Self::init_data_key(&opts, &mut meta)?;

        // Ambas ranuras se inicializan para que la primera apertura encuentre
        // una meta válida pase lo que pase.
        meta.store(storage.as_ref(), &geometry, MetaSlot::A)?;
        meta.store(storage.as_ref(), &geometry, MetaSlot::B)?;
        storage.sync()?;

        // `live_counter` arranca en 0, NO en `meta.write_counter`
        // (`COUNTER_RESERVE` si está cifrada): a diferencia de `Db::open`,
        // aquí no hay ninguna sesión previa cuyo progreso proteger, así que
        // no hace falta arrancar el contador vivo en el techo también —
        // ver el comentario del campo `write_counter` de `meta`, arriba.
        let writer_state = WriterState {
            freelist: Freelist::empty(),
            live_counter: 0,
            counter_ceiling: meta.write_counter,
        };
        Ok(Self::assemble(storage, geometry, meta, MetaSlot::A, opts, writer_state, encryption))
    }

    pub fn open(storage: Box<dyn Storage>, opts: Options) -> Result<Self> {
        let geometry = Geometry::read(storage.as_ref())?;
        let (mut meta, slot) = Meta::load(storage.as_ref(), &geometry)?;
        // Se desenvuelve ANTES de construir el `Pager` provisional que lee
        // la lista de libres, no solo el definitivo de `assemble`: si la
        // base está cifrada, sus páginas de lista de libres también lo
        // están (`Freelist::flush` usa `Pager::write_encrypted`, ver
        // `freelist.rs`), así que ese `Pager` provisional necesita la
        // misma clave para poder leerlas.
        let encryption = Self::open_data_key(&opts, &meta)?;
        let pager = Pager::new(storage, geometry, opts.cache_pages).with_encryption(encryption);
        let mut freelist = Freelist::load(&pager, meta.freelist_head, meta.freelist_tail)?;

        // Recuperación: las páginas más allá de `n_pages` las escribió una
        // transacción que nunca confirmó. Nadie las referencia y ningún lector
        // puede verlas, así que son reutilizables de inmediato — etiqueta 0.
        let file_pages = pager.file_pages()?;
        for p in meta.n_pages..file_pages {
            freelist.push(p, 0);
        }

        // `n_pages` tiene que avanzar hasta la extensión real del fichero, y no
        // solo por higiene. Sin esto, en cuanto la lista de libres agote esas
        // páginas recuperadas, el camino de extensión de `alloc` volvería a
        // repartir desde el `n_pages` viejo y entregaría por segunda vez una
        // página que ya está en uso. Es corrupción silenciosa, no una fuga.
        meta.n_pages = core::cmp::max(meta.n_pages, file_pages);

        // El contador VIVO arranca en el TECHO recuperado, no en "lo último
        // que se usó" (tarea 17, segunda ronda de revisión posterior a la
        // primera entrega, punto 3 del diseño corregido): no hay forma de
        // saber, solo con lo que quedó en disco, cuánto del margen bajo ese
        // techo llegó a usarse de verdad antes de una caída — así que se
        // asume el peor caso (todo, hasta el techo) y se arranca justo ahí.
        // Cualquier contador que una sesión anterior quemara cae por
        // definición por debajo de este valor, así que jamás se vuelve a
        // repartir. A diferencia de `Db::create`, aquí SÍ hay una sesión
        // previa cuyo progreso proteger.
        let writer_state = WriterState {
            freelist,
            live_counter: meta.write_counter,
            counter_ceiling: meta.write_counter,
        };

        let storage = pager.into_storage();
        Ok(Self::assemble(storage, geometry, meta, slot, opts, writer_state, encryption))
    }

    /// Toma `WriterState` ya construido, no `freelist`/`live_counter`
    /// sueltos (`cargo clippy`, `too_many_arguments`: eran 8 parámetros
    /// tras añadir `live_counter` en la segunda ronda de revisión posterior
    /// a la primera entrega de la tarea 17 — juntar los dos que de todos
    /// modos solo se usan para construir el mismo `WriterState` los deja
    /// en 7, sin perder nada: cada llamador YA tenía `meta` a mano para
    /// calcular `counter_ceiling`).
    fn assemble(
        storage: Box<dyn Storage>,
        geometry: Geometry,
        meta: Meta,
        slot: MetaSlot,
        opts: Options,
        writer_state: WriterState,
        encryption: Option<Encryption>,
    ) -> Self {
        Self {
            pager: Pager::new(storage, geometry, opts.cache_pages).with_encryption(encryption),
            committed: RwLock::new((meta, slot)),
            write_lock: Mutex::new(Some(writer_state)),
            readers: Mutex::new(BTreeMap::new()),
            sync: opts.sync,
            last_sync: Mutex::new(Instant::now()),
            indexes: Mutex::new(Vec::new()),
        }
    }

    /// Genera una clave de datos nueva y la envuelve con la maestra de
    /// `opts.encryption`, si la hay; deja `meta.wrapped_key` lista para
    /// guardarse. Devuelve la clave de datos (ya en claro, para que el
    /// `Pager` de esta misma apertura pueda usarla) o `None` si `opts` no
    /// pide cifrado.
    #[cfg(feature = "encryption")]
    fn init_data_key(opts: &Options, meta: &mut Meta) -> Result<Option<Encryption>> {
        let Some(master) = &opts.encryption else { return Ok(None) };
        let data_key = crate::crypto::generate_data_key()?;
        let wrap_nonce = crate::crypto::generate_nonce()?;
        meta.wrapped_key = Some(crate::crypto::wrap_key(&master.key, &data_key, wrap_nonce)?);
        Ok(Some(Encryption { key: data_key, algorithm: master.algorithm }))
    }

    /// Sin la feature `encryption` no hay forma de generar ni envolver una
    /// clave — `opts.encryption` solo puede ser `Some` aquí si algo dentro
    /// del propio crate lo coló sin pasar por la reexportación pública
    /// (gateada, ver `lib.rs`), porque fuera del crate el tipo `Encryption`
    /// ni siquiera es nombrable en este build. Falla alto en vez de crear
    /// una base sin cifrar en silencio cuando el llamante pidió cifrado.
    #[cfg(not(feature = "encryption"))]
    fn init_data_key(opts: &Options, _meta: &mut Meta) -> Result<Option<Encryption>> {
        if opts.encryption.is_some() {
            return Err(Error::BadFormat);
        }
        Ok(None)
    }

    /// Desenvuelve la clave de datos guardada en `meta` con la maestra de
    /// `opts.encryption`. Compara la intención del llamante (`opts`) contra
    /// lo que dice el fichero (`meta.flags & FLAG_ENCRYPTED`) en las cuatro
    /// combinaciones posibles: sin cifrar de los dos lados es el caso
    /// normal; pedir clave sobre un fichero sin cifrar, o abrir uno cifrado
    /// sin dar clave, son errores de uso — el segundo con el mismo
    /// `Error::Decrypt` que una clave incorrecta, porque para quien llama
    /// es la misma situación de fondo: "no puedo leer estas páginas sin la
    /// clave correcta".
    #[cfg(feature = "encryption")]
    fn open_data_key(opts: &Options, meta: &Meta) -> Result<Option<Encryption>> {
        let file_is_encrypted = meta.flags & FLAG_ENCRYPTED != 0;
        match (&opts.encryption, file_is_encrypted) {
            (None, false) => Ok(None),
            (None, true) => Err(Error::Decrypt { page: 0 }),
            (Some(_), false) => Err(Error::BadFormat),
            (Some(master), true) => {
                let wrapped = meta.wrapped_key.ok_or(Error::Decrypt { page: 0 })?;
                let data_key = crate::crypto::unwrap_key(&master.key, &wrapped)?;
                Ok(Some(Encryption { key: data_key, algorithm: master.algorithm }))
            }
        }
    }

    /// Mismo razonamiento que `init_data_key` sin la feature: si el fichero
    /// dice estar cifrado, o si `opts` trae una clave, no hay nada útil que
    /// hacer sin `chacha20poly1305`/`aes-gcm` compiladas — falla alto.
    #[cfg(not(feature = "encryption"))]
    fn open_data_key(opts: &Options, meta: &Meta) -> Result<Option<Encryption>> {
        if opts.encryption.is_some() || meta.flags & FLAG_ENCRYPTED != 0 {
            return Err(Error::BadFormat);
        }
        Ok(None)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Identificador único de la base. No hace falta un generador criptográfico:
/// solo debe distinguir ficheros, no resistir predicción.
fn db_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    id[..8].copy_from_slice(&nanos.to_le_bytes());
    let addr = &id as *const _ as usize as u64;
    id[8..].copy_from_slice(&addr.to_le_bytes());
    id
}

pub struct ReadTxn<'db> {
    db: &'db Db,
    meta: Meta,
}

impl Db {
    pub fn begin_read(&self) -> ReadTxn<'_> {
        let meta = self.committed.read().unwrap().0;
        *self.readers.lock().unwrap().entry(meta.txn_id).or_insert(0) += 1;
        ReadTxn { db: self, meta }
    }

    /// Snapshot del lector vivo más antiguo, o `None` si no hay lectores.
    /// Determina qué páginas libres puede reciclar el escritor.
    fn oldest_reader(&self) -> Option<TxnId> {
        self.readers.lock().unwrap().keys().next().copied()
    }

    /// Páginas leídas por el `Pager` desde que se abrió esta base. Solo
    /// para pruebas: expone `Pager::pages_read` (ver su comentario) para la
    /// prueba de coste de la tarea 15
    /// (`it_reads_far_fewer_pages_than_it_frees`), que necesita contar
    /// páginas, no medir tiempo.
    #[cfg(test)]
    pub fn pages_read(&self) -> u64 {
        self.pager.pages_read()
    }
}

impl<'db> ReadTxn<'db> {
    pub fn txn_id(&self) -> TxnId {
        self.meta.txn_id
    }

    /// Raíz cruda del árbol de datos. Plomería de página (ronda 3 de
    /// revisión de la tarea 16, mismo motivo que `WriteTxn::root`/
    /// `set_root`/`read_page`/`alloc`/`free` más abajo): fuera del crate no
    /// hay nada legítimo que hacer con un número de página suelto, y
    /// tenerlo público era justo lo que le permitía a un llamante externo
    /// reconstruir un `Cursor` sobre esta raíz saltándose `scan`, o
    /// simplemente leer estructura interna que no forma parte del
    /// contrato — el contrato es `get`/`scan`/`scan_index`. Su único
    /// llamador hoy son las pruebas de bajo nivel de `tree.rs` que montan
    /// árboles a mano; de ahí el `#[cfg(test)]`, igual que `pages_read` más
    /// arriba en este mismo `impl Db`.
    #[cfg(test)]
    pub(crate) fn root(&self) -> PageNo {
        self.meta.root
    }

    /// Sin llamador, ni siquiera en pruebas: el catálogo de índices vive en
    /// el árbol normal bajo `CATALOG_NS` (tarea 16), no en un árbol aparte
    /// enraizado aquí. El campo `meta.catalog_root` en sí sigue siendo parte
    /// del formato en disco (lo pedía el brief de la tarea 9, ver
    /// `Meta::encode`/`decode`) y se queda reservado — este accesor, sin
    /// nada que lo use, se marca explícitamente en vez de dejar el aviso de
    /// código muerto sin explicar.
    #[allow(dead_code)]
    pub(crate) fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    /// Bytes crudos de una página por número. Plomería de página: ver el
    /// comentario de `root`, arriba. `ReadTxn` también implementa
    /// `PageSource` (también `pub(crate)`, mismo motivo) para que `tree.rs`
    /// pueda leer páginas sin saber si viene de un lector o un escritor —
    /// esa es la vía que usa el código de producción; este método inherente
    /// solo lo llaman pruebas que ya tienen un `&ReadTxn` concreto en la
    /// mano.
    #[cfg(test)]
    pub(crate) fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }

    pub fn get(&self, ns: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        crate::tree::get(self, self.meta.root, &scoped(ns, key))
    }

    /// Recorrido de `[from, to)` dentro del espacio `ns`.
    ///
    /// **Desviación deliberada del brief**: la tarea proponía
    /// `pub fn scan(...) -> crate::tree::Cursor<'_, Self>`, construido con
    /// `Cursor::new(...).expect("el descenso inicial no falla en un árbol
    /// válido")`. Ese `.expect` convierte cualquier corrupción detectada
    /// durante el descenso inicial (`TreeLoop` de una pila corrupta,
    /// `PageType` de una página que no es la que dice ser, o un error de E/S
    /// del propio `read_page`) en un `panic!` de la API pública, justo la
    /// clase de fallo que este motor evita desde la tarea 5: "entrada
    /// corrupta se reporta como `Err`, nunca como una respuesta incorrecta
    /// silenciosa" (ver el comentario de `read_overflow`) — un panic es
    /// estrictamente peor que una respuesta silenciosa, porque además
    /// aborta el proceso. `get`, `put` y `delete` ya devuelven `Result` por
    /// esta misma razón; `scan` debe ser igual de consistente.
    ///
    /// `ns` se le pasa a `Cursor::new` en vez de escaparse aquí (ronda 1 de
    /// revisión, hallazgo 3): el propio cursor calcula `scoped(ns, from)` y
    /// `scoped(ns, to)` y recuerda con qué `ns` lo hizo, así que no hay
    /// forma de que el prefijo antepuesto al rango y el que se recorta de
    /// cada clave devuelta se desincronicen — antes eran dos decisiones
    /// separadas (`scoped(...)` aquí, `strip` allí) que nada obligaba a
    /// coincidir.
    pub fn scan(&self, ns: u8, from: &[u8], to: &[u8]) -> Result<crate::tree::Cursor<'_, Self>> {
        crate::tree::Cursor::new(self, self.meta.root, ns, from, to)
    }

    /// Claves primarias cuyas entradas de índice caen en `[from, to)`
    /// (tarea 16). `from`/`to` se comparan contra el valor indexado: en un
    /// índice no único eso es solo el prefijo de la entrada, nunca la clave
    /// primaria ni la longitud que le siguen, así que el orden que ve quien
    /// llama es el del valor indexado, aunque la clave real en el árbol
    /// lleve más bytes detrás.
    ///
    /// **Cuidado con el modismo `scan_index(id, v, v ++ [0xff])`** para "todo
    /// lo que vale exactamente `v`" (ronda 2 de revisión, hallazgo 9, sin
    /// arreglo — documentado): en un índice NO único la entrada completa es
    /// `v ++ primaria ++ longitud`, así que ese límite superior también es
    /// mayor que cualquier entrada cuya clave primaria empiece por el byte
    /// `0xff` — comparado byte a byte, `v` seguido de `0xff` es UN prefijo
    /// estricto de `v` seguido de `0xff` seguido de más bytes, y un prefijo
    /// estricto compara menor, así que esa fila cae fuera del rango
    /// `[from, to)` y `scan_index` no la devuelve, aunque su valor indexado
    /// sea `v` en todos los sentidos que importan. El límite en sí,
    /// `[from, to)`, es correcto y hace justo lo que dice; el problema es
    /// solo de este modismo concreto para construirlo. Quien necesite
    /// cubrir el rango entero de un valor indexado sin este hueco debe
    /// construir `to` con suficientes bytes `0xff` de sobra como para
    /// exceder cualquier clave primaria real posible, no solo uno.
    pub fn scan_index(&self, id: u8, from: &[u8], to: &[u8]) -> Result<Vec<Vec<u8>>> {
        let def = self
            .db
            .indexes
            .lock()
            .unwrap()
            .iter()
            .copied()
            .find(|d| d.id == id)
            .ok_or(Error::BadFormat)?;

        let mut out = Vec::new();
        let mut cursor = self.scan(def.index_ns(), from, to)?;
        while let Some((k, v)) = cursor.next()? {
            out.push(if def.unique { v } else { primary_of(&k)?.to_vec() });
        }
        Ok(out)
    }
}

/// Antepone el byte de espacio de claves. Es la única transformación entre la
/// clave que ve el usuario y la que vive en el árbol. `pub(crate)` porque
/// `tree::Cursor::new` también la necesita (ronda 1 de revisión, hallazgo 3):
/// el cursor calcula su propio prefijo internamente en vez de recibirlo ya
/// aplicado, así que esta es la única función que sabe construirlo.
pub(crate) fn scoped(ns: u8, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + key.len());
    k.push(ns);
    k.extend_from_slice(key);
    k
}

/// Acceso a páginas común a lectores y escritores, para que el árbol se
/// escriba una sola vez y sirva a ambos.
///
/// `pub(crate)` (ronda 3 de revisión de la tarea 16): si este trait fuera
/// público, un llamante externo podría invocar `read_page` a través de él
/// (`PageSource::read_page(&tx, pagina)`) igual que a través del método
/// inherente, sin que importara que ESE método inherente pasara a
/// `pub(crate)` — la visibilidad de un método de trait la fija el trait
/// entero, no cada implementación por separado, así que dejar el trait
/// público habría dejado la misma puerta abierta con otro nombre.
pub(crate) trait PageSource {
    fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>>;
}

impl PageSource for ReadTxn<'_> {
    fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }
}

impl PageSource for WriteTxn<'_> {
    fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }
}

impl Drop for ReadTxn<'_> {
    fn drop(&mut self) {
        let mut readers = self.db.readers.lock().unwrap();
        if let Some(n) = readers.get_mut(&self.meta.txn_id) {
            *n -= 1;
            if *n == 0 {
                readers.remove(&self.meta.txn_id);
            }
        }
    }
}

/// Cuánto avanza `Db::extend_counter_ceiling` el techo de contador de nonce
/// cada vez que lo extiende (tarea 17, SEGUNDA ronda de revisión posterior a
/// la primera entrega — el diseño de la primera ronda, que reservaba esto
/// por transacción en `begin_write`, tenía dos defectos BLOCKER propios:
/// una extensión a mitad de transacción podía publicar el `root` a medio
/// hacer de esa MISMA transacción como si fuera un commit real, y un aborto
/// no hacía retroceder nada, así que la siguiente transacción volvía a
/// repartir los contadores que la abortada ya había usado. Ver el
/// comentario de `WriterState::live_counter` para el diseño corregido).
///
/// Con el diseño corregido, esto YA NO es "cuánto se reserva por
/// transacción": es cuánto dura cada extensión, un evento raro e
/// independiente de los límites de transacción — la mayoría de las
/// transacciones no llegan a disparar ni una. Elegido con la medición real
/// de esta ronda de revisión: 45 000 `put` en una transacción quemaron
/// 134 218 contadores (≈3 por `put`, consistente con "un lote de mil
/// registros asigna del orden de cuatro mil páginas", ya documentado en
/// `alloc` más abajo) y la carga de referencia de este proyecto son
/// podas de cientos de miles de entradas por nodo y día (ver el comentario
/// de `WriteTxn::delete_range`) — un solo `COUNTER_RESERVE` tiene que cubrir
/// lotes de ESE orden sin extender más que alguna vez, no solo el caso de
/// prueba de 45 000. Un millón cubre, al ritmo medido, un lote de en torno a
/// 330 000 `put` antes de necesitar una sola extensión — muy por encima de
/// lo medido, con margen — y sigue siendo irrelevante frente a `u64`: mil
/// transacciones por segundo sin parar durante un siglo, si CADA una
/// disparase una extensión (no es el caso: las extensiones son mucho menos
/// frecuentes que las transacciones), consumirían del orden de 3×10¹⁸ — un
/// 17 % de `u64::MAX` (≈1,8×10¹⁹) en el peor caso, exageradamente pesimista.
const COUNTER_RESERVE: u64 = 1_000_000;

pub struct WriteTxn<'db> {
    db: &'db Db,
    guard: MutexGuard<'db, Option<WriterState>>,
    meta: Meta,
    slot: MetaSlot,
    /// Pares `(página, contador de nonce)` ya sellados en esta transacción
    /// (tarea 17). Comprobación defensiva, no la fuente real de la garantía
    /// de unicidad — esa la da la construcción de `WriterState::live_counter`
    /// (estrictamente creciente, nunca retrocede — ver su comentario) — pero
    /// convierte esa construcción de una suposición no comprobada a algo que
    /// `write_page` verifica en cada escritura: si algún cambio futuro
    /// rompe el incremento, esto lo detecta con un error en vez de sellar
    /// dos páginas con el mismo nonce en silencio.
    ///
    /// **Solo se puebla si la base está cifrada** (segunda ronda de
    /// revisión posterior a la primera entrega, hallazgo sobre coste de
    /// memoria: en una transacción de 45 000 `put` esto llegaba a costar
    /// del orden de 1,6 MB, sin dar ninguna protección real a una base SIN
    /// cifrar, donde el contador ni siquiera se usa). Ver `write_page`.
    written: BTreeSet<(PageNo, u64)>,
    /// Copia de la lista de libres tal como estaba antes de esta
    /// transacción. `alloc`/`free` mutan `guard`'s `WriterState` en el
    /// sitio, no una copia local — es el mismo objeto que sobrevive entre
    /// transacciones (ver `WriterState`) — así que si esta transacción se
    /// descarta sin `commit`, `Drop` la restaura desde aquí. Barata: `Clone`
    /// de `Freelist` solo copia lo materializado en memoria.
    pre_freelist: Freelist,
    /// Se pone a `true` solo al final de un `commit` que ya tocó la meta
    /// confirmada. Mientras sea `false`, `Drop` deshace cualquier cambio que
    /// esta transacción le haya hecho a la lista de libres persistente.
    committed: bool,
    /// Todas las páginas que ESTA transacción ha asignado alguna vez, sin
    /// importar de dónde salieron (lista de libres persistente o extensión
    /// de fichero). `free` la consulta para decidir si una página liberada
    /// va al conjunto propio (`own_free`, reciclable de inmediato) o a la
    /// lista de libres persistente (protegida hasta el commit, ver
    /// `alloc`). `BTreeSet`, no un escaneo lineal: un lote de miles de
    /// operaciones asigna y libera del orden de miles de páginas, y una
    /// comprobación de pertenencia por página convertiría esa carga en
    /// cuadrática si fuera O(n).
    self_allocated: BTreeSet<PageNo>,
    /// Páginas que esta transacción asignó y ya liberó ella misma: nunca
    /// llegaron a formar parte del árbol confirmado, así que son
    /// reciclables de inmediato, sin esperar al commit. `alloc` las
    /// consume antes de tocar la lista de libres persistente. Puro LIFO
    /// (siempre se saca la última que se metió) y acotado por lo que esta
    /// transacción llega a asignar, así que un `Vec` con `push`/`pop`
    /// basta — no hace falta orden ni pertenencia sobre este conjunto, eso
    /// ya lo resuelve `self_allocated`.
    ///
    /// **Es precisamente lo que hace que reutilizar `txn_id` como nonce
    /// fuera inseguro** (primera ronda de revisión posterior a la primera
    /// entrega, hallazgo BLOCKER): una página que sale de aquí en `alloc` y
    /// se vuelve a escribir con `write_page` recibía un `txn_id` — el de
    /// ESTA transacción — idéntico al que ya tenía la primera vez que se
    /// escribió, dentro de la MISMA transacción. Con un lote de cientos de
    /// `put` en una sola transacción esto no es un caso raro: es el camino
    /// normal, y una sola página puede reciclarse así decenas o cientos de
    /// veces (121 veces sobre 200 `put`, medido). De ahí que el nonce ya no
    /// se derive de `txn_id`, sino del contador vivo de la base — ver
    /// `WriterState::live_counter`.
    own_free: Vec<PageNo>,
}

impl Db {
    pub fn begin_write(&self) -> Result<WriteTxn<'_>> {
        // `try_lock` distingue dos causas muy distintas de fallo (ronda 2 de
        // revisión, hallazgo 7): `WouldBlock` es un escritor legítimo en
        // curso — reintentar más tarde tiene sentido — pero `Poisoned`
        // significa que una transacción anterior entró en pánico con este
        // candado tomado (el sitio más probable: un extractor de índice
        // caprichoso, ver el comentario de `IndexDef::extract`) y el candado
        // de la biblioteca estándar queda envenenado PARA SIEMPRE, no solo
        // hasta que el otro escritor termine. Colapsar los dos casos en
        // `WriterBusy`, como hacía antes, convertía ese envenenamiento en un
        // ladrillo silencioso: cada apertura posterior fallaría con un
        // mensaje que invita a reintentar, cuando reintentar nunca
        // funcionará.
        let guard = match self.write_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Err(Error::WriterBusy),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::WriterPoisoned),
        };
        let (mut meta, slot) = *self.committed.read().unwrap();
        meta.txn_id += 1;
        let pre_freelist = guard
            .as_ref()
            .expect("el estado del escritor siempre está presente")
            .freelist
            .clone();

        // Sin nada que hacer con el contador de nonce aquí (segunda ronda
        // de revisión posterior a la primera entrega): a diferencia de la
        // primera ronda, `begin_write` ya NO reserva nada — el contador
        // vivo vive en `WriterState`, sobrevive tal cual entre
        // transacciones (abortadas o no), y solo se extiende sobre la
        // marcha si hace falta, dentro de `write_page`/`commit`. Ver
        // `WriterState::live_counter`.
        Ok(WriteTxn {
            db: self,
            guard,
            meta,
            slot,
            written: BTreeSet::new(),
            pre_freelist,
            committed: false,
            self_allocated: BTreeSet::new(),
            own_free: Vec::new(),
        })
    }

    /// Extiende el techo de contador de nonce cuando el contador vivo está
    /// a punto de alcanzarlo (tarea 17, segunda ronda de revisión posterior
    /// a la primera entrega). Escribe una meta que es una COPIA EXACTA de
    /// la última meta CONFIRMADA (`self.committed`, leída aquí mismo, en el
    /// momento de la llamada) — root, lista de libres, `n_pages`, `txn_id`,
    /// todo sin tocar salvo `write_counter` — en la ranura inactiva
    /// respecto a esa meta confirmada, y sincroniza de forma INCONDICIONAL,
    /// sin mirar la política de `Sync`.
    ///
    /// **Nunca la meta de la transacción en curso.** La primera ronda de
    /// revisión encontró aquí un hallazgo BLOCKER propio: pasar la meta
    /// DE LA TRANSACCIÓN EN CURSO (con su `root` ya cambiado a medio hacer)
    /// hacía que, si el proceso moría antes del commit real, `Meta::load`
    /// recuperase esa mitad de transacción como si fuera un commit legítimo
    /// — pérdida de datos sin ni siquiera necesitar una caída, un simple
    /// `Drop` bastaba para dejarlo en ese estado. Usar SIEMPRE la última
    /// meta confirmada de verdad, con el `txn_id` intacto, hace que esta
    /// escritura nunca pueda representar más que "lo que ya estaba
    /// confirmado, con el contador más alto" — jamás una transacción a
    /// medias.
    ///
    /// **Por qué es seguro que las dos ranuras compartan `txn_id`.** Tras
    /// esta llamada, la ranura activa (con `Db.committed` sin tocar) y la
    /// inactiva (recién escrita aquí) tienen el MISMO `txn_id` pero
    /// `write_counter` distinto — `Meta::load` necesita el desempate de
    /// "mismo `txn_id`, prefiere el `write_counter` más alto" (ver su
    /// comentario) precisamente para este caso: las dos describen el MISMO
    /// árbol confirmado, así que preferir el contador más alto solo avanza
    /// el techo, nunca adopta trabajo a medias.
    ///
    /// **Por qué la sincronización es incondicional.** Es la única garantía
    /// real de que un nonce nunca se reutiliza tras una caída, sea cual sea
    /// el modo de `Sync` elegido — `Sync::Never`/`Interval` aceptan PERDER
    /// las últimas transacciones tras un corte, pero eso no cubre romper la
    /// confidencialidad de páginas que sí llegaron a sobrevivir en el medio
    /// (segunda ronda de revisión, hallazgo HIGH). Ocurre aproximadamente
    /// una vez cada `COUNTER_RESERVE` escrituras (ver su comentario), así
    /// que el coste es insignificante incluso para IoT.
    fn extend_counter_ceiling(&self, from: u64) -> Result<u64> {
        let ceiling = from.checked_add(COUNTER_RESERVE).ok_or(Error::Full)?;
        let (committed_meta, committed_slot) = *self.committed.read().unwrap();
        let mut extension = committed_meta;
        extension.write_counter = ceiling;
        let target = committed_slot.other();
        let geometry = *self.pager.geometry();
        extension.store_via(&self.pager, &geometry, target)?;
        self.pager.sync()?;
        Ok(ceiling)
    }
}

/// Deshace, para una transacción de escritura abortada, cualquier mutación
/// que `alloc` (vía `pop_refill`) o `free` le hayan hecho ya a la lista de
/// libres persistente. Sin esto, una página liberada por una transacción que
/// nunca confirma queda marcada libre para siempre mientras la meta
/// confirmada la sigue señalando como viva — dos dueños a la vez — o una
/// página reciclada de la lista de libres por esa transacción se pierde para
/// siempre, porque ni la recuperación al abrir (que solo mira más allá de
/// `n_pages`) ni nada más vuelve a ofrecerla.
impl Drop for WriteTxn<'_> {
    fn drop(&mut self) {
        if !self.committed
            && let Some(state) = self.guard.as_mut()
        {
            state.freelist = core::mem::replace(&mut self.pre_freelist, Freelist::empty());
        }
    }
}

impl<'db> WriteTxn<'db> {
    pub fn txn_id(&self) -> TxnId {
        self.meta.txn_id
    }

    /// Plomería de página cruda (ronda 3 de revisión de la tarea 16, junto
    /// con `set_root`/`catalog_root`/`set_catalog_root`/`read_page`/
    /// `write_page`/`alloc`/`free` más abajo). Antes de esta ronda, esto era
    /// `pub`, y la revisión demostró exactamente el problema: con `set_root`
    /// y `write_page` públicos, cualquiera puede construir una página a
    /// mano, escribirla, y apuntar la raíz del árbol a ella sin pasar por
    /// `put`/`delete` — es decir, sin que ningún índice se entere. Esa es
    /// justo la garantía que la tarea 16 existe para dar, así que dejarla
    /// bypasseable por una vía pública la volvía condicional a que quien
    /// llama no usara una API que el propio crate anunciaba. `pub(crate)`
    /// cierra el camino sin tocar ni una sola prueba interna.
    ///
    /// El código de producción no llama ni siquiera a la versión
    /// `pub(crate)`: `put_raw`/`delete_raw` leen y escriben `self.meta.root`
    /// directamente (acceso de campo, mismo módulo), y las funciones de
    /// `tree.rs` reciben `root: PageNo` como parámetro explícito en vez de
    /// pedírselo a un `WriteTxn`. El único llamador real son las pruebas de
    /// bajo nivel de `tree.rs`, que montan árboles a mano página a página —
    /// de ahí el `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn root(&self) -> PageNo {
        self.meta.root
    }

    #[cfg(test)]
    pub(crate) fn set_root(&mut self, root: PageNo) {
        self.meta.root = root;
    }

    /// Sin llamador, ni siquiera en pruebas — ver el comentario gemelo en
    /// `ReadTxn::catalog_root`.
    #[allow(dead_code)]
    pub(crate) fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    #[allow(dead_code)]
    pub(crate) fn set_catalog_root(&mut self, root: PageNo) {
        self.meta.catalog_root = root;
    }

    fn state(&mut self) -> &mut WriterState {
        self.guard.as_mut().expect("el estado del escritor siempre está presente")
    }

    /// Tamaño FÍSICO de página fijado al crear la base. Nadie en `tree.rs`
    /// debe usar este método para decidir cuánto cabe en una página: eso es
    /// `logical_page_size`, más abajo. Se conserva `pub` porque sigue
    /// siendo información legítima (p. ej. para calcular el tamaño de
    /// fichero desde fuera), pero ya no lo llama ningún camino que
    /// construya páginas.
    pub fn page_size(&self) -> u32 {
        self.db.pager.geometry().page_size
    }

    /// Bytes útiles de una página lógica: lo que de verdad cabe en una
    /// página una vez descontado el prefijo de cifrado, si lo hay (tarea
    /// 17). `tree.rs` (`emit`, `write_overflow`, `free_overflow`, `put`) y
    /// `freelist.rs` (`Freelist::flush`) lo usan para construir páginas y
    /// para el límite de tamaño de clave — TODO lo que antes usaba
    /// `page_size()` para esos dos fines ahora usa este método. Sin cifrado
    /// coincide con `page_size()`.
    pub fn logical_page_size(&self) -> u32 {
        self.db.pager.logical_page_size()
    }

    /// Total de páginas que ha llegado a tener el fichero hasta ahora
    /// (vivas o libres). Cota superior del número de páginas DISTINTAS
    /// alcanzables desde cualquier raíz de un árbol legítimo: en un árbol
    /// propiamente dicho — sin aliasing, cada página con un único padre —
    /// nunca hace falta visitar más páginas internas de las que existen en
    /// el fichero. `free_subtree` y `delete_range_rec` (`tree.rs`, tarea
    /// 15) la usan para acotar su trabajo total frente a un DAG corrupto
    /// que comparte hijos entre nodos distintos: ver `RangeBudget` ahí para
    /// el razonamiento completo de por qué esta cota concreta no rechaza
    /// nunca un recorrido legítimo, por grande que sea.
    pub(crate) fn n_pages(&self) -> u32 {
        self.meta.n_pages
    }

    /// Última página reservada del fichero: la cabecera es la página `0`,
    /// las dos ranuras de meta viven en `1` y `meta_b_page` (con hueco sin
    /// usar entre medias si `page_size` es menor que 4 KB — ver
    /// `meta_b_page` más arriba en este fichero) — así que ninguna página
    /// `<= meta_b_page` es jamás un hijo legítimo de un nodo interno.
    /// `pub(crate)`: la usa `tree::validate_child` (tarea 15, ronda 2 de
    /// revisión, hallazgo 1) para rechazar un hijo corrupto que caiga en
    /// una de las ranuras de meta, no solo en la página `0` — se lee de la
    /// geometría del `Pager` en vez de fijarla a un número, porque
    /// `meta_b_page` se mueve cuando el fichero crece más allá de 4 KB de
    /// `page_size`.
    pub(crate) fn last_reserved_page(&self) -> PageNo {
        self.db.pager.geometry().meta_b_page
    }

    /// Páginas en uso ahora mismo: asignadas menos libres. Solo para
    /// pruebas, para poder afirmar sobre liberaciones (p. ej. que borrar o
    /// reemplazar un valor de overflow libera de verdad su cadena vieja).
    ///
    /// Cuenta las DOS bolsas de páginas libres, no solo `state().freelist`:
    /// una página que esta misma transacción asignó y ya liberó ella misma
    /// va a `own_free`, no a la lista persistente (ver `free`), así que
    /// contar solo la lista persistente sobrestima "en uso" en exactamente
    /// ese número — precisamente el patrón de todas las pruebas de esta
    /// función (`alloc` y `free` dentro de la misma transacción sin
    /// confirmar, como al sustituir o borrar un valor de overflow que la
    /// propia transacción acaba de escribir). Sin esto, ninguna de esas
    /// pruebas vería bajar el conteo nunca, con o sin fuga real.
    #[cfg(test)]
    pub fn pages_in_use(&mut self) -> u32 {
        let n = self.meta.n_pages;
        let free = self.state().freelist.len() as u32 + self.own_free.len() as u32;
        n - free
    }

    /// Toma una página libre reutilizable o extiende el fichero.
    ///
    /// Dos fuentes, en orden. Primero el conjunto propio (`own_free`):
    /// páginas que esta misma transacción asignó y ya liberó ella misma.
    /// Nunca llegaron a formar parte del árbol confirmado — la meta vieja
    /// no las referencia — así que reutilizarlas no puede dañar nada tras
    /// un corte, y no hace falta esperar a ningún commit. Esta distinción
    /// no es un refinamiento opcional: el camino de inserción copy-on-write
    /// libera el camino raíz→hoja en cada `put`, así que un lote de mil
    /// registros asigna del orden de cuatro mil páginas y libera casi
    /// todas dentro de la misma transacción. Sin reciclarlas de inmediato,
    /// el fichero crecería unos 16 MB por lote con páginas de 4 KB — en un
    /// motor cuyo objetivo es justo el mínimo consumo de disco.
    ///
    /// Si `own_free` está vacío, la lista de libres persistente, con la
    /// meta confirmada contando como lector — el más importante: si esta
    /// transacción no llega a confirmar, la recuperación monta por ella,
    /// así que hay un lector implícito en el último commit hasta que esta
    /// acabe. Sin ese suelo, una página liberada por esta transacción pero
    /// todavía viva en el árbol confirmado en N-1 se reutilizaría en
    /// cuanto no hay lectores reales, el escritor la sobrescribiría, y un
    /// corte antes del commit dejaría la meta N-1 apuntando a basura.
    /// `WriteTxn::Drop` no lo repara — deshace la lista de libres en
    /// memoria, no lo que ya se escribió en disco — y un corte de
    /// corriente nunca llega a ejecutar `Drop`. `min` con el lector real
    /// más antiguo (si lo hay) conserva ese límite tal cual: la meta
    /// confirmada nunca es más reciente que cualquier lector real vivo.
    ///
    /// Cualquier página que salga de aquí, sea cual sea la fuente, se
    /// registra en `self_allocated`: en cuanto esta transacción la posee,
    /// liberarla de nuevo (dentro de la misma transacción) es siempre
    /// seguro y debe ir a `own_free`, no a la lista persistente — ver
    /// `free`.
    pub(crate) fn alloc(&mut self) -> Result<PageNo> {
        if let Some(p) = self.own_free.pop() {
            return Ok(p);
        }

        let committed_txn = self.db.committed.read().unwrap().0.txn_id;
        let oldest = Some(match self.db.oldest_reader() {
            Some(r) => core::cmp::min(r, committed_txn),
            None => committed_txn,
        });
        let pager = &self.db.pager;
        let p = if let Some(p) = self.state().freelist.pop_refill(pager, oldest)? {
            p
        } else {
            let p = self.meta.n_pages;
            self.meta.n_pages = p.checked_add(1).ok_or(Error::Full)?;
            p
        };
        self.self_allocated.insert(p);
        Ok(p)
    }

    /// Marca `page` como libre a partir de esta transacción.
    ///
    /// Si la asignó esta misma transacción (`self_allocated`), va al
    /// conjunto propio y vuelve a estar disponible de inmediato: nunca la
    /// vio la meta confirmada, así que no hay nada que proteger. Si venía
    /// de antes de esta transacción — del árbol confirmado — va a la lista
    /// de libres persistente etiquetada con esta transacción y no se
    /// reutiliza hasta que el commit la haga durable (ver `alloc`).
    pub(crate) fn free(&mut self, page: PageNo) {
        if self.self_allocated.contains(&page) {
            self.own_free.push(page);
        } else {
            let txn = self.meta.txn_id;
            self.state().freelist.push(page, txn);
        }
    }

    pub(crate) fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }

    /// `bytes` debe medir `logical_page_size()`. Sella (si procede) con un
    /// contador de nonce nuevo por cada llamada — NO con `self.meta.txn_id`
    /// (primera ronda de revisión posterior a la primera entrega, hallazgo
    /// BLOCKER: `txn_id` es el mismo para toda la transacción, y
    /// `WriteTxn::alloc` recicla `own_free` — la MISMA página puede
    /// escribirse muchas veces dentro de una sola transacción, ver el
    /// comentario de `own_free`) — así que el par `(página, contador)`
    /// nunca se repite sin importar cuántas veces se reescriba la misma
    /// página dentro de esta transacción. El contador en sí (`advance_counter`,
    /// `WriterState::live_counter`) sigue avanzando en cada llamada, con
    /// cifrado o sin él — barato, sin E/S — pero el guardián `written`, que
    /// SÍ cuesta memoria real en una transacción grande, solo se puebla si
    /// la base está cifrada (segunda ronda de revisión, hallazgo sobre
    /// coste de memoria — ver el comentario de `written`).
    pub(crate) fn write_page(&mut self, page: PageNo, bytes: &[u8]) -> Result<()> {
        let encrypted = self.db.pager.is_encrypted();
        let db = self.db;
        let counter = {
            let state = self.state();
            Self::advance_counter(db, &mut state.live_counter, &mut state.counter_ceiling)?
        };
        if encrypted && !self.written.insert((page, counter)) {
            // Matemáticamente inalcanzable si `advance_counter` incrementa
            // correctamente (ver su comentario) — comprobación defensiva,
            // no la fuente de la garantía. Ver el comentario de `written`.
            return Err(Error::NonceReuse { page });
        }
        self.db.pager.write_encrypted(page, counter, bytes)?;
        Ok(())
    }

    /// Núcleo de la asignación de contador de nonce, compartido por
    /// `write_page` y por el cierre que `commit` le pasa a
    /// `Freelist::flush`. Recibe referencias sueltas a los dos campos de
    /// `WriterState` que le hacen falta, no `&mut WriterState` entero ni
    /// `&mut WriteTxn`: así el compilador ve préstamos disjuntos de
    /// `state.live_counter`/`state.counter_ceiling` por un lado y
    /// `state.freelist` por otro en `commit`, que necesita las dos cosas a
    /// la vez (el cierre que arma para `Freelist::flush` sigue viva
    /// mientras `state.freelist.flush(...)` está en curso).
    ///
    /// Comprueba `db.pager.is_encrypted()` ella misma, no cada llamador por
    /// separado (segunda ronda de revisión posterior a la primera entrega):
    /// así que `write_page` Y el cierre de `commit` quedan protegidos por
    /// igual sin duplicar la comprobación — sin cifrado, `counter_ceiling`
    /// nace en 0 igual que `live_counter` (`Db::create`), así que sin esta
    /// comprobación la PRIMERA llamada de cualquiera de los dos dispararía
    /// una extensión — con su sincronización incondicional — para una base
    /// que nunca usa el contador para nada.
    fn advance_counter(db: &Db, live_counter: &mut u64, counter_ceiling: &mut u64) -> Result<u64> {
        if db.pager.is_encrypted() && *live_counter >= *counter_ceiling {
            *counter_ceiling = db.extend_counter_ceiling(*counter_ceiling)?;
        }
        let c = *live_counter;
        *live_counter += 1;
        Ok(c)
    }

    /// Escritura sin mantenimiento de índices. `put` (más abajo) la envuelve
    /// para actualizar también los índices secundarios dentro de la misma
    /// transacción; `define_index` también la usa directamente para escribir
    /// el catálogo, que nunca está indexado.
    fn put_raw(&mut self, ns: u8, key: &[u8], value: &[u8]) -> Result<()> {
        let full = scoped(ns, key);
        let root = crate::tree::put(self, self.meta.root, &full, value)?;
        self.meta.root = root;
        Ok(())
    }

    /// Borrado sin mantenimiento de índices. Ver `put_raw`.
    fn delete_raw(&mut self, ns: u8, key: &[u8]) -> Result<bool> {
        let full = scoped(ns, key);
        let (root, existed) = crate::tree::delete(self, self.meta.root, &full)?;
        self.meta.root = root;
        Ok(existed)
    }

    /// Escribe `key`/`value` en `ns` y mantiene, dentro de la MISMA
    /// transacción, cualquier índice secundario definido sobre `ns` (tarea
    /// 16) — esa atomicidad es lo único que un índice mantenido a mano con
    /// prefijos de clave no puede dar.
    ///
    /// **Contrato de error, igual que `tree::put` (ver su comentario): si
    /// esta función devuelve `Err`, abandona la transacción — déjala caer
    /// sin `commit` — en vez de reintentar sobre el mismo `tx`.** No hace
    /// falta para el caso más peligroso, el que motivó este comentario: una
    /// clave de índice no único es `indexado + primaria + 2`, y ambas
    /// mitades pueden ser individualmente legales (`page_size / 4` cada una,
    /// tarea 11) y aun así superar el límite juntas. Ese caso, y una
    /// violación de unicidad, se comprueban ENTEROS antes de mutar ninguna
    /// página (ver el bucle de más abajo): si van a fallar, fallan limpio,
    /// sin haber tocado el dato ni ningún índice, exactamente como ya hace
    /// `tree::put` con una clave primaria de sobra. El contrato de abandonar
    /// la transacción cubre lo que queda: un error real de motor (`Corrupt`,
    /// `Full`) a mitad de aplicar las mutaciones ya planeadas, el mismo tipo
    /// de fallo catastrófico que ya obliga a abandonar cualquier `put`/
    /// `delete` de este motor.
    ///
    /// **Nota sobre `KeyTooLarge` (ronda 2 de revisión, hallazgo 8, sin
    /// arreglo — documentado):** esta función reutiliza la misma variante
    /// `Error::KeyTooLarge { len, max }` que usa `tree::put` para la clave
    /// primaria, así que un `Err` de este tipo no dice POR SÍ SOLO si lo
    /// rechazó la clave primaria o una entrada de algún índice, ni cuál. Es
    /// una limitación real, de prioridad baja: `len`/`max` siguen siendo
    /// correctos y suficientes para saber "esta escritura no cabe", que es
    /// la información que importa para decidir qué hacer a continuación
    /// (nada la vuelve a intentar igual). Distinguirlo exigiría o una nueva
    /// variante de error o añadir un campo a esta, cualquiera de las dos
    /// cosas un cambio de la forma pública de `Error` fuera del alcance de
    /// esta ronda.
    pub fn put(&mut self, ns: u8, key: &[u8], value: &[u8]) -> Result<()> {
        let defs = self.db.indexes_for(ns);
        if defs.is_empty() {
            return self.put_raw(ns, key, value);
        }

        // `logical_page_size`, no `page_size` (tarea 17): es el tamaño con
        // el que `tree::put` construye páginas de verdad (ver su propio
        // `max_key`), así que este límite tiene que coincidir con el suyo o
        // una base cifrada aceptaría aquí una clave de índice que
        // `tree::put` rechazaría después, ya con la entrada vieja borrada
        // (ver el comentario de la fase de aplicación, más abajo).
        let max_key = self.logical_page_size() / 4;

        // Clave primaria demasiado grande (ronda 2 de revisión, hallazgo 3):
        // en un índice único la entrada de índice es SOLO el valor indexado
        // — la clave primaria viaja como valor, nunca como parte de la
        // clave de índice — así que el chequeo de tamaño de más abajo, que
        // solo mira entradas de índice, no la ve nunca. Sin este chequeo
        // aparte, una clave primaria de sobra pasaba la fase de
        // planificación entera, la entrada de índice se llegaba a escribir
        // de verdad en la fase de aplicación, y solo el último paso
        // (`put_raw(ns, key, value)`) fallaba — dejando esa entrada huérfana
        // en memoria si quien llama no abandonaba la transacción, la misma
        // clase de mutación prematura que el resto de esta función existe
        // para evitar. `1 +` porque `scoped()` antepone el byte de `ns`
        // antes de que la clave llegue a `tree::put`, que es quien de verdad
        // aplica este límite (ver su comentario) — comprobarlo aquí sin ese
        // `+1` habría aceptado una clave que `tree::put` iba a rechazar de
        // todas formas, un byte más allá del límite real.
        let full_key_len = 1 + key.len() as u32;
        if full_key_len > max_key {
            return Err(Error::KeyTooLarge { len: full_key_len, max: max_key });
        }

        let previous = self.get(ns, key)?;

        // Fase de planificación: solo lecturas, ninguna página se toca
        // todavía. Recoge qué entradas de índice hay que borrar (las viejas,
        // derivadas del valor anterior — su tamaño ya se validó cuando se
        // insertaron, así que borrarlas nunca puede fallar por tamaño) y
        // cuáles insertar (las nuevas, derivadas de `value`), validando de
        // paso el tamaño de cada una nueva y, en un índice único, que no
        // colisione con la de OTRA fila.
        //
        // La comprobación de unicidad compara la clave primaria ALMACENADA,
        // no solo si la entrada existe: así una fila que se reescribe con el
        // mismo valor indexado que ya tenía (p. ej. solo cambió una parte no
        // indexada del valor) no se confunde consigo misma. Comparar solo
        // existencia obligaría a borrar la entrada vieja ANTES de comprobar
        // duplicados para que este caso no fallara — y borrar antes de
        // validar es exactamente la mutación prematura que este bloque
        // entero existe para evitar.
        let mut deletions: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut insertions: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();

        for def in &defs {
            if let Some(old) = &previous {
                for ik in (def.extract)(key, old) {
                    deletions.push((def.index_ns(), index_key(def, &ik, key)));
                }
            }
            for ik in (def.extract)(key, value) {
                let entry = index_key(def, &ik, key);
                // `+ 1`: mismo motivo que arriba — la entrada de índice
                // también pasa por `scoped()` (bajo `def.index_ns()`) antes
                // de llegar a `tree::put`, que mide la clave YA con ese
                // byte de más (ronda 2 de revisión, hallazgo 2). Sin el
                // `+ 1` una entrada de exactamente `page_size / 4` bytes
                // pasaba esta comprobación y fallaba después, en la fase de
                // aplicación, ya con la entrada vieja borrada.
                let full_entry_len = entry.len() as u32 + 1;
                if full_entry_len > max_key {
                    return Err(Error::KeyTooLarge { len: full_entry_len, max: max_key });
                }
                if def.unique
                    && let Some(existing_pk) = self.get(def.index_ns(), &ik)?
                    && existing_pk != key
                {
                    return Err(Error::DuplicateKey { id: def.id });
                }
                let payload = if def.unique { key.to_vec() } else { Vec::new() };
                insertions.push((def.index_ns(), entry, payload));
            }
        }

        // Fase de aplicación: todo lo de arriba ya validó limpio, así que de
        // aquí en adelante solo puede fallar por un error real de motor —
        // el caso que el contrato de "abandona la transacción" ya cubre.
        for (idx_ns, k) in &deletions {
            self.delete_raw(*idx_ns, k)?;
        }
        for (idx_ns, k, v) in &insertions {
            self.put_raw(*idx_ns, k, v)?;
        }
        self.put_raw(ns, key, value)
    }

    /// Borra `key` de `ns` y sus entradas de índice asociadas (tarea 16),
    /// dentro de la misma transacción. Mismo contrato de error que `put`:
    /// abandona la transacción si devuelve `Err`.
    pub fn delete(&mut self, ns: u8, key: &[u8]) -> Result<bool> {
        let defs = self.db.indexes_for(ns);
        if !defs.is_empty()
            && let Some(old) = self.get(ns, key)?
        {
            for def in &defs {
                for ik in (def.extract)(key, &old) {
                    self.delete_raw(def.index_ns(), &index_key(def, &ik, key))?;
                }
            }
        }
        self.delete_raw(ns, key)
    }

    /// Borra todas las claves de `[from, to)` dentro del espacio `ns`.
    ///
    /// Es la operación que hace viable la poda diaria por retención: los
    /// números de página de las hojas viven en sus nodos padre, así que
    /// `delete_range` (`tree.rs`) nunca las lee — vuelca sus punteros a la
    /// lista de libres en bloque y desengancha el subárbol entero. El coste
    /// es proporcional al número de páginas internas, no al de entradas
    /// borradas.
    ///
    /// **Se rechaza sobre un `ns` con algún índice definido** (ronda 2 de
    /// revisión, hallazgo 1) — `Error::DeleteRangeIndexed`. Es justo la
    /// propiedad de arriba, "nunca lee las hojas", la que hace imposible
    /// mantener los índices aquí sin tirarla: no hay forma de saber qué
    /// entradas de índice retirar sin visitar cada valor borrado, y
    /// visitarlos todos vuelve a poner el coste en proporción al número de
    /// entradas, exactamente lo que esta función existe para evitar.
    ///
    /// Se consideraron tres caminos:
    /// 1. Enrutar por `delete` clave a clave cuando `ns` está indexado:
    ///    correcto, pero destruye la garantía de coste que justifica esta
    ///    función — precisamente para el caso de uso, poda por retención,
    ///    que más se beneficia de tener también un índice (la carga de
    ///    referencia de este proyecto es justo esa: cientos de miles de
    ///    entradas podadas por nodo y día).
    /// 2. Rechazar limpio con un error propio. Preserva la corrección Y la
    ///    garantía de coste sin ambigüedad, al precio de que quien llama
    ///    tenga que decidir explícitamente qué hacer en vez de que el motor
    ///    decida por él.
    /// 3. Aceptarlo SOLO cuando el índice declara que su clave empieza por
    ///    el mismo cubo temporal que la clave primaria que borra el rango
    ///    — entonces borrar el rango de datos `[from, to)` corresponde a
    ///    borrar también un rango CONTIGUO de entradas de índice, y el
    ///    camino rápido de `delete_range` serviría para ambos árboles. Es
    ///    la vía que anticipa la especificación del proyecto (sección 8).
    ///    Pero esa correspondencia depende de una propiedad de `extract`
    ///    que el motor no puede verificar — igual que la versión es la
    ///    única defensa posible contra un extractor que cambia, aquí solo
    ///    quien llama puede afirmar "mi extractor sí respeta esto", y
    ///    construir un mecanismo de declaración correcto (¿por qué campo se
    ///    marca?, ¿cómo se deriva el rango de índice a partir de `from`/
    ///    `to`?, ¿qué pasa si la declaración es falsa?) es una pieza de
    ///    diseño propia, no un arreglo de esta ronda.
    ///
    /// Se optó por (2): es la única de las tres que no puede divergir en
    /// silencio bajo ninguna circunstancia y no exige inventar superficie de
    /// API nueva sin el diseño y las pruebas que merece. (1) traiciona
    /// exactamente el caso de uso que este motor prioriza; (3) es el camino
    /// correcto a largo plazo, pero como tarea propia y deliberada, con su
    /// propio ciclo de revisión — no como parte de una ronda de correcciones
    /// sobre otro hallazgo.
    pub fn delete_range(&mut self, ns: u8, from: &[u8], to: &[u8]) -> Result<()> {
        if !self.db.indexes_for(ns).is_empty() {
            return Err(Error::DeleteRangeIndexed { ns });
        }
        let (a, b) = (scoped(ns, from), scoped(ns, to));
        let root = crate::tree::delete_range(self, self.meta.root, &a, &b)?;
        self.meta.root = root;
        Ok(())
    }

    pub fn get(&self, ns: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        crate::tree::get(self, self.meta.root, &scoped(ns, key))
    }

    /// Escribe la lista de libres, sincroniza, escribe la meta inactiva y
    /// vuelve a sincronizar. Ese orden es lo que hace el commit atómico: la
    /// meta solo apunta a páginas que ya están en disco.
    pub fn commit(mut self) -> Result<()> {
        let mut n_pages = self.meta.n_pages;
        let txn_id = self.meta.txn_id;
        {
            // Lo que quede en el conjunto propio al llegar aquí son páginas
            // que esta transacción asignó y liberó, pero que nadie volvió a
            // pedir antes de confirmar. `own_free` es puramente de esta
            // transacción — nunca se sirve a otra ni sobrevive a un aborto
            // — así que si no se vuelca aquí a la lista de libres
            // persistente antes de serializarla, estas páginas no quedan
            // referenciadas por NADA tras el commit: ni por el árbol nuevo
            // (ya no las usa) ni por la lista de libres (nunca se enteró de
            // ellas) ni por la meta vieja (las liberó esta misma
            // transacción). Fuga silenciosa, no corrupción — pero fuga al
            // fin. Se etiquetan con `txn_id`, igual que cualquier otra
            // página que libera esta transacción: la próxima que las pida
            // pasa por la misma comprobación de la meta confirmada que el
            // resto de la lista de libres.
            let state = self.guard.as_mut().expect("estado presente");
            for page in self.own_free.drain(..) {
                state.freelist.push(page, txn_id);
            }
        }
        {
            let pager = &self.db.pager;
            // La lista de libres se escribe extendiendo el fichero, nunca
            // reutilizando páginas libres: reutilizarlas mientras se serializa
            // la propia lista sería recursivo.
            let mut alloc = || -> Result<PageNo> {
                let p = n_pages;
                n_pages = p.checked_add(1).ok_or(Error::Full)?;
                Ok(p)
            };
            // Mismo contador VIVO que usa `write_page` para el resto de la
            // transacción (tarea 17): las páginas de lista de libres
            // necesitan un contador tan único como las del árbol, no uno
            // propio — ver `advance_counter` y el comentario de
            // `Freelist::flush` en `freelist.rs`. `state` se obtiene UNA
            // vez y `live_counter_ref`/`counter_ceiling_ref` reborrows de
            // sus campos, para que el compilador vea préstamos disjuntos
            // de `state.live_counter`/`state.counter_ceiling` (para el
            // cierre) y `state.freelist` (para `flush`) a la vez — el
            // cierre sigue viva durante toda la llamada a `flush`.
            let db = self.db;
            let state = self.guard.as_mut().expect("estado presente");
            let live_counter_ref = &mut state.live_counter;
            let counter_ceiling_ref = &mut state.counter_ceiling;
            let mut next_nonce = || -> Result<u64> {
                Self::advance_counter(db, live_counter_ref, counter_ceiling_ref)
            };
            let (head, tail) = state.freelist.flush(pager, &mut alloc, txn_id, &mut next_nonce)?;
            self.meta.freelist_head = head;
            self.meta.freelist_tail = tail;
        }
        self.meta.n_pages = n_pages;
        // Escribe un techo FRESCO — `live_counter` tal como quedó tras
        // TODA la actividad de esta transacción (árbol y lista de libres)
        // más `COUNTER_RESERVE` — en la meta que este commit YA iba a
        // escribir. Es puramente "de balde, para una futura apertura
        // limpia más precisa": esta escritura NO alimenta
        // `state.counter_ceiling` (el que de verdad protege contra
        // reutilización, ver su comentario) porque, bajo `Sync::Interval`/
        // `Never`, puede no llegar a sincronizarse nunca — tratarla como
        // si lo hubiera hecho sería reabrir el hallazgo HIGH de la segunda
        // ronda de revisión. Sin cifrado esto no significa nada
        // (`live_counter` nunca avanza, ver `advance_counter`), así que no
        // se escribe.
        if self.db.pager.is_encrypted() {
            let live_counter = self.guard.as_ref().expect("estado presente").live_counter;
            self.meta.write_counter = live_counter.checked_add(COUNTER_RESERVE).ok_or(Error::Full)?;
        }

        self.db.maybe_sync()?;

        let target = self.slot.other();
        let geometry = *self.db.pager.geometry();
        self.meta.store_via(&self.db.pager, &geometry, target)?;
        self.db.maybe_sync()?;

        *self.db.committed.write().unwrap() = (self.meta, target);
        self.committed = true;
        Ok(())
    }
}

impl Db {
    fn maybe_sync(&self) -> Result<()> {
        match self.sync {
            Sync::Commit => self.pager.sync(),
            Sync::Never => Ok(()),
            Sync::Interval(d) => {
                let mut last = self.last_sync.lock().unwrap();
                if last.elapsed() >= d {
                    self.pager.sync()?;
                    *last = Instant::now();
                }
                Ok(())
            }
        }
    }
}

impl Db {
    /// Registra un índice (tarea 16). Si el catálogo ya tiene ese `id` con
    /// una definición distinta, falla: el llamante decide si reconstruirlo o
    /// corregir la llamada.
    ///
    /// **Compara el registro COMPLETO del catálogo** (versión, unicidad,
    /// `ns`, nombre — todo lo que `IndexDef::encode` guarda), no solo la
    /// versión (ronda 2 de revisión, hallazgo 5). Redefinir el mismo `id`
    /// como único cuando antes no lo era, o sobre otro `ns`, bajo la MISMA
    /// versión, dejaría el índice mintiendo en silencio exactamente igual
    /// que un extractor cambiado sin subir la versión: `scan_index`
    /// buscaría en el árbol equivocado, o `put`/`delete` dejarían de
    /// comprobar una unicidad que el catálogo en disco todavía promete.
    /// Todo ese resto SÍ vive en el catálogo, así que compararlo no cuesta
    /// nada extra. Lo único que de verdad no se puede comprobar así —
    /// **y no hay forma de comprobarlo, en ninguna ronda de correcciones**
    /// — es `extract` en sí: es código del llamante, un puntero a función
    /// sin ninguna propiedad observable que distinga "la misma lógica" de
    /// "otra lógica que hoy calcula lo mismo por casualidad" (ni siquiera
    /// comparar la dirección del puntero es fiable entre unidades de
    /// compilación, ver el comentario de `IndexDef` sobre `PartialEq`).
    /// `version` sigue siendo, y seguirá siendo, la única defensa posible
    /// contra ESE cambio concreto.
    ///
    /// Registrar el mismo `id` dos veces en el mismo proceso (misma
    /// definición) es idempotente: sustituye la entrada en memoria en vez de
    /// duplicarla. Sin esto, una segunda llamada dejaría dos copias del
    /// mismo `IndexDef` en `indexes`, y `indexes_for` se lo entregaría dos
    /// veces a `WriteTxn::put`/`delete` — no corrompe nada (borrar y volver
    /// a poner la misma entrada es idempotente), pero duplica trabajo en
    /// cada escritura para siempre, en silencio.
    ///
    /// **No hace `backfill`** (ronda 2 de revisión, hallazgo 10, sin arreglo
    /// — documentado): filas escritas en `ns` ANTES de esta llamada se
    /// quedan sin indexar para siempre. Como la comparación de arriba es
    /// contra el registro tal cual quedó grabado la primera vez, reabrir
    /// más tarde con la MISMA definición nunca lo detecta ni lo avisa — el
    /// índice está simplemente incompleto desde el principio, en silencio.
    /// Levantar un índice sobre datos preexistentes exige hoy que quien
    /// llama reescriba esas filas él mismo (p. ej. un `put` de cada fila
    /// sobre su propio valor) después de `define_index`, antes de confiar
    /// en `scan_index`.
    pub fn define_index(&self, def: IndexDef) -> Result<()> {
        if def.id >= 0x80 {
            return Err(Error::BadFormat);
        }
        // (Ronda 2 de revisión, hallazgo 6): `ns` debe caer fuera de los dos
        // rangos que el propio motor se reserva — el catálogo (`ns == 0`) y
        // el espacio de cualquier índice (`ns >= INDEX_NS_BASE`, donde vive
        // CADA índice, incluido este mismo). Sin este chequeo, un `IndexDef`
        // con `ns = CATALOG_NS` indexaría el catálogo consigo mismo, y uno
        // con `ns >= INDEX_NS_BASE` indexaría las entradas crudas de OTRO
        // índice — en ambos casos, `WriteTxn::put`/`delete` empezarían a
        // mutar esos espacios reservados como si fueran datos de usuario
        // cada vez que alguien escribe ahí (incluida la propia maquinaria
        // de índices), con resultados que ninguna otra comprobación de este
        // módulo anticipa.
        if def.ns == CATALOG_NS || def.ns >= INDEX_NS_BASE {
            return Err(Error::BadFormat);
        }
        let mut tx = self.begin_write()?;
        match tx.get(CATALOG_NS, &[def.id])? {
            Some(record) => {
                let stored = IndexDef::stored_version(&record).ok_or(Error::BadFormat)?;
                if record != def.encode() {
                    return Err(Error::IndexVersionMismatch {
                        id: def.id,
                        stored,
                        provided: def.version,
                    });
                }
            }
            None => {
                tx.put_raw(CATALOG_NS, &[def.id], &def.encode())?;
                tx.commit()?;
            }
        }
        let mut indexes = self.indexes.lock().unwrap();
        match indexes.iter_mut().find(|d| d.id == def.id) {
            Some(slot) => *slot = def,
            None => indexes.push(def),
        }
        Ok(())
    }

    /// Índices registrados sobre el espacio de claves `ns`, en el orden en
    /// que se definieron.
    fn indexes_for(&self, ns: u8) -> Vec<IndexDef> {
        self.indexes.lock().unwrap().iter().copied().filter(|d| d.ns == ns).collect()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::storage::MemStorage;
    use alloc::sync::Arc;

    fn fresh() -> (Arc<MemStorage>, Db) {
        let s = Arc::new(MemStorage::new());
        let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        (s, db)
    }

    /// Permite conservar el medio tras cerrar la base, para reabrirla.
    struct ArcStorage(Arc<MemStorage>);
    impl Storage for ArcStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    #[test]
    fn a_fresh_database_is_under_five_kilobytes() {
        let (s, _db) = fresh();
        assert!(s.len().unwrap() <= 4_608, "suelo de la fase 1: 9 páginas de 512 B");
    }

    #[test]
    fn commit_makes_writes_visible_to_new_readers() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![7u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.root(), p);
        assert_eq!(r.read_page(p).unwrap()[0], 7);
    }

    #[test]
    fn a_reader_keeps_seeing_its_snapshot_after_a_later_commit() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let r = db.begin_read();
        let seen = r.root();

        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        tx.write_page(q, &alloc::vec![2u8; 512]).unwrap();
        tx.set_root(q);
        tx.commit().unwrap();

        assert_eq!(r.root(), seen, "el lector no ve el commit posterior");
        assert_eq!(db.begin_read().root(), q);
    }

    #[test]
    fn a_page_freed_while_a_reader_is_live_is_not_recycled() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let reader = db.begin_read();

        let mut tx = db.begin_write().unwrap();
        tx.free(p);
        let q = tx.alloc().unwrap();
        assert_ne!(q, p, "no se recicla mientras el lector la ve");
        tx.commit().unwrap();
        drop(reader);

        let mut tx = db.begin_write().unwrap();
        assert_eq!(tx.alloc().unwrap(), p, "reciclada cuando el lector se va");
        tx.commit().unwrap();
    }

    #[test]
    fn an_aborted_transaction_leaves_no_trace() {
        let (_s, db) = fresh();
        let before = db.begin_read().txn_id();
        {
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![9u8; 512]).unwrap();
            tx.set_root(p);
            // se descarta sin commit
        }
        assert_eq!(db.begin_read().txn_id(), before);
        assert_eq!(db.begin_read().root(), 0);
    }

    #[test]
    fn reopening_recovers_pages_leaked_by_an_interrupted_transaction() {
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![3u8; 512]).unwrap();
            // Sin commit: la página queda escrita en el fichero pero sin dueño.
        }
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        assert_eq!(tx.alloc().unwrap(), 9, "la página huérfana vuelve a la lista de libres");
        tx.commit().unwrap();
    }

    #[test]
    fn draining_the_recovered_pages_never_hands_out_a_page_twice() {
        // La recuperación mete las páginas huérfanas en la lista de libres. Si
        // `n_pages` no avanza hasta la extensión real del fichero, en cuanto esas
        // páginas se agoten el camino de extensión de `alloc` vuelve a repartir
        // desde el `n_pages` viejo y entrega una página que ya está en uso.
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..5 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
            }
            // Sin commit: las cinco quedan huérfanas en el fichero.
        }

        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let mut seen = alloc::collections::BTreeSet::new();
        for _ in 0..12 {
            let p = tx.alloc().unwrap();
            assert!(seen.insert(p), "la página {p} se repartió dos veces");
        }
        tx.commit().unwrap();
    }

    #[test]
    fn a_second_writer_is_rejected_while_one_is_open() {
        let (_s, db) = fresh();
        let _tx = db.begin_write().unwrap();
        assert_eq!(db.begin_write().err(), Some(Error::WriterBusy));
    }

    #[test]
    fn open_costs_the_same_on_a_small_and_a_large_file() {
        // Coste constante: tres lecturas, cabecera y dos metas. Se comprueba
        // contando lecturas, no midiendo tiempo.
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..2_000 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![0u8; 512]).unwrap();
            }
            tx.commit().unwrap();
        }
        s.reset_read_count();
        let _db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        assert!(s.read_count() <= 4, "apertura de coste constante");
    }

    #[test]
    fn freeing_a_page_in_an_aborted_transaction_does_not_persist() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        {
            let mut tx = db.begin_write().unwrap();
            tx.free(p);
            // se descarta sin commit
        }

        // El root confirmado sigue señalando a p: si el `free` de la
        // transacción abortada sobreviviera, la siguiente transacción
        // repartiría p como si estuviera libre mientras sigue siendo el
        // root vigente — dos dueños a la vez.
        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        assert_ne!(q, p, "p sigue en uso: el free() de la transacción abortada no debió persistir");
        tx.commit().unwrap();
    }

    #[test]
    fn an_alloc_from_the_freelist_in_an_aborted_transaction_is_not_lost() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        // Libera p de verdad (con commit), así queda en la lista de libres
        // persistente.
        let mut tx = db.begin_write().unwrap();
        tx.free(p);
        tx.commit().unwrap();

        {
            // Esta transacción hace alloc() -> saca p de la lista de
            // libres, pero se aborta sin commit.
            let mut tx = db.begin_write().unwrap();
            assert_eq!(tx.alloc().unwrap(), p);
            // se descarta sin commit
        }

        // p debería seguir disponible: nadie la posee y la transacción que
        // la recicló nunca llegó a confirmar.
        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        assert_eq!(q, p, "p se perdió: el abort no debió dejarla fuera de la lista de libres para siempre");
        tx.commit().unwrap();
    }

    /// Regresión del hallazgo 1 de la revisión de la tarea 12: sin lectores
    /// vivos, `free` seguido de `alloc` dentro de la MISMA transacción sin
    /// confirmar reciclaba una página que todavía pertenece al árbol
    /// confirmado — la meta confirmada actúa como un lector implícito que
    /// `oldest_reader` por sí solo no representa. Comprueba las dos mitades
    /// del contrato: que `alloc` no entrega esa página, y que abortar la
    /// transacción (sin `commit`) no deja ningún byte en disco distinto de
    /// como estaba.
    #[test]
    fn freeing_a_committed_page_is_not_reused_within_the_same_uncommitted_transaction() {
        let (s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![7u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let before = s.snapshot();

        {
            let mut tx = db.begin_write().unwrap();
            tx.free(p);
            let q = tx.alloc().unwrap();
            assert_ne!(
                q, p,
                "p sigue vivo en el árbol confirmado: reciclarla ya, sin que esta transacción \
                 haya confirmado, dejaría la meta confirmada apuntando a basura si hay un corte \
                 antes del commit"
            );
            // se descarta sin commit: ni `q` ni el free() de `p` deben tocar disco.
        }

        let after = s.snapshot();
        assert_eq!(
            before, after,
            "abortar sin commit no debe cambiar ni un byte del fichero ya confirmado"
        );
    }
}
