use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use std::sync::{Mutex, MutexGuard, RwLock};
use std::time::Instant;

use crate::freelist::Freelist;
use crate::header::{Geometry, FORMAT_MAJOR, MAX_PAGE_SIZE, MIN_PAGE_SIZE};
use crate::meta::{Meta, MetaSlot};
use crate::pager::Pager;
use crate::{Error, PageNo, Result, Storage, TxnId};

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
}

impl Default for Options {
    fn default() -> Self {
        Self { page_size: 512, sync: Sync::Commit, cache_pages: 32 }
    }
}

pub struct Db {
    pager: Pager,
    committed: RwLock<(Meta, MetaSlot)>,
    write_lock: Mutex<Option<WriterState>>,
    readers: Mutex<BTreeMap<TxnId, u32>>,
    sync: Sync,
    last_sync: Mutex<Instant>,
}

/// Estado que sobrevive entre transacciones de escritura: la lista de libres
/// no se relee de disco en cada una.
struct WriterState {
    freelist: Freelist,
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
        let geometry = Geometry {
            page_size: opts.page_size,
            format_major: FORMAT_MAJOR,
            format_minor: 0,
            flags: 0,
            db_id: db_id(),
            created_unix: now_unix(),
            meta_a_page: 1,
            meta_b_page: meta_b,
        };
        geometry.write(storage.as_ref())?;

        let meta = Meta {
            txn_id: 1,
            root: 0,
            catalog_root: 0,
            freelist_head: 0,
            freelist_tail: 0,
            n_pages: meta_b + 1,
            page_size_log2: opts.page_size.trailing_zeros() as u8,
            format_major: FORMAT_MAJOR,
            flags: 0,
        };
        // Ambas ranuras se inicializan para que la primera apertura encuentre
        // una meta válida pase lo que pase.
        meta.store(storage.as_ref(), &geometry, MetaSlot::A)?;
        meta.store(storage.as_ref(), &geometry, MetaSlot::B)?;
        storage.sync()?;

        Ok(Self::assemble(storage, geometry, meta, MetaSlot::A, opts, Freelist::empty()))
    }

    pub fn open(storage: Box<dyn Storage>, opts: Options) -> Result<Self> {
        let geometry = Geometry::read(storage.as_ref())?;
        let (mut meta, slot) = Meta::load(storage.as_ref(), &geometry)?;
        let pager = Pager::new(storage, geometry, opts.cache_pages);
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

        let storage = pager.into_storage();
        Ok(Self::assemble(storage, geometry, meta, slot, opts, freelist))
    }

    fn assemble(
        storage: Box<dyn Storage>,
        geometry: Geometry,
        meta: Meta,
        slot: MetaSlot,
        opts: Options,
        freelist: Freelist,
    ) -> Self {
        Self {
            pager: Pager::new(storage, geometry, opts.cache_pages),
            committed: RwLock::new((meta, slot)),
            write_lock: Mutex::new(Some(WriterState { freelist })),
            readers: Mutex::new(BTreeMap::new()),
            sync: opts.sync,
            last_sync: Mutex::new(Instant::now()),
        }
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
}

impl<'db> ReadTxn<'db> {
    pub fn txn_id(&self) -> TxnId {
        self.meta.txn_id
    }

    pub fn root(&self) -> PageNo {
        self.meta.root
    }

    pub fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    pub fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }
}

/// Acceso a páginas común a lectores y escritores, para que el árbol se
/// escriba una sola vez y sirva a ambos.
pub trait PageSource {
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

pub struct WriteTxn<'db> {
    db: &'db Db,
    guard: MutexGuard<'db, Option<WriterState>>,
    meta: Meta,
    slot: MetaSlot,
    written: Vec<PageNo>,
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
    own_free: Vec<PageNo>,
}

impl Db {
    pub fn begin_write(&self) -> Result<WriteTxn<'_>> {
        let guard = self.write_lock.try_lock().map_err(|_| Error::WriterBusy)?;
        let (mut meta, slot) = *self.committed.read().unwrap();
        meta.txn_id += 1;
        let pre_freelist = guard
            .as_ref()
            .expect("el estado del escritor siempre está presente")
            .freelist
            .clone();
        Ok(WriteTxn {
            db: self,
            guard,
            meta,
            slot,
            written: Vec::new(),
            pre_freelist,
            committed: false,
            self_allocated: BTreeSet::new(),
            own_free: Vec::new(),
        })
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

    pub fn root(&self) -> PageNo {
        self.meta.root
    }

    pub fn set_root(&mut self, root: PageNo) {
        self.meta.root = root;
    }

    pub fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    pub fn set_catalog_root(&mut self, root: PageNo) {
        self.meta.catalog_root = root;
    }

    fn state(&mut self) -> &mut WriterState {
        self.guard.as_mut().expect("el estado del escritor siempre está presente")
    }

    /// Tamaño de página fijado al crear la base. `emit` (árbol) lo necesita
    /// para saber cuánto cabe en una página nueva.
    pub fn page_size(&self) -> u32 {
        self.db.pager.geometry().page_size
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
    pub fn alloc(&mut self) -> Result<PageNo> {
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
    pub fn free(&mut self, page: PageNo) {
        if self.self_allocated.contains(&page) {
            self.own_free.push(page);
        } else {
            let txn = self.meta.txn_id;
            self.state().freelist.push(page, txn);
        }
    }

    pub fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read(page)
    }

    pub fn write_page(&mut self, page: PageNo, bytes: &[u8]) -> Result<()> {
        self.db.pager.write(page, bytes)?;
        self.written.push(page);
        Ok(())
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
            let state = self.guard.as_mut().expect("estado presente");
            let (head, tail) = state.freelist.flush(pager, &mut alloc, txn_id)?;
            self.meta.freelist_head = head;
            self.meta.freelist_tail = tail;
        }
        self.meta.n_pages = n_pages;

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
