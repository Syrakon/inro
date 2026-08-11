use alloc::boxed::Box;
use alloc::collections::BTreeMap;
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

    /// Toma una página libre reutilizable o extiende el fichero.
    pub fn alloc(&mut self) -> Result<PageNo> {
        let oldest = self.db.oldest_reader();
        let pager = &self.db.pager;
        if let Some(p) = self.state().freelist.pop_refill(pager, oldest)? {
            return Ok(p);
        }
        let p = self.meta.n_pages;
        self.meta.n_pages = p.checked_add(1).ok_or(Error::Full)?;
        Ok(p)
    }

    /// Marca `page` como libre a partir de esta transacción.
    pub fn free(&mut self, page: PageNo) {
        let txn = self.meta.txn_id;
        self.state().freelist.push(page, txn);
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
}
