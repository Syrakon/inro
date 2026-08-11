use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::header::Geometry;
use crate::{PageNo, Result, Storage};

/// Entrada de caché. `used` es un contador monótono, no un reloj: sirve solo
/// para elegir la víctima menos usada recientemente.
struct Entry {
    page_no: PageNo,
    bytes: Arc<[u8]>,
    used: u64,
}

/// Lectura y escritura de páginas con una caché de tamaño fijo.
///
/// El presupuesto es en páginas, no en bytes, y no crece nunca: es la garantía
/// de RAM constante por base abierta. Con `cache_pages = 0` cada lectura va al
/// medio de almacenamiento y se delega el cacheo al sistema operativo.
pub struct Pager {
    storage: Box<dyn Storage>,
    geometry: Geometry,
    cache: Mutex<Cache>,
    /// Número de llamadas a `read` desde la creación del `Pager`. Cuenta
    /// TODA llamada, acierto de caché o no: lo que la tarea 15 necesita
    /// medir es cuántas veces el código del árbol PIDE una página durante
    /// un recorrido (el coste que `delete_range` promete mantener
    /// proporcional a las páginas internas), no cuántas de esas peticiones
    /// tuvieron que llegar de verdad al medio de almacenamiento — eso ya lo
    /// mide `MemStorage::read_count`, a una capa de distancia, y con otro
    /// propósito (el coste de `Db::open` en `tx.rs`).
    reads: AtomicU64,
}

struct Cache {
    entries: Vec<Entry>,
    budget: usize,
    tick: u64,
}

impl Pager {
    pub fn new(storage: Box<dyn Storage>, geometry: Geometry, cache_pages: usize) -> Self {
        Self {
            storage,
            geometry,
            cache: Mutex::new(Cache {
                entries: Vec::with_capacity(cache_pages),
                budget: cache_pages,
                tick: 0,
            }),
            reads: AtomicU64::new(0),
        }
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    fn offset(&self, page_no: PageNo) -> u64 {
        page_no as u64 * self.geometry.page_size as u64
    }

    /// `read` libera el cerrojo de la caché entre comprobar el fallo y
    /// volver a tomarlo para insertar la entrada nueva: el I/O de
    /// `storage.read_at` ocurre sin el cerrojo tomado. Esa ventana podría
    /// publicar una entrada obsoleta si un `write` a la misma página se
    /// colara justo en medio. No puede: `write` (ver su documentación)
    /// solo reescribe páginas que ningún lector vivo puede estar todavía
    /// leyendo, así que esa ventana nunca se solapa con un `write` a la
    /// misma página. Esto es una precondición que impone quien llama —
    /// otra vez la capa de transacciones — y no algo que `Pager`
    /// compruebe ni haga cumplir por sí mismo.
    ///
    /// Las páginas de meta se escriben a través de este `Pager`, pero
    /// ningún lector llama nunca a `read` sobre una página de meta: la
    /// vista de un lector sale del estado ya confirmado en el momento de
    /// abrir su transacción, no de la caché del `Pager`. Las metas quedan
    /// a salvo por ese argumento distinto, no por el de arriba — y se
    /// rompe si algún código futuro empieza a leer una meta-página a
    /// través de `Pager::read`.
    pub fn read(&self, page_no: PageNo) -> Result<Arc<[u8]>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        {
            let mut c = self.cache.lock().unwrap();
            c.tick += 1;
            let tick = c.tick;
            if let Some(e) = c.entries.iter_mut().find(|e| e.page_no == page_no) {
                e.used = tick;
                return Ok(Arc::clone(&e.bytes));
            }
        }

        let mut buf = vec![0u8; self.geometry.page_size as usize];
        self.storage.read_at(self.offset(page_no), &mut buf)?;
        let bytes: Arc<[u8]> = Arc::from(buf.into_boxed_slice());

        let mut c = self.cache.lock().unwrap();
        c.insert(page_no, Arc::clone(&bytes));
        Ok(bytes)
    }

    /// Precondición que debe garantizar quien llama, no `Pager`: toda
    /// página que se reescribe aquí es, o bien recién asignada más allá de
    /// cualquier `n_pages` que un lector vivo haya visto jamás, o bien
    /// reciclada de la lista de libres solo después de que ningún lector
    /// vivo preceda a la transacción que la liberó. Esa garantía la
    /// impone la capa de transacciones — lista de libres y tabla de
    /// lectores —, no `Pager`, que no la comprueba. De ella depende que
    /// `read` (ver su documentación) nunca publique una entrada obsoleta.
    pub fn write(&self, page_no: PageNo, bytes: &[u8]) -> Result<()> {
        debug_assert_eq!(bytes.len(), self.geometry.page_size as usize);
        self.storage.write_at(self.offset(page_no), bytes)?;
        // Invalidar en vez de actualizar: una página reescrita puede además
        // haber cambiado de dueño tras pasar por la lista de libres, y servir
        // contenido antiguo bajo el mismo número sería corrupción silenciosa.
        self.cache.lock().unwrap().remove(page_no);
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        self.storage.sync()
    }

    /// Sin llamador todavía (era parte del API público que pedía el brief
    /// de la tarea 7; queda invisible al análisis de código muerto desde
    /// que `pager` pasó a `pub(crate)` en la ronda 3 de revisión de la
    /// tarea 16). Se conserva para cuando haga falta invalidar un lote de
    /// páginas sin pasar por `write` una a una — p. ej. tras una
    /// recuperación que descubre varias páginas huérfanas a la vez (ver
    /// `Db::open`).
    #[allow(dead_code)]
    pub fn invalidate(&self, pages: &[PageNo]) {
        let mut c = self.cache.lock().unwrap();
        for &p in pages {
            c.remove(p);
        }
    }

    /// Páginas que caben en el fichero actual. Se usa al abrir para detectar
    /// las que dejó una transacción interrumpida.
    pub fn file_pages(&self) -> Result<u32> {
        let len = self.storage.len()?;
        Ok((len / self.geometry.page_size as u64) as u32)
    }

    /// Devuelve el medio de almacenamiento, descartando la caché. Se usa al
    /// abrir, donde el pager provisional para leer la lista de libres se
    /// reemplaza por el definitivo.
    pub fn into_storage(self) -> Box<dyn Storage> {
        self.storage
    }

    #[cfg(test)]
    pub fn cached_pages(&self) -> usize {
        self.cache.lock().unwrap().entries.len()
    }

    /// Cuenta de páginas leídas expuesta a `Db::pages_read` (`tx.rs`), para
    /// la prueba de coste de la tarea 15
    /// (`it_reads_far_fewer_pages_than_it_frees`).
    #[cfg(test)]
    pub fn pages_read(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Solo para pruebas: si no se pudiera espiar qué páginas concretas
    /// quedan cacheadas, no habría forma de distinguir un desalojo LRU real
    /// de uno que simplemente tira una entrada cualquiera.
    #[cfg(test)]
    pub fn is_cached(&self, page_no: PageNo) -> bool {
        self.cache.lock().unwrap().entries.iter().any(|e| e.page_no == page_no)
    }
}

impl Cache {
    fn insert(&mut self, page_no: PageNo, bytes: Arc<[u8]>) {
        if self.budget == 0 {
            return;
        }
        self.tick += 1;
        if self.entries.len() >= self.budget {
            let victim = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.used)
                .map(|(i, _)| i);
            if let Some(i) = victim {
                self.entries.swap_remove(i);
            }
        }
        self.entries.push(Entry { page_no, bytes, used: self.tick });
    }

    fn remove(&mut self, page_no: PageNo) {
        if let Some(i) = self.entries.iter().position(|e| e.page_no == page_no) {
            self.entries.swap_remove(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::FORMAT_MAJOR;
    use crate::storage::MemStorage;

    fn geometry() -> Geometry {
        Geometry {
            page_size: 512, format_major: FORMAT_MAJOR, format_minor: 0, flags: 0,
            db_id: [0; 16], created_unix: 0, meta_a_page: 1, meta_b_page: 8,
        }
    }

    fn pager(cache_pages: usize) -> Pager {
        Pager::new(Box::new(MemStorage::new()), geometry(), cache_pages)
    }

    #[test]
    fn reads_back_a_written_page() {
        let p = pager(4);
        let mut page = alloc::vec![0u8; 512];
        page[100] = 42;
        p.write(3, &page).unwrap();
        assert_eq!(p.read(3).unwrap()[100], 42);
    }

    #[test]
    fn a_rewritten_page_is_not_served_stale_from_cache() {
        let p = pager(4);
        let mut page = alloc::vec![0u8; 512];
        p.write(3, &page).unwrap();
        assert_eq!(p.read(3).unwrap()[100], 0);
        page[100] = 9;
        p.write(3, &page).unwrap();
        assert_eq!(p.read(3).unwrap()[100], 9, "write invalida la entrada cacheada");
    }

    #[test]
    fn cache_never_grows_past_its_budget() {
        let p = pager(2);
        let page = alloc::vec![0u8; 512];
        for n in 0..10 {
            p.write(n, &page).unwrap();
            p.read(n).unwrap();
        }
        // No basta con "<= 2": un `insert` que no hiciera nada con ningún
        // presupuesto (no solo con 0) también pasaría esa comprobación.
        assert_eq!(p.cached_pages(), 2);
        // Las páginas tempranas quedaron fuera; solo sobreviven las dos
        // últimas tocadas.
        for n in 0..8 {
            assert!(!p.is_cached(n), "la pagina {n} deberia haber sido desalojada");
        }
        assert!(p.is_cached(8));
        assert!(p.is_cached(9));
    }

    #[test]
    fn eviction_prefers_the_least_recently_used_entry() {
        let p = pager(2);
        let page = alloc::vec![0u8; 512];
        p.write(0, &page).unwrap();
        p.read(0).unwrap();
        p.write(1, &page).unwrap();
        p.read(1).unwrap();

        // Tocar la página 0 la vuelve la más recientemente usada; la 1
        // queda como la menos usada, aunque la 0 se insertó primero. Un
        // desalojo por mero orden de inserción (FIFO) confundiría esto
        // con "la 0 es la más vieja" y desalojaría la equivocada.
        p.read(0).unwrap();

        p.write(2, &page).unwrap();
        p.read(2).unwrap();

        assert_eq!(p.cached_pages(), 2);
        assert!(p.is_cached(0), "la pagina tocada recientemente sobrevive");
        assert!(!p.is_cached(1), "la pagina menos usada se desaloja, no la mas vieja por insercion");
        assert!(p.is_cached(2), "la pagina recien insertada esta presente");
    }

    #[test]
    fn a_zero_page_budget_disables_caching() {
        let p = pager(0);
        let page = alloc::vec![0u8; 512];
        p.write(1, &page).unwrap();
        p.read(1).unwrap();
        assert_eq!(p.cached_pages(), 0);
    }

    #[test]
    fn file_pages_rounds_down_to_whole_pages() {
        let p = pager(1);
        let page = alloc::vec![0u8; 512];
        p.write(4, &page).unwrap();
        assert_eq!(p.file_pages().unwrap(), 5);
    }

    #[test]
    fn file_pages_floors_a_partial_trailing_page() {
        // Fuera de `Pager`, a través del `Storage` subyacente: deja el
        // fichero en 1001 bytes, una página completa (0..512) más una cola
        // parcial de 489 bytes que no llega a formar una página entera. El
        // suelo es correcto porque un `alloc` posterior sobrescribe esa
        // cola con una página completa; lo que este test verifica es que
        // `file_pages` no la cuenta antes de que eso pase.
        let storage = MemStorage::new();
        storage.write_at(1000, &[7]).unwrap();
        let p = Pager::new(Box::new(storage), geometry(), 1);
        assert_eq!(p.file_pages().unwrap(), 1);
    }
}
