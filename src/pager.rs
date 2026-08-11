use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
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

    #[cfg(test)]
    pub fn cached_pages(&self) -> usize {
        self.cache.lock().unwrap().entries.len()
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

    fn pager(cache_pages: usize) -> Pager {
        let g = Geometry {
            page_size: 512, format_major: FORMAT_MAJOR, format_minor: 0, flags: 0,
            db_id: [0; 16], created_unix: 0, meta_a_page: 1, meta_b_page: 8,
        };
        Pager::new(Box::new(MemStorage::new()), g, cache_pages)
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
        assert!(p.cached_pages() <= 2);
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
}
