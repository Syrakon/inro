use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::crypto::Encryption;
use crate::header::Geometry;
use crate::{PageNo, Result, Storage, TxnId};

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
    /// Cifrado por página activo, si la base se abrió con una clave de datos
    /// ya desenvuelta (tarea 17). Existe siempre — no solo bajo la feature
    /// `encryption` — porque `Encryption` en sí es un tipo simple sin
    /// dependencia de `chacha20poly1305`/`aes-gcm` (ver `crypto.rs`); lo que
    /// SÍ está tras esa feature es la capacidad de hacer algo útil con él
    /// (`seal_and_write`/`decrypt`, más abajo). Se fija después de `new`,
    /// no en el constructor: la clave de datos no se conoce hasta leer (o
    /// generar) la meta, y la meta se lee/escribe A TRAVÉS de este mismo
    /// `Pager` en `Db::open`/`Db::create` — ver `with_encryption`.
    encryption: Option<Encryption>,
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
            encryption: None,
        }
    }

    /// Activa el cifrado por página con la clave de datos ya desenvuelta.
    /// Separado de `new` a propósito (ver el comentario del campo
    /// `encryption`): no rompe ninguna de las llamadas existentes a
    /// `Pager::new` (pruebas de este módulo y de `freelist.rs` incluidas),
    /// que siguen construyendo un `Pager` sin cifrar sin cambiar una línea.
    pub fn with_encryption(mut self, encryption: Option<Encryption>) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Bytes útiles de una página lógica: lo que `PageBuilder` y todo lo que
    /// construye páginas (`tree.rs`, `freelist.rs`) debe usar en vez de
    /// `geometry().page_size`. Con cifrado, veinticuatro menos: ocho de
    /// `txn_id` en claro y dieciséis de tag (`crypto::CIPHER_PREFIX`). Sin
    /// cifrado, coincide con el tamaño físico.
    pub fn logical_page_size(&self) -> u32 {
        match &self.encryption {
            Some(_) => self.geometry.page_size - crate::crypto::CIPHER_PREFIX as u32,
            None => self.geometry.page_size,
        }
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

        // Descifrar, si procede, ANTES de cachear: la caché guarda texto
        // plano (ver el comentario de `Pager`, arriba de la struct), así que
        // un acierto de caché —el caso frecuente— no vuelve a pagar el coste
        // de autenticar. `page_no` entra en la derivación del nonce, igual
        // que en la escritura (`write_encrypted`): sin él, dos páginas
        // distintas escritas por la MISMA transacción compartirían nonce.
        let bytes: Arc<[u8]> = match &self.encryption {
            None => Arc::from(buf.into_boxed_slice()),
            Some(enc) => Arc::from(self.decrypt(enc, page_no, buf)?.into_boxed_slice()),
        };

        let mut c = self.cache.lock().unwrap();
        c.insert(page_no, Arc::clone(&bytes));
        Ok(bytes)
    }

    /// Descifra `buf` (el contenido físico completo recién leído) y devuelve
    /// solo la porción de página lógica en claro, con el prefijo de
    /// `txn_id`+tag ya recortado. Un fallo de autenticación —clave
    /// incorrecta o página manipulada— se propaga como `Error::Decrypt`, no
    /// como una página corrupta cualquiera: quien llama necesita distinguir
    /// los dos casos (ver las pruebas `a_wrong_key_fails_to_decrypt...` y
    /// `a_tampered_page_is_rejected` en `crypto.rs`).
    #[cfg(feature = "encryption")]
    fn decrypt(&self, enc: &Encryption, page_no: PageNo, mut buf: Vec<u8>) -> Result<Vec<u8>> {
        crate::crypto::open(enc, page_no, &mut buf)?;
        Ok(buf[crate::crypto::CIPHER_PREFIX..].to_vec())
    }

    /// Sin la feature `encryption`, `self.encryption` solo puede llegar aquí
    /// como `Some` si alguien construyó un `Encryption` dentro del propio
    /// crate sin pasar por la reexportación pública (gateada, ver `lib.rs`)
    /// y lo coló en `Options` — no hay ningún camino de producción que lo
    /// haga hoy. Falla alto en vez de tratar el cifrado como texto plano:
    /// devolver `buf` tal cual convertiría cabecera+tag+texto cifrado en
    /// "la página", que ni `PageRef::parse` va a aceptar como válida ni,
    /// si por algún accidente numérico lo hiciera, sería el dato real.
    #[cfg(not(feature = "encryption"))]
    fn decrypt(&self, _enc: &Encryption, _page_no: PageNo, _buf: Vec<u8>) -> Result<Vec<u8>> {
        Err(crate::Error::BadFormat)
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

    /// Como `write`, pero cifrando primero si esta base lo tiene activo.
    /// `plain` debe medir `logical_page_size()`: quien construye la página
    /// (`WriteTxn::write_page` en `tx.rs`, `Freelist::flush`) ya usa ese
    /// tamaño, así que el resultado, una vez sellado, mide exactamente
    /// `geometry().page_size` — lo que `write` exige.
    ///
    /// `txn` es la transacción que hace esta escritura: entra en la
    /// derivación del nonce junto con `page_no` (ver `crypto::seal`). Su
    /// unicidad — la invariante de la que depende TODA la confidencialidad
    /// de este esquema — es responsabilidad de quien llama: una página no
    /// debe escribirse dos veces dentro de la misma transacción. El diseño
    /// de copia en escritura del motor lo cumple por construcción (una
    /// página sucia se escribe una sola vez, al confirmar); `Pager` no
    /// tiene forma de comprobarlo por sí mismo.
    pub fn write_encrypted(&self, page_no: PageNo, txn: TxnId, plain: &[u8]) -> Result<()> {
        match &self.encryption {
            None => self.write(page_no, plain),
            Some(enc) => self.seal_and_write(enc, page_no, txn, plain),
        }
    }

    #[cfg(feature = "encryption")]
    fn seal_and_write(&self, enc: &Encryption, page_no: PageNo, txn: TxnId, plain: &[u8]) -> Result<()> {
        let mut raw = vec![0u8; self.geometry.page_size as usize];
        crate::crypto::seal(enc, page_no, txn, plain, &mut raw)?;
        self.write(page_no, &raw)
    }

    /// Mismo razonamiento que el `decrypt` gemelo, más arriba: sin la
    /// feature `encryption` no hay forma de producir un sellado real, así
    /// que falla alto en vez de escribir `plain` sin cifrar bajo la
    /// apariencia de que sí se cifró.
    #[cfg(not(feature = "encryption"))]
    fn seal_and_write(&self, _enc: &Encryption, _page_no: PageNo, _txn: TxnId, _plain: &[u8]) -> Result<()> {
        Err(crate::Error::BadFormat)
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
