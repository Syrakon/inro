use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::crypto::Encryption;
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
    /// `RwLock`, no un campo plano (tarea 18): la reubicación de la meta B
    /// necesita cambiarlo en caliente (`set_geometry`, más abajo) desde
    /// `WriteTxn`, que solo tiene `&Db` — nunca `&mut` — así que la mutación
    /// tiene que vivir detrás de una interior. `Geometry` es `Copy` de 48
    /// bytes: se lee una vez por operación (`geometry()` devuelve una copia,
    /// no una referencia) y el coste de esa copia es irrelevante frente a
    /// una lectura de página.
    geometry: RwLock<Geometry>,
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
            geometry: RwLock::new(geometry),
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

    /// Copia de la geometría actual. Antes de la tarea 18 devolvía `&Geometry`
    /// — la geometría era fija desde `Pager::new` hasta el `Drop`, así que una
    /// referencia prestada del campo era válida durante toda la vida del
    /// `Pager`. Ya no: la reubicación de la meta B (`set_geometry`, más abajo)
    /// puede cambiarla en caliente, así que una referencia prestada dejaría
    /// de reflejar la geometría vigente en cuanto esa mutación ocurriera. Una
    /// copia no tiene ese problema.
    pub fn geometry(&self) -> Geometry {
        *self.geometry.read().unwrap()
    }

    /// Bytes útiles de una página lógica: lo que `PageBuilder` y todo lo que
    /// construye páginas (`tree.rs`, `freelist.rs`) debe usar en vez de
    /// `geometry().page_size`. Con cifrado, CUARENTA menos: veinticuatro de
    /// nonce en claro y dieciséis de tag (`crypto::CIPHER_PREFIX`). Sin
    /// cifrado, coincide con el tamaño físico.
    ///
    /// Eran veinticuatro menos (8 de contador + 16 de tag) hasta el cambio
    /// a nonces aleatorios: el nonce ya no se deriva de `página ||
    /// contador`, se almacena entero, así que la página lógica encoge otros
    /// 16 bytes. Con páginas de 512 B eso deja 472 útiles (antes 488) y con
    /// 4096 B deja 4056 (antes 4072).
    ///
    /// No depende del algoritmo, a propósito: el campo de nonce mide 24 B
    /// para los dos, aunque AES-256-GCM-SIV solo use 12 — ver
    /// `crypto::STORED_NONCE_LEN` para por qué el tamaño de página lógica
    /// no puede depender de un dato que el fichero no contiene.
    pub fn logical_page_size(&self) -> u32 {
        match &self.encryption {
            Some(_) => self.geometry().page_size - crate::crypto::CIPHER_PREFIX as u32,
            None => self.geometry().page_size,
        }
    }

    /// Si esta base tiene cifrado por página activo. La usa `Db::create`/
    /// `Db::open` (`tx.rs`) para decidir si esta apertura necesita sortear
    /// un prefijo de nonce (`crypto::NonceStream`) o si puede prescindir de
    /// él por completo: sin cifrado no se sella ninguna página, así que una
    /// base sin cifrar no paga ni la lectura de `/dev/urandom` ni el estado
    /// del contador.
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    fn offset(&self, page_no: PageNo) -> u64 {
        page_no as u64 * self.geometry().page_size as u64
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

        // Una sola lectura de la geometría para toda la llamada, en vez de
        // volver a tomar el cerrojo por cada campo que hace falta: barato de
        // sobra (una copia de 48 bytes), pero no hay motivo para pagarlo dos
        // veces.
        let page_size = self.geometry().page_size;
        let mut buf = vec![0u8; page_size as usize];
        self.storage.read_at(self.offset(page_no), &mut buf)?;

        // Descifrar, si procede, ANTES de cachear: la caché guarda texto
        // plano (ver el comentario de `Pager`, arriba de la struct), así que
        // un acierto de caché —el caso frecuente— no vuelve a pagar el coste
        // de autenticar. `page_no` va a los datos asociados, igual que en la
        // escritura (`crypto::seal`): es lo que ata cada página a SU número
        // ahora que el nonce se almacena en vez de derivarse de él — sin
        // eso, copiar los bytes de una página encima de otra pasaría la
        // autenticación.
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
    /// nonce+tag ya recortado. Un fallo de autenticación —clave
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
        debug_assert_eq!(bytes.len(), self.geometry().page_size as usize);
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
    /// `stream` es el flujo de nonces de ESTA apertura (`WriterState::
    /// nonce_stream`, `tx.rs`), del que `crypto::seal` saca el nonce de
    /// esta escritura concreta. `None` significa "esta base no está
    /// cifrada", y entonces esta función es exactamente `write`.
    ///
    /// **Un `&mut` que atraviesa, no un contador suelto**, y a propósito:
    /// el nonce ya no puede construirse a partir de argumentos sueltos que
    /// alguien podría inventarse mal (la versión anterior tomaba un `u64` y
    /// dependía de que el llamante lo hiciera monótono). Al pedir el flujo
    /// entero, el único que puede producir un nonce es el propio flujo, que
    /// no existe sin un prefijo aleatorio y que avanza solo — ver
    /// `crypto::NonceStream`.
    ///
    /// Que `stream` sea `Some` cuando la base está cifrada lo garantiza
    /// `Db::create`/`Db::open`, que construyen los dos campos a la vez. Si
    /// aun así llegara `None` sobre una base cifrada, esto falla alto
    /// (`Error::BadFormat`) en vez de escribir la página en claro bajo la
    /// apariencia de que se cifró.
    pub fn write_encrypted(
        &self,
        page_no: PageNo,
        stream: Option<&mut crate::crypto::NonceStream>,
        plain: &[u8],
    ) -> Result<()> {
        match (&self.encryption, stream) {
            (None, _) => self.write(page_no, plain),
            (Some(enc), Some(stream)) => self.seal_and_write(enc, stream, page_no, plain),
            (Some(_), None) => Err(crate::Error::BadFormat),
        }
    }

    #[cfg(feature = "encryption")]
    fn seal_and_write(
        &self,
        enc: &Encryption,
        stream: &mut crate::crypto::NonceStream,
        page_no: PageNo,
        plain: &[u8],
    ) -> Result<()> {
        let mut raw = vec![0u8; self.geometry().page_size as usize];
        crate::crypto::seal(enc, stream, page_no, plain, &mut raw)?;
        self.write(page_no, &raw)
    }

    /// Mismo razonamiento que el `decrypt` gemelo, más arriba: sin la
    /// feature `encryption` no hay forma de producir un sellado real, así
    /// que falla alto en vez de escribir `plain` sin cifrar bajo la
    /// apariencia de que sí se cifró.
    #[cfg(not(feature = "encryption"))]
    fn seal_and_write(
        &self,
        _enc: &Encryption,
        _stream: &mut crate::crypto::NonceStream,
        _page_no: PageNo,
        _plain: &[u8],
    ) -> Result<()> {
        Err(crate::Error::BadFormat)
    }

    pub fn sync(&self) -> Result<()> {
        self.storage.sync()
    }

    /// Recorta el fichero a `pages` páginas y descarta de la caché todo lo
    /// que quede fuera. Único llamador: `Db::reclaim_tail` (`tx.rs`), con
    /// el candado de escritor tomado y con la meta que declara ese
    /// `n_pages` ya sincronizada — ver allí el orden completo.
    ///
    /// **La caché se limpia ANTES de recortar, no después.** Una entrada
    /// cacheada de una página que ya no existe no puede servirse a nadie
    /// mientras el escritor tiene el candado, pero si el `truncate` falla a
    /// mitad y el llamante reintenta, o si la página vuelve a existir tras
    /// una extensión posterior, servir el contenido viejo bajo el mismo
    /// número sería exactamente la corrupción silenciosa que `write` evita
    /// invalidando en vez de actualizar (ver su comentario).
    ///
    /// Ocupa el sitio del antiguo `invalidate(&[PageNo])`, que se conservaba
    /// sin llamador "para cuando haga falta invalidar un lote de páginas sin
    /// pasar por `write` una a una": ese caso ha llegado, y su forma real no
    /// es una lista de números —que en un recorte podría tener millones de
    /// entradas— sino un corte por encima del cual no queda nada. Esto
    /// cuesta O(entradas en caché), no O(páginas recortadas).
    pub fn truncate(&self, pages: PageNo) -> Result<()> {
        let len = pages as u64 * self.geometry().page_size as u64;
        self.cache.lock().unwrap().entries.retain(|e| e.page_no < pages);
        self.storage.truncate(len)
    }

    /// Páginas que caben en el fichero actual. Se usa al abrir para detectar
    /// las que dejó una transacción interrumpida, y —desde la corrección de
    /// la clase "número de página leído de disco"— como la FRONTERA contra
    /// la que se valida todo número de página que sale del medio: ver
    /// `Db::open` en `tx.rs` y `PageDomain` en `freelist.rs`.
    ///
    /// **Satura en `u32::MAX` en vez de truncar.** El motor direcciona 2^32
    /// páginas, así que un fichero más largo que eso no es representable;
    /// con `as u32` a secas, un fichero de 3 TB con páginas de 512 B (6×10^9
    /// páginas) daba la vuelta y se presentaba como 1,7×10^9 — un número
    /// PEQUEÑO, y por tanto una frontera que deja pasar exactamente los
    /// números de página que tenía que rechazar. Saturar convierte ese caso
    /// en la cota más alta posible, que es lo único honesto que se puede
    /// decir de un fichero que no cabe en el espacio de numeración.
    pub fn file_pages(&self) -> Result<u32> {
        let len = self.storage.len()?;
        Ok((len / self.geometry().page_size as u64).min(u32::MAX as u64) as u32)
    }

    /// Acceso directo al medio, sin pasar por la caché ni la geometría
    /// cacheada. Lo necesita la reubicación de la meta B (tarea 18,
    /// `WriteTxn::relocate_meta_b` en `tx.rs`), que reescribe la cabecera —
    /// la única operación del motor que lo hace, y por tanto la única que
    /// necesita este acceso: la cabecera vive en la página `0`, pero
    /// escribirla a través de `write` la trataría como una página cifrada
    /// más y la sellaría con `write_encrypted`, cuando la cabecera nunca
    /// pasa por el cifrado por página (`header::Geometry::write` escribe
    /// bytes en claro directamente).
    pub fn storage(&self) -> &dyn Storage {
        self.storage.as_ref()
    }

    /// Actualiza la geometría en caliente tras mover la meta B (tarea 18).
    /// `&self`, no `&mut self`: `WriteTxn` solo tiene `&Db`, nunca `&mut Db`
    /// (ver el comentario del campo `geometry`, arriba), así que la mutación
    /// tiene que pasar por el `RwLock` en vez de por un préstamo exclusivo
    /// normal. El tamaño de página no cambia nunca — fijo al crear la base
    /// (ver `WriteTxn::page_size`) — así que la caché, que no depende de él
    /// más que a través de esta misma geometría, sigue siendo válida.
    pub fn set_geometry(&self, geometry: Geometry) {
        *self.geometry.write().unwrap() = geometry;
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
    /// (`it_reads_far_fewer_pages_than_it_frees`) y para los bancos de la
    /// tarea 21 (`tests/size.rs`), que miden lecturas de apertura y de poda
    /// desde un binario de integración — de ahí que NO lleve `#[cfg(test)]`
    /// como `cached_pages`, justo arriba: ese binario enlaza la biblioteca
    /// compilada normalmente (sin `--cfg test`), así que un atributo
    /// `#[cfg(test)]` aquí lo dejaría invisible fuera del crate por mucho
    /// que `cargo test` esté ejecutando la prueba — la propia
    /// `pages_in_use` de `tx.rs` tiene la misma nota, con el mismo motivo.
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
