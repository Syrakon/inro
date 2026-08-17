use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::crypto::Encryption;
use crate::header::Geometry;
use crate::page::ValidPage;
use crate::{PageNo, Result, Storage};

/// Entrada de caché. `used` es un contador monótono, no un reloj: sirve solo
/// para elegir la víctima menos usada recientemente.
///
/// Guarda una página YA VALIDADA, no los bytes crudos. Ver el comentario de
/// `Pager::read` para el argumento entero: qué se amortiza con eso, y por
/// qué la invalidación no cambia ni una línea al hacerlo.
struct Entry {
    page_no: PageNo,
    page: ValidPage,
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
    /// Páginas escritas por la transacción en curso y todavía NO en el medio.
    ///
    /// Vive aquí y no en `WriteTxn` porque aquí es donde pasa toda lectura:
    /// el árbol lee por `WriteTxn::read_page`, pero la lista de libres, el
    /// catálogo y los índices leen por el pager directamente. Con el buffer
    /// en la transacción, esos tres caminos leían del fichero páginas que
    /// todavía estaban en RAM y se llevaban un `UnexpectedEof` —el fichero
    /// aún no ha crecido hasta ellas—. 186 pruebas lo dijeron a la primera.
    ///
    /// **No las ve ningún lector**, y no por cortesía: el copy-on-write
    /// escribe siempre en páginas NUEVAS, así que ninguna meta confirmada
    /// referencia una página pendiente. Un lector con un snapshot antiguo no
    /// tiene forma de nombrarlas.
    pending: Mutex<alloc::collections::BTreeMap<PageNo, Arc<[u8]>>>,
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
            pending: Mutex::new(Default::default()),
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

    /// La clave de datos de esta apertura, para quien tenga que sellar algo
    /// que NO es una página: la meta (`WriteTxn::seal_meta`, desde el
    /// formato 3). Las páginas no la necesitan — `write_encrypted`/`read`
    /// sellan y abren aquí dentro, sin que la clave salga del `Pager`.
    ///
    /// Devuelve una referencia y no una copia: `Encryption` es `Copy` (32
    /// bytes de clave), y repartir copias de material de clave por la pila
    /// es justo lo que su `Debug` a mano existe para desalentar.
    pub fn encryption(&self) -> Option<&Encryption> {
        self.encryption.as_ref()
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
    ///
    /// # Por qué devuelve una página validada y no bytes
    ///
    /// Hasta este cambio la caché guardaba `Arc<[u8]>` y todo llamante
    /// hacía `PageRef::parse` sobre lo que recibía, así que **un acierto de
    /// caché volvía a verificar el CRC de la página entera y a recorrer
    /// otra vez el bucle de validación de slots**. El CRC no se amortizaba
    /// nunca: medido, un recorrido completo pagaba un CRC de 4092 bytes por
    /// ENTRADA devuelta, porque el cursor vuelve a pedir la misma hoja en
    /// cada `next`, y una búsqueda puntual pagaba uno por cada nivel del
    /// árbol aunque la raíz llevara cacheada desde la primera consulta.
    /// Guardar `ValidPage` convierte eso en "se valida una vez, al entrar
    /// en la caché".
    ///
    /// **`parse` sigue siendo el único punto de validación.** No se ha
    /// añadido ningún camino que produzca una página sin pasar por él: lo
    /// único que cambia es dónde se llama (aquí, una vez) y que el
    /// resultado se guarda en vez de tirarse. Ver `page::ValidPage` para
    /// por qué el par (bytes, disposición) no puede desparejarse.
    ///
    /// # Invalidación: qué cambia (nada)
    ///
    /// La pregunta peligrosa de este cambio es si una entrada validada
    /// puede servirse cuando ya no debería. **La respuesta es que las
    /// reglas de invalidación son exactamente las de antes, aplicadas a las
    /// mismas entradas y en los mismos sitios**, porque lo que cambia es el
    /// TIPO guardado, no cuándo se guarda ni cuándo se tira:
    ///
    /// 1. Solo hay una forma de que el contenido de una página cambie:
    ///    `Pager::write` (y su envoltorio `write_encrypted`). Sigue
    ///    borrando la entrada de la caché justo después de escribir, así
    ///    que ninguna lectura POSTERIOR a esa escritura puede acertar
    ///    contra la entrada vieja — ni validada ni cruda. Es la misma línea
    ///    de código que antes.
    /// 2. `truncate` sigue descartando toda entrada por encima del corte,
    ///    antes de recortar, por el mismo motivo que ya documenta.
    /// 3. Una escritura de la transacción en curso pasa siempre por
    ///    `WriteTxn::write_page` → `Pager::write_encrypted` → `Pager::write`
    ///    (`tx.rs`), así que entra en el punto 1. No hay ninguna vía que
    ///    escriba una página del árbol saltándose `Pager::write`: la única
    ///    escritura directa al medio es la de la cabecera en
    ///    `relocate_meta_b`, sobre la página 0, que nadie lee por aquí.
    /// 4. Quien ya SOSTIENE una página puede seguir viéndola después de que
    ///    otro la reescriba — pero eso pasaba idéntico cuando lo que
    ///    sostenía era `Arc<[u8]>`: los bytes clonados no se enteraban de
    ///    la escritura. Que ningún lector vivo sostenga una página que el
    ///    escritor va a reescribir no lo garantiza esta capa, sino la de
    ///    transacciones (lista de libres más tabla de lectores); ver la
    ///    documentación de `write`, más abajo, que ya lo decía y sigue
    ///    valiendo palabra por palabra.
    ///
    /// Dicho al revés: si este cambio pudiera servir una página validada
    /// obsoleta, la versión anterior habría servido los BYTES obsoletos de
    /// esa misma página, y el `parse` del llamante los habría aceptado —
    /// son bytes con su CRC correcto, solo que de otro momento. El fallo
    /// que hay que evitar no es "validar demasiado pronto", es "no
    /// invalidar", y de eso no se ha tocado nada.
    pub fn read(&self, page_no: PageNo) -> Result<ValidPage> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        // Lo pendiente manda sobre el medio y sobre la caché: es la versión
        // más reciente de esa página y todavía no ha salido de la RAM.
        if let Some(bytes) = self.pending.lock().unwrap().get(&page_no) {
            return ValidPage::parse(Arc::clone(bytes), page_no);
        }
        {
            let mut c = self.cache.lock().unwrap();
            c.tick += 1;
            let tick = c.tick;
            if let Some(e) = c.entries.iter_mut().find(|e| e.page_no == page_no) {
                e.used = tick;
                return Ok(e.page.clone());
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

        // Validar ANTES de cachear, por el mismo motivo por el que se
        // descifra antes de cachear: una entrada de caché es una respuesta
        // ya preparada, y una página que no pasa `parse` no es una
        // respuesta que se pueda dar. Una página corrupta, además, no entra
        // en la caché — así que no ocupa sitio ni se le vuelve a preguntar.
        let page = ValidPage::parse(bytes, page_no)?;

        let mut c = self.cache.lock().unwrap();
        c.insert(page_no, page.clone());
        Ok(page)
    }

    /// Bytes crudos de una página, SIN validar y sin tocar la caché.
    ///
    /// Solo pruebas: las dos que escriben una página que a propósito no es
    /// una página válida (`commit_makes_writes_visible_to_new_readers` en
    /// `tx.rs`, que usa un relleno reconocible como marca) o que esperan
    /// que el descifrado falle antes de cualquier otra cosa
    /// (`a_sealed_page_moved_to_another_number_fails_to_open` en
    /// `crypto.rs`). No cachea a propósito: lo que devuelve no ha pasado
    /// por `parse`, así que no tiene nada que hacer en una caché cuya
    /// invariante es justo la contraria.
    #[cfg(test)]
    pub fn read_bytes(&self, page_no: PageNo) -> Result<Arc<[u8]>> {
        let page_size = self.geometry().page_size;
        let mut buf = vec![0u8; page_size as usize];
        self.storage.read_at(self.offset(page_no), &mut buf)?;
        Ok(match &self.encryption {
            None => Arc::from(buf.into_boxed_slice()),
            Some(enc) => Arc::from(self.decrypt(enc, page_no, buf)?.into_boxed_slice()),
        })
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
    /// Aparca una página escrita por la transacción en curso. Sale al medio
    /// en `take_pending`, al cerrar el commit — ver el campo `pending`.
    pub fn stage(&self, page_no: PageNo, bytes: &[u8]) {
        self.pending.lock().unwrap().insert(page_no, Arc::from(bytes));
    }

    /// Cuántas páginas hay aparcadas. La transacción lo usa para decidir si
    /// derrama.
    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Se lleva lo aparcado, en orden de página —que es secuencial en el
    /// fichero—. El sellado no puede hacerse aquí: la clave de nonce vive en
    /// el estado del escritor, así que quien vacía es `WriteTxn::flush_dirty`.
    pub fn take_pending(&self) -> alloc::vec::Vec<(PageNo, Arc<[u8]>)> {
        core::mem::take(&mut *self.pending.lock().unwrap()).into_iter().collect()
    }

    /// Descarta lo aparcado sin escribirlo: una transacción abandonada no deja
    /// rastro, que es lo que el contrato de `WriteTxn` promete.
    pub fn drop_pending(&self) {
        self.pending.lock().unwrap().clear();
    }

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
    fn insert(&mut self, page_no: PageNo, page: ValidPage) {
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
        self.entries.push(Entry { page_no, page, used: self.tick });
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

    /// Una página VÁLIDA con una marca reconocible en su campo `extra`.
    ///
    /// Antes bastaba con `vec![0u8; 512]` y un byte suelto cambiado: la
    /// caché guardaba bytes crudos y `Pager::read` no miraba lo que
    /// devolvía. Desde que guarda páginas ya validadas, `read` llama a
    /// `PageRef::parse`, y un relleno arbitrario no es una página — sería
    /// `Err(Corrupt)`. La marca se lee de vuelta con `extra()` en vez de
    /// indexando un byte.
    fn marked_page(mark: u32) -> alloc::vec::Vec<u8> {
        let mut b = crate::page::PageBuilder::new(512, crate::page::PageType::Leaf);
        b.set_extra(mark);
        b.build(&[]).unwrap()
    }

    #[test]
    fn reads_back_a_written_page() {
        let p = pager(4);
        p.write(3, &marked_page(42)).unwrap();
        assert_eq!(p.read(3).unwrap().page().extra(), 42);
    }

    #[test]
    fn a_rewritten_page_is_not_served_stale_from_cache() {
        let p = pager(4);
        p.write(3, &marked_page(0)).unwrap();
        assert_eq!(p.read(3).unwrap().page().extra(), 0);
        p.write(3, &marked_page(9)).unwrap();
        assert_eq!(
            p.read(3).unwrap().page().extra(),
            9,
            "write invalida la entrada cacheada"
        );
    }

    /// El riesgo propio de cachear páginas YA VALIDADAS: que una entrada
    /// validada sobreviva a una escritura y se siga sirviendo como buena.
    /// La página 3 se cachea validada, y encima se escriben bytes que NO
    /// forman una página; la lectura siguiente tiene que ver la corrupción,
    /// no la validación vieja.
    #[test]
    fn a_page_overwritten_with_garbage_is_not_served_from_the_validated_entry() {
        let p = pager(4);
        p.write(3, &marked_page(7)).unwrap();
        assert_eq!(p.read(3).unwrap().page().extra(), 7);
        assert!(p.is_cached(3));

        p.write(3, &alloc::vec![0xabu8; 512]).unwrap();
        assert!(
            matches!(p.read(3), Err(crate::Error::Corrupt { page: 3, .. })),
            "una entrada validada no puede sobrevivir a la reescritura de su pagina"
        );
    }

    /// Una página que no pasa `parse` no entra en la caché: si entrara,
    /// ocuparía un hueco del presupuesto para no poder servirse nunca, y el
    /// error tendría que volver a producirse desde una entrada guardada.
    #[test]
    fn a_corrupt_page_is_rejected_and_never_cached() {
        let p = pager(4);
        p.write(3, &alloc::vec![0xabu8; 512]).unwrap();
        assert!(matches!(p.read(3), Err(crate::Error::Corrupt { page: 3, .. })));
        assert_eq!(p.cached_pages(), 0);
        assert!(!p.is_cached(3));
    }

    #[test]
    fn cache_never_grows_past_its_budget() {
        let p = pager(2);
        for n in 0..10 {
            p.write(n, &marked_page(n)).unwrap();
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
        for n in 0..3 {
            p.write(n, &marked_page(n)).unwrap();
        }
        p.read(0).unwrap();
        p.read(1).unwrap();

        // Tocar la página 0 la vuelve la más recientemente usada; la 1
        // queda como la menos usada, aunque la 0 se insertó primero. Un
        // desalojo por mero orden de inserción (FIFO) confundiría esto
        // con "la 0 es la más vieja" y desalojaría la equivocada.
        p.read(0).unwrap();

        p.read(2).unwrap();

        assert_eq!(p.cached_pages(), 2);
        assert!(p.is_cached(0), "la pagina tocada recientemente sobrevive");
        assert!(!p.is_cached(1), "la pagina menos usada se desaloja, no la mas vieja por insercion");
        assert!(p.is_cached(2), "la pagina recien insertada esta presente");
    }

    #[test]
    fn a_zero_page_budget_disables_caching() {
        let p = pager(0);
        p.write(1, &marked_page(1)).unwrap();
        p.read(1).unwrap();
        assert_eq!(p.cached_pages(), 0);
    }

    #[test]
    fn file_pages_rounds_down_to_whole_pages() {
        let p = pager(1);
        p.write(4, &marked_page(0)).unwrap();
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
