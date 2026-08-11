//! Cifrado autenticado por página (tarea 17).
//!
//! `NONCE_LEN`/`TAG_LEN`/`WRAPPED_KEY_LEN` se compilan siempre, sin
//! condición alguna: `meta.rs` necesita `WRAPPED_KEY_LEN` incluso en una
//! compilación `no_std` sin cifrado, porque es parte del formato de
//! fichero puro (bytes 40..100 de cada meta-ranura), igual que
//! `header`/`page`. Ninguno de los tres depende de
//! `chacha20poly1305`/`aes-gcm`: son enteros calculados en tiempo de
//! compilación.
//!
//! `Algorithm`/`Encryption`/`CIPHER_PREFIX`, en cambio, están tras
//! `#[cfg(any(feature = "std", feature = "encryption"))]`: los usa
//! `pager.rs`/`tx.rs` bajo `std` (`Pager::logical_page_size`,
//! `Options::encryption`) SIN que haga falta `encryption` — son tipos
//! simples, no tocan las dependencias — y también `seal`/`open`, que
//! sí las tocan, bajo `encryption` SIN que haga falta `std` (son
//! `no_std`-compatibles, pensadas para un llamante que integre su propio
//! almacenamiento). Sin esta doble condición, un build
//! `--no-default-features` (ninguna de las dos) los deja sin ningún
//! llamador alcanzable y dispara aviso de código muerto — lo que de
//! verdad toca `chacha20poly1305`/`aes-gcm` (`seal`, `open`, `wrap_key`,
//! `unwrap_key`, `generate_data_key`/`generate_nonce`) sigue solo tras
//! `encryption`, así que ese build nunca las enlaza.
//!
//! Nota aparte, no cubierta por las cuatro comprobaciones que exige la
//! tarea: `--no-default-features --features encryption` (`no_std` CON
//! cifrado, sin `std`) compila pero avisa de código muerto en `seal`/
//! `open`/`wrap_key`/`unwrap_key`/`nonce`/`CIPHER_PREFIX`, porque este
//! módulo es `pub(crate)` (ver `lib.rs`) y en ese build no existe
//! `pager.rs`/`tx.rs` (piden `std`) que los llame — no hay ningún
//! consumidor `no_std` real todavía. El comentario de `seal`/`open` que
//! los llama "compatibles con no_std" es cierto en el sentido de qué
//! exige la propia función (nada de `std`), no en que hoy exista un
//! camino público para usarlos así.

// A diferencia de `Algorithm`/`Encryption`/`CIPHER_PREFIX` más abajo, esto
// solo hace falta bajo `encryption`: son los tipos que usan `nonce`, `seal`,
// `open`, `wrap_key`, `unwrap_key` y `generate_data_key`/`generate_nonce`,
// todas tras esa feature — `pager.rs`/`tx.rs` (que solo piden `std`) nunca
// tocan `Error`/`PageNo`/`Result`/`TxnId` DESDE ESTE fichero: usan los suyos
// propios, importados en `pager.rs`/`tx.rs`.
#[cfg(feature = "encryption")]
use crate::{Error, PageNo, Result, TxnId};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Envoltorio de la clave de datos: nonce de 12, texto cifrado de 32 y tag de
/// 16, en los bytes 40..100 de la meta.
pub const WRAPPED_KEY_LEN: usize = NONCE_LEN + 32 + TAG_LEN;

/// Bytes en claro al principio de una página cifrada: `txn_id` y tag.
#[cfg(any(feature = "std", feature = "encryption"))]
pub const CIPHER_PREFIX: usize = 8 + TAG_LEN;

#[cfg(any(feature = "std", feature = "encryption"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Por defecto. Sin aceleración por hardware mantiene entre 200 y 400 MB/s,
    /// cuatro veces más que AES en software, que es el caso de los procesadores
    /// IoT sin extensiones criptográficas.
    ChaCha20Poly1305,
    /// Para entornos con AES-NI o requisitos de cumplimiento que lo exijan.
    Aes256Gcm,
}

#[cfg(any(feature = "std", feature = "encryption"))]
#[derive(Clone, Copy)]
pub struct Encryption {
    pub key: [u8; 32],
    pub algorithm: Algorithm,
}

/// A mano, no `#[derive]`: un `derive(Debug)` volcaría `key` byte a byte en
/// cualquier `{:?}` accidental (un panic, un log, una aserción fallida en
/// una prueba) — exactamente el material que este módulo existe para
/// proteger. `Options` (`tx.rs`) sigue derivando `Debug` porque este `impl`
/// se lo permite sin exponer nada.
#[cfg(any(feature = "std", feature = "encryption"))]
impl core::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryption").field("key", &"[redactado]").field("algorithm", &self.algorithm).finish()
    }
}

/// Nonce derivado, nunca almacenado. Su unicidad depende de que una página no
/// se escriba dos veces en la misma transacción.
#[cfg(feature = "encryption")]
fn nonce(page: PageNo, txn: TxnId) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&page.to_le_bytes());
    n[4..].copy_from_slice(&txn.to_le_bytes());
    n
}

/// Cifra `plain` en `out`, que debe medir `CIPHER_PREFIX + plain.len()`.
#[cfg(feature = "encryption")]
pub fn seal(
    enc: &Encryption,
    page: PageNo,
    txn: TxnId,
    plain: &[u8],
    out: &mut [u8],
) -> Result<()> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};

    out[..8].copy_from_slice(&txn.to_le_bytes());
    out[CIPHER_PREFIX..].copy_from_slice(plain);
    let n = nonce(page, txn);

    let tag = match enc.algorithm {
        Algorithm::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new((&enc.key).into());
            cipher
                .encrypt_in_place_detached((&n).into(), &[], &mut out[CIPHER_PREFIX..])
                .map_err(|_| Error::Decrypt { page })?
        }
        #[cfg(feature = "aes")]
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
            let cipher = aes_gcm::Aes256Gcm::new((&enc.key).into());
            cipher
                .encrypt_in_place_detached((&n).into(), &[], &mut out[CIPHER_PREFIX..])
                .map_err(|_| Error::Decrypt { page })?
        }
        #[cfg(not(feature = "aes"))]
        Algorithm::Aes256Gcm => return Err(Error::BadFormat),
    };
    out[8..CIPHER_PREFIX].copy_from_slice(&tag);
    Ok(())
}

/// Descifra `raw` en sitio: tras devolver `Ok`, `raw[CIPHER_PREFIX..]`
/// contiene la página lógica en claro. El llamante (`Pager::read`) es quien
/// recorta el prefijo — este módulo no sabe nada de caché ni de cómo se
/// almacena el resultado.
#[cfg(feature = "encryption")]
pub fn open(enc: &Encryption, page: PageNo, raw: &mut [u8]) -> Result<()> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};

    let txn = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&raw[8..CIPHER_PREFIX]);
    let n = nonce(page, txn);

    match enc.algorithm {
        Algorithm::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new((&enc.key).into());
            cipher
                .decrypt_in_place_detached(
                    (&n).into(),
                    &[],
                    &mut raw[CIPHER_PREFIX..],
                    (&tag).into(),
                )
                .map_err(|_| Error::Decrypt { page })
        }
        #[cfg(feature = "aes")]
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
            let cipher = aes_gcm::Aes256Gcm::new((&enc.key).into());
            cipher
                .decrypt_in_place_detached(
                    (&n).into(),
                    &[],
                    &mut raw[CIPHER_PREFIX..],
                    (&tag).into(),
                )
                .map_err(|_| Error::Decrypt { page })
        }
        #[cfg(not(feature = "aes"))]
        Algorithm::Aes256Gcm => Err(Error::BadFormat),
    }
}

/// Fuente común de bytes aleatorios para `generate_data_key` y
/// `generate_nonce`: ambos leen `/dev/urandom` exactamente igual, así que
/// factorizarlo evita que diverjan por accidente. Gateado con
/// `encryption` además de `std` (a diferencia de lo que sugería el brief
/// original, que solo pedía `std`): sin esa `encryption` extra, esta
/// función — y `generate_data_key`/`generate_nonce` — compilarían igual en
/// un build `cargo test` (std sin cifrado), pero sin ningún llamador
/// alcanzable (`Db::create`/`open` solo las invocan bajo `encryption`,
/// ver `tx.rs`), lo que dispara el aviso de código muerto que pide
/// mantener limpio el fichero.
#[cfg(all(feature = "encryption", feature = "std"))]
fn read_random(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| Error::Io(crate::IoError::NotFound))
}

/// Clave de datos aleatoria, generada al crear la base.
///
/// Se lee de `/dev/urandom` en lugar de añadir `getrandom` como dependencia.
/// Bajo `no_std` la aporta el llamante, porque no hay fuente de entropía
/// portable sin sistema operativo.
#[cfg(all(feature = "encryption", feature = "std"))]
pub fn generate_data_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    read_random(&mut key)?;
    Ok(key)
}

/// Nonce del envoltorio de la clave de datos (ver `wrap_key`): aleatorio, no
/// derivado — la meta se reescribe en cada commit, así que un nonce
/// derivado de página+transacción se repetiría. No lo especificaba el
/// brief como función aparte, pero `wrap_key` exige un nonce fresco en
/// cada llamada y `Db::create`/rotar la maestra necesitan generarlo desde
/// algún sitio; misma fuente de entropía que `generate_data_key`, por la
/// misma razón.
#[cfg(all(feature = "encryption", feature = "std"))]
pub fn generate_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    read_random(&mut n)?;
    Ok(n)
}

/// Cifra la clave de datos con la maestra. El nonce va en claro dentro del
/// propio envoltorio: aquí no puede derivarse de página y transacción, porque
/// la meta se reescribe en cada commit y eso repetiría el nonce.
#[cfg(feature = "encryption")]
pub fn wrap_key(master: &[u8; 32], data_key: &[u8; 32], nonce_bytes: [u8; NONCE_LEN])
    -> Result<[u8; WRAPPED_KEY_LEN]>
{
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce_bytes);
    out[NONCE_LEN..NONCE_LEN + 32].copy_from_slice(data_key);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(master.into());
    let tag = cipher
        .encrypt_in_place_detached(
            (&nonce_bytes).into(),
            &[],
            &mut out[NONCE_LEN..NONCE_LEN + 32],
        )
        .map_err(|_| Error::Decrypt { page: 0 })?;
    out[NONCE_LEN + 32..].copy_from_slice(&tag);
    Ok(out)
}

#[cfg(feature = "encryption")]
pub fn unwrap_key(master: &[u8; 32], wrapped: &[u8; WRAPPED_KEY_LEN]) -> Result<[u8; 32]> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&wrapped[..NONCE_LEN]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&wrapped[NONCE_LEN..NONCE_LEN + 32]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&wrapped[NONCE_LEN + 32..]);

    let cipher = chacha20poly1305::ChaCha20Poly1305::new(master.into());
    cipher
        .decrypt_in_place_detached((&nonce_bytes).into(), &[], &mut buf, (&tag).into())
        .map_err(|_| Error::Decrypt { page: 0 })?;
    Ok(buf)
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Encryption, Options};
    use crate::Storage;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    fn opts(key: [u8; 32]) -> Options {
        Options {
            encryption: Some(Encryption { key, algorithm: Algorithm::ChaCha20Poly1305 }),
            ..Options::default()
        }
    }

    /// Permite conservar el medio tras cerrar la base, para reabrirla. Cada
    /// módulo de pruebas define su propia copia local (ver `tx.rs`,
    /// `tree.rs`, `index.rs`): es un tipo diminuto y sin estado propio del
    /// test, no algo que merezca una utilidad compartida entre módulos.
    struct ArcStorage(Arc<MemStorage>);
    impl Storage for ArcStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    /// Envuelve `MemStorage` y guarda el par `(offset, primeros 8 bytes
    /// escritos)` de cada escritura — exactamente `(página, txn_id)` para
    /// cualquier página que pase por `Pager::write_encrypted` (el `txn_id`
    /// va en claro en los primeros 8 bytes de una página cifrada, ver
    /// `CIPHER_PREFIX`). Es la instrumentación central de
    /// `no_nonce_is_ever_reused`: si el motor alguna vez reescribiera una
    /// página dentro de la misma transacción — la única forma de repetir un
    /// nonce con este esquema — esa segunda escritura caería en el mismo
    /// `offset` con el mismo `txn_id` que la primera, y el par se
    /// duplicaría en `nonces()`.
    struct RecordingStorage {
        inner: MemStorage,
        writes: Mutex<Vec<(u64, [u8; 8])>>,
    }

    impl RecordingStorage {
        fn new() -> Self {
            Self { inner: MemStorage::new(), writes: Mutex::new(Vec::new()) }
        }

        fn nonces(&self) -> Vec<(u64, [u8; 8])> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl Storage for RecordingStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.inner.read_at(o, b)
        }

        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            // Toda escritura real de este motor mide al menos una página
            // (>= `MIN_PAGE_SIZE` = 512) salvo la cabecera (64 bytes): nunca
            // menos de 8. El guard es solo defensivo, para no entrar en
            // pánico si algún día deja de ser cierto.
            if b.len() >= 8 {
                let mut first8 = [0u8; 8];
                first8.copy_from_slice(&b[..8]);
                self.writes.lock().unwrap().push((o, first8));
            }
            self.inner.write_at(o, b)
        }

        fn sync(&self) -> Result<()> { self.inner.sync() }
        fn len(&self) -> Result<u64> { self.inner.len() }
    }

    struct ArcRecording(Arc<RecordingStorage>);
    impl Storage for ArcRecording {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    #[test]
    fn data_roundtrips_through_encryption() {
        let db = Db::create(Box::new(MemStorage::new()), opts([1; 32])).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"secreto", b"valor").unwrap();
        tx.commit().unwrap();
        assert_eq!(db.begin_read().get(0x01, b"secreto").unwrap().as_deref(), Some(b"valor".as_slice()));
    }

    /// Autorrevisión (ronda propia, no del brief): las 187 pruebas
    /// existentes de `tree.rs`/`tx.rs` no se pueden correr tal cual con
    /// cifrado activo — varias construyen páginas A MANO al tamaño físico
    /// exacto (`tree.rs::raw_overflow_page` y compañía), y cambiar el
    /// tamaño de página a mitad de esas pruebas las rompería por una razón
    /// ajena a esta tarea. Esta prueba es el sustituto deliberado: el mismo
    /// TIPO de carga que esas — muchas inserciones que fuerzan divisiones
    /// de nodo, un valor por encima del umbral de overflow, borrados
    /// intercalados — pero pasando siempre por `Options.encryption =
    /// Some(...)`, que es exactamente donde se manifestaría un
    /// `page_size()` olvidado en vez de `logical_page_size()`: o
    /// `PageBuilder` construiría páginas "lógicas" de 512 B que, tras
    /// sellar, medirían 536 B físicos — reventando el
    /// `debug_assert_eq!` de `Pager::write` en cuanto se compila en modo
    /// debug — o el límite de tamaño de clave (`logical_page_size / 4`)
    /// aceptaría una clave que de verdad no cabe en la página que se
    /// termina construyendo.
    #[test]
    fn a_large_encrypted_workload_round_trips_through_splits_and_overflow() {
        let db = Db::create(Box::new(MemStorage::new()), opts([7; 32])).unwrap();

        let mut tx = db.begin_write().unwrap();
        for i in 0..300u32 {
            let value = alloc::vec![(i % 251) as u8; 20];
            tx.put(0x01, &i.to_be_bytes(), &value).unwrap();
        }
        // Por encima de `overflow_threshold(logical_page_size)` — con
        // cifrado y página de 512 B, 488 / 4 = 122 — para forzar una cadena
        // de overflow real construida a tamaño lógico.
        let big = alloc::vec![0xabu8; 300];
        tx.put(0x01, b"grande", &big).unwrap();
        // Borrados intercalados: ejercitan `free_overflow`/`emit`
        // reconstruyendo hojas ya existentes, no solo insertando en unas
        // nuevas.
        for i in (0..300u32).step_by(3) {
            tx.delete(0x01, &i.to_be_bytes()).unwrap();
        }
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..300u32 {
            let expected = if i % 3 == 0 { None } else { Some(alloc::vec![(i % 251) as u8; 20]) };
            assert_eq!(r.get(0x01, &i.to_be_bytes()).unwrap(), expected, "clave {i}");
        }
        assert_eq!(r.get(0x01, b"grande").unwrap(), Some(big));

        let mut cursor = r.scan(0x01, &0u32.to_be_bytes(), &300u32.to_be_bytes()).unwrap();
        let mut count = 0u32;
        while cursor.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 200, "200 de las 300 claves deberían sobrevivir al borrado de una de cada tres");
    }

    /// Autorrevisión: `no_nonce_is_ever_reused` (más abajo) comprueba una
    /// propiedad de CAJA NEGRA sobre el patrón de escrituras — que el par
    /// `(offset, primeros 8 bytes)` nunca se repite — pero eso por sí solo
    /// NO demuestra que `nonce(page, txn)` de verdad combine los dos
    /// valores al derivar el nonce real que ve el cifrador. Si `nonce`
    /// tuviera un fallo que la ignorara (p. ej. `nonce(page, txn) =
    /// f(txn)` solo, olvidando `page`), el cifrado y el descifrado
    /// seguirían siendo simétricos entre sí — usan la misma función rota
    /// en los dos sentidos — así que TODAS las pruebas de round-trip de
    /// este módulo (`data_roundtrips_through_encryption` incluida)
    /// seguirían en verde: el par `(offset, txn_id)` grabado por
    /// `RecordingStorage` seguiría siendo único porque `offset` distingue
    /// páginas aunque el nonce interno no lo haga. Es exactamente el "test
    /// que pasa por la razón equivocada" que pide evitar el brief. Esta
    /// prueba cierra ese hueco mirando `nonce` directamente, de caja
    /// blanca: página distinta debe cambiar el nonce con el mismo `txn`, y
    /// viceversa.
    #[test]
    fn nonce_depends_on_both_page_and_txn() {
        let same_txn_different_page = nonce(1, 100);
        let different_txn_same_page = nonce(1, 200);
        let baseline = nonce(1, 100);
        assert_ne!(nonce(2, 100), baseline, "el nonce no depende de la página");
        assert_ne!(different_txn_same_page, baseline, "el nonce no depende de la transacción");
        assert_eq!(same_txn_different_page, baseline, "debe ser determinista: mismos argumentos, mismo nonce");
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        let s = Arc::new(MemStorage::new());
        let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts([2; 32])).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"aguja", b"pajar-secreto-inconfundible").unwrap();
        tx.commit().unwrap();
        let bytes = s.snapshot();
        assert!(
            !bytes.windows(27).any(|w| w == b"pajar-secreto-inconfundible"),
            "el valor aparece en claro en el fichero"
        );
    }

    #[test]
    fn a_wrong_key_fails_to_decrypt_instead_of_returning_garbage() {
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts([3; 32])).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"k", b"v").unwrap();
            tx.commit().unwrap();
        }
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts([4; 32]));
        assert!(matches!(db, Err(Error::Decrypt { .. })));
    }

    #[test]
    fn a_tampered_page_is_rejected() {
        let s = Arc::new(MemStorage::new());
        let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts([5; 32])).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"k", b"v").unwrap();
        tx.commit().unwrap();
        let root = db.begin_read().root();
        drop(db);
        // Voltea un byte del texto cifrado de la página raíz.
        let mut bytes = s.snapshot();
        bytes[root as usize * 512 + 100] ^= 0xff;
        s.restore(bytes);
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts([5; 32])).unwrap();
        assert!(matches!(db.begin_read().get(0x01, b"k"), Err(Error::Decrypt { .. })));
    }

    #[test]
    fn no_nonce_is_ever_reused() {
        let s = Arc::new(RecordingStorage::new());
        let db = Db::create(Box::new(ArcRecording(Arc::clone(&s))), opts([6; 32])).unwrap();
        for i in 0..200u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            tx.commit().unwrap();
        }
        let nonces = s.nonces();
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "nonce repetido");
    }
}
