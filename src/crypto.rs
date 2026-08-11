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
//!
//! ## Backend portable de ChaCha20/Poly1305: medido, no forzado
//!
//! `chacha20` (dependencia transitiva de `chacha20poly1305`) elige su
//! backend en tiempo de compilación: sin ningún `--cfg`, en x86/x86_64
//! autodetecta AVX2/SSE2 en tiempo de ejecución y usa intrínsecos con
//! `unsafe` (`backends/avx2.rs`, `backends/sse2.rs` del crate `chacha20`,
//! confirmado por inspección directa del código fuente). Con
//! `RUSTFLAGS="--cfg chacha20_force_soft --cfg poly1305_force_soft"` fuerza
//! el backend portable (`backends/soft.rs`), que no contiene ni una sola
//! palabra clave `unsafe` — Rust puro, coherente con la única excepción a
//! "cero `unsafe`" que documenta este crate (ver `Cargo.toml`). `aes`/
//! `polyval` (el backend AES-GCM, tras la feature `aes`) tienen el mismo
//! patrón vía `aes_force_soft`/`polyval_force_soft`.
//!
//! Medido (no supuesto) en un Intel Core "Haswell" con AVX2+SSE2+AES-NI,
//! cifrando páginas de 4 KB con `encrypt_in_place_detached`, ~780 MB por
//! corrida, `opt-level = 3` + `lto = true`, 3 corridas por configuración:
//!
//! | Backend | MB/s (3 corridas) | Media |
//! |---|---|---|
//! | Por defecto (AVX2/SSE2, `unsafe`) | 707.0 / 738.5 / 764.9 | ~737 MB/s |
//! | Portable (`--cfg *_force_soft`, sin `unsafe`) | 359.5 / 327.7 / 376.9 | ~355 MB/s |
//!
//! El backend portable rinde **~2,1× más lento** en este hardware — la cifra
//! "200 a 400 MB/s" del comentario de `Algorithm::ChaCha20Poly1305`, más
//! abajo, es justo el rango que dio esta medición, no una cifra inventada.
//!
//! **Esto NO se fuerza en este `Cargo.toml`.** `inro` es una biblioteca:
//! `RUSTFLAGS`/`--cfg` es una decisión de quien construye el binario final
//! que la enlaza, no algo que el `Cargo.toml` de una dependencia pueda
//! fijar por sí solo. Forzarlo aquí le quitaría a quien integra `inro` la
//! posibilidad de elegir la vía rápida si ya confía en el backend con
//! `unsafe` de RustCrypto (ampliamente auditado, no código de este crate) —
//! coherente con que `forbid(unsafe_code)` en `Cargo.toml` cubre el código
//! de `inro`, no el de sus dependencias.
//!
//! ## Límite conocido, fuera del alcance de esta tarea: la meta no está autenticada
//!
//! La meta-página (`meta.rs`) solo lleva su CRC32 de siempre — no pasa por
//! `seal`/`open`, por la razón que explica el comentario de `wrap_key`: no
//! hay forma de derivar su nonce sin repetirlo, porque se reescribe en cada
//! commit. Consecuencia: quien puede escribir el fichero puede reapuntar
//! `root`/`freelist_head`/`freelist_tail` a cualquier OTRA página cifrada
//! del mismo fichero (recalculando el CRC32, que no es secreto) y esa
//! página se DESCIFRARÁ LIMPIA — el nonce que la protege liga página y
//! contador, no el PAPEL que esa página juega en el árbol. El tag de
//! autenticación certifica "esta página se cifró con esta clave para este
//! `(page, counter)`", no "esta página es la raíz legítima de este árbol
//! en este momento". Cerrarlo exigiría autenticar también la meta —
//! diseño propio, con su propio ciclo de revisión, no un ajuste de esta
//! ronda.

// A diferencia de `Algorithm`/`Encryption`/`CIPHER_PREFIX` más abajo, esto
// solo hace falta bajo `encryption`: son los tipos que usan `nonce`, `seal`,
// `open`, `wrap_key`, `unwrap_key` y `generate_data_key`/`generate_nonce`,
// todas tras esa feature — `pager.rs`/`tx.rs` (que solo piden `std`) nunca
// tocan `Error`/`PageNo`/`Result` DESDE ESTE fichero: usan los suyos
// propios, importados en `pager.rs`/`tx.rs`.
#[cfg(feature = "encryption")]
use crate::{Error, PageNo, Result};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Envoltorio de la clave de datos: nonce de 12, texto cifrado de 32 y tag de
/// 16, en los bytes 40..100 de la meta.
pub const WRAPPED_KEY_LEN: usize = NONCE_LEN + 32 + TAG_LEN;

/// Bytes en claro al principio de una página cifrada: contador de nonce (no
/// `txn_id` — ver el comentario de `nonce`, más abajo) y tag.
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

/// Nonce derivado, nunca almacenado. Su unicidad depende de que `counter`
/// nunca se repita para una misma `page` — ver `crate::tx::WriteTxn`, que es
/// quien garantiza eso reservando un tramo de contadores por adelantado
/// (`Db::extend_counter_ceiling`) en vez de derivar de `txn_id` (ronda de revisión
/// posterior a la primera entrega: `txn_id` es el mismo para TODAS las
/// páginas de una transacción, y `own_free` — tarea 12 — puede hacer que la
/// MISMA página se escriba varias veces dentro de una sola transacción,
/// reutilizando ese `txn_id` y por tanto el nonce; `counter` es un valor
/// nuevo por cada llamada a `write_page`, nunca por transacción).
///
/// Bytes literales: `page.to_le_bytes() ++ counter.to_le_bytes()`, doce en
/// total — lo comprueba `nonce_is_exactly_page_then_counter_little_endian`.
#[cfg(feature = "encryption")]
fn nonce(page: PageNo, counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&page.to_le_bytes());
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Cifra `plain` en `out`, que debe medir `CIPHER_PREFIX + plain.len()`.
/// `counter` es el contador de nonce de esta escritura concreta — NO el
/// `txn_id` de la transacción, ver el comentario de `nonce` — y viaja en
/// claro en los primeros 8 bytes de `out`, que es de donde `open` lo vuelve
/// a leer para poder rederivar el mismo nonce sin almacenarlo.
#[cfg(feature = "encryption")]
pub fn seal(
    enc: &Encryption,
    page: PageNo,
    counter: u64,
    plain: &[u8],
    out: &mut [u8],
) -> Result<()> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};

    // Comprobación explícita en vez de dejar que un tamaño equivocado entre
    // en pánico en el `copy_from_slice`/slicing de más abajo (ronda de
    // revisión posterior a la primera entrega, hallazgo LOW): `seal` es
    // `pub`, y el único guardián de tamaño que tenía antes de este cambio
    // era el `debug_assert_eq!` de `Pager::write` — ausente en release.
    if out.len() != CIPHER_PREFIX + plain.len() {
        return Err(Error::BadFormat);
    }

    out[..8].copy_from_slice(&counter.to_le_bytes());
    out[CIPHER_PREFIX..].copy_from_slice(plain);
    let n = nonce(page, counter);

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

    // Mismo razonamiento que en `seal`: sin esto, una página físicamente
    // más corta que `CIPHER_PREFIX` entraría en pánico en el slicing de
    // abajo en vez de fallar limpio.
    if raw.len() < CIPHER_PREFIX {
        return Err(Error::BadFormat);
    }

    let counter = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&raw[8..CIPHER_PREFIX]);
    let n = nonce(page, counter);

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
    // Distingue el motivo del fallo en vez de aplastarlo todo a `NotFound`
    // (ronda de revisión posterior a la primera entrega, hallazgo LOW): un
    // `/dev/urandom` que existe pero no se puede abrir por permisos se
    // reportaba como "no encontrado", que lleva a quien depura por el
    // camino equivocado (¿kernel sin `/dev/urandom`? no — permisos).
    fn map_io(e: std::io::Error) -> Error {
        use std::io::ErrorKind as K;
        Error::Io(match e.kind() {
            K::NotFound => crate::IoError::NotFound,
            K::PermissionDenied => crate::IoError::PermissionDenied,
            K::UnexpectedEof => crate::IoError::UnexpectedEof,
            _ => crate::IoError::Other(e.raw_os_error().unwrap_or(0)),
        })
    }
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(map_io)
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
    use crate::tx::{Db, Encryption, Options, Sync};
    use crate::Storage;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::time::Duration;
    use std::sync::Mutex;

    /// Parametrizado por algoritmo (ronda de revisión posterior a la
    /// primera entrega, hallazgo MEDIUM): sin esto, `--features aes`
    /// compilaba el backend AES-GCM pero ninguna prueba lo instanciaba de
    /// verdad — cobertura de compilación, no de ejecución. `opts` (más
    /// abajo) sigue siendo ChaCha20-Poly1305 para las pruebas que no
    /// necesitan variar el algoritmo; las pruebas específicas de AES-GCM
    /// usan `opts_with` directamente.
    fn opts_with(key: [u8; 32], algorithm: Algorithm) -> Options {
        Options { encryption: Some(Encryption { key, algorithm }), ..Options::default() }
    }

    fn opts(key: [u8; 32]) -> Options {
        opts_with(key, Algorithm::ChaCha20Poly1305)
    }

    /// Una escritura física tal como llegó al medio: offset y bytes
    /// completos.
    type PhysWrite = (u64, Vec<u8>);

    /// Todas las pruebas de este módulo usan `Options::default()`
    /// (`page_size` 512, meta A siempre en la página 1, meta B en la 2
    /// hasta que `relocate_meta_b` la traslada a la 8 — ver `opts_with` y
    /// `is_meta_offset`, justo abajo).
    const TEST_PAGE_SIZE: u64 = 512;

    /// Offsets que corresponden a una ranura de meta EN CUALQUIERA de sus
    /// posiciones posibles (tarea 18): la meta B vive en la página `2`
    /// hasta que el fichero crece más allá de 4 KB, y en su destino final
    /// —la `8`, con `TEST_PAGE_SIZE` de 512 B; misma fórmula que
    /// `WriteTxn::final_meta_b_page` en `tx.rs`— desde entonces. Nunca las
    /// dos posiciones a la vez, pero sí las dos en algún momento de la vida
    /// del fichero si la prueba llega a cruzar los 4 KB, así que las dos
    /// cuentan siempre — no solo la que esté activa ahora mismo.
    ///
    /// Antes de esta ronda (autorrevisión de la tarea 18) esto era un
    /// simple SUELO (`first_data_page`, la primera página que ya no podía
    /// ser meta): válido mientras la meta B era estática desde la
    /// creación, pero con la reubicación las páginas `3..8` son datos
    /// legítimos DESDE EL PRINCIPIO, así que un suelo en la `9` las
    /// contaba erróneamente como "todavía no hay datos" — el auditor de
    /// nonces veía cero páginas selladas en una base que sí las tenía
    /// (`every_sync_policy_survives_a_torn_meta_write_at_every_point`). Ni
    /// la meta A ni la B pasan nunca por `write_encrypted` (ver el
    /// comentario de `wrap_key`), así que la comprobación correcta es
    /// justo la contraria: excluir estos offsets concretos, no poner un
    /// suelo.
    fn is_meta_offset(o: u64) -> bool {
        let meta_a = TEST_PAGE_SIZE;
        let meta_b_initial = 2 * TEST_PAGE_SIZE;
        let meta_b_final = core::cmp::max(2, 4096 / TEST_PAGE_SIZE) * TEST_PAGE_SIZE;
        o == meta_a || o == meta_b_initial || o == meta_b_final
    }

    /// `(página, contador, texto cifrado)` de cada escritura que de verdad
    /// pasó por `Pager::write_encrypted`. El contador viaja en claro en los
    /// ocho primeros bytes de una página sellada (ver `seal`), así que el
    /// par `(página, contador)` ES el nonce, leído del fichero igual que lo
    /// leería un atacante.
    fn sealed_writes(writes: &[PhysWrite]) -> Vec<(PageNo, u64, &[u8])> {
        writes
            .iter()
            .filter(|(o, b)| *o > 0 && !is_meta_offset(*o) && b.len() == TEST_PAGE_SIZE as usize)
            .map(|(o, b)| {
                let page = (*o / TEST_PAGE_SIZE) as PageNo;
                let counter = u64::from_le_bytes(b[..8].try_into().unwrap());
                (page, counter, &b[CIPHER_PREFIX..])
            })
            .collect()
    }

    /// Porcentaje de bytes CERO del XOR de dos textos cifrados. Es el
    /// detector que pide la tercera ronda de revisión, y no es una
    /// heurística: con el mismo nonce y la misma clave, el flujo de clave
    /// es idéntico, así que `C1 XOR C2 == P1 XOR P2` — y dos páginas de
    /// este motor comparten casi todos sus bytes (relleno a cero, misma
    /// cabecera de página), de modo que ese XOR sale casi todo ceros. Con
    /// nonces distintos el XOR es de dos flujos de clave independientes:
    /// un byte cero cae con probabilidad 1/256, ~0,39 %.
    fn xor_zero_pct(a: &[u8], b: &[u8]) -> f64 {
        let n = core::cmp::min(a.len(), b.len());
        let zeros = (0..n).filter(|&i| a[i] ^ b[i] == 0).count();
        100.0 * zeros as f64 / n as f64
    }

    /// Veredicto sobre TODAS las escrituras selladas de una corrida.
    #[derive(Debug)]
    struct NonceAudit {
        /// Escrituras que pasaron por `write_encrypted`.
        sealed: usize,
        /// Nonces `(página, contador)` usados por más de una escritura.
        reused_nonces: usize,
        /// El peor par con nonce repetido, si lo hay: porcentaje de bytes
        /// cero de `C1 XOR C2`.
        worst_xor_zero_pct: f64,
        /// Línea base sobre pares con nonces DISTINTOS, para contrastar.
        baseline_xor_zero_pct: f64,
    }

    fn audit_nonces(writes: &[PhysWrite]) -> NonceAudit {
        let sealed = sealed_writes(writes);
        let mut by_nonce: alloc::collections::BTreeMap<(PageNo, u64), Vec<&[u8]>> =
            alloc::collections::BTreeMap::new();
        for (page, counter, ct) in &sealed {
            by_nonce.entry((*page, *counter)).or_default().push(ct);
        }

        let mut reused = 0usize;
        let mut worst = 0.0f64;
        for texts in by_nonce.values() {
            if texts.len() < 2 {
                continue;
            }
            reused += 1;
            for i in 0..texts.len() {
                for j in i + 1..texts.len() {
                    worst = worst.max(xor_zero_pct(texts[i], texts[j]));
                }
            }
        }

        // Línea base: pares consecutivos con nonces distintos.
        let mut base_sum = 0.0f64;
        let mut base_n = 0usize;
        for w in sealed.windows(2) {
            if (w[0].0, w[0].1) != (w[1].0, w[1].1) {
                base_sum += xor_zero_pct(w[0].2, w[1].2);
                base_n += 1;
            }
        }

        NonceAudit {
            sealed: sealed.len(),
            reused_nonces: reused,
            worst_xor_zero_pct: worst,
            baseline_xor_zero_pct: if base_n == 0 { 0.0 } else { base_sum / base_n as f64 },
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
    /// escritos)` de cada escritura — exactamente `(página, contador de
    /// nonce)` para cualquier página que pase por `Pager::write_encrypted`
    /// (el contador va en claro en los primeros 8 bytes de una página
    /// cifrada, ver `CIPHER_PREFIX`). Es la instrumentación central de
    /// `no_nonce_is_ever_reused`.
    ///
    /// **Historia (ronda de revisión posterior a la primera entrega):** la
    /// primera versión de esta prueba hacía UNA `put` por transacción, 200
    /// veces. Con el nonce derivado de `page || txn_id` (el diseño
    /// original), eso nunca puede colisionar — cada transacción tiene su
    /// propio `txn_id` — así que la prueba pasaba sin ejercitar el caso
    /// real: `WriteTxn::alloc` recicla `own_free` (páginas que la MISMA
    /// transacción asignó y liberó ella misma, tarea 12) dentro de una
    /// única transacción, y una carga con varias `put` en una sola
    /// transacción reescribe la MISMA página muchas veces con el MISMO
    /// `txn_id` — 121 veces la página 9 sobre 200 `put`s en una transacción,
    /// medido. El nonce ahora se deriva de un contador monótono por
    /// escritura (`page || contador`, nunca `txn_id`), así que el mismo
    /// escenario ya no colisiona — ver el comentario de `nonce` y de
    /// `Db::extend_counter_ceiling` en `tx.rs`.
    struct RecordingStorage {
        inner: MemStorage,
        writes: Mutex<Vec<PhysWrite>>,
    }

    impl RecordingStorage {
        fn new() -> Self {
            Self { inner: MemStorage::new(), writes: Mutex::new(Vec::new()) }
        }

        /// Escrituras físicas completas (offset y TODOS los bytes), no solo
        /// los ocho primeros (tercera ronda de revisión): el detector
        /// estadístico `audit_nonces` necesita el texto cifrado entero para
        /// poder xorear dos sellados que compartan nonce — el par
        /// `(offset, contador)` prueba que el nonce se repitió, pero es el
        /// XOR el que demuestra qué se pierde cuando eso pasa.
        fn raw_writes(&self) -> Vec<PhysWrite> {
            self.writes.lock().unwrap().clone()
        }

        fn nonces(&self) -> Vec<(u64, [u8; 8])> {
            self.writes
                .lock()
                .unwrap()
                .iter()
                .map(|(o, b)| {
                    let mut first8 = [0u8; 8];
                    first8.copy_from_slice(&b[..8]);
                    (*o, first8)
                })
                .collect()
        }

        /// Solo los pares que de verdad representan `(página, contador de
        /// nonce)`, descartando cabecera y meta-ranuras (ronda de revisión
        /// posterior a la primera entrega: `nonces()` sin filtrar hacía
        /// fallar esta prueba por una razón que NO es un nonce repetido).
        ///
        /// `Db::extend_counter_ceiling`/`WriteTxn::commit` escriben
        /// ranuras de meta con el MISMO `txn_id` en claro en sus primeros
        /// 8 bytes (`Meta::encode` los pone ahí,
        /// nada que ver con el contador de nonce: la meta nunca pasa por
        /// `write_encrypted`, ver el comentario de `wrap_key`). Eso
        /// produce, a propósito, un `(offset, primeros 8 bytes)` repetido
        /// por transacción que NO es un fallo de seguridad — no hay ningún
        /// nonce de por medio — pero sí lo detectaría un `dedup` que no
        /// distinguiera meta de datos. `is_meta_offset` (tarea 18,
        /// autorrevisión: sustituye el suelo `meta_b_page + 1` de antes,
        /// que asumía la meta B estática desde la creación — ver su
        /// comentario) excluye las ranuras de meta EN CUALQUIERA de sus
        /// posiciones posibles, no solo las páginas por debajo de un suelo
        /// fijo.
        fn encrypted_page_nonces(&self) -> Vec<(u64, [u8; 8])> {
            self.nonces().into_iter().filter(|(offset, _)| *offset > 0 && !is_meta_offset(*offset)).collect()
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
                self.writes.lock().unwrap().push((o, b.to_vec()));
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
    /// NO demuestra que `nonce(page, counter)` de verdad combine los dos
    /// valores al derivar el nonce real que ve el cifrador: cifrado y
    /// descifrado son simétricos entre sí (usan la misma función en los dos
    /// sentidos), así que un `nonce` roto que aun así fuera determinista
    /// deja el roundtrip funcional en verde. Es exactamente el "test que
    /// pasa por la razón equivocada" que pide evitar el brief.
    ///
    /// Primera versión de esta prueba (ronda de revisión posterior a la
    /// primera entrega, hallazgo HIGH): solo comprobaba `!=` en un puñado de
    /// puntos — "página distinta cambia el nonce", "contador distinto
    /// cambia el nonce". Insuficiente: la revisión construyó cinco
    /// `nonce()` alternativas que PASABAN esa comprobación (cambiaban ANTE
    /// el punto de prueba elegido) sin ser inyectivas — cuatro de ellas
    /// romperían la unicidad en producción:
    /// - página truncada a un byte (`1` y `257` colisionan),
    /// - contador truncado a `u32` (`counter=1` y `counter=2^32+1` colisionan),
    /// - campos solapados en la escritura de los 12 bytes,
    /// - `counter XOR page` en vez de concatenación (`(1,100)` y `(0,101)` colisionan).
    ///
    /// Esta versión comprueba la representación EXACTA (no solo "cambia
    /// algo") y un barrido de inyectividad denso más uno disperso en las
    /// fronteras de `u32`/`u64` y del posible solape de bytes.
    #[test]
    fn nonce_is_exactly_page_then_counter_little_endian() {
        let page: PageNo = 0x0102_0304;
        let counter: u64 = 0x1122_3344_5566_7788;
        let mut expected = [0u8; NONCE_LEN];
        expected[..4].copy_from_slice(&page.to_le_bytes());
        expected[4..].copy_from_slice(&counter.to_le_bytes());
        assert_eq!(nonce(page, counter), expected);
    }

    #[test]
    fn nonce_is_injective_over_page_and_counter() {
        // Barrido denso: cubre, entre otras, la colisión de "página
        // truncada a un byte" (1 y 257 caen dentro del rango) y la de
        // "counter XOR page" ((1,100) y (0,101) también).
        let mut seen = alloc::collections::BTreeSet::new();
        for page in 0..260u32 {
            for counter in 0..60u64 {
                assert!(
                    seen.insert(nonce(page, counter)),
                    "colision en el barrido denso: page={page} counter={counter}"
                );
            }
        }

        // Barrido disperso en las fronteras de representación: cubre la
        // colisión de "contador truncado a u32" (necesita counter ~ 2^32,
        // fuera del barrido denso) y cualquier solape de bytes en los
        // límites de `page` (bit 24) o `counter` (bits 32/63).
        let mut seen_sparse = alloc::collections::BTreeSet::new();
        let pages = [0u32, 1, 2, 1 << 24, (1 << 24) + 1, u32::MAX - 1, u32::MAX];
        let counters = [0u64, 1, 2, 1 << 24, 1u64 << 32, (1u64 << 32) + 1, u64::MAX];
        for &page in &pages {
            for &counter in &counters {
                assert!(
                    seen_sparse.insert(nonce(page, counter)),
                    "colision en el barrido disperso: page={page} counter={counter}"
                );
            }
        }

        // Los cuatro casos concretos de la revisión, explícitos: si algún
        // día se cambia `nonce` y uno de estos empieza a fallar, el mensaje
        // señala directamente cuál de los cinco `nonce()` rotos ha vuelto.
        assert_ne!(nonce(1, 0), nonce(257, 0), "pagina truncada a un byte");
        assert_ne!(nonce(1, 1), nonce(1, (1u64 << 32) + 1), "contador truncado a u32");
        assert_ne!(nonce(1, 100), nonce(0, 101), "contador XOR pagina (o solape de campos equivalente)");
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

    /// **La prueba central de la tarea.** Reescrita tras la ronda de
    /// revisión posterior a la primera entrega (hallazgo BLOCKER): la
    /// versión original hacía UNA `put` por transacción, 200 veces — la
    /// única forma de cargar este motor que NUNCA puebla `own_free`
    /// (`WriteTxn::alloc`, `tx.rs`) lo bastante como para que una página se
    /// reescriba dentro de la misma transacción, así que pasaba sin
    /// ejercitar el caso real. Esta versión hace 200 `put`s dentro de UNA
    /// sola transacción — el patrón de lote normal de este motor (ver el
    /// comentario de `alloc` en `tx.rs` sobre por qué `own_free` existe: un
    /// lote de mil registros asigna del orden de cuatro mil páginas y
    /// libera casi todas dentro de la misma transacción) — que es
    /// exactamente donde `own_free` recicla páginas y, con el diseño viejo
    /// (nonce derivado de `page || txn_id`), las reescribía con el nonce
    /// repetido.
    #[test]
    fn no_nonce_is_ever_reused() {
        let s = Arc::new(RecordingStorage::new());
        let db = Db::create(Box::new(ArcRecording(Arc::clone(&s))), opts([6; 32])).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..200u32 {
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
        }
        tx.commit().unwrap();
        let nonces = s.encrypted_page_nonces();
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "nonce repetido");

        // Y el mismo veredicto por la otra vía, la estadística (tercera
        // ronda de revisión): `sealed > 0` no es decoración — sin él, un
        // cambio que dejara de registrar escrituras haría pasar
        // "cero nonces repetidos" sin haber mirado ni una sola página.
        let audit = audit_nonces(&s.raw_writes());
        assert!(audit.sealed > 0, "el auditor no vio ninguna pagina sellada: {audit:?}");
        assert_eq!(audit.reused_nonces, 0, "{audit:?}");
    }

    /// Complementa la prueba de arriba con el otro eje: muchas
    /// transacciones PEQUEÑAS en vez de una grande, atravesando varias
    /// aperturas de transacción (`begin_write`/`commit`) en vez de una
    /// sola — comprueba que el contador vivo (`WriterState::live_counter`,
    /// que sobrevive tal cual entre transacciones desde la segunda ronda
    /// de revisión) se lleva bien de una a otra.
    #[test]
    fn no_nonce_is_ever_reused_across_many_small_transactions() {
        let s = Arc::new(RecordingStorage::new());
        let db = Db::create(Box::new(ArcRecording(Arc::clone(&s))), opts([9; 32])).unwrap();
        for i in 0..200u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            tx.commit().unwrap();
        }
        let nonces = s.encrypted_page_nonces();
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "nonce repetido");
    }

    /// Sonda 1 de la segunda ronda de revisión posterior a la primera
    /// entrega (hallazgo BLOCKER 2): abortar una transacción y luego
    /// confirmar otra distinta no debe reutilizar ningún contador. Con el
    /// diseño roto de la primera ronda, el contador se releía de la meta
    /// CONFIRMADA en cada `begin_write` — y como abortar no toca la meta
    /// confirmada, la segunda transacción arrancaba exactamente donde
    /// había arrancado la primera, repartiendo de nuevo los mismos
    /// contadores que la abortada ya había usado para sellar páginas
    /// reales. El caso concreto que lo demuestra: 5 `put` que se abortan,
    /// seguidos de 5 `put` DISTINTOS que sí confirman — `alloc()`, en las
    /// mismas condiciones de partida (mismo root confirmado, misma lista
    /// de libres), tiende a repartir la MISMA secuencia de páginas, así
    /// que sin el arreglo esto colisiona en página Y contador a la vez.
    #[test]
    fn a_rollback_then_a_commit_reuses_no_counter() {
        let s = Arc::new(RecordingStorage::new());
        let db = Db::create(Box::new(ArcRecording(Arc::clone(&s))), opts([31; 32])).unwrap();
        {
            let mut tx = db.begin_write().unwrap();
            for i in 0..5u32 {
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            }
            // Se descarta sin commit.
        }
        {
            let mut tx = db.begin_write().unwrap();
            for i in 100..105u32 {
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            }
            tx.commit().unwrap();
        }
        let nonces = s.encrypted_page_nonces();
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "nonce repetido tras abortar y luego confirmar");
    }

    /// Sonda 2 de la segunda ronda de revisión (hallazgo BLOCKER 1): una
    /// transacción que agota el techo de contador ya reservado, abortada
    /// a media escritura, no debe corromper NADA de lo que ya estaba
    /// confirmado al reabrir — ni perder datos, ni cambiar el `root`.
    ///
    /// Para ejercitar `Db::extend_counter_ceiling` de verdad sin necesitar
    /// más de un millón de escrituras reales (`COUNTER_RESERVE`), esta
    /// prueba manipula a mano el `write_counter` ya persistido (bytes
    /// 100..108 de cada ranura de meta, recalculando el CRC) para dejarlo
    /// artificialmente bajo — el mismo tipo de manipulación de bytes crudos
    /// que ya usa `a_tampered_page_is_rejected`, sobre un campo distinto.
    /// Con el diseño roto de la primera ronda, esto fallaba porque
    /// `advance_counter` pasaba la meta DE LA TRANSACCIÓN EN CURSO — con
    /// su `root` ya cambiado a medio hacer — a la extensión, y esa mitad
    /// de transacción se recuperaba como si fuera un commit real.
    #[test]
    fn a_transaction_that_exceeds_the_ceiling_extends_it_without_losing_committed_data() {
        let s = Arc::new(MemStorage::new());
        let master = [41u8; 32];
        let committed_root;
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts(master)).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"antes", b"confirmado").unwrap();
            tx.commit().unwrap();
            committed_root = db.begin_read().root();
        }

        // Manipula `write_counter` de las DOS ranuras de meta a un valor
        // artificialmente bajo, recalculando el CRC, para que la próxima
        // transacción agote el techo enseguida.
        let mut bytes = s.snapshot();
        // 2, no 8 (tarea 18): la meta B vive en la página 2 desde la
        // creación, y ninguna de estas dos pruebas hace crecer el fichero
        // lo bastante como para que se haya reubicado a la 8 todavía.
        for meta_page in [1usize, 2usize] {
            let base = meta_page * 512;
            bytes[base + 100..base + 108].copy_from_slice(&3u64.to_le_bytes());
            let crc = crate::crc32::checksum(&bytes[base..base + crate::meta::META_SIZE - 4]);
            bytes[base + crate::meta::META_SIZE - 4..base + crate::meta::META_SIZE]
                .copy_from_slice(&crc.to_le_bytes());
        }
        s.restore(bytes);

        {
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts(master)).unwrap();
            let mut tx = db.begin_write().unwrap();
            // Más de 3 escrituras: agota el techo manipulado y fuerza una
            // extensión real (con su propia sincronización incondicional)
            // dentro de esta misma transacción.
            for i in 0..20u32 {
                tx.put(0x02, &i.to_be_bytes(), b"a medias").unwrap();
            }
            // Se descarta sin commit.
        }

        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts(master)).unwrap();
        let r = db.begin_read();
        assert_eq!(r.root(), committed_root, "el root confirmado no debe cambiar tras abortar");
        assert_eq!(r.get(0x01, b"antes").unwrap().as_deref(), Some(b"confirmado".as_slice()));
        assert_eq!(
            r.get(0x02, &0u32.to_be_bytes()).unwrap(),
            None,
            "nada de la transaccion abortada debe verse"
        );
    }

    /// Envuelve `MemStorage` y simula un corte de corriente: las DOS
    /// ranuras de meta solo sobreviven hasta el último `sync()` real; todo
    /// lo demás (páginas de árbol, de lista de libres, la cabecera) se
    /// trata como si llegara al medio sin condición — que es exactamente
    /// lo que hace este motor: `Pager::write`/`write_encrypted` nunca
    /// miran la política de `Sync`, solo `Db::maybe_sync` (y
    /// `Db::extend_counter_ceiling`, que sincroniza sin condición) deciden
    /// si un `fsync` de verdad ocurre. También lleva el mismo registro de
    /// `(offset, primeros 8 bytes)` que `RecordingStorage`, para poder
    /// comprobar directamente que nada se reutiliza tras el "corte".
    ///
    /// Asume `Options::default()` (`page_size` 512, `meta_a_page` 1,
    /// `meta_b_page` 2) — las mismas que usa `opts()` — para saber dónde
    /// viven las dos ranuras sin tener que leer la cabecera primero.
    ///
    /// **Asume además que ninguna prueba de este módulo hace crecer el
    /// fichero más allá de 4 KB** (tarea 18: a partir de ahí,
    /// `relocate_meta_b` trasladaría la meta B a la página 8, y
    /// `META_OFFSETS` —fijo desde la construcción— dejaría de reconocer sus
    /// escrituras como escrituras de meta). Cierto para las cuatro pruebas
    /// que usan esta estructura hoy: como mucho una decena de `put`s de
    /// valores diminutos por sesión. Si una prueba futura necesitara cruzar
    /// ese umbral con este arnés, `META_OFFSETS` tendría que crecer a un
    /// tercer offset (la posición final) y `last_synced_meta` a tres
    /// ranuras, no dos — ninguna prueba de hoy lo necesita, así que no se
    /// construye sin un caso de uso real que lo ejercite.
    struct PowerLossStorage {
        inner: MemStorage,
        writes: Mutex<Vec<PhysWrite>>,
        last_synced_meta: Mutex<[[u8; 512]; 2]>,
        /// Desgarro armado: ver `arm_meta_tear`.
        tear: Mutex<Option<Tear>>,
        /// Imagen del plato en el instante del corte, o `None` si la
        /// máquina sigue viva. Ver `arm_meta_tear`.
        dead: Mutex<Option<Vec<u8>>>,
    }

    /// Escritura de meta que se corta a medias. `skip` es cuántas
    /// escrituras de meta faltan todavía antes de la que se desgarra.
    struct Tear {
        skip: usize,
        prefix: usize,
    }

    // 1024, no 4096 (tarea 18): la meta B vive en la página 2 desde la
    // creación, no en la 8 — ver el comentario de `PowerLossStorage`, justo
    // arriba, sobre por qué un valor fijo sigue siendo correcto para las
    // pruebas de este módulo.
    const META_OFFSETS: [u64; 2] = [512, 1024];

    /// Cuántos bytes de una escritura de meta desgarrada llegan al plato.
    /// 104 no es arbitrario: cae DENTRO de `write_counter` (bytes 100..108)
    /// y por debajo del CRC (108..112), así que la ranura queda siempre con
    /// un contenido mezclado y un CRC viejo — ilegible, pase lo que pase.
    /// Un prefijo más corto solo desgarra de verdad las escrituras cuyos
    /// primeros bytes cambian (las de un commit, que trae `txn_id` y `root`
    /// nuevos), y deja intacta la de una extensión, que solo toca
    /// `write_counter` y el CRC. `write_at` lo comprueba en cada desgarro
    /// en vez de confiar en que quien escribe la prueba lo tenga presente.
    const TORN_PREFIX: usize = 104;

    impl PowerLossStorage {
        fn new() -> Self {
            Self {
                inner: MemStorage::new(),
                writes: Mutex::new(Vec::new()),
                last_synced_meta: Mutex::new([[0u8; 512]; 2]),
                tear: Mutex::new(None),
                dead: Mutex::new(None),
            }
        }

        /// Arma un corte de corriente EN MITAD de una escritura de meta
        /// (tercera ronda de revisión — el agujero del arnés). La
        /// `skip`-ésima escritura de meta a partir de ahora deposita solo
        /// sus primeros `prefix` bytes; el resto de la ranura conserva el
        /// contenido anterior, así que el CRC de `Meta::decode` falla y esa
        /// ranura queda ILEGIBLE, que es exactamente lo que el diseño de
        /// dos ranuras existe para sobrevivir. La versión anterior de este
        /// ayudante solo sabía restaurar una ranura ENTERA a su último
        /// contenido sincronizado — modela "la escritura no llegó nunca",
        /// jamás "la escritura llegó a medias", así que las seis
        /// combinaciones de `Sync` pasaban bajo un modelo que excluía el
        /// único modo de fallo que importa.
        ///
        /// A partir de ese instante el medio queda MUERTO: se fotografía el
        /// plato y nada de lo que el proceso escriba después llega a él ni
        /// se registra como observable. Es la diferencia entre modelar un
        /// corte de corriente y modelar una escritura parcial que el
        /// proceso sobrevive — lo segundo no existe: si `sync()` devolvió
        /// éxito el dato es duradero, y si una escritura se desgarró es
        /// porque la máquina murió justo ahí, así que no pudo ejecutar ni
        /// una línea más. Sin esta parte del modelo el arnés atribuiría al
        /// motor reutilizaciones de contador que ningún atacante puede
        /// observar, porque esos bytes nunca existieron. Las lecturas SÍ
        /// siguen funcionando: el proceso de la prueba tiene que poder
        /// terminar su función sin errores de E/S artificiales.
        ///
        /// `simulate_power_loss` es el "reinicio" que restaura esa foto.
        fn arm_meta_tear(&self, skip: usize, prefix: usize) {
            *self.tear.lock().unwrap() = Some(Tear { skip, prefix });
        }

        /// Reinicio tras el corte. Restaura el plato a la foto del instante
        /// del corte (si lo hubo) y descarta cualquier escritura de meta
        /// posterior al último `sync()` real — simula perder los búferes
        /// del sistema operativo no vaciados a disco. Las páginas de
        /// datos/lista de libres NO se revierten: se tratan como si
        /// hubieran llegado al medio sin condición, que es el supuesto
        /// PESIMISTA correcto para esta pregunta (cuanto más texto cifrado
        /// sobreviva, más material tiene un atacante para explotar un nonce
        /// repetido).
        fn simulate_power_loss(&self) {
            if let Some(platter) = self.dead.lock().unwrap().take() {
                self.inner.restore(platter);
            }
            let saved = *self.last_synced_meta.lock().unwrap();
            for (i, &offset) in META_OFFSETS.iter().enumerate() {
                self.inner.write_at(offset, &saved[i]).unwrap();
            }
        }

        fn raw_writes(&self) -> Vec<PhysWrite> {
            self.writes.lock().unwrap().clone()
        }

        fn encrypted_page_nonces(&self) -> Vec<(u64, [u8; 8])> {
            self.writes
                .lock()
                .unwrap()
                .iter()
                .filter(|(o, _)| *o > 0 && !is_meta_offset(*o))
                .map(|(o, b)| {
                    let mut first8 = [0u8; 8];
                    first8.copy_from_slice(&b[..8]);
                    (*o, first8)
                })
                .collect()
        }
    }

    impl Storage for PowerLossStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.inner.read_at(o, b)
        }

        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            if self.dead.lock().unwrap().is_some() {
                // La máquina ya murió: esto no llega al plato (la foto de
                // `arm_meta_tear` se restaura en el reinicio) ni lo ve
                // nadie, así que tampoco se registra. Sigue escribiéndose
                // en `inner` solo para que las lecturas posteriores del
                // proceso ya muerto no fallen con un error de E/S que en la
                // vida real nadie llegaría a ver.
                return self.inner.write_at(o, b);
            }

            let meta_slot = META_OFFSETS
                .iter()
                .position(|&m| m == o && b.len() == TEST_PAGE_SIZE as usize);
            if let Some(i) = meta_slot {
                let torn = {
                    let mut tear = self.tear.lock().unwrap();
                    match tear.as_mut() {
                        Some(t) if t.skip == 0 => {
                            let prefix = t.prefix;
                            *tear = None;
                            Some(prefix)
                        }
                        Some(t) => {
                            t.skip -= 1;
                            None
                        }
                        None => None,
                    }
                };
                if let Some(prefix) = torn {
                    self.writes.lock().unwrap().push((o, b[..prefix].to_vec()));
                    self.inner.write_at(o, &b[..prefix])?;
                    // Lo que sí llegó al plato es DURADERO: sobrevive al
                    // `simulate_power_loss` posterior, a diferencia de una
                    // escritura de meta completa sin sincronizar.
                    let mut landed = [0u8; 512];
                    self.inner.read_at(o, &mut landed)?;
                    // El arnés comprueba SU PROPIA premisa: si el prefijo
                    // elegido deja la ranura todavía legible, esta prueba no
                    // está modelando ningún desgarro y pasaría por la razón
                    // equivocada. Ocurre de verdad: la meta de una extensión
                    // solo difiere de la anterior en `write_counter`
                    // (100..108) y el CRC (108..112), así que un prefijo de
                    // 56 bytes la deja byte a byte idéntica a lo que ya
                    // había — un desgarro que no desgarra nada. Ver
                    // `TORN_PREFIX`.
                    assert!(
                        crate::meta::Meta::decode(&landed).is_err(),
                        "el prefijo de {prefix} bytes deja la ranura de meta en {o} todavia \
                         legible: esta prueba no esta modelando ningun desgarro"
                    );
                    self.last_synced_meta.lock().unwrap()[i] = landed;
                    *self.dead.lock().unwrap() = Some(self.inner.snapshot());
                    return Ok(());
                }
            }

            if b.len() >= 8 {
                self.writes.lock().unwrap().push((o, b.to_vec()));
            }
            self.inner.write_at(o, b)
        }

        fn sync(&self) -> Result<()> {
            if self.dead.lock().unwrap().is_some() {
                return Ok(());
            }
            let mut saved = self.last_synced_meta.lock().unwrap();
            for (i, &offset) in META_OFFSETS.iter().enumerate() {
                let mut buf = [0u8; 512];
                let _ = self.inner.read_at(offset, &mut buf);
                saved[i] = buf;
            }
            self.inner.sync()
        }

        fn len(&self) -> Result<u64> {
            self.inner.len()
        }
    }

    struct ArcPowerLoss(Arc<PowerLossStorage>);
    impl Storage for ArcPowerLoss {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    /// Sonda 3 de la segunda ronda de revisión (hallazgo HIGH): bajo
    /// `Sync::Never` o un `Sync::Interval` largo — donde los commits
    /// normales de este motor nunca fuerzan un `fsync` — muchas
    /// transacciones pequeñas seguidas de un corte de corriente simulado
    /// no deben reutilizar ningún contador, aunque se pierdan sus efectos
    /// lógicos (esa pérdida SÍ la acepta `Sync::Never`/`Interval`
    /// explícitamente; lo que no acepta es que rompa la confidencialidad
    /// de páginas que sobrevivieron).
    #[test]
    fn sync_never_or_long_interval_survives_simulated_power_loss_without_reusing_a_counter() {
        for policy in [Sync::Never, Sync::Interval(Duration::from_secs(3600))] {
            let s = Arc::new(PowerLossStorage::new());
            let mk_opts = || Options { sync: policy, ..opts([51; 32]) };
            let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
            // Bajo ninguna de las dos políticas se sincroniza en cada
            // commit: 20 transacciones pequeñas seguidas sin que la meta
            // llegue a ser duradera entre ellas (más allá del `sync()`
            // incondicional de `Db::create`).
            for i in 0..20u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }
            drop(db);

            s.simulate_power_loss();

            let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
            for i in 100..120u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }

            let nonces = s.encrypted_page_nonces();
            let mut sorted = nonces.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                nonces.len(),
                "nonce repetido tras corte simulado bajo {policy:?}"
            );
        }
    }

    /// Sonda 3, variante combinada: fuerza una extensión real (igual que
    /// `a_transaction_that_exceeds_the_ceiling_...`, mismo truco de
    /// manipular `write_counter`) bajo `Sync::Never` específicamente, y
    /// simula un corte justo después. Si la sincronización de la extensión
    /// respetara la política de `Sync` en vez de ser incondicional (el
    /// punto 5 del diseño corregido), este caso reproduciría el hallazgo
    /// HIGH directamente: la extensión se perdería en el corte y la
    /// siguiente sesión repartiría de nuevo los contadores que la
    /// transacción de 20 escrituras ya había usado.
    #[test]
    fn an_extension_under_sync_never_survives_a_simulated_power_loss() {
        let s = Arc::new(PowerLossStorage::new());
        let mk_opts = || Options { sync: Sync::Never, ..opts([52; 32]) };
        {
            let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"antes", b"confirmado").unwrap();
            tx.commit().unwrap();
        }

        let mut bytes_snapshot = alloc::vec::Vec::new();
        {
            // Lee el contenido actual a través del propio `Storage` (no
            // hay `snapshot()` en `PowerLossStorage`): basta con leer todo
            // el fichero conocido hasta ahora.
            let len = s.len().unwrap() as usize;
            bytes_snapshot.resize(len, 0);
            s.read_at(0, &mut bytes_snapshot).unwrap();
        }
        // 2, no 8 (tarea 18): la meta B vive en la página 2 desde la
        // creación, y ninguna de estas dos pruebas hace crecer el fichero
        // lo bastante como para que se haya reubicado a la 8 todavía.
        for meta_page in [1usize, 2usize] {
            let base = meta_page * 512;
            bytes_snapshot[base + 100..base + 108].copy_from_slice(&3u64.to_le_bytes());
            let crc = crate::crc32::checksum(&bytes_snapshot[base..base + crate::meta::META_SIZE - 4]);
            bytes_snapshot[base + crate::meta::META_SIZE - 4..base + crate::meta::META_SIZE]
                .copy_from_slice(&crc.to_le_bytes());
        }
        s.write_at(0, &bytes_snapshot).unwrap();
        // Este `sync()` de la propia prueba, fuera de cualquier `Db`,
        // fotografía la manipulación de arriba como "la última duradera" —
        // equivalente a que esa manipulación llevara ahí desde siempre.
        s.sync().unwrap();

        {
            let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..20u32 {
                tx.put(0x02, &i.to_be_bytes(), b"extendido").unwrap();
            }
            tx.commit().unwrap();
        }

        s.simulate_power_loss();

        let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
        for i in 200..205u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x03, &i.to_be_bytes(), b"tras el corte").unwrap();
            tx.commit().unwrap();
        }

        let nonces = s.encrypted_page_nonces();
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "nonce repetido: la extension no sobrevivio al corte bajo Sync::Never");
    }

    /// Cuenta cuántas veces `sync()` llega de verdad al medio. Envuelve
    /// `MemStorage` como los demás ayudantes de este módulo.
    struct SyncCountingStorage {
        inner: MemStorage,
        syncs: std::sync::atomic::AtomicU64,
    }
    impl SyncCountingStorage {
        fn new() -> Self {
            Self { inner: MemStorage::new(), syncs: std::sync::atomic::AtomicU64::new(0) }
        }
        fn sync_count(&self) -> u64 {
            self.syncs.load(std::sync::atomic::Ordering::Relaxed)
        }
    }
    impl Storage for SyncCountingStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.inner.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.inner.write_at(o, b) }
        fn sync(&self) -> Result<()> {
            self.syncs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.sync()
        }
        fn len(&self) -> Result<u64> { self.inner.len() }
    }
    struct ArcSyncCounting(Arc<SyncCountingStorage>);
    impl Storage for ArcSyncCounting {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    /// Sonda 4 de la segunda ronda de revisión: el coste de sincronización
    /// por transacción, cifrada contra sin cifrar, debe coincidir en el
    /// caso común (ninguna transacción agota el techo de contador). Con el
    /// diseño roto de la primera ronda esto medía 3,0 sincronizaciones por
    /// transacción cifrada contra 2,0 sin cifrar — una reserva completa,
    /// con su propio `fsync`, en CADA `begin_write`. Con el diseño
    /// corregido el contador viaja de balde en la meta que el commit YA
    /// iba a escribir, así que no debería haber ninguna diferencia.
    ///
    /// `page_size: 4096` en las dos bases (tarea 18, autorrevisión): con el
    /// tamaño de página por defecto (512 B), 500 transacciones bastan para
    /// cruzar los 4 KB y disparar `relocate_meta_b` — una vez, con sus dos
    /// `fsync` incondicionales propios — en AMBAS bases por igual (no tiene
    /// nada que ver con el cifrado), lo que subía las dos medias a 2,004 y
    /// hacía fallar la comparación exacta contra 2,0 sin que hubiera ninguna
    /// diferencia real entre cifrada y sin cifrar. Con páginas de 4 KB la
    /// meta B ya nace en su posición definitiva (ver
    /// `page_sizes_of_four_kilobytes_or_more_never_relocate` en `tx.rs`) y
    /// la reubicación nunca se dispara, así que esta sonda vuelve a medir
    /// solo lo que dice medir.
    #[test]
    fn encrypted_transactions_sync_no_more_per_transaction_than_unencrypted_ones() {
        const N: u64 = 500;

        let unenc = Arc::new(SyncCountingStorage::new());
        {
            let opts = Options { page_size: 4096, ..Options::default() };
            let db = Db::create(Box::new(ArcSyncCounting(Arc::clone(&unenc))), opts).unwrap();
            for i in 0..N as u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }
        }

        let enc = Arc::new(SyncCountingStorage::new());
        {
            let opts = Options { page_size: 4096, ..opts([61; 32]) };
            let db = Db::create(Box::new(ArcSyncCounting(Arc::clone(&enc))), opts).unwrap();
            for i in 0..N as u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }
        }

        // Resta el `sync()` inicial de `Db::create` (uno para cada base),
        // para medir solo el coste POR TRANSACCIÓN.
        let unenc_per_tx = (unenc.sync_count() - 1) as f64 / N as f64;
        let enc_per_tx = (enc.sync_count() - 1) as f64 / N as f64;
        std::eprintln!("sin cifrar: {unenc_per_tx} syncs/tx; cifrado: {enc_per_tx} syncs/tx");
        assert_eq!(unenc_per_tx, 2.0);
        assert_eq!(enc_per_tx, 2.0, "el cifrado no debe anadir sincronizaciones por transaccion en el caso comun");
    }

    /// El coste que la sonda 4 NO medía (tercera ronda de revisión): esa
    /// mide transacciones sobre una base recién CREADA, donde `Db::create`
    /// ya siembra el techo y ninguna transacción extiende. Sobre una base
    /// REABIERTA la historia es distinta: `live_counter == counter_ceiling`
    /// al abrir (no hay forma de saber cuánto del margen llegó a usar la
    /// sesión anterior antes de morir, así que se asume el peor caso), de
    /// modo que la primera escritura cifrada de CADA sesión extiende el
    /// techo — dos escrituras de meta y dos `fsync` incondicionales.
    ///
    /// Eso es inherente, no un descuido: antes de sellar una página con el
    /// contador C tiene que existir en disco un registro que ponga el suelo
    /// por encima de C, o una caída dejaría a la sesión siguiente
    /// repartiendo C otra vez. Lo que esta prueba fija es que el coste sea
    /// CONSTANTE POR SESIÓN y no por transacción: la diferencia contra la
    /// base sin cifrar tiene que ser la misma con 100 transacciones que con
    /// 500.
    ///
    /// `page_size: 4096` (tarea 18, autorrevisión, mismo motivo que la sonda
    /// 4 de aquí arriba): con 512 B, tanto la corrida de 100 como la de 500
    /// transacciones cruzan los 4 KB y disparan `relocate_meta_b` una vez,
    /// EN LAS DOS BASES por igual (cifrada y sin cifrar) — un coste real,
    /// pero ajeno al cifrado, que esta prueba no está midiendo. Con páginas
    /// de 4 KB la meta B ya nace en su posición definitiva y la reubicación
    /// nunca se dispara.
    #[test]
    fn a_reopened_encrypted_database_pays_its_extension_once_per_session() {
        fn syncs_after_reopen(n: u64, encrypted: bool) -> u64 {
            let s = Arc::new(SyncCountingStorage::new());
            let mk_opts = || {
                let base = if encrypted { opts([62; 32]) } else { Options::default() };
                Options { page_size: 4096, ..base }
            };
            {
                let db =
                    Db::create(Box::new(ArcSyncCounting(Arc::clone(&s))), mk_opts()).unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"antes", b"confirmado").unwrap();
                tx.commit().unwrap();
            }
            let before = s.sync_count();
            let db = Db::open(Box::new(ArcSyncCounting(Arc::clone(&s))), mk_opts()).unwrap();
            for i in 0..n as u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }
            s.sync_count() - before
        }

        let (a_plain, a_enc) = (syncs_after_reopen(100, false), syncs_after_reopen(100, true));
        let (b_plain, b_enc) = (syncs_after_reopen(500, false), syncs_after_reopen(500, true));
        std::eprintln!(
            "reapertura, 100 tx: sin cifrar {a_plain}, cifrado {a_enc} (+{}); \
             500 tx: sin cifrar {b_plain}, cifrado {b_enc} (+{})",
            a_enc - a_plain,
            b_enc - b_plain
        );
        assert_eq!(a_plain, 200, "dos sincronizaciones por transaccion, como siempre");
        assert_eq!(b_plain, 1000);
        assert_eq!(
            a_enc - a_plain,
            b_enc - b_plain,
            "el sobrecoste del cifrado tiene que ser por SESION, no por transaccion"
        );
        assert_eq!(a_enc - a_plain, 2, "una extension por sesion: dos escrituras, dos fsync");
    }

    /// Meta CONFIRMADA tal como está en el fichero ahora mismo, sin pasar
    /// por `Db`: la usan las pruebas de fuga de páginas para comprobar que
    /// una transacción abortada no cambió nada de lo confirmado.
    fn on_disk_meta(s: &MemStorage) -> crate::meta::Meta {
        let g = crate::header::Geometry::read(s).unwrap();
        crate::meta::Meta::load(s, &g).unwrap().0
    }

    /// **BLOCKER de la tercera ronda de revisión.** El registro duradero
    /// del techo de contador tiene que sobrevivir a CUALQUIER escritura
    /// desgarrada, y antes de esta ronda no lo hacía: la extensión
    /// (`Db::extend_counter_ceiling`) escribía en `committed_slot.other()`
    /// y el commit siguiente escribe ESA MISMA ranura, así que el registro
    /// del techo sobrevivía exactamente una escritura de meta. Y como
    /// `live_counter == counter_ceiling` al abrir, TODA reapertura extiende
    /// en su primera escritura cifrada: la ventana se abría en cada sesión.
    ///
    /// La reproducción: crear y confirmar; reabrir (extiende); desgarrar la
    /// escritura de meta del commit; reabrir otra vez y volver a escribir.
    /// Con el defecto, la sesión 3 arranca del `write_counter` VIEJO que
    /// quedó en la otra ranura y vuelve a repartir los contadores que la
    /// sesión 2 ya quemó sellando páginas que SÍ están en el fichero.
    ///
    /// El desgarro se arma justo antes de `commit()`, no por un índice fijo
    /// de escritura de meta: así la prueba apunta a "la escritura de meta
    /// del commit" sin depender de cuántas escrituras haga la extensión.
    #[test]
    fn a_torn_commit_meta_write_after_an_extension_reuses_no_counter() {
        let s = Arc::new(PowerLossStorage::new());
        let master = [71u8; 32];

        {
            let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), opts(master)).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"antes", b"confirmado").unwrap();
            tx.commit().unwrap();
        }

        {
            let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), opts(master)).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..5u32 {
                tx.put(0x02, &i.to_be_bytes(), b"sesion dos").unwrap();
            }
            // 56 de 512 bytes: el CRC de `Meta::decode` cubre 0..108, así
            // que una ranura con 56 bytes nuevos y el resto viejos falla la
            // comprobación y queda ilegible.
            s.arm_meta_tear(0, 56);
            tx.commit().unwrap();
        }

        s.simulate_power_loss();

        {
            let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), opts(master)).unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                Some(b"confirmado".as_slice()),
                "el commit desgarrado no debe llevarse por delante lo ya confirmado"
            );
            let mut tx = db.begin_write().unwrap();
            for i in 0..5u32 {
                tx.put(0x02, &i.to_be_bytes(), b"sesion tres").unwrap();
            }
            tx.commit().unwrap();
        }

        let audit = audit_nonces(&s.raw_writes());
        std::eprintln!("{audit:?}");
        assert!(audit.sealed > 0, "el auditor no vio ninguna pagina sellada: {audit:?}");
        assert_eq!(
            audit.reused_nonces, 0,
            "nonce reutilizado tras un commit desgarrado: {audit:?} \
             (XOR de textos cifrados con el mismo nonce: {:.2} % de bytes cero, \
              linea base con nonces distintos: {:.2} %)",
            audit.worst_xor_zero_pct, audit.baseline_xor_zero_pct
        );
    }

    /// **MEDIUM de la tercera ronda de revisión: fuga de páginas sin cota.**
    /// `Db::open` subía `meta.n_pages` hasta la extensión real del fichero y
    /// guardaba ESO en `self.committed`, así que `committed` describía un
    /// estado que nunca se confirmó: las páginas recuperadas vivían solo en
    /// la lista de libres EN MEMORIA. Como `extend_counter_ceiling` copia
    /// `self.committed`, una transacción abortada dejaba en disco un
    /// `n_pages` por encima del último commit con una lista de libres que no
    /// posee la diferencia — y esas páginas se perdían para siempre, ciclo
    /// tras ciclo, sin cota.
    ///
    /// Doce ciclos abrir-extender-abortar. El control sin cifrar no escribe
    /// ninguna meta durante una transacción abortada, así que es el patrón
    /// exacto contra el que comparar.
    #[test]
    fn open_extend_abort_cycles_leak_no_pages() {
        for encrypted in [false, true] {
            let s = Arc::new(MemStorage::new());
            let mk_opts = || if encrypted { opts([81; 32]) } else { Options::default() };
            {
                let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), mk_opts()).unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"antes", b"confirmado").unwrap();
                tx.commit().unwrap();
            }
            let before = on_disk_meta(&s);

            for _ in 0..12 {
                let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), mk_opts()).unwrap();
                let mut tx = db.begin_write().unwrap();
                for i in 0..3u32 {
                    tx.put(0x02, &i.to_be_bytes(), b"a medias").unwrap();
                }
                // Se descarta sin commit.
            }

            let after = on_disk_meta(&s);
            assert_eq!(
                after.n_pages, before.n_pages,
                "cifrado={encrypted}: n_pages confirmado subio de {} a {} sin ningun commit: \
                 {} paginas perdidas",
                before.n_pages,
                after.n_pages,
                after.n_pages - before.n_pages
            );
            assert_eq!(
                (after.txn_id, after.root, after.freelist_head, after.freelist_tail),
                (before.txn_id, before.root, before.freelist_head, before.freelist_tail),
                "cifrado={encrypted}: abortar no debe cambiar nada de la meta confirmada \
                 salvo el techo de contador"
            );
            // Y lo confirmado sigue legible.
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), mk_opts()).unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                Some(b"confirmado".as_slice())
            );
        }
    }

    /// La matriz completa: cada política de `Sync` contra un desgarro en
    /// CADA una de las escrituras de meta que hace una sesión que extiende
    /// el techo, más el caso sin desgarro. Es la prueba que el arnés
    /// anterior no podía hacer (solo sabía descartar una ranura entera, ver
    /// `arm_meta_tear`).
    ///
    /// Dos propiedades por caso, no una:
    /// - **ningún contador se reutiliza** — el objetivo de la tarea;
    /// - **bajo `Sync::Commit`, lo ya confirmado sigue ahí** — sin esto, un
    ///   diseño que escriba las dos ranuras "de una tacada" con una sola
    ///   sincronización al final pasaría la primera comprobación y perdería
    ///   un commit entero: si la escritura de la ranura ACTIVA se desgarra
    ///   antes de que la de la INACTIVA sea duradera, no queda ninguna
    ///   ranura con el último estado confirmado.
    #[test]
    fn every_sync_policy_survives_a_torn_meta_write_at_every_point() {
        for policy in [Sync::Commit, Sync::Interval(Duration::from_secs(3600)), Sync::Never] {
            for tear_at in [None, Some(0), Some(1), Some(2)] {
                let s = Arc::new(PowerLossStorage::new());
                let master = [91u8; 32];
                let mk_opts = || Options { sync: policy, ..opts(master) };

                {
                    let db =
                        Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
                    let mut tx = db.begin_write().unwrap();
                    tx.put(0x01, b"antes", b"confirmado").unwrap();
                    tx.commit().unwrap();
                }
                // Bajo `Sync::Never`/`Interval` largo, el commit de la
                // sesión 1 no se sincroniza; este `sync()` de la propia
                // prueba lo fija como duradero para que las tres políticas
                // partan del mismo estado y la comprobación de
                // supervivencia del dato sea comparable.
                s.sync().unwrap();

                {
                    let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
                    if let Some(k) = tear_at {
                        s.arm_meta_tear(k, TORN_PREFIX);
                    }
                    let mut tx = db.begin_write().unwrap();
                    for i in 0..5u32 {
                        tx.put(0x02, &i.to_be_bytes(), b"sesion dos").unwrap();
                    }
                    tx.commit().unwrap();
                }

                s.simulate_power_loss();

                let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
                assert_eq!(
                    db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                    Some(b"confirmado".as_slice()),
                    "{policy:?} / desgarro en {tear_at:?}: se perdio un commit ya duradero"
                );
                {
                    let mut tx = db.begin_write().unwrap();
                    for i in 0..5u32 {
                        tx.put(0x03, &i.to_be_bytes(), b"sesion tres").unwrap();
                    }
                    tx.commit().unwrap();
                }
                drop(db);

                let audit = audit_nonces(&s.raw_writes());
                assert!(
                    audit.sealed > 0,
                    "{policy:?} / desgarro en {tear_at:?}: el auditor no vio ninguna pagina \
                     sellada, asi que 'cero nonces repetidos' no dice nada: {audit:?}"
                );
                assert_eq!(
                    audit.reused_nonces, 0,
                    "{policy:?} / desgarro en {tear_at:?}: {audit:?}"
                );
            }
        }
    }

    /// Cobertura de ejecución real para AES-256-GCM (ronda de revisión
    /// posterior a la primera entrega, hallazgo MEDIUM): sin estas tres
    /// pruebas, `--features aes` compilaba `Algorithm::Aes256Gcm` pero
    /// nunca lo instanciaba — cobertura de compilación, no de ejecución.
    #[cfg(feature = "aes")]
    mod aes_tests {
        use super::*;

        #[test]
        fn data_roundtrips_through_encryption() {
            let db =
                Db::create(Box::new(MemStorage::new()), opts_with([21; 32], Algorithm::Aes256Gcm))
                    .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"secreto", b"valor").unwrap();
            tx.commit().unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"secreto").unwrap().as_deref(),
                Some(b"valor".as_slice())
            );
        }

        #[test]
        fn a_tampered_page_is_rejected() {
            let s = Arc::new(MemStorage::new());
            let opts = opts_with([22; 32], Algorithm::Aes256Gcm);
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"k", b"v").unwrap();
            tx.commit().unwrap();
            let root = db.begin_read().root();
            drop(db);
            let mut bytes = s.snapshot();
            bytes[root as usize * 512 + 100] ^= 0xff;
            s.restore(bytes);
            let opts = opts_with([22; 32], Algorithm::Aes256Gcm);
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            assert!(matches!(db.begin_read().get(0x01, b"k"), Err(Error::Decrypt { .. })));
        }

        #[test]
        fn no_nonce_is_ever_reused() {
            let s = Arc::new(RecordingStorage::new());
            let opts = opts_with([23; 32], Algorithm::Aes256Gcm);
            let db = Db::create(Box::new(ArcRecording(Arc::clone(&s))), opts).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            }
            tx.commit().unwrap();
            let nonces = s.encrypted_page_nonces();
            let mut sorted = nonces.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), nonces.len(), "nonce repetido (AES-GCM)");
        }
    }
}
