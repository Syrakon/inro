//! Cifrado autenticado por página (tarea 17; nonces aleatorios desde la
//! ronda de cambio de diseño posterior).
//!
//! `WRAP_NONCE_LEN`/`TAG_LEN`/`WRAPPED_KEY_LEN` se compilan siempre, sin
//! condición alguna: `meta.rs` necesita `WRAPPED_KEY_LEN` incluso en una
//! compilación `no_std` sin cifrado, porque es parte del formato de
//! fichero puro (bytes 40..100 de cada meta-ranura), igual que
//! `header`/`page`. Ninguno de los tres depende de
//! `chacha20poly1305`/`aes-gcm-siv`: son enteros calculados en tiempo de
//! compilación.
//!
//! `Algorithm`/`Encryption`/`NonceStream`/`CIPHER_PREFIX`, en cambio, están
//! tras `#[cfg(any(feature = "std", feature = "encryption"))]`: los usa
//! `pager.rs`/`tx.rs` bajo `std` (`Pager::logical_page_size`,
//! `Options::encryption`, `WriterState::nonce_stream`) SIN que haga falta
//! `encryption` — son tipos simples, no tocan las dependencias — y también
//! `seal`/`open`, que sí las tocan, bajo `encryption` SIN que haga falta
//! `std` (son `no_std`-compatibles, pensadas para un llamante que integre su
//! propio almacenamiento). Sin esta doble condición, un build
//! `--no-default-features` (ninguna de las dos) los deja sin ningún
//! llamador alcanzable y dispara aviso de código muerto — lo que de
//! verdad toca `chacha20poly1305`/`aes-gcm-siv` (`seal`, `open`, `wrap_key`,
//! `unwrap_key`, `generate_data_key`/`generate_wrap_nonce`) sigue solo tras
//! `encryption`, así que ese build nunca las enlaza.
//!
//! # El nonce: prefijo aleatorio por apertura, contador dentro de ella
//!
//! ```text
//! nonce = prefijo aleatorio (16 B, sorteado UNA vez por apertura)
//!         || contador (8 B, monótono dentro de esa apertura)
//! ```
//!
//! Y, a diferencia del diseño anterior (`página || contador`, derivado y
//! nunca almacenado), **el nonce viaja entero en claro con cada página**
//! — es la única forma de poder descifrarla después, porque el prefijo
//! cambia en cada apertura y las páginas selladas por aperturas anteriores
//! siguen ahí. Ver `CIPHER_PREFIX` para el coste en disco.
//!
//! **Por qué se cambió.** El contador viajaba en claro y su TECHO se
//! persistía en la meta, junto a la clave de datos envuelta. Al vivir los
//! dos en la meta, **retroceden juntos**: restaurar una copia de seguridad
//! de una base cifrada reutilizaba todos los contadores bajo la misma clave
//! de datos — medido sobre el código anterior, 296 de 296 nonces
//! compartidos entre las dos líneas temporales, 164 con texto plano
//! distinto y hasta un 96,52 % de bytes cero en el XOR de los textos
//! cifrados: recuperación total del texto plano a partir de un
//! procedimiento de operación corriente, sin ningún atacante de por medio.
//!
//! **Por qué NO se sortea entropía en cada escritura.** Dos razones, las
//! dos verificadas: `read_random` (más abajo) abre `/dev/urandom` en CADA
//! llamada, así que un nonce aleatorio por página serían un `open` y un
//! `read` por página en un motor cuya premisa entera es el mínimo consumo
//! de CPU; y bajo `no_std` no hay ninguna fuente de entropía — hoy la
//! aleatoriedad solo hace falta al generar la clave, y ahí la aporta el
//! llamante. Un sorteo por APERTURA cuesta una lectura de `/dev/urandom`
//! por sesión, no por escritura.
//!
//! **Qué se gana.** Dentro de una apertura la unicidad está GARANTIZADA
//! (el contador es monótono y no rebobina nunca, ni siquiera al abortar
//! una transacción); entre líneas temporales distintas —una copia
//! restaurada, dos asas, dos procesos— una colisión exige repetir 128 bits
//! aleatorios. Una copia restaurada sortea un prefijo nuevo al abrir; dos
//! aperturas cualesquiera sortean prefijos distintos.
//!
//! **Qué desapareció con el cambio**, y no es un efecto colateral sino el
//! objetivo: el techo de contador persistido (`Meta::write_counter`, bytes
//! 100..108), su protocolo de extensión (dos escrituras de meta con dos
//! sincronizaciones), `COUNTER_RESERVE`, `WriterState::counter_ceiling` y
//! el `fsync` incondicional que pagaba la primera escritura de toda
//! apertura cifrada. Con un prefijo fresco por apertura, reiniciar el
//! contador en cero tras una caída es seguro por construcción, así que no
//! queda nada que persistir.
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
//! `polyval` (el backend de AES-GCM-SIV, tras la feature `aes`) tienen el
//! mismo patrón vía `aes_force_soft`/`polyval_force_soft`.
//!
//! Medido (no supuesto) en un Intel Core "Haswell" con AVX2+SSE2+AES-NI,
//! cifrando páginas de 4 KB con `encrypt_in_place_detached`, ~780 MB por
//! corrida, `opt-level = 3` + `lto = true`, 3 corridas por configuración:
//!
//! | Backend | MB/s (3 corridas) | Media |
//! |---|---|---|
//! | Por defecto (AVX2/SSE2, `unsafe`) | 707,0 / 738,5 / 764,9 | ~737 MB/s |
//! | Portable (`--cfg *_force_soft`, sin `unsafe`) | 359,5 / 327,7 / 376,9 | ~355 MB/s |
//!
//! El backend portable rinde **~2,1× más lento** en este hardware — la cifra
//! "200 a 400 MB/s" del comentario de `Algorithm::XChaCha20Poly1305`, más
//! abajo, es justo el rango que dio esta medición, no una cifra inventada.
//! La medición es del núcleo ChaCha20, que XChaCha20 comparte byte a byte:
//! XChaCha20 solo antepone una derivación HChaCha20 de coste constante (un
//! bloque) por MENSAJE, invisible frente a cifrar una página entera.
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
//! ## Qué autentica el tag, y qué sigue sin autenticar
//!
//! Cada página sellada lleva su número de página y su propio nonce
//! almacenado como **datos asociados** (`associated_data`, más abajo), así
//! que el tag cubre los tres: texto cifrado, número de página y nonce. De
//! ahí salen dos propiedades concretas:
//!
//! - **Mover bytes de una página a otra se detecta.** Copiar la página 5
//!   encima de la 9 falla al descifrar, porque la 9 se autentica con `9` en
//!   los datos asociados. Esto lo daba antes, de rebote, que el nonce se
//!   derivara de `página || contador`; al pasar a un nonce almacenado
//!   habría desaparecido si no se pusiera el número de página en los datos
//!   asociados a propósito.
//! - **Ningún byte físico de la página queda fuera del tag.** El campo de
//!   nonce mide 24 B siempre, pero AES-256-GCM-SIV solo usa 12 (ver
//!   `NonceStream::next`); esos 12 bytes de relleno también entran en los
//!   datos asociados, así que tocarlos invalida el tag en vez de pasar
//!   inadvertidos.
//!
//! ### Límite conocido, fuera del alcance de este cambio: la meta no está autenticada
//!
//! La meta-página (`meta.rs`) solo lleva su CRC32 de siempre — no pasa por
//! `seal`/`open`, por la razón que explica el comentario de `wrap_key`: se
//! reescribe en cada commit, y meterla en el esquema de nonces por página
//! exigiría su propio diseño. Consecuencia: quien puede escribir el fichero
//! puede reapuntar `root`/`freelist_head`/`freelist_tail` a cualquier OTRA
//! página cifrada del mismo fichero (recalculando el CRC32, que no es
//! secreto) y esa página se DESCIFRARÁ LIMPIA — los datos asociados ligan
//! cada página con su NÚMERO, no con el PAPEL que juega en el árbol. El tag
//! certifica "esta página se cifró con esta clave, para este número de
//! página, con este nonce", no "esta página es la raíz legítima de este
//! árbol en este momento". Cerrarlo exigiría autenticar también la meta —
//! diseño propio, con su propio ciclo de revisión.

// A diferencia de `Algorithm`/`Encryption`/`NonceStream`/`CIPHER_PREFIX` más
// abajo, esto solo hace falta bajo `encryption`: son los tipos que usan
// `seal`, `open`, `wrap_key`, `unwrap_key` y
// `generate_data_key`/`generate_wrap_nonce`, todas tras esa feature —
// `pager.rs`/`tx.rs` (que solo piden `std`) nunca tocan `Error`/`PageNo`/
// `Result` DESDE ESTE fichero: usan los suyos propios, importados en
// `pager.rs`/`tx.rs`.
#[cfg(feature = "encryption")]
use crate::{Error, PageNo, Result};

/// Nonce del envoltorio de la clave de datos en la meta (`wrap_key`), no el
/// de una página: doce bytes, aleatorios, de un solo uso por base. No lo
/// toca el cambio a nonces por apertura — ver `wrap_key`.
pub const WRAP_NONCE_LEN: usize = 12;

pub const TAG_LEN: usize = 16;

/// Envoltorio de la clave de datos: nonce de 12, texto cifrado de 32 y tag de
/// 16, en los bytes 40..100 de la meta.
pub const WRAPPED_KEY_LEN: usize = WRAP_NONCE_LEN + 32 + TAG_LEN;

/// Bytes del prefijo aleatorio que se sortea UNA vez por apertura. Dieciséis
/// es lo que le sobra a XChaCha20-Poly1305 tras reservar ocho para el
/// contador; AES-256-GCM-SIV solo puede usar los ocho primeros (ver
/// `NonceStream::next`), pero el prefijo se sortea entero siempre — sortear
/// menos bytes según el algoritmo no ahorra nada (es una sola lectura de
/// `/dev/urandom` por apertura) y sí complicaría el tipo.
#[cfg(any(feature = "std", feature = "encryption"))]
pub const NONCE_PREFIX_LEN: usize = 16;

/// Bytes de nonce que cada página cifrada almacena en claro. Veinticuatro,
/// el tamaño del nonce de XChaCha20-Poly1305, para los DOS algoritmos:
/// AES-256-GCM-SIV usa solo los doce primeros y deja el resto a cero.
///
/// **Un campo de tamaño fijo, no uno por algoritmo, y a propósito.** El
/// algoritmo NO viaja en el fichero (solo el flag `FLAG_ENCRYPTED`, ver
/// `header.rs`): lo aporta quien abre, en `Options::encryption`. Si el
/// tamaño del campo dependiera de él, el tamaño de página LÓGICA
/// (`Pager::logical_page_size`) dependería de un dato que el fichero no
/// contiene, y abrir con el algoritmo equivocado dejaría de ser un fallo
/// limpio de autenticación para convertirse en una geometría distinta. Los
/// doce bytes que AES desaprovecha se pagan una vez por página y entran en
/// los datos asociados, así que tampoco quedan sin autenticar (ver el
/// comentario del módulo).
#[cfg(any(feature = "std", feature = "encryption"))]
pub const STORED_NONCE_LEN: usize = 24;

/// Nonce de AES-256-GCM-SIV: doce bytes, de los cuales ocho son prefijo
/// aleatorio y cuatro contador (ver `NonceStream::next`).
#[cfg(feature = "encryption")]
pub const AES_NONCE_LEN: usize = 12;

/// Prefijo aleatorio que le cabe al nonce de AES-256-GCM-SIV: ocho bytes de
/// los doce, dejando cuatro para el contador. Ver `NonceStream::next` para
/// por qué este reparto y no otro.
#[cfg(feature = "encryption")]
pub const AES_PREFIX_LEN: usize = 8;

/// Bytes en claro al principio de una página cifrada: nonce completo y tag.
///
/// Cuarenta, frente a los veinticuatro del diseño anterior (8 de contador +
/// 16 de tag): el nonce ya no se deriva de `página || contador`, se
/// almacena entero, así que el sobrecoste sube 16 bytes por página y el
/// tamaño de página LÓGICA baja otros tantos.
#[cfg(any(feature = "std", feature = "encryption"))]
pub const CIPHER_PREFIX: usize = STORED_NONCE_LEN + TAG_LEN;

#[cfg(any(feature = "std", feature = "encryption"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Por defecto. Sin aceleración por hardware mantiene entre 200 y 400 MB/s,
    /// cuatro veces más que AES en software, que es el caso de los procesadores
    /// IoT sin extensiones criptográficas.
    ///
    /// **X**ChaCha20, no ChaCha20 a secas: su nonce de 24 bytes es lo que
    /// deja meter un prefijo aleatorio de 16 B junto al contador de 8 B.
    /// El coste frente a ChaCha20-Poly1305 es una derivación HChaCha20 por
    /// página (un bloque), invisible frente a cifrar la página entera.
    XChaCha20Poly1305,
    /// Para entornos con AES-NI o requisitos de cumplimiento que lo exijan.
    ///
    /// **-SIV, no GCM a secas** (cambio de esta ronda). AES-256-GCM tiene un
    /// nonce de 12 bytes: no caben 16 de prefijo más 8 de contador, así que
    /// el prefijo aleatorio que le toca es corto y una colisión entre dos
    /// aperturas deja de ser despreciable — ver la aritmética en
    /// `NonceStream::next`. AES-256-GCM-SIV (RFC 8452) es resistente a la
    /// reutilización de nonce por construcción: si dos aperturas llegaran a
    /// sortear el mismo prefijo, lo que un observador aprende es que dos
    /// textos planos eran iguales, no cuáles eran — con GCM a secas
    /// aprendería su XOR, que para páginas de este motor (casi todo relleno
    /// a cero y cabeceras iguales) es texto plano.
    Aes256GcmSiv,
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

/// Fuente de nonces de UNA apertura: el prefijo aleatorio que se sorteó al
/// abrir, más cuántos nonces se han entregado desde entonces.
///
/// **Es el tipo que hace imposible sellar sin prefijo.** `seal` no toma un
/// nonce ni un contador sueltos: toma `&mut NonceStream`, y un
/// `NonceStream` no se puede construir sin dar 16 bytes de prefijo
/// (`from_prefix`) o sin pedirle al sistema que los sortee
/// (`random`, solo bajo `std`). No hay ningún camino que selle una página
/// con un prefijo por defecto, a cero, o sin inicializar.
///
/// **Dónde vive y por qué ahí.** Bajo `std` lo guarda
/// `WriterState::nonce_stream` (`tx.rs`): estado de la BASE, no de una
/// transacción, para que sobreviva a un aborto sin rebobinar — una
/// transacción descartada no puede devolver a circulación un contador que
/// ya usó para sellar páginas que sí llegaron al medio. Bajo `no_std` lo
/// guarda quien integre su propio almacenamiento, que es también quien
/// aporta el prefijo, igual que ya aporta la clave de datos.
///
/// `issued` no rebobina JAMÁS — ni al abortar, ni cuando el prefijo se
/// vuelve a sortear por agotamiento del campo de contador de AES (ver
/// `next`). Por eso sirve además como identificador único de escritura
/// dentro de la apertura, que es lo que usa la comprobación defensiva de
/// `WriteTxn::write_page`.
///
/// **Bajo `std` SIN `encryption`** este tipo existe solo para que
/// `tx.rs`/`pager.rs`/`freelist.rs` puedan nombrarlo — `WriterState` lleva
/// un `Option<NonceStream>` que en ese build es siempre `None`, porque
/// `Db::create`/`open` ya rechazan cualquier petición de cifrado antes de
/// llegar ahí. En ese build no hay constructor alcanzable ni nadie que lea
/// `prefix`, así que el análisis de código muerto lo señalaría con razón:
/// de ahí el `allow` condicionado, que NO se aplica a ningún build donde el
/// tipo se use de verdad.
#[cfg(any(feature = "std", feature = "encryption"))]
#[cfg_attr(not(feature = "encryption"), allow(dead_code))]
pub struct NonceStream {
    prefix: [u8; NONCE_PREFIX_LEN],
    issued: u64,
}

/// A mano, igual que el de `Encryption` y por el mismo motivo: el prefijo no
/// es secreto (viaja en claro en cada página), pero volcarlo en un `{:?}`
/// accidental invita a confundirlo con material público de depuración
/// cuando en realidad es el que separa una línea temporal de otra.
#[cfg(any(feature = "std", feature = "encryption"))]
impl core::fmt::Debug for NonceStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonceStream")
            .field("prefix", &"[omitido]")
            .field("issued", &self.issued)
            .finish()
    }
}

/// Lo único que necesita `WriteTxn::write_page` bajo `std` sin `encryption`
/// (donde el resto del `impl`, más abajo, no se compila): ver el comentario
/// del tipo.
#[cfg(any(feature = "std", feature = "encryption"))]
impl NonceStream {
    /// Cuántos nonces ha entregado esta apertura. Estrictamente creciente y
    /// sin rebobinar nunca (ver el comentario del tipo), así que identifica
    /// de forma única cada escritura sellada dentro de la apertura.
    pub fn issued(&self) -> u64 {
        self.issued
    }
}

#[cfg(all(test, feature = "encryption"))]
impl NonceStream {
    /// Coloca el flujo justo donde estaría tras `issued` sellados, sin
    /// hacerlos. Lo necesita
    /// `exhausting_the_aes_counter_field_renews_the_prefix_instead_of_repeating`:
    /// el borde que esa prueba comprueba está a 2^32 escrituras, y llegar
    /// ahí de verdad no es una prueba, es un banco de varias horas. El
    /// estado resultante es exactamente el mismo — `prefix` e `issued` son
    /// los dos únicos campos del tipo.
    pub(crate) fn at_issued_for_test(prefix: [u8; NONCE_PREFIX_LEN], issued: u64) -> Self {
        Self { prefix, issued }
    }
}

#[cfg(feature = "encryption")]
impl NonceStream {
    /// Con el prefijo que aporta el llamante. Es el constructor de `no_std`:
    /// sin sistema operativo no hay fuente de entropía portable, así que los
    /// 16 bytes los pone quien integra el motor — exactamente igual que ya
    /// pone la clave de datos.
    pub fn from_prefix(prefix: [u8; NONCE_PREFIX_LEN]) -> Self {
        Self { prefix, issued: 0 }
    }

    /// Sorteando el prefijo de `/dev/urandom`. Es lo que hacen `Db::create`
    /// y `Db::open` (`tx.rs`) en cada apertura de una base cifrada: UNA
    /// lectura por apertura, no una por escritura.
    #[cfg(feature = "std")]
    pub fn random() -> Result<Self> {
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        read_random(&mut prefix)?;
        Ok(Self::from_prefix(prefix))
    }

    /// El siguiente nonce, ya en el formato de 24 bytes que se almacena con
    /// la página.
    ///
    /// # El reparto, por algoritmo
    ///
    /// - **XChaCha20-Poly1305 (24 B):** `prefijo (16) || contador (8, LE)`.
    ///   El contador es el `issued` entero, así que agotarlo exige 2^64
    ///   escrituras: inalcanzable, y aun así se comprueba en vez de
    ///   suponerse.
    /// - **AES-256-GCM-SIV (12 B):** `prefijo (8) || contador (4, LE)`, con
    ///   los 12 bytes restantes del campo almacenado a cero.
    ///
    /// # Por qué 8+4 en el caso de 12 bytes, y qué probabilidad se acepta
    ///
    /// El reparto es un intercambio directo: cada byte que se le da al
    /// prefijo se lo quita al contador. Lo que hay que acotar son dos cosas
    /// distintas.
    ///
    /// **(a) Colisión de prefijos entre dos sorteos.** Solo importa dentro
    /// de UNA base: la clave de datos es aleatoria y distinta por base
    /// (`generate_data_key`), así que dos bases nunca comparten el espacio
    /// de nonces. Con un prefijo de 8 B el espacio es 2^64 y, por la
    /// aproximación del cumpleaños, `n` sorteos colisionan con
    /// probabilidad ≈ `n² / 2^65`:
    ///
    /// | sorteos sobre una misma base | probabilidad de colisión |
    /// |---|---|
    /// | 10^4 (un reinicio por hora durante un año) | ≈ 2,7 × 10⁻¹² |
    /// | 10^6 | ≈ 2,7 × 10⁻⁸ |
    /// | 10^9 | ≈ 2,7 × 10⁻² |
    ///
    /// Un sorteo por apertura, más uno por cada 2^32 escrituras (ver (b)).
    /// **Y una colisión no es catastrófica**: por eso el algoritmo es
    /// GCM-SIV y no GCM. Con nonce repetido, GCM-SIV filtra únicamente que
    /// dos textos planos eran iguales; GCM filtraría su XOR, que sobre
    /// páginas de este motor equivale al texto plano — es literalmente el
    /// defecto que este cambio de diseño cierra. Con 4 B de prefijo (el
    /// reparto 4+8, que conservaría el contador de 8 B) la tabla sería
    /// inaceptable: 10^5 aperturas dan probabilidad ≈ 1.
    ///
    /// **(b) Agotamiento del contador de 4 B.** 2^32 = 4 294 967 296
    /// escrituras de página en UNA sola apertura. Es mucho, pero no
    /// inalcanzable en un proceso de larga vida, así que no se deja como
    /// precipicio: al desbordar el campo se sortea un prefijo nuevo y se
    /// sigue. Cuesta una lectura de `/dev/urandom` cada 2^32 escrituras —
    /// nada — y `issued` sigue avanzando sin rebobinar, así que ni el
    /// contador ni la comprobación defensiva de `write_page` se confunden.
    /// Bajo `no_std` no hay de dónde sortear: ahí el agotamiento es un
    /// error explícito (`Error::NonceExhausted`) y no un nonce repetido en
    /// silencio.
    ///
    /// XChaCha20-Poly1305 no tiene ninguno de los dos problemas: 16 B de
    /// prefijo dan ≈ `n² / 2^129` (para 10^9 sorteos, ≈ 1,5 × 10⁻²¹) y el
    /// contador de 8 B no se agota.
    pub fn next(&mut self, algorithm: Algorithm) -> Result<[u8; STORED_NONCE_LEN]> {
        let mut nonce = [0u8; STORED_NONCE_LEN];
        match algorithm {
            Algorithm::XChaCha20Poly1305 => {
                nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.prefix);
                nonce[NONCE_PREFIX_LEN..].copy_from_slice(&self.issued.to_le_bytes());
            }
            Algorithm::Aes256GcmSiv => {
                // El campo de contador es de 32 bits, así que se agota cada
                // 2^32 escrituras: cuando `issued` vuelve a caer en un
                // múltiplo de 2^32 (y no es la primera vez), el contador
                // repetiría — hay que renovar el prefijo ANTES de usarlo.
                if self.issued != 0 && self.issued as u32 == 0 {
                    self.renew_prefix()?;
                }
                nonce[..AES_PREFIX_LEN].copy_from_slice(&self.prefix[..AES_PREFIX_LEN]);
                nonce[AES_PREFIX_LEN..AES_NONCE_LEN]
                    .copy_from_slice(&(self.issued as u32).to_le_bytes());
            }
        }
        // Nunca puede desbordar en la práctica (2^64 escrituras), pero
        // `checked_add` en vez de `+= 1` deja el caso imposible como un
        // error explícito en lugar de como un `wrapping` silencioso que
        // devolvería un nonce ya usado.
        self.issued = self.issued.checked_add(1).ok_or(Error::NonceExhausted)?;
        Ok(nonce)
    }

    /// Vuelve a sortear el prefijo cuando el campo de contador de AES se
    /// agota. Ver `next`.
    #[cfg(feature = "std")]
    fn renew_prefix(&mut self) -> Result<()> {
        read_random(&mut self.prefix)
    }

    /// Sin `std` no hay `/dev/urandom` ni ninguna otra fuente portable, y el
    /// prefijo lo aportó el llamante una sola vez: el agotamiento tiene que
    /// ser un error, no un nonce repetido en silencio. Ver `next`.
    #[cfg(not(feature = "std"))]
    fn renew_prefix(&mut self) -> Result<()> {
        Err(Error::NonceExhausted)
    }
}

/// Datos asociados de una página sellada: su número y su propio nonce.
/// Autenticados, no cifrados — ver "Qué autentica el tag" en el comentario
/// del módulo para las dos propiedades concretas que dan.
#[cfg(feature = "encryption")]
fn associated_data(page: PageNo, nonce: &[u8; STORED_NONCE_LEN]) -> [u8; 4 + STORED_NONCE_LEN] {
    let mut aad = [0u8; 4 + STORED_NONCE_LEN];
    aad[..4].copy_from_slice(&page.to_le_bytes());
    aad[4..].copy_from_slice(nonce);
    aad
}

/// Cifra `plain` en `out`, que debe medir `CIPHER_PREFIX + plain.len()`.
///
/// Toma el `NonceStream` de la apertura, no un nonce ni un contador sueltos
/// (ver el comentario de `NonceStream`): el nonce se saca de ahí, se
/// escribe en claro en los primeros `STORED_NONCE_LEN` bytes de `out` — de
/// donde `open` lo vuelve a leer — y entra además en los datos asociados
/// junto con `page`.
#[cfg(feature = "encryption")]
pub fn seal(
    enc: &Encryption,
    stream: &mut NonceStream,
    page: PageNo,
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

    // El nonce se saca ANTES de tocar `out`: si el flujo estuviera agotado
    // (ver `NonceStream::next`), esto falla sin haber dejado la página a
    // medio construir.
    let nonce = stream.next(enc.algorithm)?;
    let aad = associated_data(page, &nonce);
    out[..STORED_NONCE_LEN].copy_from_slice(&nonce);
    out[CIPHER_PREFIX..].copy_from_slice(plain);

    let tag = match enc.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let cipher = chacha20poly1305::XChaCha20Poly1305::new((&enc.key).into());
            cipher
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut out[CIPHER_PREFIX..])
                .map_err(|_| Error::Decrypt { page })?
        }
        #[cfg(feature = "aes")]
        Algorithm::Aes256GcmSiv => {
            use aes_gcm_siv::aead::{AeadInPlace as _, KeyInit as _};
            let cipher = aes_gcm_siv::Aes256GcmSiv::new((&enc.key).into());
            cipher
                .encrypt_in_place_detached(
                    (&aes_nonce(&nonce)).into(),
                    &aad,
                    &mut out[CIPHER_PREFIX..],
                )
                .map_err(|_| Error::Decrypt { page })?
        }
        #[cfg(not(feature = "aes"))]
        Algorithm::Aes256GcmSiv => return Err(Error::BadFormat),
    };
    out[STORED_NONCE_LEN..CIPHER_PREFIX].copy_from_slice(&tag);
    // Instrumentación de pruebas EN EL PROPIO `seal`, no reconstruyendo
    // nonces a partir de las escrituras físicas (ver `probe`): es el único
    // punto por el que pasa absolutamente todo sellado de este motor —
    // árbol, lista de libres, cualquier camino presente o futuro — así que
    // un contador aquí no puede quedarse corto por haber olvidado filtrar
    // bien qué offsets son meta y cuáles datos, que es de lo que dependía
    // el arnés anterior.
    #[cfg(all(test, feature = "std"))]
    probe::record(page, &nonce, &out[CIPHER_PREFIX..]);
    Ok(())
}

/// Registro de todos los nonces que `seal` produce mientras una prueba
/// mantiene abierta una sesión de captura.
///
/// **Por qué aquí dentro y no en un `Storage` envolvente.** La prueba de
/// unicidad de nonces anterior a este cambio deducía el nonce de cada
/// escritura física: leía los ocho primeros bytes de cada página escrita y
/// los interpretaba como el contador, descartando por offset las escrituras
/// de cabecera y de meta. Eso obligaba a mantener, dentro del arnés, un
/// modelo de qué offsets son meta en cada instante — que cambió tres veces
/// (meta B estática, meta B reubicable, meta B reubicada y luego
/// reciclada) y en el que un fallo se manifiesta como nonces que el
/// auditor NO mira, es decir como una prueba que pasa por no haber
/// comprobado nada. Capturando en `seal` no hay nada que deducir ni que
/// filtrar: lo que se cuenta son los nonces que de verdad se usaron.
///
/// La sesión es exclusiva (`SESSION`) porque las pruebas del mismo binario
/// corren en paralelo y el registro es global: sin esa exclusión, dos
/// pruebas instrumentadas a la vez mezclarían sus nonces. No serializa la
/// suite entera, solo las pruebas que capturan.
#[cfg(all(test, feature = "encryption", feature = "std"))]
pub(crate) mod probe {
    use super::{PageNo, STORED_NONCE_LEN};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use std::sync::{Mutex, MutexGuard};

    /// Un sellado tal como lo produjo `seal`.
    pub struct Sealed {
        pub page: PageNo,
        pub nonce: [u8; STORED_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    static SESSION: Mutex<()> = Mutex::new(());

    // Por HILO, no global. `seal` llama a `record` desde cualquier prueba
    // que cifre, y `cargo test` las corre en paralelo: con un registro
    // global, los sellados de una prueba que NO captura acababan dentro de
    // la captura de otra que sí, y
    // `the_nonce_counter_restarts_at_zero_on_every_open` fallaba de forma
    // intermitente al leer en `first[0]` un sellado ajeno con otro
    // contador. `SESSION` solo serializa las capturas ENTRE SÍ; nunca aisló
    // de las no capturadoras, que es de donde venía la contaminación.
    thread_local! {
        static RECORD: RefCell<Option<Vec<Sealed>>> = const { RefCell::new(None) };
    }

    /// Sesión de captura viva. Mientras exista, `seal` anota cada nonce que
    /// produce; al soltarla, la captura se apaga.
    pub struct Capture {
        _session: MutexGuard<'static, ()>,
    }

    impl Capture {
        pub fn start() -> Self {
            // `into_inner` en vez de `unwrap`: si una prueba instrumentada
            // entra en pánico, el candado queda envenenado y TODAS las
            // demás fallarían por un motivo ajeno al que se está probando.
            let session = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            RECORD.with(|r| *r.borrow_mut() = Some(Vec::new()));
            Self { _session: session }
        }

        /// Se lleva lo capturado hasta ahora y deja el registro vacío pero
        /// activo: sirve para separar en tramos una misma sesión (p. ej. lo
        /// que selló el original de una copia de seguridad y lo que selló
        /// la copia restaurada).
        pub fn take(&self) -> Vec<Sealed> {
            RECORD.with(|r| r.borrow_mut().replace(Vec::new()).unwrap_or_default())
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            RECORD.with(|r| *r.borrow_mut() = None);
        }
    }

    pub(super) fn record(page: PageNo, nonce: &[u8; STORED_NONCE_LEN], ciphertext: &[u8]) {
        // `try_with` y no `with`: durante el desmontaje de un hilo la
        // variable local ya puede estar destruida, y `with` entraría en
        // pánico dentro de `seal` — un fallo del arnés disfrazado de fallo
        // del motor.
        let _ = RECORD.try_with(|r| {
            if let Some(v) = r.borrow_mut().as_mut() {
                v.push(Sealed { page, nonce: *nonce, ciphertext: ciphertext.to_vec() });
            }
        });
    }
}

/// Los doce bytes de nonce que usa AES-256-GCM-SIV, recortados del campo
/// almacenado de 24. Los otros doce van a cero y se autentican como datos
/// asociados; ver `STORED_NONCE_LEN`.
#[cfg(all(feature = "encryption", feature = "aes"))]
fn aes_nonce(nonce: &[u8; STORED_NONCE_LEN]) -> [u8; AES_NONCE_LEN] {
    let mut n = [0u8; AES_NONCE_LEN];
    n.copy_from_slice(&nonce[..AES_NONCE_LEN]);
    n
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

    let mut nonce = [0u8; STORED_NONCE_LEN];
    nonce.copy_from_slice(&raw[..STORED_NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&raw[STORED_NONCE_LEN..CIPHER_PREFIX]);
    let aad = associated_data(page, &nonce);

    match enc.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let cipher = chacha20poly1305::XChaCha20Poly1305::new((&enc.key).into());
            cipher
                .decrypt_in_place_detached(
                    (&nonce).into(),
                    &aad,
                    &mut raw[CIPHER_PREFIX..],
                    (&tag).into(),
                )
                .map_err(|_| Error::Decrypt { page })
        }
        #[cfg(feature = "aes")]
        Algorithm::Aes256GcmSiv => {
            use aes_gcm_siv::aead::{AeadInPlace as _, KeyInit as _};
            let cipher = aes_gcm_siv::Aes256GcmSiv::new((&enc.key).into());
            cipher
                .decrypt_in_place_detached(
                    (&aes_nonce(&nonce)).into(),
                    &aad,
                    &mut raw[CIPHER_PREFIX..],
                    (&tag).into(),
                )
                .map_err(|_| Error::Decrypt { page })
        }
        #[cfg(not(feature = "aes"))]
        Algorithm::Aes256GcmSiv => Err(Error::BadFormat),
    }
}

/// Fuente común de bytes aleatorios para `generate_data_key`,
/// `generate_wrap_nonce` y `NonceStream::random`/`renew_prefix`: todos leen
/// `/dev/urandom` exactamente igual, así que factorizarlo evita que diverjan
/// por accidente. Gateado con `encryption` además de `std`: sin esa
/// `encryption` extra, esta función — y sus llamadores — compilarían igual
/// en un build `cargo test` (std sin cifrado), pero sin ningún llamador
/// alcanzable (`Db::create`/`open` solo las invocan bajo `encryption`, ver
/// `tx.rs`), lo que dispara el aviso de código muerto que pide mantener
/// limpio el fichero.
///
/// **Abre `/dev/urandom` en CADA llamada**, y es justo la razón de que el
/// prefijo de nonce se sortee una vez por apertura y no una vez por
/// escritura: un `open` más un `read` por página convertirían el camino
/// caliente de un motor pensado para IoT en dos llamadas al sistema por
/// página escrita. Ver el comentario del módulo.
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
/// portable sin sistema operativo — igual que el prefijo de nonce, ver
/// `NonceStream::from_prefix`.
#[cfg(all(feature = "encryption", feature = "std"))]
pub fn generate_data_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    read_random(&mut key)?;
    Ok(key)
}

/// Nonce del envoltorio de la clave de datos (ver `wrap_key`): aleatorio, de
/// un solo uso. No es un nonce de página y no pasa por `NonceStream`: la
/// meta se reescribe en cada commit, pero el envoltorio de la clave se sella
/// UNA vez en la vida de la base (`Db::create`) y se copia tal cual en cada
/// escritura de meta posterior, así que doce bytes aleatorios de un solo uso
/// son exactamente lo que hace falta.
#[cfg(all(feature = "encryption", feature = "std"))]
pub fn generate_wrap_nonce() -> Result<[u8; WRAP_NONCE_LEN]> {
    let mut n = [0u8; WRAP_NONCE_LEN];
    read_random(&mut n)?;
    Ok(n)
}

/// Cifra la clave de datos con la maestra. El nonce va en claro dentro del
/// propio envoltorio.
///
/// **Sigue siendo ChaCha20-Poly1305 (nonce de 12 B), no XChaCha20 ni
/// AES-GCM-SIV, sea cual sea el `Algorithm` de las páginas.** No es un
/// descuido: este sellado ocurre una sola vez por base, con un nonce
/// aleatorio de 12 B que no se reutiliza jamás — no hay ninguna secuencia
/// que pueda colisionar, así que ni el nonce extendido ni la resistencia a
/// la reutilización aportan nada aquí. Mantenerlo fijo también deja el
/// envoltorio (y con él los bytes 40..100 de la meta) independiente del
/// algoritmo de página, que es lo que permite abrir el fichero y
/// desenvolver la clave antes de saber nada más.
#[cfg(feature = "encryption")]
pub fn wrap_key(master: &[u8; 32], data_key: &[u8; 32], nonce_bytes: [u8; WRAP_NONCE_LEN])
    -> Result<[u8; WRAPPED_KEY_LEN]>
{
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..WRAP_NONCE_LEN].copy_from_slice(&nonce_bytes);
    out[WRAP_NONCE_LEN..WRAP_NONCE_LEN + 32].copy_from_slice(data_key);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(master.into());
    let tag = cipher
        .encrypt_in_place_detached(
            (&nonce_bytes).into(),
            &[],
            &mut out[WRAP_NONCE_LEN..WRAP_NONCE_LEN + 32],
        )
        .map_err(|_| Error::Decrypt { page: 0 })?;
    out[WRAP_NONCE_LEN + 32..].copy_from_slice(&tag);
    Ok(out)
}

#[cfg(feature = "encryption")]
pub fn unwrap_key(master: &[u8; 32], wrapped: &[u8; WRAPPED_KEY_LEN]) -> Result<[u8; 32]> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    nonce_bytes.copy_from_slice(&wrapped[..WRAP_NONCE_LEN]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&wrapped[WRAP_NONCE_LEN..WRAP_NONCE_LEN + 32]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&wrapped[WRAP_NONCE_LEN + 32..]);

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
    /// compilaba el backend AES pero ninguna prueba lo instanciaba de
    /// verdad — cobertura de compilación, no de ejecución.
    fn opts_with(key: [u8; 32], algorithm: Algorithm) -> Options {
        Options { encryption: Some(Encryption { key, algorithm }), ..Options::default() }
    }

    fn opts(key: [u8; 32]) -> Options {
        opts_with(key, Algorithm::XChaCha20Poly1305)
    }

    /// **Todos los algoritmos compilados, no solo el de por defecto.** El
    /// cambio a nonces aleatorios toca a los dos por igual —cambia el
    /// nonce, el reparto prefijo/contador, los datos asociados y el
    /// formato de página— así que las pruebas de esta ronda recorren esta
    /// lista en vez de fijar ChaCha y dejar AES con un puñado de casos
    /// aparte, que era la situación anterior (3 pruebas de AES contra la
    /// suite entera de ChaCha).
    ///
    /// Sin `--features aes` la lista tiene un solo elemento y las mismas
    /// pruebas siguen valiendo: no hay ninguna rama de prueba que solo
    /// exista en una configuración.
    const ALGORITHMS: &[Algorithm] = &[
        Algorithm::XChaCha20Poly1305,
        #[cfg(feature = "aes")]
        Algorithm::Aes256GcmSiv,
    ];

    /// Todas las pruebas de este módulo usan `Options::default()`
    /// (`page_size` 512, meta A siempre en la página 1, meta B en la 2
    /// hasta que `relocate_meta_b` la traslada a la 8).
    const TEST_PAGE_SIZE: u64 = 512;

    /// Porcentaje de bytes CERO del XOR de dos textos cifrados. No es una
    /// heurística: con el mismo nonce y la misma clave bajo un cifrado de
    /// flujo, el flujo de clave es idéntico, así que `C1 XOR C2 == P1 XOR
    /// P2` — y dos páginas de este motor comparten casi todos sus bytes
    /// (relleno a cero, misma cabecera de página), de modo que ese XOR sale
    /// casi todo ceros. Con nonces distintos el XOR es de dos flujos
    /// independientes: un byte cero cae con probabilidad 1/256, ~0,39 %.
    fn xor_zero_pct(a: &[u8], b: &[u8]) -> f64 {
        let n = core::cmp::min(a.len(), b.len());
        let zeros = (0..n).filter(|&i| a[i] ^ b[i] == 0).count();
        100.0 * zeros as f64 / n as f64
    }

    /// Veredicto sobre TODOS los sellados que `crypto::seal` produjo
    /// durante una captura.
    #[derive(Debug)]
    struct NonceAudit {
        /// Llamadas a `seal` observadas.
        sealed: usize,
        /// Nonces usados por más de un sellado.
        reused_nonces: usize,
        /// El peor par con nonce repetido, si lo hay: porcentaje de bytes
        /// cero de `C1 XOR C2`.
        worst_xor_zero_pct: f64,
        /// Las dos páginas de ese peor par.
        worst_pages: Option<(PageNo, PageNo)>,
        /// Línea base sobre pares con nonces DISTINTOS, para contrastar.
        baseline_xor_zero_pct: f64,
    }

    /// Audita lo capturado. A diferencia del auditor anterior a este
    /// cambio, no deduce nada de las escrituras físicas ni necesita saber
    /// qué offsets son meta: recibe los nonces que `seal` usó de verdad.
    fn audit(sealed: &[probe::Sealed]) -> NonceAudit {
        let mut by_nonce: alloc::collections::BTreeMap<
            [u8; STORED_NONCE_LEN],
            Vec<(PageNo, &[u8])>,
        > = alloc::collections::BTreeMap::new();
        for s in sealed {
            by_nonce.entry(s.nonce).or_default().push((s.page, &s.ciphertext));
        }

        let mut reused = 0usize;
        let mut worst = 0.0f64;
        let mut worst_pages = None;
        for texts in by_nonce.values() {
            if texts.len() < 2 {
                continue;
            }
            reused += 1;
            for i in 0..texts.len() {
                for j in i + 1..texts.len() {
                    let pct = xor_zero_pct(texts[i].1, texts[j].1);
                    if pct > worst {
                        worst = pct;
                        // Las páginas concretas, no solo el porcentaje: al
                        // depurar una reutilización lo primero que hace
                        // falta es saber QUÉ dos escrituras chocaron.
                        worst_pages = Some((texts[i].0, texts[j].0));
                    }
                }
            }
        }

        let mut base_sum = 0.0f64;
        let mut base_n = 0usize;
        for w in sealed.windows(2) {
            if w[0].nonce != w[1].nonce {
                base_sum += xor_zero_pct(&w[0].ciphertext, &w[1].ciphertext);
                base_n += 1;
            }
        }

        NonceAudit {
            sealed: sealed.len(),
            reused_nonces: reused,
            worst_xor_zero_pct: worst,
            worst_pages,
            baseline_xor_zero_pct: if base_n == 0 { 0.0 } else { base_sum / base_n as f64 },
        }
    }

    /// Comprobación que hacen TODAS las pruebas que capturan: cero nonces
    /// repetidos, y al menos un sellado observado.
    ///
    /// El segundo `assert` no es decoración: sin él, cualquier cambio que
    /// dejara de sellar —o de capturar— haría pasar "cero nonces
    /// repetidos" sin haber mirado una sola página, que es exactamente el
    /// modo de fallo silencioso que este arnés existe para no tener.
    fn assert_no_reuse(sealed: &[probe::Sealed], context: &str) -> NonceAudit {
        let a = audit(sealed);
        assert!(a.sealed > 0, "{context}: no se capturo ningun sellado: {a:?}");
        assert_eq!(
            a.reused_nonces, 0,
            "{context}: nonce reutilizado ({} nonces afectados, {} sellados en total); \
             el peor par son las paginas {:?}, con un {:.2} % de bytes cero en el XOR de sus \
             textos cifrados — linea base con nonces distintos: {:.2} %",
            a.reused_nonces,
            a.sealed,
            a.worst_pages,
            a.worst_xor_zero_pct,
            a.baseline_xor_zero_pct
        );
        a
    }

    /// Los nonces de una captura, como conjunto: lo que hace falta para
    /// comprobar que dos líneas temporales no comparten ninguno.
    fn nonce_set(sealed: &[probe::Sealed]) -> alloc::collections::BTreeSet<[u8; STORED_NONCE_LEN]> {
        sealed.iter().map(|s| s.nonce).collect()
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
        fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
    }

    #[test]
    fn data_roundtrips_through_encryption() {
        for &algorithm in ALGORITHMS {
            let db =
                Db::create(Box::new(MemStorage::new()), opts_with([1; 32], algorithm)).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"secreto", b"valor").unwrap();
            tx.commit().unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"secreto").unwrap().as_deref(),
                Some(b"valor".as_slice()),
                "{algorithm:?}"
            );
        }
    }

    /// Autorrevisión (ronda propia, no del brief): las pruebas existentes
    /// de `tree.rs`/`tx.rs` no se pueden correr tal cual con cifrado activo
    /// — varias construyen páginas A MANO al tamaño físico exacto
    /// (`tree.rs::raw_overflow_page` y compañía), y cambiar el tamaño de
    /// página a mitad de esas pruebas las rompería por una razón ajena a
    /// esta tarea. Esta prueba es el sustituto deliberado: el mismo TIPO de
    /// carga que esas — muchas inserciones que fuerzan divisiones de nodo,
    /// un valor por encima del umbral de overflow, borrados intercalados —
    /// pero pasando siempre por `Options.encryption = Some(...)`, que es
    /// exactamente donde se manifestaría un `page_size()` olvidado en vez
    /// de `logical_page_size()`: o `PageBuilder` construiría páginas
    /// "lógicas" de 512 B que, tras sellar, medirían 552 B físicos —
    /// reventando el `debug_assert_eq!` de `Pager::write` en cuanto se
    /// compila en modo debug — o el límite de tamaño de clave
    /// (`logical_page_size / 4`) aceptaría una clave que de verdad no cabe
    /// en la página que se termina construyendo.
    ///
    /// Las dos cifras subieron con el cambio a nonces aleatorios (el
    /// prefijo de cifrado pasó de 24 a 40 bytes): la página física de una
    /// lógica de 512 B mide ahora 552, y el límite de clave con páginas de
    /// 512 B es `472 / 4 = 118`, no `488 / 4 = 122`.
    #[test]
    fn a_large_encrypted_workload_round_trips_through_splits_and_overflow() {
        for &algorithm in ALGORITHMS {
            let db =
                Db::create(Box::new(MemStorage::new()), opts_with([7; 32], algorithm)).unwrap();

            let mut tx = db.begin_write().unwrap();
            for i in 0..300u32 {
                let value = alloc::vec![(i % 251) as u8; 20];
                tx.put(0x01, &i.to_be_bytes(), &value).unwrap();
            }
            // Por encima de `overflow_threshold(logical_page_size)` — con
            // cifrado y página de 512 B, 472 / 4 = 118 — para forzar una
            // cadena de overflow real construida a tamaño lógico.
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
                let expected =
                    if i % 3 == 0 { None } else { Some(alloc::vec![(i % 251) as u8; 20]) };
                assert_eq!(r.get(0x01, &i.to_be_bytes()).unwrap(), expected, "{algorithm:?} clave {i}");
            }
            assert_eq!(r.get(0x01, b"grande").unwrap(), Some(big));

            let mut cursor = r.scan(0x01, &0u32.to_be_bytes(), &300u32.to_be_bytes()).unwrap();
            let mut count = 0u32;
            while cursor.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(
                count, 200,
                "{algorithm:?}: 200 de las 300 claves deberian sobrevivir al borrado de una de cada tres"
            );
        }
    }

    /// El reparto EXACTO de bytes del nonce, por algoritmo. Sustituye a
    /// `nonce_is_exactly_page_then_counter_little_endian`, que fijaba la
    /// representación del nonce derivado anterior.
    ///
    /// **Por qué comprobar la representación y no solo "cambia algo".** El
    /// mismo argumento que aquella prueba: cifrar y descifrar usan la MISMA
    /// derivación en los dos sentidos, así que un reparto roto pero
    /// determinista deja el roundtrip funcional en verde. Aquí, además, hay
    /// un modo de fallo nuevo y peor: un reparto que le diera al contador
    /// bytes que pisaran el prefijo, o que dejara el prefijo fuera del
    /// nonce, produciría nonces que se repiten entre aperturas sin que
    /// ninguna prueba de una sola apertura lo note.
    #[test]
    fn the_nonce_is_exactly_prefix_then_counter() {
        let prefix: [u8; NONCE_PREFIX_LEN] = core::array::from_fn(|i| 0xa0 | i as u8);

        // XChaCha20-Poly1305: 16 de prefijo, 8 de contador, los 24 usados.
        let mut s = NonceStream::from_prefix(prefix);
        assert_eq!(s.issued(), 0);
        let n0 = s.next(Algorithm::XChaCha20Poly1305).unwrap();
        assert_eq!(&n0[..NONCE_PREFIX_LEN], &prefix[..]);
        assert_eq!(&n0[NONCE_PREFIX_LEN..], &0u64.to_le_bytes()[..]);
        assert_eq!(s.issued(), 1);
        let n1 = s.next(Algorithm::XChaCha20Poly1305).unwrap();
        assert_eq!(&n1[..NONCE_PREFIX_LEN], &prefix[..], "el prefijo no cambia dentro de la apertura");
        assert_eq!(&n1[NONCE_PREFIX_LEN..], &1u64.to_le_bytes()[..]);

        // AES-256-GCM-SIV: 8 de prefijo, 4 de contador, y los 12 restantes
        // del campo almacenado a cero — no basura, porque entran en los
        // datos asociados y tienen que ser reproducibles.
        let mut s = NonceStream::from_prefix(prefix);
        let n0 = s.next(Algorithm::Aes256GcmSiv).unwrap();
        assert_eq!(&n0[..AES_PREFIX_LEN], &prefix[..AES_PREFIX_LEN]);
        assert_eq!(&n0[AES_PREFIX_LEN..AES_NONCE_LEN], &0u32.to_le_bytes()[..]);
        assert_eq!(&n0[AES_NONCE_LEN..], &[0u8; STORED_NONCE_LEN - AES_NONCE_LEN][..]);
        let n1 = s.next(Algorithm::Aes256GcmSiv).unwrap();
        assert_eq!(&n1[AES_PREFIX_LEN..AES_NONCE_LEN], &1u32.to_le_bytes()[..]);
    }

    /// Inyectividad del flujo dentro de una apertura: un barrido denso más
    /// uno disperso en las fronteras de representación de cada campo.
    ///
    /// El barrido disperso es el que de verdad importa aquí: colocar el
    /// contador en `issued` sin más y truncarlo al ancho del campo es
    /// correcto solo mientras el prefijo se renueve al desbordar, y esta
    /// prueba llega hasta esa frontera (2^32 para AES) por el camino
    /// barato — fijando `issued` a mano — en vez de con cuatro mil
    /// millones de escrituras reales.
    #[test]
    fn the_nonce_stream_is_injective_within_an_open() {
        for &algorithm in &[Algorithm::XChaCha20Poly1305, Algorithm::Aes256GcmSiv] {
            let mut s = NonceStream::from_prefix([0x5a; NONCE_PREFIX_LEN]);
            let mut seen = alloc::collections::BTreeSet::new();
            for i in 0..4000u32 {
                assert!(
                    seen.insert(s.next(algorithm).unwrap()),
                    "{algorithm:?}: nonce repetido en el barrido denso, escritura {i}"
                );
            }
        }
    }

    /// **El agotamiento del campo de contador de AES renueva el prefijo en
    /// vez de repetir un nonce.** Es la mitad (b) del razonamiento de
    /// `NonceStream::next`: con 4 bytes de contador, la escritura 2^32 de
    /// una misma apertura volvería a empezar en cero.
    ///
    /// Llegar ahí de verdad son 4 294 967 296 sellados; esta prueba salta
    /// hasta el borde con `at_issued_for_test`, que es exactamente el mismo
    /// estado en el que quedaría el flujo tras esas escrituras.
    #[test]
    fn exhausting_the_aes_counter_field_renews_the_prefix_instead_of_repeating() {
        let prefix = [0x11u8; NONCE_PREFIX_LEN];
        let mut s = NonceStream::at_issued_for_test(prefix, (1u64 << 32) - 1);
        let last = s.next(Algorithm::Aes256GcmSiv).unwrap();
        assert_eq!(&last[..AES_PREFIX_LEN], &prefix[..AES_PREFIX_LEN]);
        assert_eq!(&last[AES_PREFIX_LEN..AES_NONCE_LEN], &u32::MAX.to_le_bytes()[..]);

        // La siguiente vuelve a contador 0 — que es justo lo que repetiría
        // el nonce si el prefijo no cambiara.
        let wrapped = s.next(Algorithm::Aes256GcmSiv).unwrap();
        assert_eq!(&wrapped[AES_PREFIX_LEN..AES_NONCE_LEN], &0u32.to_le_bytes()[..]);
        assert_ne!(
            &wrapped[..AES_PREFIX_LEN],
            &prefix[..AES_PREFIX_LEN],
            "al desbordar el contador de 32 bits el prefijo TIENE que renovarse: sin eso, \
             este nonce es identico al primero de la apertura"
        );

        // Y `issued` no rebobina con la renovación: es lo que hace que la
        // comprobación defensiva de `WriteTxn::write_page` siga siendo
        // válida a un lado y otro del desbordamiento.
        assert_eq!(s.issued(), 1u64 << 32 | 1);
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        for &algorithm in ALGORITHMS {
            let s = Arc::new(MemStorage::new());
            let db = Db::create(
                Box::new(ArcStorage(Arc::clone(&s))),
                opts_with([2; 32], algorithm),
            )
            .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"aguja", b"pajar-secreto-inconfundible").unwrap();
            tx.commit().unwrap();
            let bytes = s.snapshot();
            assert!(
                !bytes.windows(27).any(|w| w == b"pajar-secreto-inconfundible"),
                "{algorithm:?}: el valor aparece en claro en el fichero"
            );
        }
    }

    #[test]
    fn a_wrong_key_fails_to_decrypt_instead_of_returning_garbage() {
        for &algorithm in ALGORITHMS {
            let s = Arc::new(MemStorage::new());
            {
                let db = Db::create(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([3; 32], algorithm),
                )
                .unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"k", b"v").unwrap();
                tx.commit().unwrap();
            }
            let db =
                Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts_with([4; 32], algorithm));
            assert!(matches!(db, Err(Error::Decrypt { .. })), "{algorithm:?}");
        }
    }

    #[test]
    fn a_tampered_page_is_rejected() {
        for &algorithm in ALGORITHMS {
            let s = Arc::new(MemStorage::new());
            let db = Db::create(
                Box::new(ArcStorage(Arc::clone(&s))),
                opts_with([5; 32], algorithm),
            )
            .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"k", b"v").unwrap();
            tx.commit().unwrap();
            let root = db.begin_read().root();
            drop(db);
            // Voltea un byte del texto cifrado de la página raíz.
            let mut bytes = s.snapshot();
            bytes[root as usize * 512 + CIPHER_PREFIX + 20] ^= 0xff;
            s.restore(bytes);
            let db =
                Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts_with([5; 32], algorithm))
                    .unwrap();
            assert!(
                matches!(db.begin_read().get(0x01, b"k"), Err(Error::Decrypt { .. })),
                "{algorithm:?}"
            );
        }
    }

    /// **Mover una página sellada a otro número de página se detecta.**
    ///
    /// Con el nonce derivado de `página || contador`, esto salía gratis: el
    /// número de página entraba en el nonce, así que descifrar en otro
    /// offset usaba otro nonce y fallaba. Al pasar a un nonce ALMACENADO
    /// esa protección habría desaparecido sin más — los bytes traen su
    /// propio nonce, así que se descifrarían igual de bien en cualquier
    /// sitio — si no se metiera el número de página en los datos asociados
    /// a propósito (`crypto::associated_data`). Esta prueba es lo que
    /// impide que esa decisión se revierta sin que nadie lo note.
    #[test]
    fn a_sealed_page_moved_to_another_page_number_is_rejected() {
        for &algorithm in ALGORITHMS {
            let s = Arc::new(MemStorage::new());
            let db = Db::create(
                Box::new(ArcStorage(Arc::clone(&s))),
                opts_with([13; 32], algorithm),
            )
            .unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..60u32 {
                tx.put(0x01, &i.to_be_bytes(), &[7u8; 60]).unwrap();
            }
            tx.commit().unwrap();
            let root = db.begin_read().root();
            drop(db);

            // Copia la raíz encima de OTRA página de datos, con todos sus
            // bytes intactos: nonce, tag y texto cifrado. Lo único que
            // cambia es dónde vive.
            let mut bytes = s.snapshot();
            let victim = (root as usize) + 1;
            let ps = TEST_PAGE_SIZE as usize;
            let (src, dst) = (root as usize * ps, victim * ps);
            let copy: Vec<u8> = bytes[src..src + ps].to_vec();
            bytes[dst..dst + ps].copy_from_slice(&copy);
            s.restore(bytes);

            let db = Db::open(
                Box::new(ArcStorage(Arc::clone(&s))),
                opts_with([13; 32], algorithm),
            )
            .unwrap();
            // Leer esa página tiene que fallar la autenticación, no
            // devolver el contenido de la raíz bajo otro número.
            let seen = db.begin_read().read_page(victim as PageNo);
            assert!(
                matches!(seen, Err(Error::Decrypt { .. })),
                "{algorithm:?}: una pagina sellada movida a otro numero se descifro limpia: {seen:?}"
            );
        }
    }

    /// **Ningún byte físico de una página cifrada queda fuera del tag.**
    ///
    /// El campo de nonce mide 24 B para los dos algoritmos, pero
    /// AES-256-GCM-SIV solo usa 12: los otros 12 son relleno. Si el relleno
    /// no entrara en los datos asociados, sería una región de cada página
    /// del fichero que cualquiera puede cambiar sin que la autenticación se
    /// entere — no explotable de forma obvia, pero sí exactamente el tipo
    /// de hueco que nadie quiere descubrir después. Esta prueba toca
    /// también un byte del nonce PROPIAMENTE dicho, que fallaría de todas
    /// formas, para que el caso interesante no dependa de leer bien el
    /// mensaje de fallo.
    #[test]
    fn tampering_with_any_byte_of_the_stored_nonce_is_rejected() {
        for &algorithm in ALGORITHMS {
            for at in [0usize, AES_NONCE_LEN, STORED_NONCE_LEN - 1] {
                let s = Arc::new(MemStorage::new());
                let db = Db::create(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([14; 32], algorithm),
                )
                .unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"k", b"v").unwrap();
                tx.commit().unwrap();
                let root = db.begin_read().root();
                drop(db);

                let mut bytes = s.snapshot();
                bytes[root as usize * TEST_PAGE_SIZE as usize + at] ^= 0xff;
                s.restore(bytes);

                let db = Db::open(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([14; 32], algorithm),
                )
                .unwrap();
                assert!(
                    matches!(db.begin_read().get(0x01, b"k"), Err(Error::Decrypt { .. })),
                    "{algorithm:?}: cambiar el byte {at} del campo de nonce no se detecto"
                );
            }
        }
    }

    /// La carga de trabajo que ejerce ESTA prueba, compartida por las dos
    /// que la usan (la de unicidad de nonces y la de la copia de
    /// seguridad). Toca, a propósito, todo lo que puede reciclar páginas o
    /// reescribir la misma varias veces:
    ///
    /// - una transacción grande (el patrón de lote de este motor, donde
    ///   `own_free` recicla páginas DENTRO de la transacción y una misma
    ///   página puede reescribirse decenas de veces);
    /// - cadenas de overflow, creadas y liberadas;
    /// - borrados intercalados y reinserción sobre las mismas claves;
    /// - una transacción abortada (que no debe devolver contadores al
    ///   circuito);
    /// - `delete_range`, que libera subárboles enteros;
    /// - muchas transacciones pequeñas.
    fn demanding_workload(db: &Db, salt: u32) {
        // 1. Transacción grande, con overflow y borrados dentro.
        let mut tx = db.begin_write().unwrap();
        for i in 0..500u32 {
            tx.put(0x01, &(i + salt).to_be_bytes(), &[(i % 251) as u8; 24]).unwrap();
        }
        for i in (0..500u32).step_by(7) {
            tx.put(0x02, &(i + salt).to_be_bytes(), &alloc::vec![0xcd; 400]).unwrap();
        }
        for i in (0..500u32).step_by(3) {
            tx.delete(0x01, &(i + salt).to_be_bytes()).unwrap();
        }
        // Reinserción sobre claves recién borradas: reconstruye hojas que
        // esta misma transacción ya había reescrito.
        for i in (0..500u32).step_by(3) {
            tx.put(0x01, &(i + salt).to_be_bytes(), b"reinsertado").unwrap();
        }
        tx.commit().unwrap();

        // 2. Transacción abortada.
        {
            let mut tx = db.begin_write().unwrap();
            for i in 0..40u32 {
                tx.put(0x03, &(i + salt).to_be_bytes(), b"abortado").unwrap();
            }
            // Se descarta sin commit.
        }

        // 3. `delete_range` sobre un tramo, y sobre el espacio de overflow.
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, &salt.to_be_bytes(), &(salt + 200).to_be_bytes()).unwrap();
        tx.delete_range(0x02, &salt.to_be_bytes(), &(salt + 250).to_be_bytes()).unwrap();
        tx.commit().unwrap();

        // 4. Muchas transacciones pequeñas.
        for i in 0..60u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x04, &(i + salt).to_be_bytes(), b"pequenya").unwrap();
            tx.commit().unwrap();
        }
    }

    /// **La prueba central del cambio.** Cuenta los nonces que
    /// `crypto::seal` produjo de verdad — no los que se puedan deducir de
    /// las escrituras físicas, ver `probe` — sobre una carga exigente que
    /// atraviesa varias sesiones con reaperturas de por medio, y para los
    /// DOS algoritmos.
    ///
    /// La corrida de referencia anterior a este cambio fueron 3 686
    /// sellados con cero duplicados, todos con ChaCha20-Poly1305. Esta
    /// exige al menos esa cifra POR ALGORITMO, así que AES-256-GCM-SIV deja
    /// de tener menos cobertura que ChaCha: es el mismo listón, no uno
    /// rebajado.
    #[test]
    fn no_nonce_is_ever_reused() {
        /// Suelo heredado de la corrida de referencia previa al cambio.
        /// Comprobarlo evita el peor modo de fallo de una prueba de
        /// unicidad: que la carga deje de sellar lo que creía sellar y
        /// "cero duplicados" pase a no significar nada.
        const REFERENCE_SEALS: usize = 3_686;

        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let s = Arc::new(MemStorage::new());

            // Sesión 1: creación.
            {
                let db = Db::create(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([6; 32], algorithm),
                )
                .unwrap();
                demanding_workload(&db, 0);
            }
            // Sesión 2 y 3: reaperturas, cada una con su propio prefijo.
            for salt in [1000u32, 2000] {
                let db = Db::open(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([6; 32], algorithm),
                )
                .unwrap();
                demanding_workload(&db, salt);
            }

            let sealed = capture.take();
            let a = assert_no_reuse(&sealed, &alloc::format!("{algorithm:?}"));
            std::eprintln!("{algorithm:?}: {} sellados, {} nonces repetidos", a.sealed, a.reused_nonces);
            assert!(
                a.sealed >= REFERENCE_SEALS,
                "{algorithm:?}: solo {} sellados, por debajo de la corrida de referencia \
                 ({REFERENCE_SEALS}): la carga dejo de ejercitar lo que creia ejercitar",
                a.sealed
            );
        }
    }

    /// Complementa la prueba de arriba con el otro eje: muchas
    /// transacciones PEQUEÑAS en vez de una grande, atravesando muchas
    /// aperturas de transacción (`begin_write`/`commit`) en vez de una
    /// sola — comprueba que el flujo de nonces (`WriterState::nonce_stream`,
    /// que sobrevive tal cual entre transacciones) se lleva bien de una a
    /// otra.
    #[test]
    fn no_nonce_is_ever_reused_across_many_small_transactions() {
        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let db =
                Db::create(Box::new(MemStorage::new()), opts_with([9; 32], algorithm)).unwrap();
            for i in 0..200u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
                tx.commit().unwrap();
            }
            assert_no_reuse(&capture.take(), &alloc::format!("{algorithm:?}"));
        }
    }

    /// Sonda 1 de la segunda ronda de revisión posterior a la primera
    /// entrega (hallazgo BLOCKER 2): abortar una transacción y luego
    /// confirmar otra distinta no debe reutilizar ningún nonce. Con el
    /// diseño roto de aquella ronda, el contador se releía de la meta
    /// CONFIRMADA en cada `begin_write` — y como abortar no toca la meta
    /// confirmada, la segunda transacción arrancaba exactamente donde
    /// había arrancado la primera, repartiendo de nuevo los mismos
    /// contadores que la abortada ya había usado para sellar páginas
    /// reales.
    ///
    /// Sigue valiendo con nonces aleatorios, y por la misma razón de fondo:
    /// el flujo vive en `WriterState`, que `WriteTxn::Drop` no toca. El
    /// caso concreto que lo demuestra: 5 `put` que se abortan, seguidos de
    /// 5 `put` DISTINTOS que sí confirman — `alloc()`, en las mismas
    /// condiciones de partida, tiende a repartir la MISMA secuencia de
    /// páginas, así que un flujo que rebobinara al abortar colisionaría
    /// aquí.
    #[test]
    fn a_rollback_then_a_commit_reuses_no_nonce() {
        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let db =
                Db::create(Box::new(MemStorage::new()), opts_with([31; 32], algorithm)).unwrap();
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
            assert_no_reuse(&capture.take(), &alloc::format!("{algorithm:?} tras abortar"));
        }
    }

    /// **Defecto 1 muerto: restaurar una copia de seguridad.**
    ///
    /// El procedimiento es el más corriente que existe en operaciones:
    /// copiar el fichero, seguir escribiendo en el original, y más tarde
    /// abrir la copia y seguir escribiendo también en ella. Son dos líneas
    /// temporales que arrancan del mismo estado y comparten la MISMA clave
    /// de datos, porque la clave envuelta viaja en la copia.
    ///
    /// **Lo que producía el código anterior a este cambio.** El contador de
    /// nonce y su techo se persistían en la meta, junto a la clave
    /// envuelta, así que los dos retrocedían juntos: la copia restaurada
    /// arrancaba su contador exactamente donde lo había dejado el original
    /// en el instante de la copia, y volvía a repartir los mismos valores
    /// bajo la misma clave. Medido por la revisión que motivó este cambio:
    /// **296 de 296 nonces compartidos entre las dos líneas, 164 de ellos
    /// con texto plano distinto, y hasta un 96,52 % de bytes cero en el XOR
    /// de los textos cifrados que compartían nonce** — recuperación del
    /// texto plano, no un riesgo teórico.
    ///
    /// Ahora la copia sortea su propio prefijo de 16 bytes al abrirse, así
    /// que las dos líneas viven en espacios de nonces separados por 128
    /// bits aleatorios. Esta prueba comprueba justo eso: intersección
    /// vacía entre los dos conjuntos de nonces.
    #[test]
    fn a_restored_backup_shares_no_nonce_with_the_timeline_it_was_copied_from() {
        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let original = Arc::new(MemStorage::new());

            // Estado común, y la copia.
            let db = Db::create(
                Box::new(ArcStorage(Arc::clone(&original))),
                opts_with([77; 32], algorithm),
            )
            .unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..120u32 {
                tx.put(0x01, &i.to_be_bytes(), &[3u8; 32]).unwrap();
            }
            tx.commit().unwrap();
            let backup_bytes = original.snapshot();
            // Lo sellado hasta aquí es común a las dos líneas: se descarta
            // para que la comparación sea entre lo que cada una escribió
            // DESPUÉS de separarse, que es donde estaba el defecto.
            let _common = capture.take();

            // Línea A: el original sigue escribiendo.
            for i in 0..80u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"linea-a").unwrap();
                tx.commit().unwrap();
            }
            drop(db);
            let timeline_a = nonce_set(&capture.take());

            // Línea B: la copia se abre y escribe lo MISMO, que es el peor
            // caso — con nonces compartidos, textos planos iguales bajo el
            // mismo nonce dan el XOR más revelador posible.
            let restored = Arc::new(MemStorage::new());
            restored.restore(backup_bytes);
            let db = Db::open(
                Box::new(ArcStorage(Arc::clone(&restored))),
                opts_with([77; 32], algorithm),
            )
            .unwrap();
            for i in 0..80u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), b"linea-a").unwrap();
                tx.commit().unwrap();
            }
            drop(db);
            let timeline_b = nonce_set(&capture.take());

            assert!(!timeline_a.is_empty() && !timeline_b.is_empty(), "{algorithm:?}: sin sellados que comparar");
            let shared: Vec<_> = timeline_a.intersection(&timeline_b).collect();
            assert!(
                shared.is_empty(),
                "{algorithm:?}: la copia restaurada comparte {} de {} nonces con el original \
                 — es el defecto que este cambio cierra",
                shared.len(),
                timeline_b.len()
            );
        }
    }

    /// **Defecto 2 muerto: dos asas sobre el mismo fichero.**
    ///
    /// `Error::AlreadyOpen` (`storage.rs`) ya impide construir la segunda
    /// asa dentro del mismo proceso, así que el caso no se puede montar tal
    /// cual. Lo que esta prueba demuestra es la propiedad de fondo, la que
    /// hace que ese rechazo deje de ser lo ÚNICO que separa las dos asas
    /// de compartir nonces: dos aperturas del mismo fichero, una tras otra,
    /// sortean prefijos distintos, así que no podrían colisionar ni aunque
    /// el guardián no existiera — que es exactamente la situación de dos
    /// PROCESOS, donde no hay guardián posible (sección 3.4 de la
    /// especificación).
    ///
    /// Antes de este cambio la propiedad era la contraria: las dos
    /// aperturas arrancaban su contador desde el mismo `write_counter` de
    /// la meta y repartían los mismos nonces.
    #[test]
    fn two_opens_of_the_same_file_draw_different_prefixes() {
        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let s = Arc::new(MemStorage::new());
            {
                let db = Db::create(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([88; 32], algorithm),
                )
                .unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"k", b"v").unwrap();
                tx.commit().unwrap();
            }
            let first = nonce_set(&capture.take());

            // Dos reaperturas más, cada una escribiendo exactamente lo
            // mismo: mismo estado de partida, misma secuencia de páginas,
            // mismo contador dentro de cada apertura. Lo único que las
            // separa es el prefijo.
            let mut sets = alloc::vec![first];
            for _ in 0..2 {
                let db = Db::open(
                    Box::new(ArcStorage(Arc::clone(&s))),
                    opts_with([88; 32], algorithm),
                )
                .unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"k", b"v").unwrap();
                tx.commit().unwrap();
                drop(db);
                sets.push(nonce_set(&capture.take()));
            }

            for (i, a) in sets.iter().enumerate() {
                assert!(!a.is_empty(), "{algorithm:?}: la apertura {i} no sello nada");
                for (j, b) in sets.iter().enumerate().skip(i + 1) {
                    assert!(
                        a.intersection(b).next().is_none(),
                        "{algorithm:?}: las aperturas {i} y {j} comparten un nonce"
                    );
                }
            }
        }
    }

    /// El contador arranca en cero en CADA apertura — es lo que hace
    /// innecesario persistirlo, y por tanto lo que justifica haber borrado
    /// `Meta::write_counter` y su protocolo de extensión.
    ///
    /// Comprobarlo explícitamente importa: si alguna apertura futura
    /// volviera a arrastrar el contador de la sesión anterior, esta prueba
    /// no fallaría por sí sola (arrastrarlo también es seguro), pero su
    /// PAREJA —`two_opens_of_the_same_file_draw_different_prefixes`— y esta
    /// juntas fijan las dos mitades del contrato: prefijo nuevo, contador
    /// desde cero.
    #[test]
    fn the_nonce_counter_restarts_at_zero_on_every_open() {
        let capture = probe::Capture::start();
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts([99; 32])).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..30u32 {
                tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            }
            tx.commit().unwrap();
        }
        let first = capture.take();
        {
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts([99; 32])).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"otra", b"v").unwrap();
            tx.commit().unwrap();
        }
        let second = capture.take();

        // Los 8 últimos bytes del nonce de XChaCha20 son el contador.
        let counter_of = |s: &probe::Sealed| u64::from_le_bytes(s.nonce[NONCE_PREFIX_LEN..].try_into().unwrap());
        assert_eq!(counter_of(&first[0]), 0, "la primera apertura arranca en cero");
        assert_eq!(
            counter_of(&second[0]),
            0,
            "la SEGUNDA apertura tambien arranca en cero: no queda ningun contador persistido"
        );
        assert!(
            first.len() > 1 && counter_of(&first[1]) == 1,
            "y avanza de uno en uno dentro de la apertura"
        );
    }

    /// Una transacción abortada no debe corromper NADA de lo confirmado al
    /// reabrir — ni perder datos, ni cambiar el `root`.
    ///
    /// **Antes de este cambio esta prueba necesitaba montar un andamio.**
    /// Era la sonda 2 de la segunda ronda de revisión de la tarea 17, y el
    /// caso que perseguía era "una transacción que agota el techo de
    /// contador reservado y se aborta a media escritura": para llegar ahí
    /// sin hacer un millón de escrituras reales (`COUNTER_RESERVE`) había
    /// que manipular a mano el `write_counter` persistido en las dos
    /// ranuras de meta, recalculando sus CRC. Sin techo que agotar, ni
    /// contador que persistir, ni extensión que pueda publicar una
    /// transacción a medias, el andamio entero sobra y lo que queda es la
    /// propiedad de fondo, que sigue importando: abortar no cambia nada de
    /// lo confirmado.
    #[test]
    fn an_aborted_transaction_leaves_the_committed_state_untouched() {
        for &algorithm in ALGORITHMS {
            let s = Arc::new(MemStorage::new());
            let mk = || opts_with([41; 32], algorithm);
            let committed_root;
            {
                let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), mk()).unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"antes", b"confirmado").unwrap();
                tx.commit().unwrap();
                committed_root = db.begin_read().root();
            }

            {
                let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), mk()).unwrap();
                let mut tx = db.begin_write().unwrap();
                for i in 0..20u32 {
                    tx.put(0x02, &i.to_be_bytes(), b"a medias").unwrap();
                }
                // Se descarta sin commit.
            }

            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), mk()).unwrap();
            let r = db.begin_read();
            assert_eq!(
                r.root(),
                committed_root,
                "{algorithm:?}: el root confirmado no debe cambiar tras abortar"
            );
            assert_eq!(r.get(0x01, b"antes").unwrap().as_deref(), Some(b"confirmado".as_slice()));
            assert_eq!(
                r.get(0x02, &0u32.to_be_bytes()).unwrap(),
                None,
                "{algorithm:?}: nada de la transaccion abortada debe verse"
            );
        }
    }


    /// Envuelve `MemStorage` y simula un corte de corriente: las DOS
    /// ranuras de meta solo sobreviven hasta el último `sync()` real; todo
    /// lo demás (páginas de árbol, de lista de libres, la cabecera) se
    /// trata como si llegara al medio sin condición — que es exactamente
    /// lo que hace este motor: `Pager::write`/`write_encrypted` nunca
    /// miran la política de `Sync`, y desde la eliminación del techo de
    /// contador de nonce solo `Db::maybe_sync` decide si un `fsync` de
    /// verdad ocurre — antes había además una sincronización incondicional
    /// por sesión, la de `Db::extend_counter_ceiling`, que este arnés tenía
    /// que tener en cuenta.
    ///
    /// **Ya no registra escrituras físicas.** Lo hacía para que las
    /// pruebas pudieran deducir de ellas los nonces usados; eso lo da
    /// ahora `probe`, capturando en el propio `seal` (ver su comentario).
    /// Lo que queda aquí es solo el modelo de corte de corriente.
    ///
    /// Asume `Options::default()` (`page_size` 512, `meta_a_page` 1,
    /// `meta_b_page` 2, salvo que la prueba cruce los 4 KB y dispare
    /// `relocate_meta_b`, que la traslada a la 8) — las mismas que usa
    /// `opts()` — para saber dónde viven las tres posiciones posibles sin
    /// tener que leer la cabecera primero.
    ///
    /// **Ronda de revisión posterior a la tarea 18: el arnés original no
    /// llegaba a ejercitar NADA de lo que esa tarea introdujo.**
    /// `META_OFFSETS` solo cubría `[512, 1024]` (meta A y la posición
    /// INICIAL de la meta B) — la posición FINAL, `4096`, nunca se
    /// reconocía como escritura de meta, así que un desgarro ahí caía en el
    /// camino genérico (se registra igual, pero sin la protección de
    /// `simulate_power_loss`/el autochequeo de que de verdad desgarra algo).
    /// Y no había NINGÚN mecanismo para desgarrar la cabecera: `TORN_PREFIX`
    /// (104) es mayor que `HEADER_SIZE` (64), así que ni por accidente podía
    /// aplicarse ahí, y `arm_meta_tear` solo reconocía escrituras de 512 B
    /// exactos —el tamaño de una ranura de meta, nunca el de una cabecera
    /// (64 B). Con "216 pruebas pasan" como única evidencia, ninguna de las
    /// dos correcciones de esta ronda (recuperación de páginas huérfanas,
    /// espejo de cabecera) tenía ninguna prueba capaz de contradecirla.
    ///
    /// Ahora `META_OFFSETS` tiene TRES posiciones (la tercera es la final,
    /// misma fórmula que `WriteTxn::final_meta_b_page`) y existe un
    /// mecanismo paralelo, `arm_header_tear`/`HEADER_OFFSETS`, para
    /// desgarrar la cabecera principal (offset `0`) o su espejo (offset
    /// `HEADER_MIRROR_OFFSET`) — ver `Geometry::write_mirror` en
    /// `header.rs`. Los dos mecanismos comparten el mismo `dead`: un corte
    /// es un corte, no importa cuál de las dos escrituras lo dispara.
    struct PowerLossStorage {
        inner: MemStorage,
        last_synced_meta: Mutex<[[u8; 512]; 3]>,
        last_synced_header: Mutex<[[u8; crate::header::HEADER_SIZE]; 2]>,
        /// Desgarro de meta armado: ver `arm_meta_tear`.
        meta_tear: Mutex<Option<Tear>>,
        /// Desgarro de cabecera armado: ver `arm_header_tear`.
        header_tear: Mutex<Option<Tear>>,
        /// Imagen del plato en el instante del corte, o `None` si la
        /// máquina sigue viva. Ver `arm_meta_tear`/`arm_header_tear`.
        dead: Mutex<Option<Vec<u8>>>,
    }

    /// Escritura (de meta o de cabecera) que se corta a medias. `skip` es
    /// cuántas escrituras del tipo correspondiente faltan todavía antes de
    /// la que se desgarra.
    struct Tear {
        skip: usize,
        prefix: usize,
    }

    /// Meta A (página 1), meta B en su posición inicial (página 2) y meta B
    /// en su posición final (página 8 con `page_size` de 512 B — misma
    /// fórmula que `WriteTxn::final_meta_b_page`). Solo la tercera es nueva
    /// respecto al arnés previo a esta ronda.
    const META_OFFSETS: [u64; 3] = [512, 1024, 4096];

    /// Cabecera principal (offset `0`) y su espejo (offset
    /// `HEADER_MIRROR_OFFSET` = `HEADER_SIZE` = 64) — ver
    /// `Geometry::write_mirror`.
    const HEADER_OFFSETS: [u64; 2] = [0, crate::header::HEADER_MIRROR_OFFSET];

    /// Cuántos bytes de una escritura de meta desgarrada llegan al plato.
    /// 104 no es arbitrario: cae por debajo del CRC (108..112) y por encima
    /// de todos los campos que un commit cambia (`txn_id` los primeros
    /// ocho, y de ahí a `n_pages`), así que la ranura queda siempre con un
    /// contenido mezclado y un CRC viejo — ilegible, pase lo que pase.
    ///
    /// Se eligió originalmente por caer DENTRO de `write_counter` (bytes
    /// 100..108), que era lo único que cambiaba una escritura de extensión
    /// de techo: con ese campo y su protocolo eliminados, ya no hay
    /// escrituras de meta que no vengan de un commit, y cualquier prefijo
    /// que cubra el `txn_id` desgarra de verdad. `write_at` lo comprueba en
    /// cada desgarro
    /// en vez de confiar en que quien escribe la prueba lo tenga presente.
    const TORN_PREFIX: usize = 104;

    impl PowerLossStorage {
        fn new() -> Self {
            Self {
                inner: MemStorage::new(),
                last_synced_meta: Mutex::new([[0u8; 512]; 3]),
                last_synced_header: Mutex::new([[0u8; crate::header::HEADER_SIZE]; 2]),
                meta_tear: Mutex::new(None),
                header_tear: Mutex::new(None),
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
            *self.meta_tear.lock().unwrap() = Some(Tear { skip, prefix });
        }

        /// Igual que `arm_meta_tear`, pero para la `skip`-ésima escritura de
        /// CABECERA (principal o espejo, `HEADER_OFFSETS`) a partir de
        /// ahora — ronda de revisión posterior a la tarea 18: sin esto, el
        /// arnés no podía desgarrar `WriteTxn::relocate_meta_b`'s reescritura
        /// de cabecera en absoluto, porque `arm_meta_tear` solo reconoce
        /// escrituras de 512 B (una ranura de meta), nunca las 64 B de una
        /// cabecera.
        fn arm_header_tear(&self, skip: usize, prefix: usize) {
            *self.header_tear.lock().unwrap() = Some(Tear { skip, prefix });
        }

        /// Reinicio tras el corte. Restaura el plato a la foto del instante
        /// del corte (si lo hubo) y descarta cualquier escritura de meta o
        /// de cabecera posterior al último `sync()` real — simula perder
        /// los búferes del sistema operativo no vaciados a disco. Las
        /// páginas de datos/lista de libres NO se revierten: se tratan como
        /// si hubieran llegado al medio sin condición, que es el supuesto
        /// PESIMISTA correcto para esta pregunta (cuanto más texto cifrado
        /// sobreviva, más material tiene un atacante para explotar un nonce
        /// repetido).
        fn simulate_power_loss(&self) {
            if let Some(platter) = self.dead.lock().unwrap().take() {
                self.inner.restore(platter);
            }
            let saved_meta = *self.last_synced_meta.lock().unwrap();
            for (i, &offset) in META_OFFSETS.iter().enumerate() {
                self.inner.write_at(offset, &saved_meta[i]).unwrap();
            }
            let saved_header = *self.last_synced_header.lock().unwrap();
            for (i, &offset) in HEADER_OFFSETS.iter().enumerate() {
                self.inner.write_at(offset, &saved_header[i]).unwrap();
            }
        }

        /// Toma el desgarro de meta armado si esta escritura (offset, 512 B
        /// exactos) es una de las tres posiciones posibles Y le toca a
        /// esta escritura en concreto (el contador `skip` ya llegó a cero).
        fn take_meta_tear(&self, o: u64, len: usize) -> Option<(usize, usize)> {
            let i = META_OFFSETS.iter().position(|&m| m == o && len == TEST_PAGE_SIZE as usize)?;
            let mut tear = self.meta_tear.lock().unwrap();
            match tear.as_mut() {
                Some(t) if t.skip == 0 => {
                    let prefix = t.prefix;
                    *tear = None;
                    Some((i, prefix))
                }
                Some(t) => {
                    t.skip -= 1;
                    None
                }
                None => None,
            }
        }

        /// Igual que `take_meta_tear`, para las dos posiciones de cabecera
        /// (64 B exactos).
        fn take_header_tear(&self, o: u64, len: usize) -> Option<(usize, usize)> {
            let i = HEADER_OFFSETS
                .iter()
                .position(|&m| m == o && len == crate::header::HEADER_SIZE)?;
            let mut tear = self.header_tear.lock().unwrap();
            match tear.as_mut() {
                Some(t) if t.skip == 0 => {
                    let prefix = t.prefix;
                    *tear = None;
                    Some((i, prefix))
                }
                Some(t) => {
                    t.skip -= 1;
                    None
                }
                None => None,
            }
        }
    }

    impl Storage for PowerLossStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.inner.read_at(o, b)
        }

        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            if self.dead.lock().unwrap().is_some() {
                // La máquina ya murió: esto no llega al plato (la foto de
                // `arm_meta_tear`/`arm_header_tear` se restaura en el
                // reinicio) ni lo ve nadie, así que tampoco se registra.
                // Sigue escribiéndose en `inner` solo para que las lecturas
                // posteriores del proceso ya muerto no fallen con un error
                // de E/S que en la vida real nadie llegaría a ver.
                return self.inner.write_at(o, b);
            }

            if let Some((i, prefix)) = self.take_meta_tear(o, b.len()) {
                self.inner.write_at(o, &b[..prefix])?;
                // Lo que sí llegó al plato es DURADERO: sobrevive al
                // `simulate_power_loss` posterior, a diferencia de una
                // escritura de meta completa sin sincronizar.
                let mut landed = [0u8; 512];
                self.inner.read_at(o, &mut landed)?;
                // El arnés comprueba SU PROPIA premisa: si el prefijo
                // elegido deja la ranura todavía legible, esta prueba no
                // está modelando ningún desgarro y pasaría por la razón
                // equivocada. Ocurría de verdad mientras existieron las
                // escrituras de extensión de techo, que solo diferían de
                // la meta anterior en `write_counter` (100..108) y el CRC:
                // un prefijo de 56 bytes las dejaba byte a byte idénticas
                // a lo que ya había — un desgarro que no desgarra nada. La
                // comprobación se queda como guardia del arnés. Ver
                // `TORN_PREFIX`.
                // Mismo alargado derivado que en la rama de cabecera, más
                // abajo, y por el mismo motivo: el prefijo pedido es el
                // punto de partida, no la última palabra.
                let mut prefix = prefix;
                while crate::meta::Meta::decode(&landed).is_ok() && prefix < b.len() {
                    prefix += 1;
                    self.inner.write_at(o, &b[..prefix])?;
                    self.inner.read_at(o, &mut landed)?;
                }
                assert!(
                    crate::meta::Meta::decode(&landed).is_err(),
                    "ningun prefijo entre {prefix} y {} deja ilegible la ranura de meta en \
                     {o}: los bytes nuevos no difieren de los que ya habia",
                    b.len()
                );
                self.last_synced_meta.lock().unwrap()[i] = landed;
                *self.dead.lock().unwrap() = Some(self.inner.snapshot());
                return Ok(());
            }

            if let Some((i, prefix)) = self.take_header_tear(o, b.len()) {
                self.inner.write_at(o, &b[..prefix])?;
                let mut landed = [0u8; crate::header::HEADER_SIZE];
                self.inner.read_at(o, &mut landed)?;
                // Misma comprobación de premisa que la de meta, arriba:
                // si el prefijo elegido deja la cabecera todavía legible
                // (p. ej. 8 o 40 — ver el comentario de
                // `a_torn_header_rewrite_...` en `tx.rs`, los bytes que no
                // difieren nunca entre la cabecera vieja y la nueva), esta
                // prueba no está modelando ningún desgarro.
                // El prefijo pedido es el PUNTO DE PARTIDA, no la última
                // palabra: se alarga hasta que el desgarro de verdad deja
                // la cabecera ilegible. Sin esto la prueba parpadeaba una
                // de cada ~14 corridas, y por la razón de siempre en este
                // arnés — conocimiento fijado a mano en vez de derivado.
                // El CRC de la cabecera depende de `db_id`, que se sortea
                // al crear la base, así que para algunos sorteos los bytes
                // nuevos por debajo del corte coincidían con los que ya
                // había y el desgarro no desgarraba nada. La guardia hacía
                // bien en saltar; lo que estaba mal era el prefijo.
                let mut prefix = prefix;
                while crate::header::Geometry::decode(&landed).is_ok() && prefix < b.len() {
                    prefix += 1;
                    self.inner.write_at(o, &b[..prefix])?;
                    self.inner.read_at(o, &mut landed)?;
                }
                assert!(
                    crate::header::Geometry::decode(&landed).is_err(),
                    "ningun prefijo entre {prefix} y {} deja ilegible la cabecera en {o}: \
                     los bytes nuevos no difieren de los que ya habia, asi que esta \
                     escritura no cambia nada y desgarrarla no modela nada",
                    b.len()
                );
                self.last_synced_header.lock().unwrap()[i] = landed;
                *self.dead.lock().unwrap() = Some(self.inner.snapshot());
                return Ok(());
            }

            self.inner.write_at(o, b)
        }

        fn sync(&self) -> Result<()> {
            if self.dead.lock().unwrap().is_some() {
                return Ok(());
            }
            {
                let mut saved = self.last_synced_meta.lock().unwrap();
                for (i, &offset) in META_OFFSETS.iter().enumerate() {
                    let mut buf = [0u8; 512];
                    let _ = self.inner.read_at(offset, &mut buf);
                    saved[i] = buf;
                }
            }
            {
                let mut saved = self.last_synced_header.lock().unwrap();
                for (i, &offset) in HEADER_OFFSETS.iter().enumerate() {
                    let mut buf = [0u8; crate::header::HEADER_SIZE];
                    let _ = self.inner.read_at(offset, &mut buf);
                    saved[i] = buf;
                }
            }
            self.inner.sync()
        }

        fn len(&self) -> Result<u64> {
            self.inner.len()
        }

        fn truncate(&self, len: u64) -> Result<()> {
            self.inner.truncate(len)
        }
    }

    struct ArcPowerLoss(Arc<PowerLossStorage>);
    impl Storage for ArcPowerLoss {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
        fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
    }

    /// Sonda 3 de la segunda ronda de revisión (hallazgo HIGH): bajo
    /// `Sync::Never` o un `Sync::Interval` largo — donde los commits
    /// normales de este motor nunca fuerzan un `fsync` — muchas
    /// transacciones pequeñas seguidas de un corte de corriente simulado
    /// no deben reutilizar ningún nonce, aunque se pierdan sus efectos
    /// lógicos (esa pérdida SÍ la acepta `Sync::Never`/`Interval`
    /// explícitamente; lo que no acepta es que rompa la confidencialidad
    /// de páginas que sobrevivieron).
    ///
    /// **Con nonces aleatorios esto pasa por una razón mucho más simple, y
    /// esa simplificación es el objetivo del cambio.** Antes hacía falta
    /// que la reserva de contadores llegara a disco de forma duradera
    /// ANTES de sellar con ellos —de ahí un `fsync` incondicional que ni
    /// `Sync::Never` podía evitar— porque la sesión de después del corte
    /// releía el techo del fichero. Ahora la sesión de después del corte
    /// sortea un prefijo nuevo, así que no hay nada que hacer durable: da
    /// igual cuánto se pierda en el corte, la sesión siguiente no puede
    /// pisar nonces de la anterior.
    #[test]
    fn sync_never_or_long_interval_survives_simulated_power_loss_without_reusing_a_nonce() {
        for &algorithm in ALGORITHMS {
            for policy in [Sync::Never, Sync::Interval(Duration::from_secs(3600))] {
                let capture = probe::Capture::start();
                let s = Arc::new(PowerLossStorage::new());
                let mk_opts = || Options { sync: policy, ..opts_with([51; 32], algorithm) };
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
                drop(db);

                assert_no_reuse(
                    &capture.take(),
                    &alloc::format!("{algorithm:?} / {policy:?} tras corte simulado"),
                );
            }
        }
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
        fn truncate(&self, len: u64) -> Result<()> { self.inner.truncate(len) }
    }
    struct ArcSyncCounting(Arc<SyncCountingStorage>);
    impl Storage for ArcSyncCounting {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
        fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
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

    /// **El coste que la sonda 4 no medía, y la prueba directa de que el
    /// aparato de techo de contador ya no existe.**
    ///
    /// La sonda 4 mide transacciones sobre una base recién CREADA. Sobre
    /// una base REABIERTA la historia era distinta: `live_counter ==
    /// counter_ceiling` al abrir (no había forma de saber cuánto del margen
    /// llegó a usar la sesión anterior antes de morir, así que se asumía el
    /// peor caso), de modo que la primera escritura cifrada de CADA sesión
    /// extendía el techo — **dos escrituras de meta y dos `fsync`
    /// incondicionales por sesión**, que ni `Sync::Never` podía evitar.
    /// Esta prueba fijaba esa cifra en `+2` y la declaraba inherente.
    ///
    /// **Ya no lo es, y ese es justo el punto.** Con un prefijo aleatorio
    /// nuevo por apertura no hay nada que reservar ni que hacer durable
    /// antes de sellar, así que el sobrecoste de sincronización del cifrado
    /// sobre una base reabierta es exactamente **cero**. La prueba se
    /// conserva con el mismo nombre invertido: mide lo mismo y ahora exige
    /// `+0` donde antes exigía `+2`.
    ///
    /// `page_size: 4096` (tarea 18, autorrevisión, mismo motivo que la sonda
    /// 4 de aquí arriba): con 512 B, tanto la corrida de 100 como la de 500
    /// transacciones cruzan los 4 KB y disparan `relocate_meta_b` una vez,
    /// EN LAS DOS BASES por igual (cifrada y sin cifrar) — un coste real,
    /// pero ajeno al cifrado, que esta prueba no está midiendo. Con páginas
    /// de 4 KB la meta B ya nace en su posición definitiva y la reubicación
    /// nunca se dispara.
    #[test]
    fn a_reopened_encrypted_database_pays_no_extra_sync_at_all() {
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
            a_enc, a_plain,
            "una base cifrada reabierta ya no paga NINGUNA sincronizacion de mas: si esto \
             vuelve a ser +2, ha vuelto la reserva duradera de contadores de nonce"
        );
        assert_eq!(b_enc, b_plain);
    }


    /// **El coste en espacio del cambio, medido.** El prefijo de cifrado
    /// pasó de 24 bytes (8 de contador + 16 de tag) a 40 (24 de nonce
    /// almacenado + 16 de tag), así que la página LÓGICA encoge 16 bytes y
    /// hacen falta más páginas para los mismos datos.
    ///
    /// Se mide con una carga acotada (600 registros), no con el banco de
    /// `tests/size.rs`: lo que hay que fijar es la relación entre tamaño
    /// físico y lógico y su efecto, no el rendimiento absoluto.
    ///
    /// Los dos tamaños que este motor usa de verdad: 512 B por defecto y
    /// 4096 B en los perfiles grandes.
    #[test]
    fn the_space_cost_of_the_forty_byte_cipher_prefix() {
        fn file_len(page_size: u32, encrypted: bool) -> u64 {
            let s = Arc::new(MemStorage::new());
            let base = if encrypted { opts([64; 32]) } else { Options::default() };
            let o = Options { page_size, ..base };
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), o).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..600u32 {
                tx.put(0x01, &i.to_be_bytes(), &[0xa5u8; 48]).unwrap();
            }
            tx.commit().unwrap();
            s.len().unwrap()
        }

        assert_eq!(CIPHER_PREFIX, 40, "24 de nonce almacenado mas 16 de tag");
        for page_size in [512u32, 4096] {
            let logical = page_size - CIPHER_PREFIX as u32;
            let (plain, enc) = (file_len(page_size, false), file_len(page_size, true));
            let overhead = 100.0 * (enc as f64 - plain as f64) / plain as f64;
            std::eprintln!(
                "pagina de {page_size} B: logica {logical} B ({:.1} % del fisico); \
                 fichero sin cifrar {plain} B, cifrado {enc} B (+{:.1} %)",
                100.0 * logical as f64 / page_size as f64,
                overhead
            );
            // El prefijo por página es fijo: lo que cambia con el tamaño de
            // página es qué FRACCIÓN representa. Con 512 B son 40 de cada
            // 512 (7,8 %); con 4096 B, 40 de cada 4096 (1,0 %).
            assert_eq!(logical, page_size - 40);
            assert!(
                enc >= plain,
                "una base cifrada no puede ocupar menos que la misma sin cifrar"
            );
            // Cota de cordura, no una cifra clavada: el crecimiento real
            // depende de cuántas claves caben por hoja a cada tamaño, que
            // no es lineal en el prefijo. Lo que esta cota descarta es un
            // cambio que multiplicara el fichero.
            assert!(
                overhead < 25.0,
                "pagina de {page_size} B: el cifrado infla el fichero un {overhead:.1} %"
            );
        }
    }

    /// Meta CONFIRMADA tal como está en el fichero ahora mismo, sin pasar
    /// por `Db`: la usan las pruebas de fuga de páginas para comprobar que
    /// una transacción abortada no cambió nada de lo confirmado.
    fn on_disk_meta(s: &MemStorage) -> crate::meta::Meta {
        let g = crate::header::Geometry::read(s).unwrap();
        crate::meta::Meta::load(s, &g).unwrap().0
    }

    /// **BLOCKER de la tercera ronda de revisión de la tarea 17, hoy sin
    /// mecanismo que pueda reproducirlo.** El registro duradero del techo
    /// de contador tenía que sobrevivir a CUALQUIER escritura desgarrada, y
    /// no lo hacía: la extensión escribía en `committed_slot.other()` y el
    /// commit siguiente escribe ESA MISMA ranura, así que el registro del
    /// techo sobrevivía exactamente una escritura de meta. Si esa escritura
    /// se desgarraba, `Meta::load` caía en la otra ranura, que conservaba
    /// el `write_counter` VIEJO, y la sesión siguiente volvía a repartir
    /// los contadores que la sesión muerta ya había usado. Medido
    /// entonces: cinco pares repetidos, 95,90 % de bytes cero en el XOR
    /// contra un 0,33 % de línea base.
    ///
    /// Sin techo, sin extensión y sin contador persistido, ese camino no
    /// existe. La prueba se conserva porque el ESCENARIO sigue siendo
    /// válido y es de los más duros que hay — una escritura de meta
    /// desgarrada entre dos sesiones que siguen escribiendo — y porque su
    /// veredicto sigue siendo el que importa: ningún nonce repetido, y
    /// ningún commit ya duradero perdido.
    #[test]
    fn a_torn_commit_meta_write_reuses_no_nonce() {
        for &algorithm in ALGORITHMS {
            let capture = probe::Capture::start();
            let s = Arc::new(PowerLossStorage::new());
            let mk = || opts_with([71; 32], algorithm);

            {
                let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), mk()).unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"antes", b"confirmado").unwrap();
                tx.commit().unwrap();
            }

            {
                let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk()).unwrap();
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
                let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk()).unwrap();
                assert_eq!(
                    db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                    Some(b"confirmado".as_slice()),
                    "{algorithm:?}: el commit desgarrado no debe llevarse por delante lo ya confirmado"
                );
                let mut tx = db.begin_write().unwrap();
                for i in 0..5u32 {
                    tx.put(0x02, &i.to_be_bytes(), b"sesion tres").unwrap();
                }
                tx.commit().unwrap();
            }

            assert_no_reuse(
                &capture.take(),
                &alloc::format!("{algorithm:?} tras un commit de meta desgarrado"),
            );
        }
    }

    /// **MEDIUM de la tercera ronda de revisión: fuga de páginas sin cota.**
    /// `Db::open` subía `meta.n_pages` hasta la extensión real del fichero y
    /// guardaba ESO en `self.committed`, así que `committed` describía un
    /// estado que nunca se confirmó: las páginas recuperadas vivían solo en
    /// la lista de libres EN MEMORIA. Como la extensión del techo de
    /// contador de nonce copiaba `self.committed` y la escribía a mitad de
    /// transacción, una transacción abortada dejaba en disco un `n_pages`
    /// por encima del último commit con una lista de libres que no posee la
    /// diferencia — y esas páginas se perdían para siempre, ciclo tras
    /// ciclo, sin cota.
    ///
    /// **El vehículo concreto de aquella fuga ya no existe**: sin extensión
    /// no hay ninguna escritura de meta a mitad de transacción, así que hoy
    /// una transacción abortada de una base cifrada escribe exactamente lo
    /// mismo que una sin cifrar: nada. La prueba se conserva porque lo que
    /// fija es la propiedad, no el vehículo — abortar no publica `n_pages`
    /// — y porque es la que detectaría que un camino nuevo vuelva a
    /// escribir meta fuera de un commit.
    ///
    /// Doce ciclos abrir-escribir-abortar. El control sin cifrar es el
    /// patrón
    /// exacto contra el que comparar.
    #[test]
    fn open_write_abort_cycles_leak_no_pages() {
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
                "cifrado={encrypted}: abortar no debe cambiar NADA de la meta confirmada"
            );
            // Y lo confirmado sigue legible.
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), mk_opts()).unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                Some(b"confirmado".as_slice())
            );
        }
    }

    /// La matriz completa: cada política de `Sync`, para cada algoritmo,
    /// contra un desgarro en CADA una de las escrituras de meta que hace
    /// una sesión, más el caso sin desgarro. Es la prueba que el arnés
    /// anterior no podía hacer (solo sabía descartar una ranura entera, ver
    /// `arm_meta_tear`).
    ///
    /// **Recorre los dos algoritmos desde este cambio.** Antes la matriz de
    /// durabilidad entera era solo de ChaCha; AES tenía tres pruebas
    /// sueltas. Como el cambio de nonce toca a los dos por igual, dejar la
    /// matriz con uno solo habría significado no comprobar en AES ni el
    /// desgarro de meta ni la supervivencia entre sesiones.
    ///
    /// Dos propiedades por caso, no una:
    /// - **ningún nonce se reutiliza** — el objetivo de la tarea;
    /// - **bajo `Sync::Commit`, lo ya confirmado sigue ahí** — sin esto, un
    ///   diseño que escriba las dos ranuras "de una tacada" con una sola
    ///   sincronización al final pasaría la primera comprobación y perdería
    ///   un commit entero: si la escritura de la ranura ACTIVA se desgarra
    ///   antes de que la de la INACTIVA sea duradera, no queda ninguna
    ///   ranura con el último estado confirmado.
    #[test]
    fn every_sync_policy_survives_a_torn_meta_write_at_every_point() {
        for &algorithm in ALGORITHMS {
        for policy in [Sync::Commit, Sync::Interval(Duration::from_secs(3600)), Sync::Never] {
            for tear_at in [None, Some(0), Some(1), Some(2)] {
                let capture = probe::Capture::start();
                let s = Arc::new(PowerLossStorage::new());
                let mk_opts = || Options { sync: policy, ..opts_with([91; 32], algorithm) };

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

                assert_no_reuse(
                    &capture.take(),
                    &alloc::format!("{algorithm:?} / {policy:?} / desgarro en {tear_at:?}"),
                );
            }
        }
        }
    }

    /// Matriz de la tarea 18 (ronda de revisión posterior a la entrega):
    /// cada política de `Sync`, con la ranura activa en A o en B antes del
    /// commit que reubica, contra un desgarro en CADA una de las tres
    /// escrituras que hace `relocate_meta_b` — la copia de la meta en la
    /// posición nueva, el espejo de cabecera, y la cabecera principal — con
    /// el prefijo de corte eligido para caer DENTRO de la región que
    /// cambia en cada una (`TORN_PREFIX` para la meta; 44..48 o 60..64 para
    /// cualquiera de las dos cabeceras, ver el comentario de
    /// `a_torn_header_rewrite_does_not_permanently_brick_the_database` en
    /// `tx.rs`).
    ///
    /// El arnés anterior a esta ronda no podía construir NINGUNO de estos
    /// casos: `META_OFFSETS` no reconocía la posición final de la meta B
    /// (4096) como una ranura de meta, y no existía ningún mecanismo para
    /// desgarrar una cabecera (64 B) en absoluto — ver el comentario de
    /// `PowerLossStorage`. "216 pruebas pasan" no era evidencia de nada
    /// sobre esta tarea.
    ///
    /// Tres propiedades por caso:
    /// - **ningún contador se reutiliza jamás** — el contrato de la tarea
    ///   17, que esta reubicación no debe romper;
    /// - **la base sigue pudiendo abrirse** — el hallazgo HIGH que el
    ///   espejo de cabecera cierra: antes de esa corrección, cualquier
    ///   desgarro dentro de la región 44..64 dejaba `Db::open` fallando
    ///   para siempre;
    /// - **el commit anterior a la reubicación sigue legible, y ninguna de
    ///   las 200 claves que trae el commit interrumpido queda corrupta ni
    ///   parcialmente visible** — el hallazgo BLOCKER de la recuperación de
    ///   páginas huérfanas: si `Db::open` recuperase la página destino
    ///   hacia la lista de libres, una escritura posterior la reutilizaría
    ///   como dato, y una reubicación posterior le escribiría meta encima.
    ///
    /// **Registro de una intermitencia (2026-08-11), sin perseguir:** esta
    /// prueba falló UNA vez en una corrida de la suite completa con
    /// `--features encryption`, y no se repitió en cuatro intentos
    /// posteriores bajo las mismas condiciones. Es anterior a esta ronda —
    /// ya estaba presente en `33a7962` ("fix: cierra fuga de reubicacion y
    /// cabecera desgarrada"), la corrección del hallazgo HIGH que esta
    /// misma matriz verifica — así que no es una regresión de este cambio.
    /// No se investigó más allá de esto: podría ser un problema de orden
    /// del arnés (estado compartido entre casos de la matriz, o entre
    /// pruebas del mismo binario) o una carrera real que la matriz roza sin
    /// aislarla todavía. Quien la vuelva a ver debería anotar aquí la
    /// política de `Sync`, la ranura activa y el punto de corte concretos
    /// (el mensaje de `assert` los incluye) en vez de volver a partir de
    /// cero.
    #[test]
    fn relocation_survives_a_torn_write_at_every_cut_point_under_every_sync_policy() {
        #[derive(Debug, Clone, Copy)]
        enum Cut {
            /// La copia de la meta confirmada en la posición nueva (offset
            /// 4096): la primera escritura de meta que hace la transacción
            /// que reubica — y, desde que no existe la extensión de techo
            /// de contador, la primera escritura de meta a secas de esa
            /// transacción, sin condiciones.
            MetaAtNewPosition,
            /// El espejo de cabecera (offset 64): la primera escritura de
            /// CABECERA de la transacción.
            HeaderMirror(usize),
            /// La cabecera principal (offset 0): la segunda.
            HeaderPrimary(usize),
        }

        let cuts = [
            Cut::MetaAtNewPosition,
            Cut::HeaderMirror(45),
            Cut::HeaderMirror(47),
            Cut::HeaderMirror(61),
            Cut::HeaderMirror(63),
            Cut::HeaderPrimary(45),
            Cut::HeaderPrimary(47),
            Cut::HeaderPrimary(61),
            Cut::HeaderPrimary(63),
        ];

        for &algorithm in ALGORITHMS {
        for policy in [Sync::Commit, Sync::Interval(Duration::from_secs(3600)), Sync::Never] {
            for active_slot_b in [false, true] {
                for &cut in &cuts {
                    let capture = probe::Capture::start();
                    let s = Arc::new(PowerLossStorage::new());
                    let mk_opts = || Options { sync: policy, ..opts_with([93; 32], algorithm) };

                    let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts()).unwrap();
                    let mut tx = db.begin_write().unwrap();
                    tx.put(0x01, b"antes", b"confirmado").unwrap();
                    tx.commit().unwrap();

                    if active_slot_b {
                        // Un commit vacio mas: `commit` siempre escribe en
                        // `self.slot.other()`, asi que dos commits reales
                        // dejan la ranura activa en B.
                        db.begin_write().unwrap().commit().unwrap();
                    }
                    // Bajo `Sync::Never`/`Interval` largo esto puede no
                    // estar sincronizado todavia; lo fija como duradero
                    // para que las tres politicas partan del mismo estado.
                    s.sync().unwrap();

                    match cut {
                        Cut::MetaAtNewPosition => s.arm_meta_tear(0, TORN_PREFIX),
                        Cut::HeaderMirror(prefix) => s.arm_header_tear(0, prefix),
                        Cut::HeaderPrimary(prefix) => s.arm_header_tear(1, prefix),
                    }

                    // Cruza los 4 KB: dispara `relocate_meta_b`, cuya
                    // escritura correspondiente este arnés desgarra.
                    let mut tx = db.begin_write().unwrap();
                    for i in 0..200u32 {
                        tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
                    }
                    tx.commit().unwrap();

                    s.simulate_power_loss();

                    let db = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), mk_opts())
                        .unwrap_or_else(|e| {
                            panic!(
                                "{policy:?} / activa={} / corte={cut:?}: la base debe seguir \
                                 pudiendose abrir tras el corte: {e:?}",
                                if active_slot_b { "B" } else { "A" }
                            )
                        });
                    assert_eq!(
                        db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                        Some(b"confirmado".as_slice()),
                        "{policy:?} / activa={} / corte={cut:?}: se perdio un commit ya duradero",
                        if active_slot_b { "B" } else { "A" }
                    );
                    {
                        let r = db.begin_read();
                        for i in [0u32, 50, 199] {
                            let seen = r.get(0x02, &i.to_be_bytes()).unwrap();
                            assert!(
                                seen.is_none() || seen.as_deref() == Some(&[0u8; 40][..]),
                                "{policy:?} / activa={} / corte={cut:?}: clave {i} corrupta \
                                 (ni ausente ni con su valor completo): {seen:?}",
                                if active_slot_b { "B" } else { "A" }
                            );
                        }
                    }

                    // Comprobación directa del hallazgo BLOCKER (recuperación
                    // de páginas huérfanas): un `alloc()` normal, tras esta
                    // reapertura, no debe entregar JAMÁS la página destino de
                    // la reubicación — sin esta comprobación explícita, un
                    // taller de seguimiento pequeño (como el de abajo) no
                    // necesariamente llega a agotar el resto de la lista de
                    // libres hasta alcanzarla, y el caso pasaría por la razón
                    // equivocada.
                    {
                        let mut tx = db.begin_write().unwrap();
                        let target = tx.meta_b_relocation_target();
                        for _ in 0..30 {
                            let p = tx.alloc().unwrap();
                            assert_ne!(
                                p, target,
                                "{policy:?} / activa={} / corte={cut:?}: la recuperacion de \
                                 paginas huerfanas entrego la pagina destino de la reubicacion",
                                if active_slot_b { "B" } else { "A" }
                            );
                        }
                        // Se descarta sin commit: solo interesa lo que
                        // `alloc()` está dispuesto a repartir.
                    }

                    // Una transaccion mas, para dar a `relocate_meta_b`
                    // ocasion de reintentarse y de que la sesion siga
                    // sellando paginas con normalidad.
                    {
                        let mut tx = db.begin_write().unwrap();
                        for i in 300..320u32 {
                            tx.put(0x03, &i.to_be_bytes(), b"tras el corte").unwrap();
                        }
                        tx.commit().unwrap();
                    }
                    drop(db);

                    assert_no_reuse(
                        &capture.take(),
                        &alloc::format!(
                            "{algorithm:?} / {policy:?} / activa={} / corte={cut:?}",
                            if active_slot_b { "B" } else { "A" }
                        ),
                    );
                }
            }
        }
        }
    }

    /// Aquí vivía `mod aes_tests`: tres pruebas sueltas (roundtrip, página
    /// manipulada, unicidad de nonces) que existían porque `--features aes`
    /// compilaba el backend pero ninguna prueba lo instanciaba de verdad —
    /// cobertura de compilación, no de ejecución.
    ///
    /// **Se ha disuelto en el resto del módulo, y eso es una mejora, no una
    /// pérdida.** Tres pruebas propias frente a la suite entera de ChaCha
    /// dejaban a AES sin matriz de durabilidad, sin corte de corriente, sin
    /// reubicación de meta B y sin ninguna de las pruebas nuevas de este
    /// cambio. Ahora todas las pruebas de cifrado de este fichero recorren
    /// `ALGORITHMS` (ver su comentario), así que AES-256-GCM-SIV pasa
    /// exactamente por los mismos casos que XChaCha20-Poly1305 — incluidos
    /// los dos defectos que este cambio entierra, la copia de seguridad
    /// restaurada y las dos aperturas.
    ///
    /// Las únicas pruebas que no recorren la lista son las que no dependen
    /// del algoritmo (`the_nonce_counter_restarts_at_zero_on_every_open`,
    /// que lee el contador en la posición que ocupa en el nonce de
    /// XChaCha20, y las de coste de sincronización, que miden `fsync` y no
    /// criptografía) y las que lo fijan a mano porque comprueban el reparto
    /// de bytes de CADA algoritmo por separado
    /// (`the_nonce_is_exactly_prefix_then_counter`,
    /// `exhausting_the_aes_counter_field_...`), que se compilan y ejecutan
    /// sin necesitar la feature `aes` porque solo tocan `NonceStream`, no
    /// el cifrador.
    const _: () = ();
}
