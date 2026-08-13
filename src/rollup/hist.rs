//! Histograma logarítmico de 16 cubetas para la latencia.
//!
//! Es la pieza que hace viable el esquema de agregados (sección 12.3 de la
//! especificación): da percentiles 50, 95 y 99 con error **acotado** en unas
//! decenas de bytes, mientras que un percentil exacto exigiría conservar los
//! registros crudos, que a las 6 horas ya no existen.
//!
//! ## La escalera, y por qué es de base 2 y no más fina
//!
//! ```text
//! cubeta  0 → [0, 0]            (latencia cero exacta)
//! cubeta  k → [2^(k-1), 2^k−1]  para k = 1..14
//! cubeta 15 → [16384, ∞)        abierta por arriba
//! ```
//!
//! Con 16 cubetas hay que repartir un rango y una precisión que se oponen
//! directamente: la cubeta más alta tiene que llegar al orden del *timeout*
//! de un HTTP (decenas de segundos) o toda la cola cae en un único cajón sin
//! forma. Cubriendo `[1, 16384)` con 14 cubetas cerradas, cada una abarca un
//! factor de 2 exacto. Una escalera de base √2 daría la mitad de anchura
//! relativa pero solo llegaría a 256 ms con las mismas 16 cubetas — inútil
//! para una latencia con cola. La especificación pide «logarítmico de 16
//! cubetas» y esa restricción fija la base: es aritmética, no una preferencia.
//!
//! ## Qué error produce, exactamente
//!
//! **Garantía dura, comprobable y comprobada:** `percentile` NO devuelve un
//! número suelto, devuelve el intervalo `[lo, hi]` en el que el percentil
//! exacto está **garantizado** que cae, más una estimación puntual dentro de
//! él. La garantía de contención es exacta por construcción — el percentil de
//! rango `r` es el valor de la muestra que ocupa ese rango, esa muestra vive
//! en alguna cubeta, y `percentile` devuelve los bordes de esa cubeta — y se
//! verifica en `containment_holds_on_every_distribution` contra percentiles
//! exactos calculados sobre las muestras ordenadas.
//!
//! De ahí sale la cota de error de una estimación puntual: para las cubetas
//! cerradas `hi < 2·lo`, así que *cualquier* punto del intervalo está a menos
//! del 100% del valor verdadero, y el punto óptimo (`4/3·lo`, el que iguala el
//! error relativo en los dos extremos) lo deja en **33,3% como máximo**. La
//! estimación que devuelve este módulo no es esa: interpola por rango dentro
//! de la cubeta, que es peor en el peor caso (una cubeta con toda su masa en
//! un borde) y bastante mejor en la práctica — medido en
//! `interpolated_estimate_error_on_realistic_latencies`.
//!
//! **El techo de la cubeta 15 lo cierra `max_latency`**, que el `Bucket` sí
//! almacena: sin él la cubeta más alta es abierta y no habría intervalo que
//! devolver. Y `max_latency` recorta además el `hi` de *cualquier* cubeta —
//! ninguna muestra lo supera, así que `min(hi_cubeta, max_latency)` sigue
//! siendo un techo válido y a veces mucho más estrecho.
//!
//! ## Sin coma flotante, a propósito
//!
//! Todo el módulo es aritmética entera. `f64::ceil` y compañía son de `std`,
//! no de `core`, y este módulo tiene que compilar bajo `no_std` (ver
//! `rollup/mod.rs`). El percentil se pide en **por mil** (`500`, `950`, `990`)
//! justamente para no necesitar un flotante en la interfaz.

use crate::error::{Error, Result};

/// Número de cubetas. Fijado por la especificación (sección 12.3).
pub const BUCKETS: usize = 16;

/// Primera cubeta abierta por arriba.
pub const LAST: usize = BUCKETS - 1;

/// Histograma logarítmico de latencias en milisegundos.
///
/// `u64` por cubeta y no `u32`: un agregado de resolución diaria en un nodo
/// enterprise ve del orden de 1,7 millones de peticiones al día, muy lejos de
/// desbordar `u32`, pero mezclar anchuras obligaría a razonar en cada suma
/// sobre si `requests` (`u64`) y la cubeta (`u32`) pueden divergir. Cuesta 128
/// bytes por entrada de RAM y esa cifra está medida y publicada en el informe,
/// no escondida.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Histogram {
    counts: [u64; BUCKETS],
}

/// Percentil estimado a partir del histograma.
///
/// `lo` y `hi` son una **garantía**: el percentil exacto de las muestras que
/// alimentaron el histograma cae en `[lo, hi]`, ambos incluidos. `estimate`
/// es un punto dentro de ese intervalo, y solo eso: una comodidad para pintar
/// una gráfica, no una promesa más fuerte que el intervalo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Percentile {
    pub lo: u32,
    pub hi: u32,
    pub estimate: u32,
}

/// Cubeta a la que pertenece `v` milisegundos.
///
/// `32 - leading_zeros` es `floor(log2(v)) + 1` para `v > 0`, que es
/// exactamente el índice buscado: `v = 1` → 1, `v = 2..3` → 2, `v = 4..7` → 3.
/// Se satura en `LAST` en vez de truncar, para que `u32::MAX` caiga en la
/// cubeta abierta y no dé la vuelta (invariante 2: nunca una respuesta
/// equivocada).
pub fn bucket_of(v: u32) -> usize {
    if v == 0 {
        return 0;
    }
    let k = 32 - v.leading_zeros() as usize;
    if k > LAST { LAST } else { k }
}

/// Borde inferior (inclusivo) de la cubeta `k`.
pub fn bucket_lo(k: usize) -> u32 {
    if k == 0 { 0 } else { 1u32 << (k - 1) }
}

/// Borde superior (inclusivo) de la cubeta `k`, sin contar `max_latency`.
///
/// `None` para la cubeta abierta: quien la consulte necesita cerrarla con el
/// `max_latency` que el `Bucket` almacena aparte. Devolver `u32::MAX` en su
/// lugar habría sido un techo formalmente correcto y prácticamente inútil, y
/// además invisible: nadie se entera de que el intervalo es de 4 mil millones.
pub fn bucket_hi(k: usize) -> Option<u32> {
    if k == 0 {
        Some(0)
    } else if k == LAST {
        None
    } else {
        Some((1u32 << k) - 1)
    }
}

impl Histogram {
    pub fn new() -> Self {
        Histogram { counts: [0; BUCKETS] }
    }

    /// Cuentas por cubeta, en orden.
    pub fn counts(&self) -> &[u64; BUCKETS] {
        &self.counts
    }

    /// Construye desde cuentas ya conocidas. Solo lo usa el decodificador,
    /// que ya validó lo que hay dentro.
    pub(crate) fn from_counts(counts: [u64; BUCKETS]) -> Self {
        Histogram { counts }
    }

    /// Total de muestras.
    pub fn total(&self) -> u64 {
        // `saturating_add` y no `checked`: este método lo llaman las
        // comprobaciones del decodificador, que necesitan un número con el
        // que comparar aunque las cuentas vengan manipuladas. Saturar da un
        // total distinto de `requests` y por tanto un `Err`, que es el
        // desenlace correcto; propagar un `Result` desde aquí solo movería
        // el mismo rechazo de sitio.
        self.counts.iter().fold(0u64, |a, &b| a.saturating_add(b))
    }

    /// Cubeta no vacía más alta, o `None` si el histograma está vacío.
    pub fn highest(&self) -> Option<usize> {
        self.counts.iter().rposition(|&c| c > 0)
    }

    /// Registra una muestra de `v` milisegundos.
    pub fn record(&mut self, v: u32) -> Result<()> {
        self.record_many(v, 1)
    }

    /// Registra `n` muestras de `v` milisegundos de una vez.
    ///
    /// No es una comodidad de pruebas: quien funde agregados ya resumidos —o
    /// reconstruye una celda desde otra fuente— tiene la cuenta, no las
    /// muestras, y hacerlo con un bucle de `record` sería `O(n)` por una suma
    /// que es `O(1)`. Mantiene la relación que `Bucket::decode` comprueba
    /// (la suma del histograma iguala las peticiones) por construcción,
    /// porque `Bucket::record_many` sube las dos cosas a la vez.
    pub fn record_many(&mut self, v: u32, n: u64) -> Result<()> {
        let k = bucket_of(v);
        self.counts[k] = self.counts[k].checked_add(n).ok_or(Error::BadFormat)?;
        Ok(())
    }

    /// Suma `other` cubeta a cubeta.
    pub fn merge(&mut self, other: &Histogram) -> Result<()> {
        for k in 0..BUCKETS {
            self.counts[k] = self.counts[k].checked_add(other.counts[k]).ok_or(Error::BadFormat)?;
        }
        Ok(())
    }

    /// Percentil `permille` (por mil: 500 = p50, 950 = p95, 990 = p99),
    /// cerrando la cubeta abierta con `max_latency`.
    ///
    /// Definición de percentil: **rango más cercano**, la clásica — el valor
    /// de la muestra en la posición `ceil(n · p)` de la lista ordenada, con
    /// posiciones desde 1. Es la misma definición que usa
    /// `exact_percentile` en las pruebas, y tienen que coincidir o la
    /// garantía de contención se rompería en los bordes por una discrepancia
    /// de definición y no por un fallo del histograma — el modo exacto en
    /// que una comprobación pasa mientras el sistema está roto.
    ///
    /// `None` si el histograma está vacío o `permille` está fuera de
    /// `1..=1000`.
    pub fn percentile(&self, permille: u32, max_latency: u32) -> Option<Percentile> {
        let n = self.total();
        if n == 0 || permille == 0 || permille > 1000 {
            return None;
        }
        // rango = ceil(n · permille / 1000), en enteros y sin desbordar:
        // `n` cabe en u64 y `permille` en 10 bits.
        let rank = (n.saturating_mul(permille as u64)).div_ceil(1000).max(1);

        let mut cum = 0u64;
        for k in 0..BUCKETS {
            let c = self.counts[k];
            if c == 0 {
                continue;
            }
            if cum + c >= rank {
                let lo = bucket_lo(k);
                // `max_latency` recorta el techo de CUALQUIER cubeta, no
                // solo de la abierta: ninguna muestra lo supera. En la
                // cubeta 15 es además el único techo que existe.
                let hi = match bucket_hi(k) {
                    Some(h) => h.min(max_latency),
                    None => max_latency,
                };
                // Un `max_latency` incoherente con el histograma (que el
                // decodificador rechaza, pero que este método podría ver si
                // alguien construye un `Bucket` a mano) dejaría `hi < lo`.
                // Se corrige subiéndolo a `lo`, nunca al revés: devolver un
                // intervalo invertido sería una respuesta equivocada.
                let hi = hi.max(lo);
                // Interpolación por rango dentro de la cubeta: la muestra
                // j-ésima de las `c` que hay aquí se sitúa en el punto medio
                // del j-ésimo de `c` sub-intervalos iguales. Con `c = 1` cae
                // en el centro exacto de la cubeta.
                let j = rank - cum; // 1..=c
                let span = (hi - lo) as u64;
                let estimate = lo + ((span * (2 * j - 1)) / (2 * c)) as u32;
                return Some(Percentile { lo, hi, estimate });
            }
            cum += c;
        }
        // Inalcanzable: `rank <= n` y las cuentas suman `n`, así que el
        // bucle sale siempre por el `return`. Se devuelve `None` en vez de
        // `unreachable!()` porque un pánico en una función que recibe datos
        // decodificados del disco es exactamente lo que la invariante 2
        // prohíbe, y `total()` satura (ver su comentario), que es el único
        // camino por el que la suma podría no cuadrar.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Percentil exacto por rango más cercano sobre las muestras crudas.
    /// **Tiene que usar la misma definición que `Histogram::percentile`** —
    /// ver su comentario.
    fn exact_percentile(samples: &mut [u32], permille: u32) -> u32 {
        samples.sort_unstable();
        let n = samples.len() as u64;
        let rank = (n * permille as u64).div_ceil(1000).max(1);
        samples[(rank - 1) as usize]
    }

    /// Generador congruencial lineal propio: `rand` sería una dependencia y
    /// este proyecto no las tiene. Los parámetros son los de Numerical
    /// Recipes; sirve para repartir muestras, no para criptografía.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 16) as u32
        }
        /// Uniforme en `[0, n)`.
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
    }

    /// Cuatro repartos de latencia con forma distinta, todos plausibles en un
    /// edge real.
    fn distributions() -> Vec<(&'static str, Vec<u32>)> {
        let mut out = Vec::new();
        let mut r = Lcg(12345);

        // Casi todo rápido, cola larga: la forma normal de una API.
        let mut d = Vec::new();
        for _ in 0..20_000 {
            let x = r.below(1000);
            d.push(if x < 900 {
                1 + r.below(20)
            } else if x < 990 {
                20 + r.below(180)
            } else {
                200 + r.below(3000)
            });
        }
        out.push(("cola larga", d));

        // Bimodal: caché acertada (1-3 ms) o fallada (80-120 ms).
        let mut d = Vec::new();
        for _ in 0..20_000 {
            d.push(if r.below(100) < 70 { 1 + r.below(3) } else { 80 + r.below(40) });
        }
        out.push(("bimodal", d));

        // Todo en la cubeta abierta: timeouts.
        let mut d = Vec::new();
        for _ in 0..5_000 {
            d.push(20_000 + r.below(40_000));
        }
        out.push(("timeouts", d));

        // Constante: el caso degenerado que rompe cualquier interpolación
        // ingenua.
        out.push(("constante", alloc::vec![7u32; 3_000]));

        // Uniforme muy ancha.
        let mut d = Vec::new();
        for _ in 0..20_000 {
            d.push(r.below(5_000));
        }
        out.push(("uniforme", d));

        out
    }

    #[test]
    fn bucket_boundaries_are_exactly_the_powers_of_two() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        assert_eq!(bucket_of(7), 3);
        assert_eq!(bucket_of(8), 4);
        assert_eq!(bucket_of(8191), 13);
        assert_eq!(bucket_of(8192), 14);
        assert_eq!(bucket_of(16383), 14);
        assert_eq!(bucket_of(16384), LAST);
        assert_eq!(bucket_of(u32::MAX), LAST, "la cubeta abierta satura, no da la vuelta");
    }

    #[test]
    fn every_value_lands_inside_the_bounds_of_its_own_bucket() {
        // Barrido denso por debajo de 2^15 y por los bordes de cada potencia.
        let mut probes: Vec<u32> = (0..4096).collect();
        for k in 0..32 {
            let p = 1u32 << k;
            probes.push(p.saturating_sub(1));
            probes.push(p);
            probes.push(p.saturating_add(1));
        }
        probes.push(u32::MAX);
        for v in probes {
            let k = bucket_of(v);
            assert!(v >= bucket_lo(k), "{v} por debajo del borde bajo de la cubeta {k}");
            if let Some(h) = bucket_hi(k) {
                assert!(v <= h, "{v} por encima del borde alto de la cubeta {k}");
            }
        }
    }

    #[test]
    fn containment_holds_on_every_distribution() {
        for (name, samples) in distributions() {
            let mut h = Histogram::new();
            let mut max = 0u32;
            for &v in &samples {
                h.record(v).unwrap();
                max = max.max(v);
            }
            for permille in [1u32, 250, 500, 900, 950, 990, 999, 1000] {
                let mut copy = samples.clone();
                let exact = exact_percentile(&mut copy, permille);
                let p = h.percentile(permille, max).unwrap();
                assert!(
                    p.lo <= exact && exact <= p.hi,
                    "{name} p{permille}: exacto {exact} fuera de [{}, {}]",
                    p.lo,
                    p.hi
                );
                assert!(
                    p.lo <= p.estimate && p.estimate <= p.hi,
                    "{name} p{permille}: estimación {} fuera de su propio intervalo",
                    p.estimate
                );
            }
        }
    }

    #[test]
    fn the_reported_interval_is_never_wider_than_a_factor_of_two_below_the_open_bucket() {
        // La cota que se publica: para cubetas cerradas, `hi < 2·lo`, de
        // donde sale el 33,3% del punto óptimo.
        for k in 2..LAST {
            let lo = bucket_lo(k);
            let hi = bucket_hi(k).unwrap();
            assert!(hi < 2 * lo, "cubeta {k}: [{lo}, {hi}] más ancha que un factor de 2");
        }
    }

    #[test]
    fn a_constant_distribution_is_reported_exactly_when_the_bucket_is_a_single_value() {
        let mut h = Histogram::new();
        for _ in 0..100 {
            h.record(1).unwrap();
        }
        let p = h.percentile(990, 1).unwrap();
        assert_eq!((p.lo, p.hi, p.estimate), (1, 1, 1));
    }

    #[test]
    fn max_latency_tightens_the_interval_of_a_wide_bucket() {
        // Todas las muestras valen 5 ms: cubeta 3 = [4, 7], pero
        // `max_latency = 5` recorta el techo a 5.
        let mut h = Histogram::new();
        for _ in 0..10 {
            h.record(5).unwrap();
        }
        let p = h.percentile(500, 5).unwrap();
        assert_eq!(p.lo, 4);
        assert_eq!(p.hi, 5, "max_latency tiene que recortar el techo de la cubeta");
    }

    #[test]
    fn an_empty_histogram_has_no_percentile() {
        assert_eq!(Histogram::new().percentile(500, 0), None);
    }

    #[test]
    fn permille_outside_its_range_is_refused_instead_of_wrapping() {
        let mut h = Histogram::new();
        h.record(1).unwrap();
        assert_eq!(h.percentile(0, 1), None);
        assert_eq!(h.percentile(1001, 1), None);
        assert_eq!(h.percentile(u32::MAX, 1), None);
    }

    #[test]
    fn merge_adds_bucket_by_bucket() {
        let mut a = Histogram::new();
        a.record(1).unwrap();
        a.record(1000).unwrap();
        let mut b = Histogram::new();
        b.record(1).unwrap();
        a.merge(&b).unwrap();
        assert_eq!(a.total(), 3);
        assert_eq!(a.counts()[1], 2);
    }

    #[test]
    fn record_and_merge_refuse_to_overflow() {
        let mut a = Histogram::from_counts([u64::MAX; BUCKETS]);
        assert!(a.record(1).is_err());
        let b = Histogram::from_counts([1; BUCKETS]);
        assert!(a.merge(&b).is_err());
    }

    /// Publica el error de la estimación puntual. No es una prueba de
    /// contención (esa es `containment_holds_on_every_distribution`): mide
    /// cuánto se desvía el punto que se devuelve por comodidad, y fija un
    /// techo generoso para que una regresión grande se note.
    ///
    /// Tras `feature = "std"` solo por el `println!` que publica los números:
    /// bajo `--no-default-features` el crate es `no_std` y `std::println!` no
    /// resuelve. La contención, que es la garantía de verdad, se comprueba en
    /// la prueba de arriba, que sí corre en las dos compilaciones.
    #[cfg(feature = "std")]
    #[test]
    fn interpolated_estimate_error_on_realistic_latencies() {
        let mut worst = 0.0f64;
        for (name, samples) in distributions() {
            let mut h = Histogram::new();
            let mut max = 0u32;
            for &v in &samples {
                h.record(v).unwrap();
                max = max.max(v);
            }
            for permille in [500u32, 950, 990] {
                let mut copy = samples.clone();
                let exact = exact_percentile(&mut copy, permille) as f64;
                let p = h.percentile(permille, max).unwrap();
                let err = if exact == 0.0 {
                    0.0
                } else {
                    ((p.estimate as f64) - exact).abs() / exact * 100.0
                };
                std::println!(
                    "hist {name} p{permille}: exacto {exact} estimado {} intervalo [{}, {}] error {err:.1}%",
                    p.estimate,
                    p.lo,
                    p.hi
                );
                if err > worst {
                    worst = err;
                }
            }
        }
        std::println!("hist: peor error de la estimación puntual {worst:.1}%");
        assert!(worst <= 50.0, "el error de la estimación puntual subió a {worst:.1}%");
    }
}
