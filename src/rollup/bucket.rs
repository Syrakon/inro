//! El agregado de una celda: contadores más histograma, y su codificación.
//!
//! Un `Bucket` es lo que la sección 12.3 de la especificación pide guardar por
//! cada `(resolución, ts_bucket, dimensión, valor)`: `requests`, `errors`,
//! `bytes_in`, `bytes_out`, `max_latency` y el histograma logarítmico de 16
//! cubetas.
//!
//! ## Formato en disco
//!
//! ```text
//! [versión u8 = 1]
//! [requests varint][errors varint][bytes_in varint][bytes_out varint]
//! [max_latency varint]
//! [máscara varint]                 bit k = 1 ⇔ la cubeta k no está vacía
//! [cuenta varint] × popcount(máscara)
//! ```
//!
//! Todo varint LEB128, el mismo del motor (`crate::varint`). La máscara de 16
//! bits más una cuenta por cubeta viva cuesta, para un agregado horario real
//! con cuatro o cinco cubetas pobladas, **unos 8 bytes** — por debajo de los
//! «unos 20 bytes» que la especificación reserva al histograma. El tamaño
//! medio medido del valor completo está en el informe.
//!
//! **Sin CRC propio, a propósito.** La página que contiene esta celda ya lleva
//! un CRC32 sobre todo su contenido y `PageRef::parse` es la única frontera de
//! validación de una página (invariante 1). Un CRC por valor duplicaría ese
//! trabajo y ese espacio sin cubrir ningún camino nuevo: para que estos bytes
//! lleguen manipulados a `decode`, la página entera tiene que haber pasado su
//! propio CRC.
//!
//! ## Lo que `decode` comprueba, y por qué cada cosa
//!
//! El decodificador no se limita a leer los campos: comprueba tres relaciones
//! que son **ciertas por construcción** en cualquier bucket que este módulo
//! haya escrito, de modo que un valor manipulado se rechaza con `Err` en vez
//! de devolver un informe silenciosamente equivocado (invariante 2).
//!
//! 1. `errors <= requests`.
//! 2. `suma del histograma == requests`. Cada petición observada aporta
//!    exactamente una muestra de latencia, así que la igualdad es exacta.
//! 3. `bucket_of(max_latency) == cubeta no vacía más alta`. `max_latency` es
//!    una de las muestras (luego su cubeta no está vacía) y ninguna la supera
//!    (luego no hay ninguna más alta poblada). La igualdad, otra vez, es
//!    exacta — y es la comprobación que atrapa un solo byte cambiado en
//!    `max_latency`, que las dos anteriores dejarían pasar.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::rollup::hist::{BUCKETS, Histogram, Percentile, bucket_of};
use crate::varint;

/// Versión del formato de un valor de agregado. Un byte por celda.
pub const BUCKET_VERSION: u8 = 1;

/// Agregado de una celda.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Bucket {
    pub requests: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub max_latency: u32,
    pub hist: Histogram,
}

impl Bucket {
    pub fn new() -> Self {
        Bucket::default()
    }

    /// Está vacío: ninguna petición registrada.
    pub fn is_empty(&self) -> bool {
        self.requests == 0
    }

    /// Registra una petición.
    ///
    /// `error` lo decide quien llama, no este módulo: qué cuenta como error
    /// depende de la aplicación (un 404 esperado puede no serlo, un 200 con
    /// cuerpo de error sí), y adivinarlo desde `status` aquí sería imponer
    /// una política que la capa de agregación no tiene por qué tener.
    pub fn record(
        &mut self,
        latency_ms: u32,
        bytes_in: u64,
        bytes_out: u64,
        error: bool,
    ) -> Result<()> {
        self.requests = self.requests.checked_add(1).ok_or(Error::BadFormat)?;
        if error {
            self.errors = self.errors.checked_add(1).ok_or(Error::BadFormat)?;
        }
        self.bytes_in = self.bytes_in.checked_add(bytes_in).ok_or(Error::BadFormat)?;
        self.bytes_out = self.bytes_out.checked_add(bytes_out).ok_or(Error::BadFormat)?;
        if latency_ms > self.max_latency {
            self.max_latency = latency_ms;
        }
        self.hist.record(latency_ms)
    }

    /// Suma `other` a este bucket. La operación que hace conmutativo el
    /// esquema entero: fusionar el estado en RAM con el que ya estaba en
    /// disco, o volcar un valor desalojado del top-K al cajón `otros`.
    pub fn merge(&mut self, other: &Bucket) -> Result<()> {
        self.requests = self.requests.checked_add(other.requests).ok_or(Error::BadFormat)?;
        self.errors = self.errors.checked_add(other.errors).ok_or(Error::BadFormat)?;
        self.bytes_in = self.bytes_in.checked_add(other.bytes_in).ok_or(Error::BadFormat)?;
        self.bytes_out = self.bytes_out.checked_add(other.bytes_out).ok_or(Error::BadFormat)?;
        if other.max_latency > self.max_latency {
            self.max_latency = other.max_latency;
        }
        self.hist.merge(&other.hist)
    }

    /// Percentil `permille` (500 = p50, 950 = p95, 990 = p99) de la latencia.
    /// Ver `hist::Percentile`: `lo`/`hi` son una garantía, `estimate` una
    /// comodidad.
    pub fn percentile(&self, permille: u32) -> Option<Percentile> {
        self.hist.percentile(permille, self.max_latency)
    }

    /// Bytes que ocupará `encode`.
    pub fn encoded_len(&self) -> usize {
        let mut n = 1
            + varint::len(self.requests)
            + varint::len(self.errors)
            + varint::len(self.bytes_in)
            + varint::len(self.bytes_out)
            + varint::len(self.max_latency as u64);
        let mut mask = 0u64;
        for (k, &c) in self.hist.counts().iter().enumerate() {
            if c > 0 {
                mask |= 1 << k;
                n += varint::len(c);
            }
        }
        n + varint::len(mask)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; self.encoded_len()];
        let mut i = 0;
        out[i] = BUCKET_VERSION;
        i += 1;
        for v in [self.requests, self.errors, self.bytes_in, self.bytes_out, self.max_latency as u64]
        {
            i += varint::write(&mut out[i..], v);
        }
        let mut mask = 0u64;
        for (k, &c) in self.hist.counts().iter().enumerate() {
            if c > 0 {
                mask |= 1 << k;
            }
        }
        i += varint::write(&mut out[i..], mask);
        for &c in self.hist.counts().iter() {
            if c > 0 {
                i += varint::write(&mut out[i..], c);
            }
        }
        debug_assert_eq!(i, out.len(), "encoded_len no coincide con lo escrito");
        out
    }

    /// Decodifica un valor de agregado.
    ///
    /// Cualquier desviación —versión desconocida, varint truncado, bytes de
    /// sobra al final, máscara con bits imposibles, o cualquiera de las tres
    /// relaciones del comentario de módulo— sale como `Err`, nunca como un
    /// bucket a medias (invariante 2).
    pub fn decode(bytes: &[u8]) -> Result<Bucket> {
        let mut i = 0;
        // `BadFormat` también para una versión POSTERIOR, no
        // `Error::VersionTooNew`: esa variante dice «el FICHERO usa una
        // versión de formato que este binario no entiende» y la produce
        // `Geometry::decode` sobre la cabecera. Reutilizarla aquí haría que
        // un solo byte manipulado dentro de una celda de datos se presentara
        // como un fichero de otra versión, que es un diagnóstico equivocado
        // y manda a quien depura al sitio equivocado.
        match bytes.first() {
            Some(&v) if v == BUCKET_VERSION => i += 1,
            _ => return Err(Error::BadFormat),
        }

        let mut field = || -> Result<u64> {
            let (v, n) = varint::read(&bytes[i..]).ok_or(Error::BadFormat)?;
            i += n;
            Ok(v)
        };
        // Cinco llamadas separadas y no un bucle sobre un array: el cierre
        // toma `i` prestado y devolver los cinco valores desde un bucle
        // obligaría a un `Vec` intermedio en el camino de lectura.
        let requests = field()?;
        let errors = field()?;
        let bytes_in = field()?;
        let bytes_out = field()?;
        let max_latency_raw = field()?;
        let mask = field()?;

        let mut counts = [0u64; BUCKETS];
        if mask >= (1u64 << BUCKETS) {
            return Err(Error::BadFormat);
        }
        for (k, slot) in counts.iter_mut().enumerate() {
            if mask & (1 << k) != 0 {
                let c = field()?;
                // Un bit puesto con cuenta cero no lo escribe nunca
                // `encode`, y aceptarlo daría dos codificaciones distintas
                // para el mismo bucket: se rechaza para que la
                // representación sea única y `encode(decode(x)) == x`.
                if c == 0 {
                    return Err(Error::BadFormat);
                }
                *slot = c;
            }
        }
        if i != bytes.len() {
            return Err(Error::BadFormat);
        }
        if max_latency_raw > u32::MAX as u64 {
            return Err(Error::BadFormat);
        }
        let max_latency = max_latency_raw as u32;

        let hist = Histogram::from_counts(counts);
        if errors > requests {
            return Err(Error::BadFormat);
        }
        if hist.total() != requests {
            return Err(Error::BadFormat);
        }
        match hist.highest() {
            None => {
                // Histograma vacío: el bucket entero tiene que estarlo.
                if requests != 0 || max_latency != 0 {
                    return Err(Error::BadFormat);
                }
            }
            Some(k) => {
                if bucket_of(max_latency) != k {
                    return Err(Error::BadFormat);
                }
            }
        }

        Ok(Bucket { requests, errors, bytes_in, bytes_out, max_latency, hist })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bucket {
        let mut b = Bucket::new();
        b.record(3, 100, 900, false).unwrap();
        b.record(40, 120, 1200, true).unwrap();
        b.record(1, 80, 400, false).unwrap();
        b.record(900, 200, 5000, false).unwrap();
        b
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let b = sample();
        let bytes = b.encode();
        assert_eq!(bytes.len(), b.encoded_len());
        assert_eq!(Bucket::decode(&bytes).unwrap(), b);
    }

    #[test]
    fn an_empty_bucket_roundtrips() {
        let b = Bucket::new();
        let bytes = b.encode();
        assert_eq!(Bucket::decode(&bytes).unwrap(), b);
    }

    #[test]
    fn a_realistic_hourly_bucket_fits_in_far_less_than_the_specs_twenty_bytes_of_histogram() {
        // Una hora de un endpoint corriente: 500 peticiones repartidas por
        // cinco cubetas de latencia.
        let mut b = Bucket::new();
        for i in 0..500u32 {
            let lat = match i % 10 {
                0..=5 => 2,
                6..=7 => 9,
                8 => 30,
                9 => 140,
                _ => 700,
            };
            b.record(lat, 300, 4000, i % 97 == 0).unwrap();
        }
        let hist_only = b.encoded_len()
            - (1 + varint::len(b.requests)
                + varint::len(b.errors)
                + varint::len(b.bytes_in)
                + varint::len(b.bytes_out)
                + varint::len(b.max_latency as u64));
        assert!(hist_only <= 20, "el histograma ocupa {hist_only} bytes, por encima de los 20");
    }

    #[test]
    fn truncated_input_is_refused_at_every_length() {
        let full = sample().encode();
        for cut in 0..full.len() {
            assert!(
                Bucket::decode(&full[..cut]).is_err(),
                "un prefijo de {cut} bytes se aceptó como bucket entero"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(Bucket::decode(&bytes).is_err());
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut bytes = sample().encode();
        bytes[0] = 2;
        assert!(matches!(Bucket::decode(&bytes), Err(Error::BadFormat)));
        bytes[0] = 0;
        assert!(matches!(Bucket::decode(&bytes), Err(Error::BadFormat)));
        assert!(matches!(Bucket::decode(&[]), Err(Error::BadFormat)));
    }

    #[test]
    fn every_single_byte_flip_is_either_refused_or_decodes_to_a_coherent_bucket() {
        // La garantía que de verdad importa (invariante 2): un byte
        // cambiado no puede producir un bucket que MIENTA. O sale `Err`, o
        // sale un bucket que cumple sus propias relaciones — nunca un
        // `requests` que no case con su histograma.
        let full = sample().encode();
        let mut refused = 0usize;
        let mut accepted = 0usize;
        for i in 0..full.len() {
            for bit in 0..8 {
                let mut m = full.clone();
                m[i] ^= 1 << bit;
                match Bucket::decode(&m) {
                    Err(_) => refused += 1,
                    Ok(b) => {
                        accepted += 1;
                        assert!(b.errors <= b.requests);
                        assert_eq!(b.hist.total(), b.requests);
                        assert_eq!(b.encode(), m, "la codificación tiene que ser única");
                    }
                }
            }
        }
        assert!(refused > 0 && refused + accepted == full.len() * 8);
    }

    #[test]
    fn errors_above_requests_is_refused() {
        let mut b = sample();
        b.errors = b.requests + 1;
        assert!(Bucket::decode(&b.encode()).is_err());
    }

    #[test]
    fn a_histogram_that_does_not_sum_to_requests_is_refused() {
        let mut b = sample();
        b.requests += 1;
        assert!(Bucket::decode(&b.encode()).is_err());
    }

    #[test]
    fn a_max_latency_outside_its_own_bucket_is_refused() {
        let mut b = sample();
        // 900 ms está en la cubeta 10 ([512, 1023]); 1024 sube a la 11, que
        // el histograma no tiene poblada.
        b.max_latency = 1024;
        assert!(Bucket::decode(&b.encode()).is_err());
        // Y por debajo también: 100 ms deja la cubeta 10 poblada sin que
        // ninguna muestra la justifique.
        b.max_latency = 100;
        assert!(Bucket::decode(&b.encode()).is_err());
    }

    #[test]
    fn a_mask_bit_with_a_zero_count_is_refused() {
        // Se construye a mano: `encode` nunca produce esto.
        let mut bytes = Vec::new();
        bytes.push(BUCKET_VERSION);
        let mut tmp = [0u8; 10];
        for v in [1u64, 0, 0, 0, 1] {
            let n = varint::write(&mut tmp, v);
            bytes.extend_from_slice(&tmp[..n]);
        }
        let n = varint::write(&mut tmp, 0b11); // cubetas 0 y 1
        bytes.extend_from_slice(&tmp[..n]);
        let n = varint::write(&mut tmp, 1);
        bytes.extend_from_slice(&tmp[..n]);
        let n = varint::write(&mut tmp, 0); // cuenta cero con el bit puesto
        bytes.extend_from_slice(&tmp[..n]);
        assert!(Bucket::decode(&bytes).is_err());
    }

    #[test]
    fn a_mask_with_bits_above_sixteen_is_refused() {
        let mut bytes = Vec::new();
        bytes.push(BUCKET_VERSION);
        let mut tmp = [0u8; 10];
        for v in [0u64, 0, 0, 0, 0] {
            let n = varint::write(&mut tmp, v);
            bytes.extend_from_slice(&tmp[..n]);
        }
        let n = varint::write(&mut tmp, 1 << 20);
        bytes.extend_from_slice(&tmp[..n]);
        assert!(Bucket::decode(&bytes).is_err());
    }

    #[test]
    fn merge_is_commutative_and_conserves_every_field() {
        let a = sample();
        let mut b = Bucket::new();
        b.record(7, 1, 2, true).unwrap();
        b.record(20_000, 3, 4, false).unwrap();

        let mut ab = a;
        ab.merge(&b).unwrap();
        let mut ba = b;
        ba.merge(&a).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.requests, a.requests + b.requests);
        assert_eq!(ab.errors, a.errors + b.errors);
        assert_eq!(ab.bytes_in, a.bytes_in + b.bytes_in);
        assert_eq!(ab.bytes_out, a.bytes_out + b.bytes_out);
        assert_eq!(ab.max_latency, a.max_latency.max(b.max_latency));
        assert_eq!(Bucket::decode(&ab.encode()).unwrap(), ab, "la fusión sigue siendo decodable");
    }

    #[test]
    fn record_refuses_to_overflow_instead_of_wrapping() {
        let mut b = Bucket::new();
        b.bytes_out = u64::MAX;
        assert!(b.record(1, 0, 1, false).is_err());
        let mut b = Bucket::new();
        b.requests = u64::MAX;
        assert!(b.record(1, 0, 0, false).is_err());
    }
}
