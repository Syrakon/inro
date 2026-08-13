//! Disposición de la clave de un agregado, y los rangos que se derivan de
//! ella.
//!
//! ```text
//! [0x02][res u8][ts_bucket u32 BE][dim u8]                     ← totales
//! [0x02][res u8][ts_bucket u32 BE][dim u8][tag u8][valor...]   ← por dimensión
//! ```
//!
//! El primer byte, `0x02`, **no forma parte de lo que este módulo construye**:
//! es el espacio de claves, y el motor lo antepone él mismo en
//! `WriteTxn::put(ns, clave, valor)` (`tx::scoped`). Todo lo que se pasa por
//! aquí es la clave *dentro* del espacio. La especificación escribe la clave
//! entera como `[0x02][resolución][ts_bucket u32][dimensión...]` porque
//! describe los bytes en disco; el reparto entre argumento y clave es del
//! motor, no una desviación.
//!
//! ## `ts_bucket` en big-endian, y por qué no es cosmético
//!
//! El árbol ordena por bytes. Con big-endian, orden lexicográfico y orden
//! cronológico son el mismo, y de ahí salen las dos operaciones que el esquema
//! necesita: leer un intervalo de tiempo es UN recorrido de rango contiguo, y
//! podar todo lo anterior a un corte es UN `delete_range`, que libera
//! subárboles enteros sin visitar entrada por entrada. En little-endian ambas
//! degeneran en un recorrido completo con filtro.
//!
//! ## El cajón `otros` y el byte de tag
//!
//! `tag` separa el cajón (`TAG_OTROS`, sin nada detrás) de un valor literal
//! (`TAG_LITERAL`, seguido de los bytes del valor). Cuesta un byte por fila y
//! compra dos cosas:
//!
//! - **Imposible de confundir.** La alternativa de coste cero —reservar el
//!   valor vacío para el cajón— haría que un país desconocido, o cualquier
//!   dimensión que la aplicación deje en blanco, cayera en el cajón sin que
//!   nadie se entere. Eso es una respuesta equivocada silenciosa, que es lo
//!   que este proyecto trata peor que un error.
//! - **Un solo recorrido por dimensión.** Con `TAG_OTROS` a 0x00 el cajón
//!   ordena el primero dentro de su dimensión, así que el rango
//!   `[res][ts][dim] .. [res][ts][dim+1]` lo trae junto con las K entradas,
//!   sin una lectura puntual aparte.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Espacio de claves de los agregados. Convención del caso de uso de quota
/// (sección 10 de la especificación), **no** un espacio reservado del motor:
/// `arquitectura.md` documenta `0x01..0x7F` como datos de usuario, y este
/// módulo escribe con `WriteTxn::put` como cualquier otro llamante.
pub const AGG_NS: u8 = 0x02;

/// El cajón `otros`. Sin bytes detrás.
pub const TAG_OTROS: u8 = 0x00;
/// Un valor literal de la dimensión. Le siguen sus bytes.
pub const TAG_LITERAL: u8 = 0x01;

/// Longitud de la clave de un total: `[res][ts×4][dim]`.
pub const TOTAL_KEY_LEN: usize = 6;
/// Longitud mínima de la clave de una dimensión: la del total más el tag.
pub const DIM_KEY_MIN_LEN: usize = TOTAL_KEY_LEN + 1;

/// Clave del total de la celda `(res, ts_bucket)`.
pub fn total_key(res: u8, ts_bucket: u32, dim: u8) -> Vec<u8> {
    let mut k = Vec::with_capacity(TOTAL_KEY_LEN);
    k.push(res);
    k.extend_from_slice(&ts_bucket.to_be_bytes());
    k.push(dim);
    k
}

/// Clave de un valor concreto de una dimensión.
pub fn dim_key(res: u8, ts_bucket: u32, dim: u8, value: Option<&[u8]>) -> Vec<u8> {
    let mut k = total_key(res, ts_bucket, dim);
    match value {
        None => k.push(TAG_OTROS),
        Some(v) => {
            k.push(TAG_LITERAL);
            k.extend_from_slice(v);
        }
    }
    k
}

/// Prefijo `[res][ts_bucket]` de una celda entera.
pub fn cell_prefix(res: u8, ts_bucket: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(5);
    k.push(res);
    k.extend_from_slice(&ts_bucket.to_be_bytes());
    k
}

/// Rango `[desde, hasta)` que cubre la celda `(res, ts_bucket)` entera.
///
/// El límite superior es el prefijo de la celda SIGUIENTE. Cuando `ts_bucket`
/// es `u32::MAX` no hay siguiente, y se usa `[res + 1]`: un byte, que compara
/// mayor que cualquier clave que empiece por `res`. Y si además `res` es 255
/// —imposible con las tres resoluciones que existen, pero la aritmética no lo
/// sabe— el techo es la clave vacía extendida, `[0xff; 6]`, que sigue siendo
/// mayor que cualquier clave de esa resolución.
pub fn cell_range(res: u8, ts_bucket: u32) -> (Vec<u8>, Vec<u8>) {
    let from = cell_prefix(res, ts_bucket);
    let to = match ts_bucket.checked_add(1) {
        Some(next) => cell_prefix(res, next),
        None => match res.checked_add(1) {
            Some(r) => alloc::vec![r],
            None => alloc::vec![0xff; TOTAL_KEY_LEN + 1],
        },
    };
    (from, to)
}

/// Rango `[desde, hasta)` de una dimensión dentro de una celda: trae el cajón
/// y las K entradas de una vez.
pub fn dim_range(res: u8, ts_bucket: u32, dim: u8) -> (Vec<u8>, Vec<u8>) {
    let from = total_key(res, ts_bucket, dim);
    let to = match dim.checked_add(1) {
        Some(d) => total_key(res, ts_bucket, d),
        None => cell_range(res, ts_bucket).1,
    };
    (from, to)
}

/// Rango `[desde, hasta)` de una resolución entre dos `ts_bucket`.
pub fn bucket_range(res: u8, from_bucket: u32, to_bucket: u32) -> (Vec<u8>, Vec<u8>) {
    (cell_prefix(res, from_bucket), cell_prefix(res, to_bucket))
}

/// Clave descompuesta.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Parsed<'a> {
    pub res: u8,
    pub ts_bucket: u32,
    pub dim: u8,
    /// `None` en un total (no hay tag) y también en el cajón `otros`. Se
    /// distinguen por `dim`: `is_total` lo dice sin ambigüedad.
    pub value: Option<&'a [u8]>,
    pub is_total: bool,
}

/// Descompone una clave de agregado.
///
/// `total_dim` es el byte que marca la fila de totales; se pasa en vez de
/// codificarlo aquí para que este módulo no tenga que conocer el enumerado de
/// dimensiones, que vive un nivel más arriba.
///
/// Cualquier clave que no encaje —demasiado corta, un tag desconocido, un
/// total con bytes de sobra detrás— sale como `Err`. El espacio `0x02` es
/// escribible por la API pública (ver `AGG_NS`), así que estas claves pueden
/// venir de cualquiera y no se pueden suponer bien formadas.
pub fn parse(key: &[u8], total_dim: u8) -> Result<Parsed<'_>> {
    if key.len() < TOTAL_KEY_LEN {
        return Err(Error::BadFormat);
    }
    let res = key[0];
    let ts_bucket = u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
    let dim = key[5];
    if dim == total_dim {
        if key.len() != TOTAL_KEY_LEN {
            return Err(Error::BadFormat);
        }
        return Ok(Parsed { res, ts_bucket, dim, value: None, is_total: true });
    }
    if key.len() < DIM_KEY_MIN_LEN {
        return Err(Error::BadFormat);
    }
    let value = match key[TOTAL_KEY_LEN] {
        TAG_OTROS => {
            if key.len() != DIM_KEY_MIN_LEN {
                return Err(Error::BadFormat);
            }
            None
        }
        TAG_LITERAL => {
            // Un literal vacío no lo escribe nunca `dim_key` con
            // `Some(...)` no vacío, pero la aplicación sí puede pasar una
            // dimensión vacía y entonces esta clave es legítima: se acepta,
            // y es exactamente el caso que el byte de tag existe para NO
            // confundir con el cajón.
            Some(&key[DIM_KEY_MIN_LEN..])
        }
        _ => return Err(Error::BadFormat),
    };
    Ok(Parsed { res, ts_bucket, dim, value, is_total: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOTAL: u8 = 0;

    #[test]
    fn a_total_key_roundtrips() {
        let k = total_key(1, 12345, TOTAL);
        let p = parse(&k, TOTAL).unwrap();
        assert_eq!((p.res, p.ts_bucket, p.dim, p.is_total, p.value), (1, 12345, TOTAL, true, None));
    }

    #[test]
    fn a_literal_and_the_drawer_never_collide() {
        let drawer = dim_key(1, 7, 2, None);
        let empty = dim_key(1, 7, 2, Some(b""));
        assert_ne!(drawer, empty, "el cajón y una dimensión vacía tienen que ser claves distintas");
        assert_eq!(parse(&drawer, TOTAL).unwrap().value, None);
        assert_eq!(parse(&empty, TOTAL).unwrap().value, Some(&b""[..]));
    }

    #[test]
    fn keys_sort_chronologically_because_the_timestamp_is_big_endian() {
        // La propiedad de la que dependen `scan` y `delete_range`.
        let mut ks: Vec<Vec<u8>> = alloc::vec![
            total_key(1, 300, TOTAL),
            total_key(1, 2, TOTAL),
            total_key(1, 70_000, TOTAL),
            total_key(1, 0, TOTAL),
            total_key(1, u32::MAX, TOTAL),
        ];
        let expected = alloc::vec![0u32, 2, 300, 70_000, u32::MAX];
        ks.sort();
        let got: Vec<u32> = ks.iter().map(|k| parse(k, TOTAL).unwrap().ts_bucket).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn a_cell_range_covers_its_own_rows_and_no_others() {
        let (from, to) = cell_range(1, 100);
        for dim in [0u8, 1, 2, 3, 4] {
            let k = if dim == TOTAL { total_key(1, 100, dim) } else { dim_key(1, 100, dim, Some(b"x")) };
            assert!(k >= from && k < to, "dim {dim} fuera del rango de su celda");
        }
        assert!(total_key(1, 99, TOTAL) < from);
        assert!(total_key(1, 101, TOTAL) >= to);
        // Otra resolución no entra jamás.
        assert!(total_key(2, 100, TOTAL) >= to);
        assert!(total_key(0, 100, TOTAL) < from);
    }

    #[test]
    fn a_dim_range_brings_the_drawer_along_with_the_entries() {
        let (from, to) = dim_range(1, 100, 2);
        assert!(dim_key(1, 100, 2, None) >= from);
        assert!(dim_key(1, 100, 2, None) < to);
        assert!(dim_key(1, 100, 2, Some(&[0xff; MAXV])) < to);
        assert!(dim_key(1, 100, 3, None) >= to, "no se cuela la dimensión siguiente");
        assert!(total_key(1, 100, TOTAL) < from);
    }
    const MAXV: usize = 64;

    #[test]
    fn the_last_bucket_of_a_resolution_still_has_a_valid_upper_bound() {
        let (from, to) = cell_range(1, u32::MAX);
        assert!(from < to);
        assert!(total_key(1, u32::MAX, TOTAL) >= from);
        assert!(total_key(1, u32::MAX, TOTAL) < to);
        let (from, to) = cell_range(255, u32::MAX);
        assert!(from < to);
        assert!(dim_key(255, u32::MAX, 255, Some(&[0xff; 8])) < to);
    }

    #[test]
    fn a_malformed_key_is_refused_instead_of_decoded_wrong() {
        assert!(parse(&[], TOTAL).is_err());
        assert!(parse(&[1, 2, 3, 4, 5], TOTAL).is_err(), "clave corta");
        // Total con basura detrás.
        let mut k = total_key(1, 5, TOTAL);
        k.push(9);
        assert!(parse(&k, TOTAL).is_err());
        // Tag desconocido.
        let mut k = total_key(1, 5, 2);
        k.push(0x7f);
        assert!(parse(&k, TOTAL).is_err());
        // Cajón con bytes detrás.
        let mut k = dim_key(1, 5, 2, None);
        k.push(0);
        assert!(parse(&k, TOTAL).is_err());
        // Dimensión sin tag.
        let k = total_key(1, 5, 2);
        assert!(parse(&k, TOTAL).is_err());
    }

    #[test]
    fn every_truncation_of_a_valid_key_is_refused_or_parses_coherently() {
        let full = dim_key(1, 999, 3, Some(b"/api/v1/orders"));
        for cut in 0..full.len() {
            if let Ok(p) = parse(&full[..cut], TOTAL) {
                // Si acepta, tiene que ser porque el prefijo es en sí una
                // clave válida más corta — nunca una lectura fuera de rango.
                assert!(cut >= TOTAL_KEY_LEN);
                assert_eq!(p.res, 1);
            }
        }
    }
}
