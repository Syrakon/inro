//! CRC-32 (IEEE 802.3, polinomio reflejado 0xEDB88320), escrito a mano en
//! lugar de una dependencia.
//!
//! **Es el bucle más caliente del motor, no una utilidad de formato.**
//! `PageRef::parse` verifica el CRC de la página ENTERA en cada acceso, y la
//! caché del `Pager` guarda BYTES, no páginas ya validadas: un acierto de
//! caché vuelve a pagar el CRC completo. Medido (ver más abajo), una
//! búsqueda puntual a profundidad 3 hace cuatro `parse` y gasta el 80 % de
//! su tiempo aquí dentro.
//!
//! ## Dos implementaciones, una salida
//!
//! Producen el MISMO CRC byte a byte —lo comprueba
//! `slice_by_eight_matches_the_byte_at_a_time_oracle` contra el bucle byte
//! a byte original, sobre muchas longitudes y muchos troceados—; lo único
//! que cambia es cuánta tabla estática se paga por cuánta velocidad.
//!
//! Medido en `--release` sobre 4092 bytes (una página de 4096 menos su
//! propio campo de CRC), Intel Haswell a 3,1 GHz, mediana de cuatro
//! corridas:
//!
//! | Implementación | Tabla | ns/byte | µs/página | MB/s | vs. byte a byte |
//! |---|---:|---:|---:|---:|---:|
//! | byte a byte | 1 KB | 2,38 | 9,72 | 421 | 1,0× |
//! | slice-by-4 | 4 KB | 0,80 | 3,28 | 1 249 | 3,0× |
//! | **slice-by-8** | **8 KB** | **0,53** | **2,17** | **1 888** | **4,5×** |
//!
//! De punta a punta, sobre una base de 300 000 entradas con la forma de una
//! serie temporal por nodo (páginas de 4096 B, árbol de profundidad 3):
//!
//! | | antes | después |
//! |---|---:|---:|
//! | `PageRef::parse` (142 slots) | 11,47 µs | 4,45 µs |
//! | `get` puntual (4 `parse`) | 46,4 µs | 18,2 µs |
//! | `scan` completo, por entrada | 11,38 µs | 4,28 µs |
//!
//! El suelo que queda es el `parse` sin CRC (2,18 µs) y la lectura de
//! página: con el CRC ya en 2,17 µs, el bucle de validación de slots pasa
//! a ser la mitad del coste de `parse`, y ya no tiene sentido volver aquí
//! antes que a él.
//!
//! ## Por qué el reparto va atado a `std`, y no es una excusa para no elegir
//!
//! Los 8 KB de tablas NO son gratis en un microcontrolador: son 8 KB de
//! `.rodata` —flash, no RAM: el consumo de RAM no se mueve— que en una
//! pieza de 64 KB son el 12 % del presupuesto entero. Pagarlos en todas
//! partes contradiría el criterio dominante del crate. Pero el reparto de
//! coste y beneficio no es simétrico, y por eso la línea cae donde cae:
//!
//! - **De dónde sale la ganancia.** El bucle byte a byte no está limitado
//!   por trabajo sino por LATENCIA: cada iteración necesita el resultado de
//!   la carga de tabla de la anterior. 2,38 ns/byte son ~7,4 ciclos por
//!   byte para dos operaciones de ALU y una carga de L1. Slice-by-8 rompe
//!   esa cadena en ocho cargas INDEPENDIENTES por cada 8 bytes: el mismo
//!   número de cargas por byte, pero solapables. Eso lo cobra un núcleo
//!   fuera de orden con caché de datos —exactamente la máquina que tiene
//!   `std`—; un Cortex-M en orden y sin caché no puede solapar nada y se
//!   queda con una fracción de la mejora, pagando los 8 KB enteros.
//! - **Dónde está el volumen.** Sin `std` no hay `pager`, ni `tree`, ni
//!   transacciones (ver `lib.rs`): la compilación `no_std` es la capa de
//!   formato pura, donde quien integra parsea páginas sueltas a mano. Los
//!   cuatro CRC de página por `get` y el CRC por entrada recorrida existen
//!   solo en el motor completo, que es el que lleva `std`.
//!
//! Beneficio concentrado donde está `std`, coste concentrado donde no está.
//! La alternativa intermedia —slice-by-4 en todas partes, 4 KB— se midió y
//! se descartó: se queda 1,51× por detrás de slice-by-8 (0,80 contra 0,53
//! ns/byte, ~4 µs más por `get`) y seguiría cobrándole 3 KB extra al
//! microcontrolador que menos partido les saca. Repartir el coste rinde
//! más que promediarlo.

/// Tablas de 256 entradas: ocho con `std` (slice-by-8), una sin `std`
/// (byte a byte). Ver la nota del módulo para el porqué del reparto.
#[cfg(feature = "std")]
const N_TABLES: usize = 8;
#[cfg(not(feature = "std"))]
const N_TABLES: usize = 1;

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// `TABLES[0]` es la tabla de siempre: el CRC de un byte suelto.
/// `TABLES[n][i]` es el de ese mismo byte seguido de `n` ceros, que es lo
/// que deja avanzar ocho bytes de una vez — cada byte del bloque aporta su
/// contribución ya desplazada hasta el final del bloque, y las ocho se
/// combinan con XOR. Se deriva de la anterior con un paso del mismo bucle
/// byte a byte, así que las ocho salen de una sola definición del
/// polinomio: `make_table`.
const fn make_tables() -> [[u32; 256]; N_TABLES] {
    let mut t = [[0u32; 256]; N_TABLES];
    t[0] = make_table();
    let mut n = 1;
    while n < N_TABLES {
        let mut i = 0;
        while i < 256 {
            let prev = t[n - 1][i];
            t[n][i] = t[0][(prev & 0xff) as usize] ^ (prev >> 8);
            i += 1;
        }
        n += 1;
    }
    t
}

static TABLES: [[u32; 256]; N_TABLES] = make_tables();

/// Acumulador incremental. Hace falta porque el CRC de una página cubre
/// tramos no contiguos: todo menos el propio campo de CRC.
#[derive(Clone)]
pub struct Hasher(u32);

impl Hasher {
    pub fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    /// Slice-by-8: consume ocho bytes por vuelta y termina el resto byte a
    /// byte.
    ///
    /// **El resto se maneja por llamada, no por mensaje, y tiene que ser
    /// así**: `update` recibe trozos de longitud arbitraria (una página
    /// llega en dos, `..8` y `12..`), y el estado de un CRC es solo `c`, así
    /// que cortar en cualquier sitio y seguir da el mismo resultado. Un
    /// trozo de 3 bytes se procesa entero byte a byte y el siguiente vuelve
    /// a arrancar el bucle de ocho: los bloques de ocho NO tienen que estar
    /// alineados con el principio del mensaje.
    ///
    /// `from_le_bytes` sobre bytes ya extraídos del slice, y no una lectura
    /// de `u64` del buffer, es lo que hace esto independiente del orden de
    /// bytes de la máquina: el índice de cada tabla sale de la POSICIÓN del
    /// byte en el flujo, que es la misma en little y en big endian.
    #[cfg(feature = "std")]
    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        let mut blocks = data.chunks_exact(8);
        for w in blocks.by_ref() {
            let lo = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) ^ c;
            let hi = u32::from_le_bytes([w[4], w[5], w[6], w[7]]);
            c = TABLES[7][(lo & 0xff) as usize]
                ^ TABLES[6][((lo >> 8) & 0xff) as usize]
                ^ TABLES[5][((lo >> 16) & 0xff) as usize]
                ^ TABLES[4][(lo >> 24) as usize]
                ^ TABLES[3][(hi & 0xff) as usize]
                ^ TABLES[2][((hi >> 8) & 0xff) as usize]
                ^ TABLES[1][((hi >> 16) & 0xff) as usize]
                ^ TABLES[0][(hi >> 24) as usize];
        }
        for &byte in blocks.remainder() {
            c = TABLES[0][((c ^ byte as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    /// Byte a byte contra una sola tabla de 1 KB. Ver la nota del módulo:
    /// sin `std` no hay motor que amortice ocho tablas, y el núcleo que las
    /// pagaría no puede solapar sus cargas.
    #[cfg(not(feature = "std"))]
    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        for &byte in data {
            c = TABLES[0][((c ^ byte as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    pub fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

/// CRC-32 de `data`.
pub fn checksum(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn matches_known_vectors() {
        assert_eq!(checksum(b""), 0x0000_0000);
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
        assert_eq!(checksum(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut h = Hasher::new();
        h.update(b"1234");
        h.update(b"56789");
        assert_eq!(h.finish(), checksum(b"123456789"));
    }

    /// La implementación byte a byte contra una sola tabla: lo que había
    /// aquí antes de slice-by-8, conservada literalmente como oráculo.
    fn oracle(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &byte in data {
            c = TABLES[0][((c ^ byte as u32) & 0xff) as usize] ^ (c >> 8);
        }
        c ^ 0xFFFF_FFFF
    }

    /// Bytes pseudoaleatorios reproducibles: un LCG, para que un fallo
    /// siempre se reproduzca con los mismos datos.
    fn pseudorandom(len: usize, seed: u32) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (s >> 24) as u8
            })
            .collect()
    }

    /// El oráculo no vale de nada si la tabla de la que tira está mal, así
    /// que la tabla se contrasta a su vez contra el polinomio bit a bit,
    /// sin ninguna tabla de por medio. Cierra el círculo: polinomio →
    /// `TABLES[0]` → oráculo → slice-by-8.
    #[test]
    fn table_zero_matches_the_bitwise_polynomial() {
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            assert_eq!(TABLES[0][i as usize], c, "entrada {i} de TABLES[0]");
        }
    }

    /// Cada tabla derivada tiene que ser "el byte de la anterior, avanzado
    /// un puesto más": si `TABLES[n]` se genera mal, slice-by-8 falla solo
    /// para algunos bytes de algunas posiciones, que es justo el error que
    /// los vectores conocidos no ven.
    #[cfg(feature = "std")]
    #[test]
    fn each_derived_table_advances_one_more_zero_byte() {
        for (n, table) in TABLES.iter().enumerate().skip(1) {
            for (i, &entry) in table.iter().enumerate() {
                // El CRC de `i` seguido de `n` bytes cero, calculado byte a
                // byte sin usar `table`.
                let mut c = TABLES[0][i];
                for _ in 0..n {
                    c = TABLES[0][(c & 0xff) as usize] ^ (c >> 8);
                }
                assert_eq!(entry, c, "TABLES[{n}][{i}]");
            }
        }
    }

    /// El caso que los vectores conocidos no cubren: longitudes que no son
    /// múltiplo de 8 y troceados que parten un bloque de ocho por la mitad.
    /// `update` se llama con trozos arbitrarios en producción —el CRC de
    /// una página son dos llamadas, `..8` y `12..`— así que el resto no
    /// puede depender de dónde empiece el mensaje.
    #[test]
    fn slice_by_eight_matches_the_byte_at_a_time_oracle() {
        // Longitudes: todas de 0 a 129 (cubre 0, <8, exactamente 8, y todos
        // los restos posibles varias veces), más tamaños de página reales.
        let lens: Vec<usize> = (0..=129).chain([255, 256, 511, 512, 4084, 4092, 4096]).collect();

        for len in lens {
            let data = pseudorandom(len, len as u32 + 7);
            let expected = oracle(&data);
            assert_eq!(checksum(&data), expected, "una sola llamada, longitud {len}");

            // 1) Todos los cortes en dos posibles. Para len >= 8 esto parte
            //    un bloque de ocho por la mitad en la mayoría de los casos.
            for split in 0..=len {
                let mut h = Hasher::new();
                h.update(&data[..split]);
                h.update(&data[split..]);
                assert_eq!(h.finish(), expected, "longitud {len}, corte en {split}");
            }

            // 2) Troceados en muchos trozos de tamaño irregular, incluidos
            //    trozos vacíos y trozos de 1..=9 bytes (nunca alineados con
            //    el bloque de ocho).
            for pattern in [
                &[1usize, 2, 3, 4, 5, 6, 7][..],
                &[3, 5, 9, 1, 7][..],
                &[0, 1, 0, 8, 0, 9][..],
                &[9, 9, 9][..],
                &[7, 1][..],
                &[1][..],
            ] {
                let mut h = Hasher::new();
                let mut at = 0;
                let mut k = 0;
                while at < len {
                    let take = pattern[k % pattern.len()].min(len - at);
                    h.update(&data[at..at + take]);
                    at += take;
                    k += 1;
                    // Un patrón que solo tuviera ceros no avanzaría nunca:
                    // el `.min` de arriba no lo impide, este `if` sí.
                    if pattern.iter().all(|&p| p == 0) {
                        break;
                    }
                }
                assert_eq!(h.finish(), expected, "longitud {len}, patrón {pattern:?}");
            }
        }
    }

    /// Un byte cambiado en cualquier posición tiene que cambiar el CRC —
    /// incluidas las posiciones del último bloque incompleto, que es donde
    /// un slice-by-N mal escrito se deja bytes sin procesar.
    #[test]
    fn every_byte_position_affects_the_checksum() {
        for len in [1usize, 7, 8, 9, 15, 16, 17, 4092] {
            let data = pseudorandom(len, 12345);
            let base = checksum(&data);
            for i in 0..len {
                let mut m = data.clone();
                m[i] ^= 0x80;
                assert_ne!(checksum(&m), base, "longitud {len}, byte {i} sin efecto");
            }
        }
    }
}
