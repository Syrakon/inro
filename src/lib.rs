//! # inro
//!
//! Minimum-footprint embedded key-value database engine, in pure Rust.
//!
//! inro is designed around a single dominant criterion: the smallest possible
//! consumption of disk, RAM and CPU. It targets resource-constrained edge and
//! IoT devices, and servers holding thousands of tiny per-tenant databases.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub(crate) mod crc32;
pub(crate) mod varint;
pub mod storage;
// `header`, `meta` y `page` son el formato de fichero puro — estructuras y
// funciones sobre `&[u8]`, sin `std::sync`/`std::fs` — deliberadamente
// utilizables sin la parte `std` del motor (`tx`/`tree`/`pager`/`freelist`,
// más abajo), a diferencia de esos cuatro. Por eso NO se tocan en la ronda 3
// de revisión de la tarea 16, aunque el mismo razonamiento que reduce el
// resto del API a `Db`/`WriteTxn`/`ReadTxn` se aplique a primera vista:
// hacerlos `pub(crate)` sí se probó, y `cargo build --no-default-features`
// pasó de cero avisos a treinta — sin `tx`/`tree` (que son su único
// consumidor interno, y están tras `#[cfg(feature = "std")]`) esas
// estructuras dejan de tener NINGÚN llamador dentro del crate en una
// compilación `no_std`, y el análisis de código muerto las señala en
// cascada hasta `crc32`/`varint`. Mantenerlos como el resto del crate
// (`pub mod`, exactamente como ya estaban) preserva ese uso — sí
// intencional, no un descuido — sin reabrir ninguna vía de escritura: nada
// de lo que hay aquí dentro deja tocar un `Db` vivo, porque para eso hacen
// falta `WriteTxn::write_page`/`alloc`/`set_root`, que sí quedan cerrados
// más abajo. `MIN_PAGE_SIZE`/`MAX_PAGE_SIZE` de `header` se reexportan
// sueltas más abajo por comodidad: es el único sitio donde se puede
// consultar el rango válido de `Options::page_size` sin adivinarlo a base
// de `Db::create` fallando con `BadFormat`.
pub mod header;
pub mod meta;
pub mod page;
#[cfg(feature = "std")]
pub(crate) mod pager;
#[cfg(feature = "std")]
pub(crate) mod freelist;
// `tx` se queda `pub(crate)` por la misma razón: `WriteTxn`/`ReadTxn` viven
// aquí, pero el módulo en sí no debe ser navegable desde fuera del crate —
// solo los tipos que de verdad forman el API público, reexportados sueltos
// más abajo. La diferencia entre "el tipo es público" y "el módulo que lo
// define es público" es exactamente lo que cierra este hallazgo: antes,
// `pub mod tx` hacía navegable `inro::tx::WriteTxn::write_page` aunque nadie
// lo pensara como parte del API — ahora ese camino no existe, solo
// `inro::WriteTxn` con los métodos que de verdad pertenecen al contrato.
#[cfg(feature = "std")]
pub(crate) mod tx;
// `tree` es el árbol crudo: `put`/`delete`/`delete_range`/`get` aquí no
// saben nada de índices ni de espacios de claves con significado — son las
// funciones que `WriteTxn::put`/`delete`/`delete_range` envuelven
// precisamente para mantener el índice a la vez que el dato (tarea 16).
// Antes de esta ronda, `pub mod tree` las dejaba llamables directamente
// desde fuera del crate con una clave `[ns] ++ pk` construida a mano,
// saltándose el envoltorio entero y dejando el índice divergiendo en
// silencio — la revisión lo demostró así. `pub(crate)` cierra ese camino
// por construcción: ningún `pub fn` de dentro de `tree` es alcanzable desde
// fuera del crate mientras el propio módulo no lo sea, sin tener que
// auditar cada función una a una (mismo patrón que ya usan `crc32`/
// `varint` en este fichero).
//
// `Cursor` es la única excepción: `ReadTxn::scan` lo devuelve, así que
// tiene que poder nombrarse desde fuera aunque el módulo que lo define no
// sea navegable — se reexporta suelto más abajo. Su constructor
// (`Cursor::new`) se queda `pub(crate)` en `tree.rs`: la única forma
// sancionada de conseguir un `Cursor` es `ReadTxn::scan`, que ya fija su
// `root` al de la transacción — un constructor público habría dejado
// reconstruir uno con un `root` arbitrario, otro camino para leer el árbol
// sin pasar por `Db`.
#[cfg(feature = "std")]
pub(crate) mod tree;
#[cfg(feature = "std")]
pub mod index;

pub use error::{CorruptKind, Error, IoError, Result};
pub use storage::Storage;
pub use header::{MAX_PAGE_SIZE, MIN_PAGE_SIZE};
#[cfg(feature = "std")]
pub use tx::{Db, Options, ReadTxn, Sync, WriteTxn};
#[cfg(feature = "std")]
pub use index::IndexDef;
#[cfg(feature = "std")]
pub use tree::Cursor;

/// Número de página. El fichero direcciona 2^32 páginas: 2 TB con páginas de
/// 512 bytes, 16 TB con páginas de 4 KB.
pub type PageNo = u32;

/// Identificador de transacción. Monótono y nunca reutilizado: de él depende
/// la unicidad del nonce de cifrado (tarea 18).
pub type TxnId = u64;
