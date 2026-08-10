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

pub use error::{CorruptKind, Error, IoError, Result};

/// Número de página. El fichero direcciona 2^32 páginas: 2 TB con páginas de
/// 512 bytes, 16 TB con páginas de 4 KB.
pub type PageNo = u32;

/// Identificador de transacción. Monótono y nunca reutilizado: de él depende
/// la unicidad del nonce de cifrado (tarea 18).
pub type TxnId = u64;
