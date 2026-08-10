//! # inro
//!
//! Minimum-footprint embedded key-value database engine, in pure Rust.
//!
//! inro is designed around a single dominant criterion: the smallest possible
//! consumption of disk, RAM and CPU. It targets two environments — resource-
//! constrained edge and IoT devices, and servers holding thousands of tiny
//! per-tenant databases in one process.
//!
//! **This release reserves the crate name.** The engine is under active design
//! and no public API is available yet. See the repository for status.

#![forbid(unsafe_code)]
#![no_std]
