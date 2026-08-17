# inro

> From the Japanese 印籠 (*inrō*): the small, tightly fitted case that held a
> seal and its ink — carried on the belt, holding everything essential in the
> least possible space.

**inro** is an embedded key-value database engine written in pure Rust, designed
around a single dominant criterion: the smallest possible consumption of **disk,
RAM and CPU**.

It is deliberately the counterpart to [Arkeion](https://gitlab.com/syrakon/arkeion).
Arkeion optimises for auditability, versioning and query power. inro optimises for
footprint, and gives up SQL, time-travel and branching to get there.

## Target environments

- **Edge and IoT.** Few megabytes of RAM, slow CPUs, flash with limited write
  endurance, single process.
- **Multi-tenant servers.** Thousands of tiny databases open at once, one per
  tenant, where RAM per open database is the dominant cost.

## Design goals

- A freshly created database occupies under 2 KB.
- Constant, configurable RAM per open database.
- Opening a database costs a constant number of reads, whatever the file size.
- No background threads, no compaction, no periodic maintenance.

## Status

**Phase one — the core — is implemented and measured.** Copy-on-write B+tree,
free list, transactions with a single writer and lock-free readers, secondary
indexes, range delete by subtree unlink, per-page authenticated encryption, and
a temporal aggregation layer that lets reports outlive the raw records behind
them.

Measured, not estimated — a million synthetic rows with the exact shape of a
real request log, 4 KB pages:

| | |
|---|---|
| Bytes per log entry | **34.14** |
| A freshly created database | **1,536 bytes** |
| Opening a database | **4 physical reads**, identical at 30 KB, at 14 MB and at 2 GB |
| Same workload against SQLite | **39% smaller file**, pruning **123× faster** |
| Runtime dependencies | **zero** by default (`cargo tree --edges normal` is one line) |
| `unsafe` in inro itself | **zero**, forbidden crate-wide from `Cargo.toml` |

**There is no published API yet.** The crate name is reserved while the engine
lives in a private repository; phases two to four — RAM and CPU, append-only
segments, columnar encoding — are still ahead.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

Part of the [Syrakon](https://gitlab.com/syrakon) sovereign European data
infrastructure stack.
