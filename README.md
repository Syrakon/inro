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

**Name reservation.** The design is complete and implementation has not started.
There is no public API yet.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

Part of the [Syrakon](https://gitlab.com/syrakon) sovereign European data
infrastructure stack.
