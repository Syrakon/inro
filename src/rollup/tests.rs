//! Pruebas de la capa de agregación que necesitan una base viva.
//!
//! Las de codificación pura (histograma, bucket, clave, top-K) viven en su
//! propio módulo y corren también bajo `--no-default-features --features
//! rollup`. Este fichero está tras `std` porque monta un `Db` de verdad.

#![cfg(feature = "std")]

use super::*;
use crate::storage::MemStorage;
use crate::tx::{Db, Options, Sync};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;

fn db() -> Db {
    Db::create(
        Box::new(MemStorage::new()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap()
}

/// Instante base: 2026-08-13T00:00:00Z redondeado a un día exacto.
const T0: u64 = 1_786_320_000;

fn obs<'a>(ts: u64, endpoint: &'a [u8], status: u16, latency: u32) -> Observation<'a> {
    Observation {
        ts,
        latency_ms: latency,
        bytes_in: 100,
        bytes_out: 1000,
        status,
        error: status >= 500,
        endpoint,
        country: b"ES",
        user: b"u1",
    }
}

/// Generador congruencial lineal propio; `rand` sería una dependencia.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

#[test]
fn a_single_observation_lands_in_all_three_resolutions() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(T0 + 7, b"/a", 200, 12)).unwrap();
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    for res in RESOLUTIONS {
        let tsb = res.bucket_of(T0 + 7).unwrap();
        let t = read_total(&rd, res, tsb).unwrap().expect("falta el total");
        assert_eq!(t.requests, 1, "{res:?}");
        assert_eq!(t.bytes_out, 1000);
        assert_eq!(t.max_latency, 12);
    }
}

#[test]
fn the_minute_resolution_keeps_only_totals_and_status() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(T0, b"/a", 200, 5)).unwrap();
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let tsb = Resolution::Minute.bucket_of(T0).unwrap();
    assert!(!read_dimension(&rd, Resolution::Minute, tsb, Dimension::Status).unwrap().is_empty());
    for d in [Dimension::Endpoint, Dimension::Country, Dimension::User] {
        assert!(
            read_dimension(&rd, Resolution::Minute, tsb, d).unwrap().is_empty(),
            "{d:?} no debería existir en resolución de minuto"
        );
    }
    let tsb = Resolution::Hour.bucket_of(T0).unwrap();
    for d in [Dimension::Status, Dimension::Endpoint, Dimension::Country, Dimension::User] {
        assert!(
            !read_dimension(&rd, Resolution::Hour, tsb, d).unwrap().is_empty(),
            "{d:?} falta en resolución de hora"
        );
    }
}

/// La propiedad central del esquema: lo que dicen las filas de una dimensión,
/// cajón incluido, suma exactamente lo que dice la fila de totales.
#[test]
fn the_dimension_rows_plus_the_drawer_always_add_up_to_the_total() {
    let db = db();
    let mut r = Rollup::new(Config { top_k: 8, ..Config::default() });
    let mut n = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;
    for batch in 0..5 {
        let mut tx = db.begin_write().unwrap();
        for i in 0..400u32 {
            let ep = format!("/users/{}/orders", i % 97);
            let status = if i % 31 == 0 { 500 } else { 200 };
            let mut o = obs(T0 + (batch * 400 + i) as u64 % 3000, ep.as_bytes(), status, i % 900);
            o.bytes_out = 7;
            r.observe(&mut tx, &o).unwrap();
            n += 1;
            bytes += 7;
            if status >= 500 {
                errors += 1;
            }
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();
    }

    let rd = db.begin_read();
    let mut total_req = 0u64;
    let mut total_bytes = 0u64;
    let mut total_err = 0u64;
    // Suma de todas las celdas de la resolución horaria.
    let rows = read_range(&rd, Resolution::Hour, 0, u32::MAX, 100_000).unwrap();
    let mut by_dim: alloc::collections::BTreeMap<(u32, u8), (u64, u64, u64)> =
        alloc::collections::BTreeMap::new();
    for row in &rows {
        if row.dim == Dimension::Total {
            total_req += row.bucket.requests;
            total_bytes += row.bucket.bytes_out;
            total_err += row.bucket.errors;
        } else {
            let e = by_dim.entry((row.ts_bucket, row.dim.code())).or_default();
            e.0 += row.bucket.requests;
            e.1 += row.bucket.bytes_out;
            e.2 += row.bucket.errors;
        }
    }
    assert_eq!(total_req, n, "los totales no cuadran con lo observado");
    assert_eq!(total_bytes, bytes);
    assert_eq!(total_err, errors);

    // Y cada dimensión, celda a celda, suma su propio total.
    let mut totals: alloc::collections::BTreeMap<u32, u64> = alloc::collections::BTreeMap::new();
    for row in &rows {
        if row.dim == Dimension::Total {
            totals.insert(row.ts_bucket, row.bucket.requests);
        }
    }
    for ((tsb, dim), (req, b, err)) in by_dim {
        let t = totals[&tsb];
        assert_eq!(req, t, "dimensión {dim} de la celda {tsb} no suma el total");
        assert_eq!(b, t * 7);
        let _ = err;
    }
}

#[test]
fn the_number_of_rows_per_cell_is_bounded_by_k_however_wild_the_cardinality() {
    let db = db();
    let k = 8u16;
    let mut r = Rollup::new(Config { top_k: k, ..Config::default() });
    let mut tx = db.begin_write().unwrap();
    for i in 0..5_000u32 {
        // Una ruta distinta por petición: el ataque de la sección 12.4.
        let ep = format!("/users/{i}/orders");
        r.observe(&mut tx, &obs(T0 + 1, ep.as_bytes(), 200, 3)).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 1).unwrap();
    let rows = read_dimension(&rd, Resolution::Hour, tsb, Dimension::Endpoint).unwrap();
    assert!(
        rows.len() <= k as usize + 1,
        "{} filas para 5000 rutas distintas, por encima de K+1 = {}",
        rows.len(),
        k + 1
    );
    let drawer = rows.iter().find(|r| r.is_drawer()).expect("falta el cajón otros");
    assert!(drawer.bucket.requests > 0);
    let sum: u64 = rows.iter().map(|r| r.bucket.requests).sum();
    assert_eq!(sum, 5_000, "el cajón tiene que recoger todo lo desalojado");
}

#[test]
fn a_second_batch_extends_the_same_cell_instead_of_replacing_it() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    for _ in 0..3 {
        let mut tx = db.begin_write().unwrap();
        for _ in 0..10 {
            r.observe(&mut tx, &obs(T0 + 5, b"/a", 200, 4)).unwrap();
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();
    }
    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 5).unwrap();
    assert_eq!(read_total(&rd, Resolution::Hour, tsb).unwrap().unwrap().requests, 30);
}

/// El caso que motiva la carga desde disco: el proceso se reinicia a mitad de
/// hora y el `Rollup` arranca vacío. Sin carga, el primer volcado
/// sobrescribiría la fila con solo lo visto desde el arranque.
#[test]
fn a_restarted_rollup_does_not_overwrite_what_was_already_on_disk() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    for _ in 0..10 {
        r.observe(&mut tx, &obs(T0 + 5, b"/a", 200, 4)).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    // Reinicio: un `Rollup` nuevo, sin nada en RAM.
    let mut r2 = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    for _ in 0..5 {
        r2.observe(&mut tx, &obs(T0 + 5, b"/a", 200, 4)).unwrap();
    }
    r2.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 5).unwrap();
    assert_eq!(
        read_total(&rd, Resolution::Hour, tsb).unwrap().unwrap().requests,
        15,
        "el reinicio perdió lo que ya estaba en disco"
    );
    let ep = read_dimension(&rd, Resolution::Hour, tsb, Dimension::Endpoint).unwrap();
    assert_eq!(ep.len(), 1);
    assert_eq!(ep[0].bucket.requests, 15);
}

/// Lo que garantiza que el agregado no puede desincronizarse del crudo: si la
/// transacción no confirma, no se escribe NI el crudo NI el agregado.
#[test]
fn an_aborted_transaction_leaves_neither_the_raw_record_nor_the_aggregate() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    {
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"clave", b"valor").unwrap();
        r.observe(&mut tx, &obs(T0 + 5, b"/a", 200, 4)).unwrap();
        r.flush(&mut tx).unwrap();
        // Sin `commit`: se cae al salir del bloque.
    }
    r.reset(); // el contrato del módulo
    let rd = db.begin_read();
    assert_eq!(rd.get(0x01, b"clave").unwrap(), None);
    let tsb = Resolution::Hour.bucket_of(T0 + 5).unwrap();
    assert_eq!(read_total(&rd, Resolution::Hour, tsb).unwrap(), None);
}

/// El contrato de `reset`: tras un aborto, el estado en RAM daba por escrito
/// un borrado que no ocurrió. Sin `reset` se contaría dos veces.
#[test]
fn resetting_after_an_abort_keeps_the_totals_exact() {
    let db = db();
    let mut r = Rollup::new(Config { top_k: 2, ..Config::default() });
    let mut n = 0u64;

    // Primer lote confirmado: dos endpoints en disco.
    let mut tx = db.begin_write().unwrap();
    for i in 0..20u32 {
        r.observe(&mut tx, &obs(T0 + 5, if i % 2 == 0 { b"/a" } else { b"/b" }, 200, 4)).unwrap();
        n += 1;
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    // Segundo lote que desaloja y NO confirma.
    {
        let mut tx = db.begin_write().unwrap();
        for _ in 0..30 {
            r.observe(&mut tx, &obs(T0 + 5, b"/c", 200, 4)).unwrap();
        }
        r.flush(&mut tx).unwrap();
    }
    r.reset();

    // Tercer lote, ya con el estado reconstruido de disco.
    let mut tx = db.begin_write().unwrap();
    for _ in 0..7 {
        r.observe(&mut tx, &obs(T0 + 5, b"/a", 200, 4)).unwrap();
        n += 1;
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 5).unwrap();
    let total = read_total(&rd, Resolution::Hour, tsb).unwrap().unwrap();
    assert_eq!(total.requests, n, "el total no cuadra tras el aborto");
    let rows = read_dimension(&rd, Resolution::Hour, tsb, Dimension::Endpoint).unwrap();
    let sum: u64 = rows.iter().map(|r| r.bucket.requests).sum();
    assert_eq!(sum, n, "las filas de endpoint no suman el total tras el aborto");
}

#[test]
fn open_cells_never_pass_the_configured_cap() {
    let db = db();
    let mut r = Rollup::new(Config { max_open_cells: 2, ..Config::default() });
    let mut tx = db.begin_write().unwrap();
    // Marcas de tiempo que avanzan una hora cada vez: cada una abre una celda
    // nueva en las tres resoluciones.
    for h in 0..50u64 {
        r.observe(&mut tx, &obs(T0 + h * 3600, b"/a", 200, 4)).unwrap();
        for open in r.open_cells() {
            assert!(open <= 2, "celdas abiertas {open} por encima del tope");
        }
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    // Y lo desalojado sí llegó al disco.
    let rd = db.begin_read();
    let rows = read_range(&rd, Resolution::Hour, 0, u32::MAX, 10_000).unwrap();
    let totals: u64 =
        rows.iter().filter(|r| r.dim == Dimension::Total).map(|r| r.bucket.requests).sum();
    assert_eq!(totals, 50, "se perdieron celdas al desalojarlas de RAM");
}

#[test]
fn pruning_removes_the_old_cells_and_leaves_the_rest_untouched() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    for h in 0..40u64 {
        r.observe(&mut tx, &obs(T0 + h * 3600, b"/a", 200, 4)).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();
    r.reset();

    let cut = Resolution::Hour.bucket_of(T0 + 20 * 3600).unwrap();
    let mut tx = db.begin_write().unwrap();
    prune_before(&mut tx, Resolution::Hour, cut).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let rows = read_range(&rd, Resolution::Hour, 0, u32::MAX, 10_000).unwrap();
    assert!(rows.iter().all(|r| r.ts_bucket >= cut), "quedaron celdas por debajo del corte");
    let kept: u64 =
        rows.iter().filter(|r| r.dim == Dimension::Total).map(|r| r.bucket.requests).sum();
    assert_eq!(kept, 20, "se podó de más o de menos");
    // Las otras resoluciones no se han tocado.
    let mins = read_range(&rd, Resolution::Minute, 0, u32::MAX, 10_000).unwrap();
    assert!(!mins.is_empty(), "la poda de la hora se llevó por delante el minuto");
    let days = read_range(&rd, Resolution::Day, 0, u32::MAX, 10_000).unwrap();
    assert!(!days.is_empty(), "la poda de la hora se llevó por delante el día");
}

#[test]
fn the_cutoff_helper_matches_the_documented_retentions() {
    let now = T0 + 1_000_000;
    assert_eq!(Resolution::Minute.default_retention_secs(), 48 * 3600);
    assert_eq!(Resolution::Hour.default_retention_secs(), 30 * 86_400);
    assert_eq!(Resolution::Day.default_retention_secs(), 730 * 86_400);
    for res in RESOLUTIONS {
        let cut = res.cutoff_bucket(now, res.default_retention_secs()).unwrap();
        assert_eq!(cut, res.bucket_of(now - res.default_retention_secs()).unwrap());
    }
    // Una retención mayor que la edad del universo unix no da la vuelta.
    assert_eq!(Resolution::Day.cutoff_bucket(10, u64::MAX).unwrap(), 0);
}

#[test]
fn a_timestamp_that_does_not_fit_the_bucket_width_is_refused_not_truncated() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    // Con resolución de minuto, `u64::MAX / 60` no cabe en u32.
    assert!(r.observe(&mut tx, &obs(u64::MAX, b"/a", 200, 4)).is_err());
    assert!(Resolution::Minute.bucket_of(u64::MAX).is_none());
    // El límite exacto sí cabe.
    assert_eq!(Resolution::Minute.bucket_of(u32::MAX as u64 * 60), Some(u32::MAX));
}

#[test]
fn a_foreign_row_planted_in_the_aggregate_namespace_is_reported_not_swallowed() {
    // `0x02` es un espacio de datos de usuario en este motor: cualquiera
    // puede escribir ahí. La capa tiene que dar `Err`, no una respuesta
    // equivocada ni un pánico (invariante 2).
    let db = db();
    let mut tx = db.begin_write().unwrap();
    // Clave DENTRO del rango de la resolución de minuto (primer byte 0), con
    // un byte de dimensión que no existe.
    tx.put(AGG_NS, &[0u8, 0, 0, 0, 5, 99], b"da igual el valor").unwrap();
    // Y una clave bien formada con un valor que no es un bucket.
    let k = key::total_key(Resolution::Minute.code(), 6, Dimension::Total.code());
    tx.put(AGG_NS, &k, b"tampoco esto es un bucket").unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    let e = read_range(&rd, Resolution::Minute, 0, u32::MAX, 1000);
    assert!(e.is_err(), "una fila ajena se coló como agregado");
    assert!(read_total(&rd, Resolution::Minute, 6).is_err(), "un valor ajeno se decodificó");

    // Y observar sobre esa misma celda tampoco puede entrar en pánico.
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    let res = r.observe(&mut tx, &obs(T0, b"/a", 200, 4));
    assert!(res.is_ok() || res.is_err());
}

#[test]
fn a_truncated_bucket_value_on_disk_is_reported_as_an_error() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(T0, b"/a", 200, 4)).unwrap();
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let tsb = Resolution::Hour.bucket_of(T0).unwrap();
    let k = key::total_key(Resolution::Hour.code(), tsb, Dimension::Total.code());
    let mut tx = db.begin_write().unwrap();
    let v = tx.get(AGG_NS, &k).unwrap().unwrap();
    tx.put(AGG_NS, &k, &v[..v.len() - 1]).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    assert!(read_total(&rd, Resolution::Hour, tsb).is_err());
}

/// La razón de ser del histograma: percentiles sin los crudos. Se comprueba
/// contra los percentiles exactos de las mismas muestras.
#[test]
fn percentiles_read_back_from_disk_contain_the_exact_ones() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut rng = Lcg(99);
    let mut samples: Vec<u32> = Vec::new();
    let mut tx = db.begin_write().unwrap();
    for _ in 0..20_000 {
        let lat = if rng.below(100) < 92 { 1 + rng.below(25) } else { 30 + rng.below(2500) };
        samples.push(lat);
        r.observe(&mut tx, &obs(T0 + 3, b"/a", 200, lat)).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    samples.sort_unstable();
    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 3).unwrap();
    let b = read_total(&rd, Resolution::Hour, tsb).unwrap().unwrap();
    let mut lines: Vec<String> = Vec::new();
    for permille in [500u32, 950, 990] {
        let rank = (samples.len() as u64 * permille as u64).div_ceil(1000).max(1);
        let exact = samples[(rank - 1) as usize];
        let p = b.percentile(permille).unwrap();
        assert!(
            p.lo <= exact && exact <= p.hi,
            "p{permille}: exacto {exact} fuera del intervalo [{}, {}]",
            p.lo,
            p.hi
        );
        let err = ((p.estimate as f64) - exact as f64).abs() / exact as f64 * 100.0;
        lines.push(format!(
            "p{permille}: exacto {exact}, intervalo [{}, {}], estimado {} ({err:.1}%)",
            p.lo, p.hi, p.estimate
        ));
    }
    std::println!("percentiles desde disco: {}", lines.join(" | "));
}

#[test]
fn the_engine_refuses_an_index_over_the_aggregate_namespace_before_it_can_diverge() {
    // No es una prueba de esta capa sino de la frontera con el motor: si
    // alguien declara un índice sobre `0x02`, `delete_range` —la poda— queda
    // rechazado. Mejor eso que una poda que huerfana el índice en silencio.
    let db = db();
    fn extract(_k: &[u8], v: &[u8]) -> Vec<Vec<u8>> {
        vec![v.to_vec()]
    }
    db.define_index(crate::index::IndexDef {
        id: 3,
        name: "agg",
        version: 1,
        ns: AGG_NS,
        unique: false,
        extract,
    })
    .unwrap();
    let mut tx = db.begin_write().unwrap();
    assert!(prune_before(&mut tx, Resolution::Hour, 10).is_err());
}

#[test]
fn ram_stays_bounded_across_a_long_run_with_exploding_cardinality() {
    let db = db();
    let mut r = Rollup::new(Config { top_k: 32, ..Config::default() });
    let mut peak = 0usize;
    for batch in 0..20u32 {
        let mut tx = db.begin_write().unwrap();
        for i in 0..500u32 {
            let ep = format!("/users/{}/orders", batch * 500 + i);
            let user = format!("u{}", batch * 500 + i);
            let mut o = obs(T0 + (batch * 500 + i) as u64, ep.as_bytes(), 200, 5);
            o.user = user.as_bytes();
            r.observe(&mut tx, &o).unwrap();
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();
        peak = peak.max(r.ram_bytes());
    }
    std::println!("rollup: pico de RAM {peak} bytes con 10.000 valores distintos por dimensión");
    assert!(peak < 512 * 1024, "la RAM del agregador subió a {peak} bytes");
}
