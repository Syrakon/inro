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
    // Las TRES: el perfil por defecto apaga el minuto, así que este caso pide
    // explícitamente el de tiempo real.
    let mut r = Rollup::new(Config::realtime());
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

/// El perfil por defecto (`Profile::Reports`) **no escribe ni una fila de
/// resolución de minuto**. Ahí está la mayor parte del ahorro de disco, y es
/// lo que le cuesta al panel su zoom en tiempo real, así que se comprueba en
/// vez de suponerse. `K` se queda en 32: bajarlo aportaba 2,1 GB de los 16,1
/// del perfil y dejaba el informe por dimensión inservible.
#[test]
fn the_default_profile_writes_no_minute_resolution_at_all() {
    let db = db();
    let cfg = Config::default();
    assert_eq!(cfg, Config::reports());
    assert_eq!(cfg.top_k, 32);
    assert!(!cfg.keeps(Resolution::Minute));
    assert_eq!(cfg.active().collect::<Vec<_>>(), vec![Resolution::Hour, Resolution::Day]);

    let mut r = Rollup::new(cfg);
    let mut tx = db.begin_write().unwrap();
    for i in 0..300u32 {
        r.observe(&mut tx, &obs(T0 + i as u64, b"/a", 200, 12)).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();

    let rd = db.begin_read();
    assert!(
        read_range(&rd, Resolution::Minute, 0, u32::MAX, 10_000).unwrap().is_empty(),
        "el perfil por defecto escribió filas de minuto"
    );
    for res in [Resolution::Hour, Resolution::Day] {
        let tsb = res.bucket_of(T0).unwrap();
        assert_eq!(read_total(&rd, res, tsb).unwrap().unwrap().requests, 300, "{res:?}");
    }
    // Y con K = 32 la celda horaria son 133 filas como mucho: 1 total + cuatro
    // dimensiones de K entradas y un cajón.
    let tsb = Resolution::Hour.bucket_of(T0).unwrap();
    let rows = read_range(&rd, Resolution::Hour, tsb, tsb + 1, 10_000).unwrap();
    assert!(rows.len() <= 1 + 4 * (32 + 1), "{} filas en una celda horaria", rows.len());
}

/// Los tres perfiles son la escalera que documenta el módulo: `Reports` solo
/// cambia `K` respecto al de por defecto, y `Realtime` es el único que añade
/// la resolución de minuto y las retenciones largas de la sección 12.3.
#[test]
fn the_three_profiles_are_the_ladder_the_docs_describe() {
    let (m, r, rt) = (Config::minimal(), Config::reports(), Config::realtime());
    assert_eq!((m.top_k, m.minute), (4, false));
    assert_eq!((r.top_k, r.minute), (32, false));
    assert_eq!((rt.top_k, rt.minute), (32, true));
    assert_eq!(m.retention_secs, r.retention_secs, "`Reports` solo cambia K");
    assert_eq!(r.retention(Resolution::Hour), 7 * 86_400);
    assert_eq!(rt.retention(Resolution::Hour), 30 * 86_400);
    assert_eq!(rt.retention(Resolution::Day), 730 * 86_400);
    assert_eq!(Config::default(), r, "el defecto es Reports, no Minimal");
    assert_eq!(Profile::default(), Profile::Reports);
}

#[test]
fn the_minute_resolution_keeps_only_totals_and_status() {
    let db = db();
    let mut r = Rollup::new(Config::realtime());
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
    // Con el perfil de tiempo real, para que la poda de la hora tenga celdas
    // de minuto vecinas que NO deba llevarse por delante.
    let mut r = Rollup::new(Config::realtime());
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
    // La retención es del PERFIL, no de la resolución: 7 días de hora en el
    // de por defecto, 30 en el de tiempo real. Preguntárselo a un `Resolution`
    // suelto —lo que hacía `default_retention_secs`— daría la del perfil
    // equivocado sin decirlo.
    let min = Config::minimal();
    assert_eq!(min.retention(Resolution::Hour), 7 * 86_400);
    assert_eq!(min.retention(Resolution::Day), 90 * 86_400);
    let rt = Config::realtime();
    assert_eq!(rt.retention(Resolution::Minute), 48 * 3600);
    assert_eq!(rt.retention(Resolution::Hour), 30 * 86_400);
    assert_eq!(rt.retention(Resolution::Day), 730 * 86_400);

    for cfg in [min, rt] {
        for res in RESOLUTIONS {
            let cut = cfg.cutoff_bucket(res, now).unwrap();
            assert_eq!(cut, res.bucket_of(now - cfg.retention(res)).unwrap());
            assert_eq!(cut, res.cutoff_bucket(now, cfg.retention(res)).unwrap());
        }
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

    // Y observar sobre esa misma celda tampoco puede entrar en pánico. Con el
    // perfil de tiempo real, que es el que abre —y por tanto carga de disco—
    // la celda de minuto donde está plantada la fila ajena.
    let mut r = Rollup::new(Config::realtime());
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
    // Los DOS perfiles, porque `K` es el factor dominante de esta cifra: la
    // RAM del agregador es K entradas por (resolución, celda, dimensión) y
    // cada entrada carga un histograma de 128 bytes.
    fn peak_ram(cfg: Config) -> usize {
        let db = db();
        let mut r = Rollup::new(cfg);
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
        peak
    }
    let minimal = peak_ram(Config::default());
    let realtime = peak_ram(Config::realtime());
    std::println!(
        "rollup, 10.000 valores distintos por dimensión: pico de RAM {minimal} B con el perfil \
         por defecto (K=4, sin minuto) y {realtime} B con el de tiempo real (K=32, tres \
         resoluciones)"
    );
    assert!(minimal < realtime, "K = 4 tendría que gastar menos RAM que K = 32");
    assert!(realtime < 512 * 1024, "la RAM del agregador subió a {realtime} bytes");
}

/// El desalojo de un valor que YA tiene fila en disco tiene que borrar esa
/// fila, no solo mover su contenido al cajón.
///
/// **Esta prueba existe porque una mutación deliberada la reclamó**: quitar
/// entero el bloque de borrados de `write_cell` no lo atrapaba ninguna de las
/// diecisiete pruebas de este fichero. Sin el borrado, la fila vieja sigue en
/// disco con su contenido *y* ese mismo contenido está en el cajón: al leer,
/// las peticiones se cuentan dos veces y la dimensión suma más que su propio
/// total. Es una respuesta equivocada silenciosa, la clase de fallo que la
/// invariante 2 pone por encima de un `Err`.
#[test]
fn a_value_evicted_after_it_reached_disk_loses_its_row_too() {
    let db = db();
    let mut r = Rollup::new(Config { top_k: 2, ..Config::default() });
    let mut n = 0u64;
    // Cuatro endpoints que se turnan la cabeza: cada lote deja dos en disco y
    // desaloja a los otros dos en el siguiente.
    let eps: [&[u8]; 4] = [b"/a", b"/b", b"/c", b"/d"];
    for batch in 0..8u32 {
        let mut tx = db.begin_write().unwrap();
        for i in 0..40u32 {
            // El endpoint dominante rota por lote.
            let e = eps[((batch + i / 10) % 4) as usize];
            r.observe(&mut tx, &obs(T0 + 5, e, 200, 4)).unwrap();
            n += 1;
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();
    }

    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0 + 5).unwrap();
    let rows = read_dimension(&rd, Resolution::Hour, tsb, Dimension::Endpoint).unwrap();
    assert!(
        rows.len() <= 3,
        "{} filas en disco con K = 2: sobreviven filas de valores ya desalojados",
        rows.len()
    );
    let sum: u64 = rows.iter().map(|r| r.bucket.requests).sum();
    let total = read_total(&rd, Resolution::Hour, tsb).unwrap().unwrap();
    assert_eq!(total.requests, n);
    assert_eq!(sum, n, "las filas de endpoint suman {sum} para {n} peticiones reales");
}

// ---------------------------------------------------------------------------
// Ciclo de retención (`Rollup::retain`).
// ---------------------------------------------------------------------------

/// Espacio de claves del crudo en estas pruebas.
const RAW_NS: u8 = RAW_NS_RECOMMENDED;

/// Clave cruda del esquema de referencia: `[ts BE u64][seq u16]`.
fn raw_key(ts: u64, seq: u16) -> Vec<u8> {
    let mut k = Vec::with_capacity(10);
    k.extend_from_slice(&ts.to_be_bytes());
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Escribe `n` registros crudos por hora durante `hours` horas terminando en
/// `end_secs`, observándolos en la misma transacción. `unit` es la unidad del
/// instante en la CLAVE; la observación siempre va en segundos.
fn write_and_observe(
    db: &Db,
    r: &mut Rollup,
    end_secs: u64,
    hours: u64,
    per_hour: u16,
    unit: RawTime,
) -> u64 {
    let mut n = 0u64;
    for h in 0..hours {
        let base = end_secs - (hours - h) * 3_600;
        let mut tx = db.begin_write().unwrap();
        for s in 0..per_hour {
            let ts = base + (s as u64 * 3_600) / per_hour as u64;
            let k = raw_key(ts * unit.per_second(), s);
            tx.put(RAW_NS, &k, b"v").unwrap();
            r.observe(&mut tx, &obs(ts, b"/a", 200, 5)).unwrap();
            n += 1;
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();
    }
    n
}

/// Cuenta las claves vivas del crudo y devuelve el `ts` de la más antigua.
fn raw_live(db: &Db) -> (u64, Option<u64>) {
    let rd = db.begin_read();
    let mut cur = rd.scan(RAW_NS, b"", &[0xff; 12]).unwrap();
    let (mut n, mut first) = (0u64, None);
    while let Some((k, _)) = cur.next().unwrap() {
        if first.is_none() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&k[..8]);
            first = Some(u64::from_be_bytes(b));
        }
        n += 1;
    }
    (n, first)
}

/// El ciclo completo: el crudo fuera de la ventana desaparece y el agregado
/// que lo resume sobrevive.
#[test]
fn a_full_cycle_drops_the_raw_and_keeps_the_aggregate_that_summarises_it() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let now = T0 + 12 * 3_600;
    let n = write_and_observe(&db, &mut r, now, 12, 60, RawTime::Seconds);
    let (before, _) = raw_live(&db);
    assert_eq!(before, n);

    let mut tx = db.begin_write().unwrap();
    let st = r.retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds))).unwrap();
    tx.commit().unwrap();

    let (after, oldest) = raw_live(&db);
    assert_eq!(st.raw_cutoff, Some((now - RawWindow::SIX_HOURS).to_be_bytes()));
    assert!(after < before, "la poda no se llevó nada: {after} de {before}");
    assert_eq!(after, n / 2, "la ventana de 6 h de 12 h de crudo tenía que dejar la mitad");
    assert!(
        oldest.unwrap() >= now - RawWindow::SIX_HOURS,
        "sobrevivió un registro de {} anterior al corte {}",
        oldest.unwrap(),
        now - RawWindow::SIX_HOURS
    );

    // Y el agregado de las horas ya podadas sigue ahí, con su cuenta entera.
    let rd = db.begin_read();
    let mut summed = 0u64;
    for h in 0..12u64 {
        let tsb = Resolution::Hour.bucket_of(now - (12 - h) * 3_600).unwrap();
        let total = read_total(&rd, Resolution::Hour, tsb)
            .unwrap()
            .unwrap_or_else(|| panic!("falta el agregado de la hora {h}, cuyo crudo ya no existe"));
        summed += total.requests;
    }
    assert_eq!(summed, n, "los agregados suman {summed} para {n} peticiones");
}

/// `retain` vuelca ANTES de podar: sin ese orden, la celda en curso —que solo
/// vive en RAM— se quedaría sin fila mientras su crudo ya no existe.
#[test]
fn retain_flushes_before_it_prunes_so_the_open_cell_survives_its_own_raw() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let now = T0 + 3_600;
    // A mano y SIN `flush`: todo lo observado se queda en RAM.
    let mut n = 0u64;
    let mut tx = db.begin_write().unwrap();
    for s in 0..120u16 {
        let ts = now - 3_600 + s as u64 * 30;
        tx.put(RAW_NS, &raw_key(ts, s), b"v").unwrap();
        r.observe(&mut tx, &obs(ts, b"/a", 200, 5)).unwrap();
        n += 1;
    }
    // Ventana de cero segundos: se lleva TODO el crudo escrito hasta `now`.
    let st = r.retain(&mut tx, now, Some(RawWindow::new(RAW_NS, 0, RawTime::Seconds))).unwrap();
    tx.commit().unwrap();

    assert!(st.flush.rows_written > 0, "el ciclo no volcó nada antes de podar");
    let (live, _) = raw_live(&db);
    assert_eq!(live, 0, "quedaron {live} registros crudos tras una ventana de cero");

    let rd = db.begin_read();
    let mut seen = 0u64;
    for tsb in [
        Resolution::Hour.bucket_of(now - 3_600).unwrap(),
        Resolution::Hour.bucket_of(now).unwrap(),
    ] {
        if let Some(t) = read_total(&rd, Resolution::Hour, tsb).unwrap() {
            seen += t.requests;
        }
    }
    assert_eq!(seen, n, "el agregado retiene {seen} de {n} peticiones cuyo crudo ya no existe");
}

/// Podar el espacio de los agregados «como si fuera el crudo» borraría lo que
/// el propio ciclo acaba de volcar, y con el crudo detrás no habría con qué
/// rehacerlo.
#[test]
fn retain_refuses_the_aggregate_namespace_as_a_raw_window() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(T0, b"/a", 200, 5)).unwrap();
    let err = r
        .retain(&mut tx, T0 + 86_400, Some(RawWindow::six_hours(AGG_NS, RawTime::Seconds)))
        .unwrap_err();
    assert_eq!(err, Error::ReservedNamespace { ns: AGG_NS });
    // Y el rechazo es ANTES de tocar nada: ni volcó ni podó.
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();
    let rd = db.begin_read();
    let tsb = Resolution::Hour.bucket_of(T0).unwrap();
    assert!(read_total(&rd, Resolution::Hour, tsb).unwrap().is_some());
}

/// Rellenando historia hacia atrás, el corte de retención cae POR ENCIMA de
/// una celda todavía abierta. Se recorta hasta ella y se dice.
#[test]
fn retain_clamps_the_cutoff_to_the_oldest_open_cell_instead_of_erasing_it() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    // La celda abierta es la de T0; `now` va un año por delante, así que el
    // corte de la hora (7 días) y el del día (90) quedan muy por encima.
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(T0, b"/a", 200, 5)).unwrap();
    let now = T0 + 365 * 86_400;
    let st = r.retain(&mut tx, now, None).unwrap();
    tx.commit().unwrap();

    let hour = Resolution::Hour.code() as usize;
    let day = Resolution::Day.code() as usize;
    assert!(st.clamped[hour] && st.clamped[day], "el corte no se recortó: {st:?}");
    assert_eq!(st.aggregate_cutoff[hour], Some(Resolution::Hour.bucket_of(T0).unwrap()));
    assert_eq!(st.aggregate_cutoff[day], Some(Resolution::Day.bucket_of(T0).unwrap()));

    let rd = db.begin_read();
    for res in [Resolution::Hour, Resolution::Day] {
        let tsb = res.bucket_of(T0).unwrap();
        assert!(
            read_total(&rd, res, tsb).unwrap().is_some(),
            "{res:?}: la poda se llevó la celda que sigue abierta en RAM"
        );
    }
}

/// Sin recorte no habría nada que recortar: con el corte por debajo de toda
/// celda abierta, `clamped` está en falso y el corte es el del perfil.
#[test]
fn the_normal_cycle_does_not_clamp_anything() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let now = T0 + 8 * 86_400;
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(now, b"/a", 200, 5)).unwrap();
    let st = r.retain(&mut tx, now, None).unwrap();
    tx.commit().unwrap();
    assert_eq!(st.clamped, [false; 3]);
    let hour = Resolution::Hour.code() as usize;
    assert_eq!(st.aggregate_cutoff[hour], Config::default().cutoff_bucket(Resolution::Hour, now));
    // El día también se poda, aunque no haya nada tan viejo: el corte es un
    // instante unix absoluto (`now − 90 d`), no una cuenta desde el arranque,
    // así que un `delete_range` vacío se emite igual y cuesta un descenso.
    assert_eq!(
        st.aggregate_cutoff[Resolution::Day.code() as usize],
        Config::default().cutoff_bucket(Resolution::Day, now)
    );
    // El minuto está apagado en el perfil por defecto: ni se mira.
    assert_eq!(st.aggregate_cutoff[Resolution::Minute.code() as usize], None);
}

/// La unidad del instante de la clave decide cuánto se borra, y equivocarla es
/// la única forma de que este ciclo destruya datos.
#[test]
fn the_raw_time_unit_decides_how_much_the_cycle_deletes() {
    for unit in [RawTime::Seconds, RawTime::Millis] {
        let db = db();
        let mut r = Rollup::new(Config::default());
        let now = T0 + 12 * 3_600;
        let n = write_and_observe(&db, &mut r, now, 12, 30, unit);

        // La unidad CORRECTA deja media ventana.
        let mut tx = db.begin_write().unwrap();
        r.retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, unit))).unwrap();
        tx.commit().unwrap();
        let (after, _) = raw_live(&db);
        assert_eq!(after, n / 2, "unidad {unit:?}: sobreviven {after} de {n}");

        // La EQUIVOCADA, en el sentido peligroso, se lo lleva todo; en el otro,
        // nada. Se comprueban las dos direcciones porque no son simétricas.
        let wrong = match unit {
            RawTime::Seconds => RawTime::Millis,
            RawTime::Millis => RawTime::Seconds,
        };
        let mut tx = db.begin_write().unwrap();
        r.retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, wrong))).unwrap();
        tx.commit().unwrap();
        let (after_wrong, _) = raw_live(&db);
        match unit {
            // Claves en segundos, corte en milisegundos: barre el log entero.
            RawTime::Seconds => assert_eq!(after_wrong, 0),
            // Claves en milisegundos, corte en segundos: no borra nada.
            RawTime::Millis => assert_eq!(after_wrong, after),
        }
    }
}

/// El rechazo del motor sobre un espacio indexado llega tal cual al ciclo, sin
/// que este haya podado ya la mitad.
#[test]
fn retain_propagates_the_engines_refusal_over_an_indexed_raw_namespace() {
    let db = db();
    fn extract(k: &[u8], _v: &[u8]) -> Vec<Vec<u8>> {
        vec![k.to_vec()]
    }
    db.define_index(crate::index::IndexDef {
        id: 4,
        name: "raw",
        version: 1,
        ns: RAW_NS,
        unique: false,
        extract,
    })
    .unwrap();
    let mut r = Rollup::new(Config::default());
    let now = T0 + 12 * 3_600;
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(now, b"/a", 200, 5)).unwrap();
    let err = r
        .retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds)))
        .unwrap_err();
    assert_eq!(err, Error::DeleteRangeIndexed { ns: RAW_NS });
}

/// Muchos ciclos seguidos en régimen permanente: el número de registros vivos
/// se queda quieto, que es lo que hace que el fichero pueda estabilizarse.
#[test]
fn the_live_raw_count_reaches_a_plateau_across_many_cycles() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let per_hour = 60u16;
    let mut live = Vec::new();
    for h in 0..24u64 {
        let now = T0 + (h + 1) * 3_600;
        let mut tx = db.begin_write().unwrap();
        for s in 0..per_hour {
            let ts = T0 + h * 3_600 + (s as u64 * 3_600) / per_hour as u64;
            tx.put(RAW_NS, &raw_key(ts, s), b"v").unwrap();
            r.observe(&mut tx, &obs(ts, b"/a", 200, 5)).unwrap();
        }
        r.retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds))).unwrap();
        tx.commit().unwrap();
        live.push(raw_live(&db).0);
    }
    // Desde la sexta hora en adelante, exactamente seis horas de crudo vivo.
    let steady = 6 * per_hour as u64;
    for (h, n) in live.iter().enumerate().skip(6) {
        assert_eq!(*n, steady, "hora {h}: {n} registros vivos, esperados {steady}");
    }
}

/// El podador que **no observa nada**: un `Rollup` recién construido, sin
/// ninguna celda abierta, poda por el corte del perfil sin recortar nada. Es
/// el caso del proceso de retención separado del escritor.
#[test]
fn a_rollup_that_never_observed_still_runs_a_complete_cycle() {
    let db = db();
    // Un escritor deja datos.
    let mut writer = Rollup::new(Config::default());
    let now = T0 + 30 * 86_400;
    let n = write_and_observe(&db, &mut writer, now, 3, 20, RawTime::Seconds);
    // Y el podador, que es otro objeto y no ha observado jamás.
    let mut pruner = Rollup::new(Config::default());
    let mut tx = db.begin_write().unwrap();
    let st = pruner
        .retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds)))
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(st.flush, FlushStats::default(), "no tenía nada que volcar");
    assert_eq!(st.clamped, [false; 3], "sin celdas abiertas no hay nada que recortar");
    assert_eq!(
        st.aggregate_cutoff[Resolution::Hour.code() as usize],
        Config::default().cutoff_bucket(Resolution::Hour, now)
    );
    // Tres horas de crudo dentro de una ventana de seis: no se borra nada.
    assert_eq!(raw_live(&db).0, n);
}

/// Con el perfil de tiempo real las TRES resoluciones se podan, cada una por
/// su retención. Es lo que distingue `retain` de tres `prune_before` a mano:
/// no hay forma de olvidarse de una.
#[test]
fn every_active_resolution_gets_its_own_cutoff() {
    let db = db();
    let cfg = Config::realtime();
    let mut r = Rollup::new(cfg);
    let now = T0 + 800 * 86_400;
    let mut tx = db.begin_write().unwrap();
    r.observe(&mut tx, &obs(now, b"/a", 200, 5)).unwrap();
    let st = r.retain(&mut tx, now, None).unwrap();
    tx.commit().unwrap();
    for res in [Resolution::Minute, Resolution::Hour, Resolution::Day] {
        assert_eq!(
            st.aggregate_cutoff[res.code() as usize],
            cfg.cutoff_bucket(res, now),
            "{res:?} no se podó por su propia retención"
        );
    }
}

/// Un reloj imposible con la clave en milisegundos haría saturar el corte, y
/// un corte saturado **borra el log entero**. Se rechaza antes de tocar nada.
#[test]
fn an_impossible_clock_is_refused_before_the_cycle_touches_anything() {
    let db = db();
    let mut r = Rollup::new(Config::default());
    let now = T0 + 12 * 3_600;
    let n = write_and_observe(&db, &mut r, now, 12, 30, RawTime::Millis);

    let mut tx = db.begin_write().unwrap();
    let err = r
        .retain(&mut tx, u64::MAX, Some(RawWindow::six_hours(RAW_NS, RawTime::Millis)))
        .unwrap_err();
    assert_eq!(err, Error::BadFormat);
    tx.commit().unwrap();
    assert_eq!(raw_live(&db).0, n, "el reloj roto se llevó registros");

    // El mismo reloj en segundos NO desborda, así que sí poda — y podar todo
    // es la respuesta correcta a ese reloj, no un desbordamiento.
    let mut tx = db.begin_write().unwrap();
    let st =
        r.retain(&mut tx, u64::MAX, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds))).unwrap();
    tx.commit().unwrap();
    assert_eq!(st.raw_cutoff, Some((u64::MAX - RawWindow::SIX_HOURS).to_be_bytes()));
    assert_eq!(raw_live(&db).0, 0);
}
