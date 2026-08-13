//! Mediciones de la capa de agregación (`inro::rollup`).
//!
//! **Ninguna de estas pruebas toca `tests/size.rs`**, que corre bancos de un
//! millón de registros y está entero `#[ignore]`. Las de aquí están acotadas a
//! propósito para poder ejecutarse a mano en una máquina de desarrollo, en
//! modo `debug`, sin colgar a nadie: la más cara escribe ~180.000 filas de
//! agregado, no millones de registros crudos.
//!
//! Van `#[ignore]` igual que sus vecinas de `size.rs` —imprimen números, no
//! comprueban un umbral que deba fallar en cada `cargo test`— salvo
//! `the_aggregate_layer_writes_far_less_than_the_raw_records_it_summarises`,
//! que sí fija un techo y corre siempre: es la regresión que de verdad
//! importaría (que la agregación pase a costar más que el crudo).
//!
//! ## Qué se mide y qué se compone
//!
//! - **Amplificación de escritura**: bytes FÍSICOS escritos al `Storage`, con
//!   y sin agregación, sobre exactamente la misma carga cruda. Medido de
//!   punta a punta, sin componer nada.
//! - **Coste en disco de los agregados por tier**: se mide el tamaño de
//!   fichero de un juego COMPLETO de filas de agregado para las retenciones de
//!   cada perfil —el de por defecto (`Profile::Minimal`: sin minuto, 7 d de
//!   hora, 90 d de día, K = 4) y el de tiempo real (`Profile::Realtime`, el
//!   literal de la sección 12.3: 48 h de minuto, 30 d de hora, 2 años de día,
//!   K = 32)—, con las magnitudes de contador reales de cada plan. Las filas
//!   se generan con
//!   el codificador de verdad (`Bucket::encode`) y la disposición de clave de
//!   verdad; lo que NO se hace es reproducir petición a petición los 15
//!   millones de requests mensuales de un nodo pro, que a 20 µs por `observe`
//!   serían cinco minutos por celda. El número de filas por celda **sí se
//!   mide** contra un `Rollup` real (`rows_per_cell_measured_against_a_real_rollup`).
//! - **El crudo de 6 horas** se compone con los **34,14 B/entrada medidos** en
//!   la tarea 21 (`tests/size.rs`), que es la constante que la integración
//!   continua vigila. No se vuelve a medir aquí.

#![cfg(all(feature = "std", feature = "rollup"))]

use inro::rollup::{Bucket, Config, Dimension, Observation, Resolution, Rollup, key};
use inro::storage::FileStorage;
use inro::{Db, Options, Storage, Sync};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Envoltorio que cuenta escrituras físicas y bytes, al nivel más bajo que
/// hay: cualquier byte que el motor mande al medio pasa por aquí.
struct CountingStorage<S: Storage> {
    inner: S,
    writes: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl<S: Storage> CountingStorage<S> {
    fn new(inner: S) -> (Self, Arc<AtomicU64>, Arc<AtomicU64>) {
        let w = Arc::new(AtomicU64::new(0));
        let b = Arc::new(AtomicU64::new(0));
        (CountingStorage { inner, writes: w.clone(), bytes: b.clone() }, w, b)
    }
}

impl<S: Storage> Storage for CountingStorage<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> inro::Result<()> {
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> inro::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.inner.write_at(offset, buf)
    }
    fn sync(&self) -> inro::Result<()> {
        self.inner.sync()
    }
    fn len(&self) -> inro::Result<u64> {
        self.inner.len()
    }
    fn truncate(&self, len: u64) -> inro::Result<()> {
        self.inner.truncate(len)
    }
}

/// Bytes por entrada cruda medidos en la tarea 21 (`tests/size.rs`,
/// `bytes_per_log_entry_stay_under_the_threshold`), con el umbral de 40 que
/// la integración continua vigila. Aquí se usa para componer el crudo de la
/// tabla por tier, no se vuelve a medir.
const RAW_BYTES_PER_ENTRY: f64 = 34.14;

/// Peticiones por segundo del escenario que mide la sección 12.4: un nodo
/// **pro**, 150 rps, un commit por lote de mil registros.
///
/// El ritmo NO es un detalle: fija cuántas celdas de agregado toca un lote. A
/// 150 rps, mil registros son 6,7 segundos —una celda de minuto, una de hora,
/// una de día— y las filas de agregado se reparten entre mil registros
/// crudos. A 2 rps (el ritmo que usaba una primera versión de este banco, y
/// que es el de un nodo *micro*) el mismo lote cruza diecisiete minutos y el
/// agregado sale ~130 veces más caro por registro. Medir la amplificación de
/// un nodo pro con el ritmo de un micro habría dado un número correcto para
/// una pregunta que nadie hizo.
const RPS: u64 = 150;

fn push_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

/// Códigos de estado que ve un edge real. La cardinalidad de esta dimensión
/// SÍ importa para el agregado (es la única que la resolución de minuto
/// guarda), así que se usa un juego realista de doce en vez de los dos de
/// `tests/size.rs`. **No cambia el tamaño del registro crudo**: el campo
/// sigue siendo un varint de un byte con cualquiera de estos valores.
const STATUS: [u16; 12] = [200, 201, 204, 301, 304, 400, 401, 403, 404, 429, 500, 503];

fn status_of(i: u32) -> u16 {
    // Reparto sesgado a 200, como el tráfico real.
    if i % 100 < 82 { 200 } else { STATUS[(i % 12) as usize] }
}

/// Registro crudo con la forma de `request_logs` del edge, la misma de
/// `tests/size.rs` salvo el VALOR del byte de estado (ver `STATUS`), que no
/// altera su anchura.
fn synthetic_log(i: u32) -> (Vec<u8>, Vec<u8>) {
    let ts = 1_760_000_000_000u64 + i as u64 * 1000 / RPS;
    let mut key = Vec::with_capacity(10);
    key.extend_from_slice(&ts.to_be_bytes());
    key.extend_from_slice(&((i % 8) as u16).to_be_bytes());

    let mut v = Vec::with_capacity(32);
    v.push(if i.is_multiple_of(7) { 1 } else { 0 });
    v.push(status_of(i) as u8 % 128);
    push_varint(&mut v, (i % 400) as u64);
    push_varint(&mut v, 500 + (i % 9000) as u64);
    push_varint(&mut v, 100 + (i % 900) as u64);
    v.extend_from_slice(&((192u32 << 24) | (i % 65_536)).to_le_bytes());
    v.push((i % 40) as u8);
    v.push(0);
    push_varint(&mut v, (i % 200) as u64);
    push_varint(&mut v, (i % 5_000) as u64);
    push_varint(&mut v, (i % 300) as u64);
    push_varint(&mut v, (i % 1_200) as u64);
    push_varint(&mut v, (i % 10_000) as u64);
    push_varint(&mut v, (i % 10_000) as u64);
    (key, v)
}

/// La observación que corresponde al registro crudo `i`. Mismas dimensiones
/// que el registro: 200 endpoints, 40 países, 10.000 usuarios.
fn synthetic_observation(i: u32, ep: &mut String, user: &mut String, country: &mut String) {
    ep.clear();
    ep.push_str("/api/v1/");
    ep.push_str(&(i % 200).to_string());
    user.clear();
    user.push('u');
    user.push_str(&(i % 10_000).to_string());
    country.clear();
    country.push_str(&(i % 40).to_string());
}

fn obs<'a>(i: u32, ep: &'a str, user: &'a str, country: &'a str) -> Observation<'a> {
    Observation {
        ts: 1_760_000_000u64 + i as u64 / RPS,
        latency_ms: i % 400,
        bytes_in: 100 + (i % 900) as u64,
        bytes_out: 500 + (i % 9000) as u64,
        status: status_of(i),
        error: status_of(i) >= 500,
        endpoint: ep.as_bytes(),
        country: country.as_bytes(),
        user: user.as_bytes(),
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(name);
    let _ = std::fs::remove_file(&p);
    p
}

/// Resultado de una corrida.
struct Run {
    bytes: u64,
    writes: u64,
    size: u64,
    rows: u64,
}

/// Escribe `n` registros crudos en lotes de `batch`, opcionalmente agregando
/// en la MISMA transacción.
///
/// `flush_every`: cada cuántos commits se vuelca el agregado. `Some(1)` es el
/// modo que esta capa implementa y que la sección 12.4 exige —el agregado va
/// en el mismo commit que el crudo— y `Some(n)` con n mayor mide lo que
/// costaría la mitigación de fase 2 (volcar cada hora en vez de cada lote),
/// que NO está implementada aquí. `None` es la línea base sin agregar.
fn run_workload(
    path: &std::path::Path,
    n: u32,
    batch: u32,
    flush_every: Option<u32>,
    raw_ns: u8,
    cfg: Config,
) -> Run {
    let (store, writes, bytes) = CountingStorage::new(FileStorage::open(path).unwrap());
    let db = Db::create(
        Box::new(store),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();

    // Solo se cuenta la carga, no la creación del fichero.
    writes.store(0, Ordering::Relaxed);
    bytes.store(0, Ordering::Relaxed);

    let mut r = Rollup::new(cfg);
    let mut rows = 0u64;
    let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
    for (c, chunk) in (0..n).collect::<Vec<_>>().chunks(batch as usize).enumerate() {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            let (k, v) = synthetic_log(i);
            tx.put(raw_ns, &k, &v).unwrap();
            if flush_every.is_some() {
                synthetic_observation(i, &mut ep, &mut user, &mut country);
                r.observe(&mut tx, &obs(i, &ep, &user, &country)).unwrap();
            }
        }
        if let Some(f) = flush_every
            && (c as u32 + 1).is_multiple_of(f)
        {
            rows += r.flush(&mut tx).unwrap().rows_written;
        }
        tx.commit().unwrap();
    }
    drop(db);
    let size = std::fs::metadata(path).unwrap().len();
    Run { bytes: bytes.load(Ordering::Relaxed), writes: writes.load(Ordering::Relaxed), size, rows }
}

/// Amplificación de escritura que la agregación añade, medida sobre la misma
/// carga cruda con y sin ella.
///
/// **Se publican DOS métricas y no son la misma cosa**, distinción que la
/// sección 12.4 no hacía:
///
/// - **Crecimiento del fichero** — bytes que acaban en disco. Es lo que mide
///   la tabla de la sección 12.4 (110 KB para 34 KB útiles, 3,3x), así que es
///   la que hay que comparar con ella.
/// - **Tráfico físico de escritura** — bytes que el motor manda de verdad al
///   `Storage`. Es mucho mayor porque el copy-on-write reescribe el camino
///   raíz-hoja en CADA `put`, no una vez por commit, y esas páginas
///   intermedias se sobrescriben unas a otras dentro de la misma transacción.
///   Es el número que decide la vida de una tarjeta SD o de un SSD en un nodo
///   IoT, y no estaba medido en ninguna parte de este proyecto.
#[test]
#[ignore]
fn write_amplification_added_by_the_aggregate_path() {
    const N: u32 = 20_000;
    const BATCH: u32 = 1_000;
    let commits = (N / BATCH) as u64;
    let useful: u64 = (0..N)
        .map(|i| {
            let (k, v) = synthetic_log(i);
            (k.len() + v.len()) as u64
        })
        .sum();

    // Todo en la disposición RECOMENDADA: crudo por encima de los agregados,
    // ver `RAW_NS_RECOMMENDED`. Con el crudo en `0x01` los tres números de
    // abajo estarían dominados por la pérdida del sesgo de anexado, que se
    // mide aparte en
    // `one_aggregate_row_costs_the_raw_path_its_append_split_bias`.
    let ns = inro::rollup::RAW_NS_RECOMMENDED;
    let p1 = tmp("inro-rollup-amp-raw.inro");
    let raw = run_workload(&p1, N, BATCH, None, ns, Config::default());
    let _ = std::fs::remove_file(&p1);

    println!("--- amplificacion de escritura: {N} registros, lotes de {BATCH}, {commits} commits, {RPS} rps ---");
    println!("utiles (clave+valor logicos): {useful} B = {:.2} B/entrada", useful as f64 / N as f64);
    println!(
        "  solo crudo (linea base)  {:>9} B  {:>7.2} B/entrada  {:>8} B/commit  amplificacion {:.2}x  |  fisico {} B ({} B/commit)",
        raw.size,
        raw.size as f64 / N as f64,
        raw.size / commits,
        raw.size as f64 / useful as f64,
        raw.bytes,
        raw.bytes / commits
    );

    // Los DOS perfiles. El de por defecto escribe una celda de 21 filas y solo
    // dos resoluciones; el de tiempo real, 133 filas y tres, con la de minuto
    // rotando sesenta veces más deprisa.
    for (pname, cfg) in [("por defecto (K=4, sin minuto)", Config::default()),
                         ("tiempo real (K=32, 12.3)", Config::realtime())] {
        let p2 = tmp("inro-rollup-amp-agg.inro");
        let agg = run_workload(&p2, N, BATCH, Some(1), ns, cfg);
        let p3 = tmp("inro-rollup-amp-lazy.inro");
        let lazy = run_workload(&p3, N, BATCH, Some(10), ns, cfg);

        println!();
        println!("=== perfil {pname} ===");
        println!("CRECIMIENTO DEL FICHERO (comparable con la tabla de la seccion 12.4)");
        for (name, r) in [("crudo+agregado", &agg), ("agregado cada 10", &lazy)] {
            println!(
                "  {name:<18} {:>9} B  {:>7.2} B/entrada  {:>8} B/commit  amplificacion {:.2}x",
                r.size,
                r.size as f64 / N as f64,
                r.size / commits,
                r.size as f64 / useful as f64
            );
        }
        println!(
            "  la capa anade {} B/commit ({:.2}x sobre los utiles, {:+.1}% sobre el crudo solo)",
            (agg.size - raw.size) / commits,
            (agg.size - raw.size) as f64 / useful as f64,
            (agg.size as f64 / raw.size as f64 - 1.0) * 100.0
        );
        println!("TRAFICO FISICO DE ESCRITURA");
        for (name, r) in [("crudo+agregado", &agg), ("agregado cada 10", &lazy)] {
            println!(
                "  {name:<18} {:>11} B en {:>7} escrituras  {:>9} B/commit",
                r.bytes,
                r.writes,
                r.bytes / commits
            );
        }
        println!(
            "  la capa anade {:+.1}% de trafico fisico ({:+.1}% volcando cada 10); {} B por fila de agregado escrita",
            (agg.bytes as f64 / raw.bytes as f64 - 1.0) * 100.0,
            (lazy.bytes as f64 / raw.bytes as f64 - 1.0) * 100.0,
            (agg.bytes - raw.bytes) / agg.rows.max(1)
        );
        println!(
            "  filas de agregado: {} con volcado por commit ({} por commit); {} volcando cada 10",
            agg.rows,
            agg.rows / commits,
            lazy.rows
        );
        let _ = std::fs::remove_file(&p2);
        let _ = std::fs::remove_file(&p3);
    }
}

/// Filas por celda que produce un `Rollup` real con la cardinalidad del edge
/// (200 endpoints, 12 estados, 40 países, muchos usuarios), en los DOS
/// perfiles. Es el número que la tabla por tier multiplica por las celdas de
/// cada retención, así que se mide en vez de suponerse.
#[test]
fn rows_per_cell_measured_against_a_real_rollup() {
    for (pname, cfg) in
        [("por defecto", Config::default()), ("tiempo real (12.3)", Config::realtime())]
    {
        let path = tmp(&format!("inro-rollup-rows-{}.inro", cfg.top_k));
        let db = Db::create(
            Box::new(FileStorage::open(&path).unwrap()),
            Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        let mut r = Rollup::new(cfg);
        let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
        let mut tx = db.begin_write().unwrap();
        // 3.000 peticiones dentro del MISMO minuto: llenan una celda de cada
        // resolución activa con la cardinalidad completa.
        for i in 0..3_000u32 {
            synthetic_observation(i, &mut ep, &mut user, &mut country);
            let mut o = obs(i, &ep, &user, &country);
            o.ts = 1_760_000_000;
            r.observe(&mut tx, &o).unwrap();
        }
        r.flush(&mut tx).unwrap();
        tx.commit().unwrap();

        let rd = db.begin_read();
        let mut counts = [0usize; 3];
        for res in [Resolution::Minute, Resolution::Hour, Resolution::Day] {
            let tsb = res.bucket_of(1_760_000_000).unwrap();
            let rows = inro::rollup::read_range(&rd, res, tsb, tsb + 1, 10_000).unwrap();
            counts[res.code() as usize] = rows.len();
            let drawers = rows.iter().filter(|r| r.is_drawer()).count();
            println!(
                "perfil {pname} (K = {}): {res:?}: {} filas por celda ({drawers} cajones `otros`)",
                cfg.top_k,
                rows.len()
            );
        }
        drop(rd);
        drop(db);
        let _ = std::fs::remove_file(&path);

        // Cota dura: 1 total + por dimensión K entradas y un cajón.
        let k = cfg.top_k as usize;
        if cfg.keeps(Resolution::Minute) {
            assert!(counts[0] <= 1 + (k + 1), "minuto: {} filas", counts[0]);
            assert!(counts[0] > 0, "el perfil retiene el minuto y no escribió nada");
        } else {
            assert_eq!(counts[0], 0, "el perfil no retiene el minuto y escribió {} filas", counts[0]);
        }
        assert!(counts[1] <= 1 + 4 * (k + 1), "hora: {} filas", counts[1]);
        assert_eq!(counts[1], counts[2], "hora y día guardan las mismas dimensiones");
    }
}

/// Tiers de `quota` (`edge/src/protection/limits.rs`, la fuente única).
struct Tier {
    name: &'static str,
    monthly: u64,
    raw_days: u64,
}

const TIERS: [Tier; 4] = [
    Tier { name: "micro", monthly: 200_000, raw_days: 2 },
    Tier { name: "starter", monthly: 2_000_000, raw_days: 3 },
    Tier { name: "pro", monthly: 15_000_000, raw_days: 5 },
    Tier { name: "enterprise", monthly: 50_000_000, raw_days: 7 },
];

/// Construye un bucket con las magnitudes de contador que le tocan a una
/// celda de `requests` peticiones. No llama a `record` una vez por petición
/// (a 15 millones al mes eso son minutos por celda): reparte las cuentas por
/// cubetas de latencia como lo haría la carga real y las inyecta de golpe,
/// pero por el mismo `Bucket` público, de modo que lo que se codifica es
/// exactamente lo que produce el codificador de verdad.
fn representative_bucket(requests: u64, variant: u64) -> Bucket {
    let mut b = Bucket::new();
    if requests == 0 {
        return b;
    }
    // Reparto de latencias de una API real: la mayoría rápido, una cola
    // pequeña. Seis cubetas del histograma pobladas, que es lo que se ve en
    // una celda horaria de verdad.
    let shape: [(u32, u64); 6] =
        [(2, 55), (5, 25), (12, 10), (40, 6), (180, 3), (900 + (variant % 400) as u32, 1)];
    let weight: u64 = shape.iter().map(|(_, w)| w).sum();
    let bin = 300 + variant % 700;
    let bout = 4_000 + variant % 9_000;
    let mut assigned = 0u64;
    for (i, (lat, w)) in shape.iter().enumerate() {
        let n = if i + 1 == shape.len() {
            requests.saturating_sub(assigned)
        } else {
            (requests * w / weight).max(1).min(requests.saturating_sub(assigned))
        };
        if n == 0 {
            continue;
        }
        assigned += n;
        // Una parte son errores, como en la carga real (~1%).
        let errs = n / 97;
        b.record_many(*lat, bin, bout, true, errs).unwrap();
        b.record_many(*lat, bin, bout, false, n - errs).unwrap();
    }
    b
}

/// Plantilla de una celda: las claves exactas (dimensión y valor) que un
/// `Rollup` real produce con la cardinalidad del edge. Se saca del motor, no
/// se inventa, para que la tabla por tier multiplique filas reales.
fn cell_template(res: Resolution, cfg: Config) -> Vec<(Dimension, Option<Vec<u8>>)> {
    let path = tmp(&format!("inro-rollup-tpl-{}-{}.inro", res.code(), cfg.top_k));
    let db = Db::create(
        Box::new(FileStorage::open(&path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();
    let mut r = Rollup::new(cfg);
    let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
    let mut tx = db.begin_write().unwrap();
    for i in 0..3_000u32 {
        synthetic_observation(i, &mut ep, &mut user, &mut country);
        let mut o = obs(i, &ep, &user, &country);
        o.ts = 1_760_000_000;
        r.observe(&mut tx, &o).unwrap();
    }
    r.flush(&mut tx).unwrap();
    tx.commit().unwrap();
    let rd = db.begin_read();
    let tsb = res.bucket_of(1_760_000_000).unwrap();
    let out = inro::rollup::read_range(&rd, res, tsb, tsb + 1, 10_000)
        .unwrap()
        .into_iter()
        .map(|row| (row.dim, row.value))
        .collect();
    drop(rd);
    drop(db);
    let _ = std::fs::remove_file(&path);
    out
}

/// Un perfil de retención y cardinalidad. La política de cuándo podar es del
/// llamante (ver `rollup::prune_before`), así que aquí se miden tres: el de
/// **por defecto** (`Profile::Minimal`), el de **tiempo real**
/// (`Profile::Realtime`, la sección 12.3 al pie de la letra) y uno intermedio,
/// para poner número a lo que cuesta cada palanca.
struct Prof {
    name: &'static str,
    cfg: Config,
}

const PROFILES: [Prof; 5] = [
    // El de POR DEFECTO desde esta tarea: K = 4, sin resolución de minuto,
    // 7 días de hora y 90 días de día.
    Prof { name: "POR DEFECTO (Profile::Minimal)", cfg: Config::minimal() },
    // Las mismas retenciones del perfil por defecto pero con K = 16 y K = 32.
    // Están aquí porque `top_k_accuracy_at_the_default_k_of_four` mide que con
    // K = 4 el informe por endpoint deja de servir: estas dos filas son lo que
    // cuesta en disco recuperarlo SIN volver a la resolución de minuto.
    Prof {
        name: "por defecto pero K=16",
        cfg: Config {
            top_k: 16,
            minute: false,
            hour: true,
            day: true,
            max_open_cells: 2,
            retention_secs: [48 * 3_600, 7 * 86_400, 90 * 86_400],
        },
    },
    Prof { name: "informes (Profile::Reports, K=32 sin minuto)", cfg: Config::reports() },
    // El opt-in: `Profile::Realtime`, sección 12.3 al pie de la letra.
    Prof { name: "tiempo real (Profile::Realtime, 12.3)", cfg: Config::realtime() },
    // Intermedio, solo para ver la pendiente entre los dos: K = 8, 6 h de
    // minuto, 30 d de hora, 1 año de día.
    Prof {
        name: "intermedio (K=8, 6h/30d/1a)",
        cfg: Config {
            top_k: 8,
            minute: true,
            hour: true,
            day: true,
            max_open_cells: 2,
            retention_secs: [6 * 3_600, 30 * 86_400, 365 * 86_400],
        },
    },
];

/// Celdas que retiene un perfil en una resolución: su retención dividida por
/// la anchura de la celda, y cero si la resolución está apagada. **Se deriva
/// del `Config`, no se escribe a mano**, para que la tabla mida exactamente lo
/// que el perfil dice y no lo que alguien copió.
fn cells_of(cfg: &Config, res: Resolution) -> u64 {
    if cfg.keeps(res) { cfg.retention(res) / res.seconds() } else { 0 }
}

/// Coste en disco de los agregados por tier y por perfil, con el crudo de 6
/// horas compuesto a partir de los 34,14 B/entrada medidos.
#[test]
#[ignore]
fn aggregate_disk_per_tier_under_six_hour_raw_retention() {
    let order = [Resolution::Minute, Resolution::Hour, Resolution::Day];

    for prof in PROFILES {
        let cfg = prof.cfg;
        let templates: Vec<Vec<(Dimension, Option<Vec<u8>>)>> =
            order.iter().map(|res| cell_template(*res, cfg)).collect();
        let cells: Vec<u64> = order.iter().map(|res| cells_of(&cfg, *res)).collect();

        println!();
        println!("=== perfil \"{}\": K = {} ===", prof.name, cfg.top_k);
        for (i, res) in order.iter().enumerate() {
            println!(
                "  {res:?}: {} celdas ({} d de retencion) x {} filas medidas",
                cells[i],
                cfg.retention(*res) / 86_400,
                templates[i].len()
            );
        }

        // Mezcla de flota 55/30/13/2 (sección 12.2), a los dos tamaños de
        // flota que el dueño maneja.
        let mut fleet = 0.0f64;
        let mix = [0.55, 0.30, 0.13, 0.02];

        for (ti, t) in TIERS.iter().enumerate() {
            let per_day = t.monthly / 30;
            let path = tmp(&format!("inro-rollup-tier-{}-{}.inro", t.name, cfg.top_k));
            let db = Db::create(
                Box::new(FileStorage::open(&path).unwrap()),
                Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
            )
            .unwrap();

            let mut rows_written = 0u64;
            let mut per_res: Vec<(Resolution, u64, u64)> = Vec::new();
            for (i, res) in order.iter().enumerate() {
                let tpl = &templates[i];
                let cells = cells[i];
                let cell_requests = match res {
                    Resolution::Minute => per_day / (24 * 60),
                    Resolution::Hour => per_day / 24,
                    Resolution::Day => per_day,
                }
                .max(1);
                let dims = (tpl.len() as u64).saturating_sub(1).max(1);
                let share = (cell_requests * 4 / dims).max(1);
                let before = std::fs::metadata(&path).unwrap().len();
                let mut rows_here = 0u64;

                let mut tx = db.begin_write().unwrap();
                let mut in_tx = 0u32;
                for c in 0..cells {
                    let tsb = c as u32;
                    for (j, (dim, value)) in tpl.iter().enumerate() {
                        let b = if *dim == Dimension::Total {
                            representative_bucket(cell_requests, 0)
                        } else {
                            representative_bucket(share, j as u64)
                        };
                        let k = if *dim == Dimension::Total {
                            key::total_key(res.code(), tsb, dim.code())
                        } else {
                            key::dim_key(res.code(), tsb, dim.code(), value.as_deref())
                        };
                        tx.put(inro::rollup::AGG_NS, &k, &b.encode()).unwrap();
                        rows_here += 1;
                        in_tx += 1;
                    }
                    if in_tx >= 5_000 {
                        tx.commit().unwrap();
                        tx = db.begin_write().unwrap();
                        in_tx = 0;
                    }
                }
                tx.commit().unwrap();
                let after = std::fs::metadata(&path).unwrap().len();
                rows_written += rows_here;
                per_res.push((*res, rows_here, after - before));
            }
            drop(db);
            let agg_size = std::fs::metadata(&path).unwrap().len();
            let _ = std::fs::remove_file(&path);

            let raw_6h = (t.monthly as f64 / 30.0 / 4.0) * RAW_BYTES_PER_ENTRY;
            let raw_today = (t.monthly as f64 / 30.0 * t.raw_days as f64) * RAW_BYTES_PER_ENTRY;
            let total = raw_6h + agg_size as f64;
            fleet += mix[ti] * total;
            println!(
                "  {:<11} hoy {:>9.0} KB | crudo 6h {:>8.0} KB | agregados {:>7.0} KB ({rows_written} filas, {:.1} B/fila) | TOTAL {:>8.0} KB",
                t.name,
                raw_today / 1024.0,
                raw_6h / 1024.0,
                agg_size as f64 / 1024.0,
                agg_size as f64 / rows_written as f64,
                total / 1024.0
            );
            for (res, rows, bytes) in per_res {
                if rows == 0 {
                    println!("              {res:?}: no retenida en este perfil");
                    continue;
                }
                println!(
                    "              {res:?}: {rows} filas, {:>7.0} KB ({:.1} B/fila)",
                    bytes as f64 / 1024.0,
                    bytes as f64 / rows as f64
                );
            }
        }
        for n in [1360.0f64, 2700.0] {
            println!(
                "  FLOTA de {n:.0} con mezcla 55/30/13/2: {:.2} GB",
                n * fleet / 1024.0 / 1024.0 / 1024.0
            );
        }
        println!("  (hoy, sin agregar y con la retencion cruda de cada plan: 58 GB a 2700; proyeccion del duenno: 2,5 GB)");
    }
}

/// La única de este fichero que NO va `#[ignore]`: fija el techo que de
/// verdad importaría si se rompiera. Un día de agregados horarios tiene que
/// costar mucho menos que el crudo que resume.
#[test]
fn the_aggregate_layer_writes_far_less_than_the_raw_records_it_summarises() {
    const N: u32 = 4_000;
    let path = tmp("inro-rollup-ratio.inro");
    let db = Db::create(
        Box::new(FileStorage::open(&path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();
    let mut r = Rollup::new(Config::default());
    let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
    let mut raw_bytes = 0u64;
    let mut agg_bytes = 0u64;
    for chunk in (0..N).collect::<Vec<_>>().chunks(1000) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            let (k, v) = synthetic_log(i);
            raw_bytes += (k.len() + v.len()) as u64;
            tx.put(inro::rollup::RAW_NS_RECOMMENDED, &k, &v).unwrap();
            synthetic_observation(i, &mut ep, &mut user, &mut country);
            r.observe(&mut tx, &obs(i, &ep, &user, &country)).unwrap();
        }
        agg_bytes += r.flush(&mut tx).unwrap().bytes_written;
        tx.commit().unwrap();
    }
    drop(db);
    let _ = std::fs::remove_file(&path);
    println!(
        "crudo lógico {raw_bytes} B, agregado lógico {agg_bytes} B, razón {:.2}",
        agg_bytes as f64 / raw_bytes as f64
    );
    assert!(
        agg_bytes < raw_bytes,
        "el agregado ({agg_bytes} B) cuesta más que el crudo que resume ({raw_bytes} B)"
    );
}

// ---------------------------------------------------------------------------
// Lo que cuesta bajar K de 32 a 4, medido sobre repartos realistas.
// ---------------------------------------------------------------------------

/// Generador congruencial lineal propio; `rand` sería una dependencia.
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    /// Uniforme en `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Reparto zipf-iano: probabilidad del rango `r` proporcional a `1/r^s`.
///
/// **Es la forma que hay que usar y no la uniforme.** Con un reparto uniforme
/// de 200 endpoints, el «verdadero top-4» es ruido puro y cualquier top-K
/// parece igual de bueno o de malo; el tráfico real está concentrado, y es esa
/// concentración la que decide si `K = 4` basta.
struct Zipf {
    cum: Vec<f64>,
}

impl Zipf {
    fn new(n: usize, s: f64) -> Self {
        let mut cum = Vec::with_capacity(n);
        let mut acc = 0.0f64;
        for r in 1..=n {
            acc += 1.0 / (r as f64).powf(s);
            cum.push(acc);
        }
        for c in cum.iter_mut() {
            *c /= acc;
        }
        Zipf { cum }
    }
    fn pick(&self, u: f64) -> usize {
        match self.cum.binary_search_by(|c| c.partial_cmp(&u).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(self.cum.len() - 1),
        }
    }
    /// Masa de tráfico que se llevan los `k` valores más frecuentes.
    fn head_mass(&self, k: usize) -> f64 {
        self.cum[(k - 1).min(self.cum.len() - 1)]
    }
}

/// Un reparto de dimensión con nombre.
struct Shape {
    name: &'static str,
    values: usize,
    s: f64,
    /// Fracción de las peticiones que van a un valor ÚNICO (el ataque de
    /// cardinalidad de la sección 12.4: `/users/48213/orders`).
    unique_share: f64,
}

/// Lo que una corrida deja medido.
#[derive(Default)]
struct Acc {
    trials: u64,
    set_hits: u64,
    order_hits: u64,
    top1_hits: u64,
    drawer_share: f64,
    exact_counts: u64,
    reported: u64,
    worst_understatement: f64,
    overstatements: u64,
    conservation_failures: u64,
}

/// Una corrida: `n` observaciones del reparto `shape` por un `TopK` de `k`
/// entradas, comparadas contra las cuentas EXACTAS de las mismas
/// observaciones.
fn accuracy_trial(acc: &mut Acc, shape: &Shape, n: u64, k: u16, seed: u64) {
    use std::collections::HashMap;
    let z = Zipf::new(shape.values, shape.s);
    let mut rng = Lcg(seed);
    let mut t = inro::rollup::TopK::new(k);
    let mut truth: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut uniq = 0u64;
    for i in 0..n {
        let v = if rng.unit() < shape.unique_share {
            uniq += 1;
            format!("/users/{}/orders", seed * 1_000_003 + uniq)
        } else {
            format!("/api/v1/{}", z.pick(rng.unit()))
        };
        *truth.entry(v.as_bytes().to_vec()).or_insert(0) += 1;
        t.record(v.as_bytes(), (i % 400) as u32, 7, 11, i % 50 == 0).unwrap();
    }

    // Conservación exacta, campo a campo.
    let sum_req: u64 = t.entries().iter().map(|e| e.bucket.requests).sum();
    let sum_in: u64 = t.entries().iter().map(|e| e.bucket.bytes_in).sum();
    let sum_hist: u64 = t.entries().iter().map(|e| e.bucket.hist.total()).sum();
    if sum_req + t.drawer.requests != n
        || sum_in + t.drawer.bytes_in != n * 7
        || sum_hist + t.drawer.hist.total() != n
    {
        acc.conservation_failures += 1;
    }

    // Verdad: los cuatro valores más frecuentes de ESTAS observaciones.
    let mut real: Vec<(Vec<u8>, u64)> = truth.into_iter().collect();
    real.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let true_top: Vec<(Vec<u8>, u64)> = real.iter().take(4).cloned().collect();
    let real_map: std::collections::HashMap<&[u8], u64> =
        real.iter().map(|(v, c)| (v.as_slice(), *c)).collect();

    // Lo informado: las cuatro entradas de mayor cuenta informada.
    let mut rep: Vec<(&[u8], u64)> =
        t.entries().iter().map(|e| (e.value.as_slice(), e.bucket.requests)).collect();
    rep.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let rep_top: Vec<(&[u8], u64)> = rep.iter().take(4).cloned().collect();

    // Acierto de conjunto CON EMPATES EQUIVALENTES: dos valores con la misma
    // frecuencia verdadera son intercambiables, y a los volúmenes de un micro
    // (277 peticiones por hora) los empates son la norma. Exigir el valor
    // exacto mediría el desempate, no la precisión.
    let mut want: Vec<u64> = true_top.iter().map(|(_, c)| *c).collect();
    let mut got: Vec<u64> =
        rep_top.iter().map(|(v, _)| real_map.get(*v).copied().unwrap_or(0)).collect();
    want.sort_unstable();
    got.sort_unstable();
    if want == got {
        acc.set_hits += 1;
    }
    let got_ordered: Vec<u64> =
        rep_top.iter().map(|(v, _)| real_map.get(*v).copied().unwrap_or(0)).collect();
    let want_ordered: Vec<u64> = true_top.iter().map(|(_, c)| *c).collect();
    if got_ordered == want_ordered {
        acc.order_hits += 1;
    }
    if !rep_top.is_empty()
        && !true_top.is_empty()
        && real_map.get(rep_top[0].0).copied().unwrap_or(0) == true_top[0].1
    {
        acc.top1_hits += 1;
    }

    // Exactitud de las cuentas informadas de esas entradas.
    for (v, reported) in &rep_top {
        let real_c = real_map.get(*v).copied().unwrap_or(0);
        acc.reported += 1;
        if *reported > real_c {
            acc.overstatements += 1;
        } else if *reported == real_c {
            acc.exact_counts += 1;
        }
        if real_c > 0 {
            let miss = (real_c - reported.min(&real_c)) as f64 / real_c as f64;
            acc.worst_understatement = acc.worst_understatement.max(miss);
        }
    }

    acc.drawer_share += t.drawer.requests as f64 / n as f64;
    acc.trials += 1;
}

/// **Lo que cuesta el `K = 4` del perfil por defecto**, medido contra las
/// cuentas exactas de las mismas observaciones.
///
/// La cota de subestimación de Space-Saving es `N/K`: bajar de `K = 32` a
/// `K = 4` la afloja **ocho veces**. Esta prueba pone número a lo que eso
/// significa de verdad sobre repartos zipf-ianos —el tráfico real está
/// concentrado, no repartido— a los volúmenes de celda horaria de cada plan:
///
/// - con qué frecuencia el top-4 informado ES el top-4 verdadero,
/// - cuánto tráfico acaba en el cajón `otros` (lo que el panel no puede
///   nombrar),
/// - si las cuentas informadas siguen siendo exactas y nunca exageradas.
#[test]
#[ignore]
fn top_k_accuracy_at_the_default_k_of_four() {
    let shapes = [
        Shape { name: "endpoints, zipf s=1,0 (200 valores)", values: 200, s: 1.0, unique_share: 0.0 },
        Shape { name: "user agents, zipf s=1,4 (25 valores)", values: 25, s: 1.4, unique_share: 0.0 },
        Shape { name: "codigos de estado, zipf s=2,5 (12 valores)", values: 12, s: 2.5, unique_share: 0.0 },
        Shape {
            name: "endpoints zipf + 30% de rutas unicas (ataque 12.4)",
            values: 200,
            s: 1.0,
            unique_share: 0.30,
        },
    ];

    for shape in &shapes {
        let z = Zipf::new(shape.values, shape.s);
        println!();
        println!("=== reparto \"{}\" ===", shape.name);
        println!(
            "  masa teorica de la cabeza: top-4 {:.1}% | top-32 {:.1}% (sin contar el {:.0}% de unicos)",
            z.head_mass(4) * 100.0,
            z.head_mass(32) * 100.0,
            shape.unique_share * 100.0
        );
        println!(
            "  {:<12} {:>8} {:>4} {:>12} {:>8} {:>7} {:>9} {:>12} {:>10} {:>8}",
            "tier", "N/celda", "K", "top-4 exacto", "orden", "top-1", "cajon", "subestim.", "cuentas", "exagera"
        );
        for t in TIERS.iter() {
            // Peticiones de una celda HORARIA, que es la resolución más fina
            // que el perfil por defecto retiene.
            let n = (t.monthly / 30 / 24).max(1);
            let trials = (2_000_000 / n).clamp(5, 200);
            for k in [4u16, 8, 16, 32] {
                let mut acc = Acc::default();
                for s in 0..trials {
                    accuracy_trial(&mut acc, shape, n, k, 0x1234_5678 + s * 7919);
                }
                let pc = |x: u64| x as f64 / acc.trials as f64 * 100.0;
                println!(
                    "  {:<12} {n:>8} {k:>4} {:>11.1}% {:>7.1}% {:>6.1}% {:>8.1}% {:>11.1}% {:>9.1}% {:>8}",
                    t.name,
                    pc(acc.set_hits),
                    pc(acc.order_hits),
                    pc(acc.top1_hits),
                    acc.drawer_share / acc.trials as f64 * 100.0,
                    acc.worst_understatement * 100.0,
                    acc.exact_counts as f64 / acc.reported as f64 * 100.0,
                    acc.overstatements
                );
                assert_eq!(acc.overstatements, 0, "una cuenta informada supera la verdadera");
                assert_eq!(acc.conservation_failures, 0, "la conservacion se rompio");
            }
        }
    }
    println!();
    println!("  'cajon' = % del trafico que el panel NO puede nombrar; 'subestim.' = peor error");
    println!("  relativo de una entrada informada; 'cuentas' = % de entradas informadas cuya cuenta");
    println!("  es EXACTA; 'exagera' = veces que lo informado supera lo verdadero (tiene que ser 0).");
}

/// **El hallazgo que esta capa estuvo a punto de introducir sin que nadie lo
/// midiera**, y por eso tiene prueba propia.
///
/// `tree.rs` reparte una hoja que se desborda por el punto medio salvo cuando
/// la clave que entra es la **mayor de todo el árbol** y la hoja es la de más
/// a la derecha (`SplitBias::Append`, `insert_rec`: `rightmost && i ==
/// page.n_slots()`). Esa es la optimización que bajó el crudo de 67,72 a
/// 34,14 bytes por entrada, porque un log se inserta siempre por el final.
///
/// Los agregados viven en el espacio `0x02` y el crudo en el `0x01`, y el
/// motor antepone ese byte a la clave: **en cuanto existe UNA sola fila de
/// agregado, ninguna clave cruda vuelve a ser la mayor del árbol**, el sesgo
/// de anexado deja de dispararse y el llenado de hoja vuelve al ~50% del
/// reparto por el punto medio.
///
/// Esta prueba mide el efecto con una sola fila plantada, aislándolo del
/// volumen de los agregados en sí.
#[test]
#[ignore]
fn one_aggregate_row_costs_the_raw_path_its_append_split_bias() {
    const N: u32 = 20_000;
    fn raw_only(path: &std::path::Path, plant: bool) -> u64 {
        raw_in_ns(path, plant, 0x01)
    }
    fn raw_in_ns(path: &std::path::Path, plant: bool, raw_ns: u8) -> u64 {
        let db = Db::create(
            Box::new(FileStorage::open(path).unwrap()),
            Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        if plant {
            let mut tx = db.begin_write().unwrap();
            let k = key::total_key(Resolution::Day.code(), 0, Dimension::Total.code());
            let mut b = Bucket::new();
            b.record(1, 1, 1, false).unwrap();
            tx.put(inro::rollup::AGG_NS, &k, &b.encode()).unwrap();
            tx.commit().unwrap();
        }
        for chunk in (0..N).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic_log(i);
                tx.put(raw_ns, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
        drop(db);
        std::fs::metadata(path).unwrap().len()
    }
    let p1 = tmp("inro-rollup-bias-clean.inro");
    let p2 = tmp("inro-rollup-bias-planted.inro");
    let p3 = tmp("inro-rollup-bias-above.inro");
    let clean = raw_only(&p1, false);
    let planted = raw_only(&p2, true);
    // Y el arreglo, que no cuesta nada: el crudo en un espacio de claves POR
    // ENCIMA del de los agregados, de modo que sigue siendo la mayor clave
    // del árbol y el sesgo de anexado se vuelve a disparar.
    let above = raw_in_ns(&p3, true, inro::rollup::RAW_NS_RECOMMENDED);
    println!("--- efecto de una sola fila de agregado sobre el sesgo de anexado ---");
    println!("crudo en 0x01, nada en 0x02:  {clean} B = {:.2} B/entrada", clean as f64 / N as f64);
    println!("crudo en 0x01, UNA fila 0x02: {planted} B = {:.2} B/entrada  ({:+.1}%)",
        planted as f64 / N as f64, (planted as f64 / clean as f64 - 1.0) * 100.0);
    println!("crudo en 0x{:02x}, UNA fila 0x02: {above} B = {:.2} B/entrada  ({:+.1}%)",
        inro::rollup::RAW_NS_RECOMMENDED, above as f64 / N as f64,
        (above as f64 / clean as f64 - 1.0) * 100.0);
    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);
    let _ = std::fs::remove_file(&p3);
    assert!(
        above as f64 <= clean as f64 * 1.02,
        "el crudo por encima de los agregados tendria que recuperar el sesgo de anexado"
    );
}

/// El camino de lectura del crudo con y sin agregados en el mismo árbol.
///
/// Los agregados viven en el MISMO árbol que los registros crudos (un solo
/// árbol y una sola raíz por commit, sección 10 de la especificación), así que
/// añaden altura y hojas por las que un `get` del crudo desciende. Esta prueba
/// pone número a ese coste, que es lo único por lo que esta capa puede tocar
/// el rendimiento del camino crudo — el motor en sí no cambia salvo por un
/// método nuevo (`WriteTxn::scan`) que ningún camino existente llama.
#[test]
#[ignore]
fn the_raw_read_path_with_and_without_aggregates_in_the_same_tree() {
    const N: u32 = 50_000;
    let ns = inro::rollup::RAW_NS_RECOMMENDED;

    fn build(path: &std::path::Path, n: u32, with_agg: bool, ns: u8, cfg: Config) -> Db {
        let db = Db::create(
            Box::new(FileStorage::open(path).unwrap()),
            Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        let mut r = Rollup::new(cfg);
        let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
        for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic_log(i);
                tx.put(ns, &k, &v).unwrap();
                if with_agg {
                    synthetic_observation(i, &mut ep, &mut user, &mut country);
                    r.observe(&mut tx, &obs(i, &ep, &user, &country)).unwrap();
                }
            }
            if with_agg {
                r.flush(&mut tx).unwrap();
            }
            tx.commit().unwrap();
        }
        db
    }

    println!("--- camino de lectura del crudo, {N} entradas ---");
    for (name, with_agg, cfg) in [
        ("sin agregados", false, Config::default()),
        ("agg por defecto", true, Config::default()),
        ("agg tiempo real", true, Config::realtime()),
    ] {
        let path = tmp(&format!("inro-rollup-read-{name}.inro"));
        let db = build(&path, N, with_agg, ns, cfg);
        let rd = db.begin_read();

        // `get` puntual: 5.000 claves repartidas.
        let probes: Vec<Vec<u8>> = (0..5_000u32).map(|j| synthetic_log(j * 10).0).collect();
        let t0 = std::time::Instant::now();
        let mut found = 0u32;
        for k in &probes {
            if rd.get(ns, k).unwrap().is_some() {
                found += 1;
            }
        }
        let per_get = t0.elapsed().as_secs_f64() / probes.len() as f64 * 1e6;
        assert_eq!(found, 5_000);

        // Recorrido completo del espacio crudo.
        let t0 = std::time::Instant::now();
        let mut cur = rd.scan(ns, &[], &[0xff; 16]).unwrap();
        let mut seen = 0u64;
        while cur.next().unwrap().is_some() {
            seen += 1;
        }
        let scan = t0.elapsed().as_secs_f64();
        assert_eq!(seen, N as u64);
        drop(cur);
        drop(rd);
        drop(db);
        let size = std::fs::metadata(&path).unwrap().len();
        let _ = std::fs::remove_file(&path);
        println!(
            "  {name:<14} get {per_get:.2} us | recorrido de {N} entradas {scan:.4} s | fichero {size} B"
        );
    }
}
