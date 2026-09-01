//! Régimen permanente de un inquilino: ¿el fichero llega a una meseta?
//!
//! `tests/rollup_size.rs` mide lo que CUESTA la capa de agregación.
//! Esto mide lo que la capa **ahorra**, que es una pregunta distinta y que no
//! se puede contestar sin podar: mientras el crudo no se borre, los agregados
//! solo suman disco. Aquí se simula un inquilino corriendo días enteros con
//! el ciclo de retención de `Rollup::retain` (volcar → podar agregados →
//! podar crudo → `reclaim_tail`) y se mira si el fichero se para.
//!
//! **Ninguna de estas pruebas toca `tests/size.rs`.** Todas van `#[ignore]`
//! salvo la última, que es un techo barato y sí corre siempre.
//!
//! ## Cómo se ejecutan
//!
//! ```text
//! cargo test --release --test retention_size -- --ignored --nocapture \
//!     the_file_reaches_a_plateau_under_a_steady_tenant
//! ```
//!
//! Dos variables de entorno acotan la corrida, porque un mes de un nodo
//! *enterprise* son cincuenta millones de registros:
//!
//! - `INRO_SIM_DAYS` — días simulados (30 por defecto).
//! - `INRO_SIM_TIERS` — lista separada por comas (`micro,starter,pro,enterprise`
//!   por defecto).
//!
//! ## Qué es tiempo simulado y qué no
//!
//! El reloj es un `u64` que avanza una hora por iteración: **no se espera**.
//! Lo que sí es real es todo lo demás — cada registro se escribe, cada
//! observación pasa por el agregador, cada poda es un `delete_range` de
//! verdad y cada `reclaim_tail` es un recorte de verdad del fichero. El
//! volumen tampoco se escala: un día simulado de un nodo *pro* escribe sus
//! 500.000 registros.
//!
//! ## El ritmo: el tope mensual, no el tope de rps
//!
//! Los perfiles de carga de referencia fijan DOS topes por plan, y no son la
//! misma carga:
//!
//! | Tier | Mensual | rps |
//! |---|---|---|
//! | micro | 200.000 | 5 |
//! | starter | 2.000.000 | 25 |
//! | pro | 15.000.000 | 150 |
//! | enterprise | 50.000.000 | 500 |
//!
//! **Los dos topes son incompatibles sostenidos**: 5 rps durante 30 días son
//! 12,96 millones de peticiones, 65 veces el tope mensual de *micro*; 150 rps
//! son 388 millones, 26 veces el de *pro*. El rps es el techo de ráfaga que el
//! limitador deja pasar en un instante, no el volumen que el plan compra. El
//! volumen que decide el disco es el mensual, y es el que usa
//! `docs/agregacion.md` en todas sus proyecciones (`monthly / 30 / 4` para las
//! 6 horas de crudo). Por eso la simulación reparte el tope mensual a ritmo
//! constante: es la única lectura que se puede comparar de tú a tú con la
//! tabla que hay que falsar.
//!
//! El rps sí aparece, en `the_burst_ceiling_of_a_plan_bounds_the_live_raw`:
//! una hora entera al tope de ráfaga, para poner número al peor caso que el
//! plan permite.

#![cfg(all(feature = "std", feature = "rollup"))]

use inro::rollup::{
    AGG_NS, Config, Observation, RAW_NS_RECOMMENDED, RawTime, RawWindow, Resolution, Rollup,
};
use inro::storage::FileStorage;
use inro::{Db, Options, Sync};

/// Espacio de claves del crudo, el del mapa de la sección 10.
const RAW_NS: u8 = RAW_NS_RECOMMENDED;

/// La ventana que decidió el dueño.
const RAW_SECS: u64 = RawWindow::SIX_HOURS;

/// Instante de arranque: un día unix exacto, para que las celdas empiecen
/// alineadas y el primer día no salga a medias.
const T0: u64 = 1_786_320_000;

/// Registros por transacción, el lote del escritor agrupado del edge.
const BATCH: u64 = 1_000;

/// Bytes por entrada cruda medidos en `tests/size.rs`. Aquí NO se usa para
/// componer nada: solo para comparar contra lo medido.
const RAW_BYTES_PER_ENTRY: f64 = 34.14;

struct Tier {
    name: &'static str,
    monthly: u64,
    /// Tope de ráfaga del plan. No fija el volumen (ver el comentario de
    /// módulo), solo el peor caso instantáneo.
    rps: u64,
    /// Proyección de `docs/agregacion.md` §8.3 con el perfil por defecto
    /// (`Reports`), en KB. Es la cifra que esta prueba existe para falsar.
    projected_kb: f64,
}

const TIERS: [Tier; 4] = [
    Tier { name: "micro", monthly: 200_000, rps: 5, projected_kb: 1_052.0 },
    Tier { name: "starter", monthly: 2_000_000, rps: 25, projected_kb: 1_628.0 },
    Tier { name: "pro", monthly: 15_000_000, rps: 150, projected_kb: 5_367.0 },
    Tier { name: "enterprise", monthly: 50_000_000, rps: 500, projected_kb: 15_140.0 },
];

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

const STATUS: [u16; 12] = [200, 201, 204, 301, 304, 400, 401, 403, 404, 429, 500, 503];

fn status_of(i: u64) -> u16 {
    if i % 100 < 82 { 200 } else { STATUS[(i % 12) as usize] }
}

/// Clave cruda del esquema de referencia: `[ts BE u64][seq u16]`, con el
/// instante en **segundos**. Es la disposición que hace que la poda por
/// tiempo sea un `delete_range` sobre un rango contiguo.
fn raw_key(ts: u64, seq: u16) -> Vec<u8> {
    let mut k = Vec::with_capacity(10);
    k.extend_from_slice(&ts.to_be_bytes());
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Valor con los catorce campos de `request_logs`, idéntico en forma al de
/// `tests/size.rs` — es lo que hace que los 34,14 B/entrada sean comparables.
fn raw_value(i: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.push(if i.is_multiple_of(7) { 1 } else { 0 });
    v.push(status_of(i) as u8 % 128);
    push_varint(&mut v, i % 400);
    push_varint(&mut v, 500 + i % 9_000);
    push_varint(&mut v, 100 + i % 900);
    v.extend_from_slice(&((192u32 << 24) | (i % 65_536) as u32).to_le_bytes());
    v.push((i % 40) as u8);
    v.push(0);
    push_varint(&mut v, i % 200);
    push_varint(&mut v, i % 5_000);
    push_varint(&mut v, i % 300);
    push_varint(&mut v, i % 1_200);
    push_varint(&mut v, i % 10_000);
    push_varint(&mut v, i % 10_000);
    v
}

/// Dimensiones de la observación `i`, con la cardinalidad del edge: 200
/// endpoints, 40 países, 10.000 usuarios.
fn dims(i: u64, ep: &mut String, user: &mut String, country: &mut String) {
    ep.clear();
    ep.push_str("/api/v1/");
    ep.push_str(&(i % 200).to_string());
    user.clear();
    user.push('u');
    user.push_str(&(i % 10_000).to_string());
    country.clear();
    country.push_str(&(i % 40).to_string());
}

fn obs<'a>(i: u64, ts: u64, ep: &'a str, user: &'a str, country: &'a str) -> Observation<'a> {
    Observation {
        ts,
        latency_ms: (i % 400) as u32,
        bytes_in: 100 + i % 900,
        bytes_out: 500 + i % 9_000,
        status: status_of(i),
        error: status_of(i) >= 500,
        endpoint: ep.as_bytes(),
        country: country.as_bytes(),
        user: user.as_bytes(),
    }
}

/// Ruta temporal **con el pid dentro**, y no es cosmético.
///
/// Estas mediciones se lanzan a mano, en segundo plano y a menudo varias a la
/// vez para repartirlas por los núcleos. Con un nombre fijo, dos corridas del
/// mismo tier comparten fichero: la segunda hace `remove_file` sobre el de la
/// primera —que sigue escribiendo por su descriptor, ya sobre un inodo sin
/// nombre— y a partir de ahí **`file_kb` de la primera mide el fichero de la
/// segunda**. Ocurrió: una corrida de *pro* informó de una caída de 1,26 MB en
/// un día que no era suya, y solo se descubrió porque `pager::truncate` tiene
/// un único llamador y ninguno de los dos `reclaim_tail` de esos días había
/// devuelto nada. Un número creíble y falso, que es exactamente lo que este
/// proyecto trata peor que un error.
fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Política de sincronización de la corrida. `Sync::Never` por defecto —es la
/// de todos los bancos de este proyecto, así que es la que hace comparables
/// estas cifras con las de `docs/agregacion.md`— y `INRO_SIM_SYNC=commit` para
/// la otra, que **no da el mismo tamaño de fichero**: bajo `Never` el motor no
/// puede reutilizar una página liberada hasta que el punto durable la alcanza,
/// y eso obliga a extender el fichero de más (ver el comentario del `enum
/// Sync`, «un margen constante»). Medir las dos es la única forma de separar
/// ese margen de lo que la poda de verdad ahorra.
fn sync_mode() -> Sync {
    match std::env::var("INRO_SIM_SYNC").as_deref() {
        Ok("commit") => Sync::Commit,
        _ => Sync::Never,
    }
}

fn open(path: &std::path::Path) -> Db {
    Db::create(
        Box::new(FileStorage::open(path).unwrap()),
        Options { page_size: 4096, sync: sync_mode(), ..Options::default() },
    )
    .unwrap()
}

fn file_kb(path: &std::path::Path) -> f64 {
    std::fs::metadata(path).unwrap().len() as f64 / 1024.0
}

/// Cuenta claves vivas de un espacio y suma sus bytes lógicos.
fn live(db: &Db, ns: u8) -> (u64, u64) {
    let rd = db.begin_read();
    let mut cur = rd.scan(ns, b"", &[0xff; 24]).unwrap();
    let (mut n, mut bytes) = (0u64, 0u64);
    while let Some((k, v)) = cur.next().unwrap() {
        n += 1;
        bytes += (k.len() + v.len()) as u64;
    }
    (n, bytes)
}

/// Páginas realmente en uso (fichero menos lista de libres).
fn pages_in_use(db: &Db) -> u32 {
    let mut tx = db.begin_write().unwrap();
    tx.pages_in_use()
}

/// Cuántos registros escribe esta hora, repartidos segundo a segundo. Devuelve
/// el número escrito.
fn write_hour(
    db: &Db,
    r: &mut Rollup,
    hour_start: u64,
    per_hour: u64,
    counter: &mut u64,
    aggregate: bool,
) -> u64 {
    let (mut ep, mut user, mut country) = (String::new(), String::new(), String::new());
    let mut done = 0u64;
    let mut in_tx = 0u64;
    let mut tx = db.begin_write().unwrap();
    for s in 0..3_600u64 {
        let target = per_hour * (s + 1) / 3_600;
        while done < target {
            let seq = (done - per_hour * s / 3_600) as u16;
            let i = *counter;
            let ts = hour_start + s;
            tx.put(RAW_NS, &raw_key(ts, seq), &raw_value(i)).unwrap();
            if aggregate {
                dims(i, &mut ep, &mut user, &mut country);
                r.observe(&mut tx, &obs(i, ts, &ep, &user, &country)).unwrap();
            }
            *counter += 1;
            done += 1;
            in_tx += 1;
            if in_tx >= BATCH {
                if aggregate {
                    r.flush(&mut tx).unwrap();
                }
                tx.commit().unwrap();
                tx = db.begin_write().unwrap();
                in_tx = 0;
            }
        }
    }
    if aggregate {
        r.flush(&mut tx).unwrap();
    }
    tx.commit().unwrap();
    done
}

/// Una fila de la tabla diaria.
struct Day {
    day: u64,
    size_kb: f64,
    after_reclaim_kb: f64,
    reclaimed_kb: f64,
    pages: u32,
    raw_rows: u64,
    agg_rows: u64,
    raw_logical: u64,
    agg_logical: u64,
}

fn env_days() -> u64 {
    std::env::var("INRO_SIM_DAYS").ok().and_then(|s| s.parse().ok()).unwrap_or(30)
}

fn env_tiers() -> Vec<usize> {
    match std::env::var("INRO_SIM_TIERS") {
        Err(_) => (0..TIERS.len()).collect(),
        Ok(s) => s
            .split(',')
            .filter_map(|name| TIERS.iter().position(|t| t.name == name.trim()))
            .collect(),
    }
}

/// Corre `days` días de un tier y devuelve la serie diaria.
fn simulate(path: &std::path::Path, per_hour: u64, days: u64, label: &str) -> Vec<Day> {
    let db = open(path);
    let mut r = Rollup::new(Config::default());
    let mut counter = 0u64;
    let mut out = Vec::new();
    let start = std::time::Instant::now();
    for d in 0..days {
        for h in 0..24u64 {
            let hour_start = T0 + (d * 24 + h) * 3_600;
            write_hour(&db, &mut r, hour_start, per_hour, &mut counter, true);
            // El ciclo de retención, una vez por hora: es lo que haría un
            // podador real, y da 24 ciclos por día simulado.
            let now = hour_start + 3_600;
            let mut tx = db.begin_write().unwrap();
            r.retain(&mut tx, now, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds))).unwrap();
            tx.commit().unwrap();
        }
        let size_kb = file_kb(path);
        let reclaimed = db.reclaim_tail().unwrap();
        let after_reclaim_kb = file_kb(path);
        let (raw_rows, raw_logical) = live(&db, RAW_NS);
        let (agg_rows, agg_logical) = live(&db, AGG_NS);
        let row = Day {
            day: d + 1,
            size_kb,
            after_reclaim_kb,
            reclaimed_kb: reclaimed as f64 / 1024.0,
            pages: pages_in_use(&db),
            raw_rows,
            agg_rows,
            raw_logical,
            agg_logical,
        };
        println!(
            "  [{label}] dia {:>3}: fichero {:>10.1} KB | reclaim {:>8.1} KB -> {:>10.1} KB | \
             paginas {:>7} | crudo {:>8} filas ({:.0} KB) | agg {:>7} filas ({:.0} KB) | {:.0}s",
            row.day,
            row.size_kb,
            row.reclaimed_kb,
            row.after_reclaim_kb,
            row.pages,
            row.raw_rows,
            row.raw_logical as f64 / 1024.0,
            row.agg_rows,
            row.agg_logical as f64 / 1024.0,
            start.elapsed().as_secs_f64()
        );
        out.push(row);
    }
    drop(db);
    out
}

/// **La medición principal.** Un inquilino corriendo días enteros con el ciclo
/// de retención completo, a los cuatro tiers.
#[test]
#[ignore]
fn the_file_reaches_a_plateau_under_a_steady_tenant() {
    let days = env_days();
    println!("=== meseta con {days} dias simulados, perfil por defecto (Reports) ===");
    for ti in env_tiers() {
        let t = &TIERS[ti];
        let per_hour = t.monthly / 30 / 24;
        let path = tmp(&format!("inro-plateau-{}.inro", t.name));
        println!(
            "\n--- {} : {} req/mes, {per_hour} req/h, ventana de crudo {} h, tope de rafaga {} rps ---",
            t.name,
            t.monthly,
            RAW_SECS / 3_600,
            t.rps
        );
        let series = simulate(&path, per_hour, days, t.name);
        let _ = std::fs::remove_file(&path);
        report(t, &series, per_hour);
    }
}

fn report(t: &Tier, series: &[Day], per_hour: u64) {
    let last = series.last().unwrap();
    let expected_live = per_hour * RAW_SECS / 3_600;
    println!(
        "  {} | meseta {:.1} KB (tras reclaim {:.1} KB) | proyeccion {:.0} KB | {:.2}x",
        t.name,
        last.size_kb,
        last.after_reclaim_kb,
        t.projected_kb,
        last.size_kb / t.projected_kb
    );
    println!(
        "  crudo vivo {} filas (esperadas {expected_live}), {:.1} B/fila logica; \
         agregado {} filas, {:.1} B/fila logica",
        last.raw_rows,
        last.raw_logical as f64 / last.raw_rows.max(1) as f64,
        last.agg_rows,
        last.agg_logical as f64 / last.agg_rows.max(1) as f64
    );
    println!(
        "  crudo compuesto a 34,14 B/entrada: {:.1} KB; medido en fichero (todo incluido): {:.1} KB",
        expected_live as f64 * RAW_BYTES_PER_ENTRY / 1024.0,
        last.size_kb
    );
    // Crecimiento del último tercio de la serie: ¿plano o todavía subiendo?
    if series.len() >= 6 {
        let third = series.len() / 3;
        let a = &series[series.len() - 2 * third];
        let b = last;
        let per_day = (b.size_kb - a.size_kb) / (b.day - a.day) as f64;
        println!(
            "  pendiente del ultimo tercio (dia {} -> {}): {per_day:+.1} KB/dia",
            a.day, b.day
        );
    }
    let total_reclaimed: f64 = series.iter().map(|d| d.reclaimed_kb).sum();
    println!("  reclaim_tail devolvio {total_reclaimed:.1} KB en {} llamadas", series.len());
}

/// Lo mismo pero **sin agregar**: aísla el crudo para poder ver el llenado de
/// hoja a lo largo de muchos ciclos de poda.
///
/// La pregunta es concreta: `delete_rec` colapsa nodos internos de un solo
/// hijo pero **no funde hojas medio vacías** (`docs/invariantes.md` §3), y el
/// sesgo de anexado que baja el crudo a 34,14 B/entrada solo se dispara
/// insertando por el final. Un ciclo de poda que deje hojas raquíticas por
/// abajo mientras se anexa por arriba haría subir los bytes por entrada viva
/// ciclo tras ciclo, y el efecto solo se ve acumulado.
#[test]
#[ignore]
fn raw_leaf_fill_across_repeated_prune_cycles() {
    let days = env_days();
    for ti in env_tiers() {
        let t = &TIERS[ti];
        let per_hour = t.monthly / 30 / 24;
        let path = tmp(&format!("inro-leaffill-{}.inro", t.name));
        let db = open(path.as_path());
        let mut r = Rollup::new(Config::default());
        let mut counter = 0u64;
        println!("\n--- llenado de hoja, {} ({per_hour} req/h), SOLO crudo ---", t.name);
        let page = 4096f64;
        for d in 0..days {
            for h in 0..24u64 {
                let hour_start = T0 + (d * 24 + h) * 3_600;
                write_hour(&db, &mut r, hour_start, per_hour, &mut counter, false);
                let cut = RawWindow::six_hours(RAW_NS, RawTime::Seconds).cutoff_key(hour_start + 3_600).unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.delete_range(RAW_NS, b"", &cut).unwrap();
                tx.commit().unwrap();
            }
            let (rows, logical) = live(&db, RAW_NS);
            let pages = pages_in_use(&db);
            println!(
                "  dia {:>3}: {rows} filas vivas, {pages} paginas en uso, \
                 {:.2} B/entrada en uso, {:.2} B/entrada de fichero, {:.1}% de llenado logico",
                d + 1,
                pages as f64 * page / rows.max(1) as f64,
                file_kb(&path) * 1024.0 / rows.max(1) as f64,
                logical as f64 * 100.0 / (pages as f64 * page)
            );
        }
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

/// El peor caso que el plan permite: una hora entera al tope de rps.
///
/// No es el régimen permanente (ver el comentario de módulo: sostener el rps
/// rompería el tope mensual en dos días), pero sí acota lo que el crudo puede
/// llegar a ocupar dentro de su ventana si el inquilino gasta su mes en unas
/// horas.
#[test]
#[ignore]
fn the_burst_ceiling_of_a_plan_bounds_the_live_raw() {
    for ti in env_tiers() {
        let t = &TIERS[ti];
        let per_hour = t.rps * 3_600;
        let path = tmp(&format!("inro-burst-{}.inro", t.name));
        let db = open(path.as_path());
        let mut r = Rollup::new(Config::default());
        let mut counter = 0u64;
        // Seis horas seguidas al tope: la ventana entera llena de ráfaga.
        for h in 0..6u64 {
            let hour_start = T0 + h * 3_600;
            write_hour(&db, &mut r, hour_start, per_hour, &mut counter, true);
            let mut tx = db.begin_write().unwrap();
            r.retain(&mut tx, hour_start + 3_600, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds)))
                .unwrap();
            tx.commit().unwrap();
        }
        let (rows, logical) = live(&db, RAW_NS);
        let size = file_kb(&path);
        let month_in_hours = t.monthly as f64 / per_hour as f64;
        println!(
            "  {:<11} 6 h al tope de {} rps: {rows} filas vivas, {:.0} KB logicos, fichero {size:.0} KB \
             (el mes entero cabe en {month_in_hours:.1} h a ese ritmo)",
            t.name,
            t.rps,
            logical as f64 / 1024.0
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

/// La única que NO va `#[ignore]`: el ciclo de retención tiene que hacer que
/// el fichero deje de crecer. Barata a propósito — un día simulado de un nodo
/// diminuto — porque lo que fija es la regresión que de verdad importaría.
#[test]
fn the_retention_cycle_stops_the_file_from_growing() {
    let path = tmp("inro-plateau-guard.inro");
    let db = open(path.as_path());
    let mut r = Rollup::new(Config::default());
    let mut counter = 0u64;
    let per_hour = 240u64;
    let mut sizes = Vec::new();
    let mut live_per_hour = Vec::new();
    for h in 0..24u64 {
        let hour_start = T0 + h * 3_600;
        write_hour(&db, &mut r, hour_start, per_hour, &mut counter, true);
        let mut tx = db.begin_write().unwrap();
        r.retain(&mut tx, hour_start + 3_600, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds)))
            .unwrap();
        tx.commit().unwrap();
        sizes.push(file_kb(&path));
        live_per_hour.push(live(&db, RAW_NS).0);
    }
    let (rows, _) = live(&db, RAW_NS);
    drop(db);
    let _ = std::fs::remove_file(&path);

    // Hora a hora: la ventana se llena en seis y a partir de ahí no se mueve.
    // Es la invariante fuerte del ciclo, y comprobarla en CADA hora atrapa
    // tanto una poda que no borra como una que borra de mas.
    for (h, n) in live_per_hour.iter().enumerate() {
        let esperado = (h as u64 + 1).min(RAW_SECS / 3_600) * per_hour;
        assert_eq!(*n, esperado, "hora {h}: {n} registros crudos vivos, esperados {esperado}");
    }
    // El crudo vivo es exactamente la ventana, ni un registro mas.
    assert_eq!(rows, per_hour * RAW_SECS / 3_600, "el crudo vivo no es la ventana de 6 h");

    // Y el fichero de la segunda mitad del día crece mucho menos que el de la
    // primera: la primera llena la ventana, la segunda ya solo acumula
    // agregado.
    let ramp = sizes[11] - sizes[0];
    let steady = sizes[23] - sizes[12];
    println!("rampa (h0-h11) {ramp:.1} KB, regimen (h12-h23) {steady:.1} KB, {rows} filas vivas");
    assert!(
        steady < ramp,
        "el fichero crece igual en régimen ({steady:.1} KB) que en la rampa ({ramp:.1} KB): \
         la poda no está liberando nada"
    );
}

/// Dónde se va el disco que la proyección no contaba: **el llenado de hoja del
/// espacio de agregados**.
///
/// La proyección de `docs/agregacion.md` §8.3 midió el juego completo de filas
/// escribiéndolo **una vez y en orden de clave ascendente** sobre una base
/// recién creada. Un `Rollup` real no escribe así, y esta prueba separa las
/// tres diferencias para poner número a cada una:
///
/// - **A**: todas las filas en orden ascendente. Es lo que midió la proyección.
/// - **B**: mismas filas, celdas en orden, pero **desordenadas dentro de la
///   celda** — que es como las emite `write_cell` (por ranura de dimensión y,
///   dentro, en el orden de la tabla del top-K, que no es el de la clave).
/// - **C**: como B, pero con las celdas de **día intercaladas
///   cronológicamente** entre las de hora, como ocurre de verdad. Las claves
///   de día (`res = 2`) ordenan por encima de todas las de hora (`res = 1`),
///   así que en cuanto existe una sola fila de día **ninguna inserción de hora
///   vuelve a ser la mayor del espacio** y el sesgo de anexado de `tree.rs`
///   deja de dispararse.
///
/// Es exactamente la trampa que `RAW_NS_RECOMMENDED` documenta entre espacios
/// de claves, una capa más abajo: allí la arreglaron acotando la región de
/// anexado a `[ns, ns+1)`; **dentro de un espacio no hay ninguna cota más
/// fina**, así que `0x02` la sigue pagando entera.
#[test]
#[ignore]
fn where_the_aggregate_space_loses_its_leaf_fill() {
    use inro::rollup::{Bucket, Dimension, key};

    // La meseta de un micro con el perfil por defecto: 7 días de hora y 90 de
    // día, 112 filas por celda (medidas en `rollup_size.rs`).
    const HOUR_CELLS: u32 = 7 * 24;
    const DAY_CELLS: u32 = 90;
    const K: u32 = 32;

    /// Las **112** filas de una celda que `rows_per_cell_measured_against_a_real_rollup`
    /// mide con la cardinalidad del edge: la de totales, doce de estado (doce
    /// valores distintos, por debajo de `K`, así que sin cajón), y `K` + cajón
    /// por cada una de endpoint, país y usuario.
    fn cell_rows(res: u8, tsb: u32) -> Vec<Vec<u8>> {
        let mut out = vec![key::total_key(res, tsb, Dimension::Total.code())];
        for i in 0..12u32 {
            let v = format!("{}-{i:04}", Dimension::Status.code());
            out.push(key::dim_key(res, tsb, Dimension::Status.code(), Some(v.as_bytes())));
        }
        for dim in [Dimension::Endpoint, Dimension::Country, Dimension::User] {
            out.push(key::dim_key(res, tsb, dim.code(), None));
            for i in 0..K {
                let v = format!("{}-{i:04}", dim.code());
                out.push(key::dim_key(res, tsb, dim.code(), Some(v.as_bytes())));
            }
        }
        out
    }

    fn value() -> Vec<u8> {
        let mut b = Bucket::new();
        for (lat, n) in [(2u32, 55u64), (5, 25), (12, 10), (40, 6), (180, 3), (900, 1)] {
            b.record_many(lat, 400, 6_000, false, n * 3).unwrap();
        }
        b.encode()
    }

    /// Desordena dentro de la celda como lo hace la tabla del top-K: se
    /// recorre a saltos de un primo, que no es el orden de la clave.
    fn scramble(mut rows: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let n = rows.len();
        let mut out = Vec::with_capacity(n);
        let mut i = 0usize;
        let mut taken = vec![false; n];
        for _ in 0..n {
            while taken[i] {
                i = (i + 1) % n;
            }
            taken[i] = true;
            out.push(core::mem::take(&mut rows[i]));
            i = (i + 37) % n;
        }
        out
    }

    fn measure(label: &str, plan: Vec<Vec<u8>>, rows: usize) {
        let path = tmp(&format!("inro-fill-{label}.inro"));
        let db = open(path.as_path());
        let v = value();
        let mut tx = db.begin_write().unwrap();
        let mut n = 0u32;
        for k in &plan {
            tx.put(AGG_NS, k, &v).unwrap();
            n += 1;
            if n.is_multiple_of(2_000) {
                tx.commit().unwrap();
                tx = db.begin_write().unwrap();
            }
        }
        tx.commit().unwrap();
        let pages = pages_in_use(&db);
        let logical = plan.iter().map(|k| (k.len() + v.len()) as u64).sum::<u64>();
        let _ = db.reclaim_tail().unwrap();
        let size = file_kb(&path);
        drop(db);
        let _ = std::fs::remove_file(&path);
        println!(
            "  {label:<28} {rows} filas | {pages} paginas en uso ({:.0} KB) | fichero {size:.0} KB \
             | logico {:.0} KB | llenado {:.1}%",
            pages as f64 * 4.0,
            logical as f64 / 1024.0,
            logical as f64 * 100.0 / (pages as f64 * 4096.0)
        );
    }

    let mut sorted: Vec<Vec<u8>> = Vec::new();
    for t in 0..HOUR_CELLS {
        sorted.extend(cell_rows(Resolution::Hour.code(), t));
    }
    for t in 0..DAY_CELLS {
        sorted.extend(cell_rows(Resolution::Day.code(), t));
    }
    let total = sorted.len();
    sorted.sort();
    measure("A orden de clave", sorted, total);

    let mut by_cell: Vec<Vec<u8>> = Vec::new();
    for t in 0..HOUR_CELLS {
        by_cell.extend(scramble(cell_rows(Resolution::Hour.code(), t)));
    }
    for t in 0..DAY_CELLS {
        by_cell.extend(scramble(cell_rows(Resolution::Day.code(), t)));
    }
    measure("B revuelto en la celda", by_cell, total);

    // Las MISMAS filas que A y B, escritas en el orden en que ocurren: las 90
    // celdas de día se abren una cada 24 celdas de hora, así que ya hay filas
    // de `res = 2` por encima cuando se escribe la primera hora del día 2.
    let mut chrono: Vec<Vec<u8>> = Vec::new();
    for d in 0..DAY_CELLS {
        for h in 0..24u32 {
            let t = d * 24 + h;
            if t < HOUR_CELLS {
                chrono.extend(scramble(cell_rows(Resolution::Hour.code(), t)));
            }
        }
        chrono.extend(scramble(cell_rows(Resolution::Day.code(), d)));
    }
    assert_eq!(chrono.len(), total, "C tiene que escribir exactamente las filas de A y B");
    measure("C dia intercalado (real)", chrono, total);
}

/// **Qué bloquea `reclaim_tail` en régimen permanente**, medido en vez de
/// razonado.
///
/// La sospecha era concreta: los agregados sobreviven al crudo, crecen de
/// forma monótona durante 90 días y por tanto sus páginas se asignan **tarde**
/// —números de página altos— mientras las del crudo se liberan y se vuelven a
/// pedir sin parar por abajo. `reclaim_tail` solo se lleva el **sufijo** libre
/// del fichero (`docs/runbook.md` §7.5), así que una sola página viva alta
/// basta para que no devuelva nada.
///
/// El experimento distingue las dos causas sin ambigüedad: se llega al régimen
/// permanente, se recorta; luego se borra **todo el crudo** y se recorta otra
/// vez; luego **todos los agregados** y se recorta una tercera. Si lo que está
/// arriba fuera el crudo, el segundo recorte devolvería el grueso. Si son los
/// agregados, no devuelve casi nada y el tercero sí.
#[test]
#[ignore]
fn what_blocks_reclaim_tail_in_the_steady_state() {
    for ti in env_tiers() {
        let t = &TIERS[ti];
        let per_hour = t.monthly / 30 / 24;
        let path = tmp(&format!("inro-block-{}.inro", t.name));
        let db = open(path.as_path());
        let mut r = Rollup::new(Config::default());
        let mut counter = 0u64;
        // Tres días: la ventana de crudo lleva mucho girando y hay agregado de
        // hora y de día en disco.
        for h in 0..72u64 {
            let hour_start = T0 + h * 3_600;
            write_hour(&db, &mut r, hour_start, per_hour, &mut counter, true);
            let mut tx = db.begin_write().unwrap();
            r.retain(&mut tx, hour_start + 3_600, Some(RawWindow::six_hours(RAW_NS, RawTime::Seconds)))
                .unwrap();
            tx.commit().unwrap();
        }
        let steady = file_kb(&path);
        let r1 = db.reclaim_tail().unwrap() as f64 / 1024.0;
        let after1 = file_kb(&path);
        let live1 = pages_in_use(&db);

        // Fuera TODO el crudo.
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(RAW_NS, b"", &[0xff; 12]).unwrap();
        tx.commit().unwrap();
        let r2 = db.reclaim_tail().unwrap() as f64 / 1024.0;
        let after2 = file_kb(&path);
        let live2 = pages_in_use(&db);

        // Y ahora TODO el agregado.
        r.reset();
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(AGG_NS, b"", &[0xff; 12]).unwrap();
        tx.commit().unwrap();
        let r3 = db.reclaim_tail().unwrap() as f64 / 1024.0;
        let after3 = file_kb(&path);
        let live3 = pages_in_use(&db);

        println!(
            "  {:<11} regimen {steady:>9.0} KB -> reclaim {r1:>8.0} KB -> {after1:>9.0} KB ({live1} pag. vivas)\n\
             {:<13} sin crudo:     reclaim {r2:>8.0} KB -> {after2:>9.0} KB ({live2} pag. vivas)\n\
             {:<13} sin agregados: reclaim {r3:>8.0} KB -> {after3:>9.0} KB ({live3} pag. vivas)",
            t.name, "", ""
        );
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

/// El llenado de hoja que consigue un `Rollup` REAL, no una reconstrucción
/// sintética de sus filas.
///
/// `where_the_aggregate_space_loses_its_leaf_fill`, arriba, separa las causas
/// escribiendo las filas a mano en tres órdenes distintos. Esta mide lo único
/// que importa para el disco de un inquilino: cuántas páginas gasta la capa
/// cuando la usa quien la usa de verdad, y si el sesgo de anexado de `tree.rs`
/// llega a dispararse alguna vez.
///
/// El umbral es un llenado del **93%**, que es donde debe quedar una escritura
/// en orden de clave (medida aparte: 96,1%). Con el volcado desordenado esta
/// misma carga da 85%, así que el umbral discrimina: si se pone en rojo, el
/// volcado ha vuelto a emitir las filas fuera de orden.
#[test]
#[ignore]
fn the_aggregate_layer_fills_its_leaves() {
    let path = tmp("inro-agg-fill.inro");
    let _ = std::fs::remove_file(&path);
    let db = Db::create(
        Box::new(FileStorage::open(&path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();
    let mut rollup = Rollup::new(Config::default());

    // Tres días de un inquilino con la cardinalidad del edge: suficientes
    // celdas horarias para que el árbol tenga varios niveles, y días de sobra
    // para que las claves de día se intercalen con las de hora, que es lo que
    // apaga el sesgo de anexado.
    let mut rows = 0u64;
    let mut bytes = 0u64;

    for hour in 0..72u32 {
        let mut tx = db.begin_write().unwrap();
        for i in 0..200u32 {
            let ep = format!("/e{}", i % 60);
            let user = format!("u{}", i % 400);
            rollup
                .observe(
                    &mut tx,
                    &Observation {
                        ts: T0 + u64::from(hour) * 3_600 + u64::from(i) * 17,
                        endpoint: ep.as_bytes(),
                        user: user.as_bytes(),
                        country: if i % 3 == 0 { b"ES" } else { b"FR" },
                        status: if i % 50 == 0 { 500 } else { 200 },
                        latency_ms: 5 + i % 90,
                        bytes_in: 300,
                        bytes_out: 1_200,
                        error: i % 50 == 0,
                    },
                )
                .unwrap();
        }
        let st = rollup.flush(&mut tx).unwrap();
        rows += st.rows_written;
        bytes += st.bytes_written;
        tx.commit().unwrap();
    }

    let pages = pages_in_use(&db);

    // El estado final tal cual quedó, leído del propio árbol: así el control
    // replica exactamente las mismas claves y los mismos tamaños de valor,
    // sin que la prueba tenga que saber cómo se construyen.
    let final_rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let rd = db.begin_read();
        let mut c = rd.scan(0x02, &[], &[0xff; 16]).unwrap();
        let mut out = Vec::new();
        while let Some((k, v)) = c.next().unwrap() {
            out.push((k, v));
        }
        out
    };
    drop(db);
    let _ = std::fs::remove_file(&path);

    // Control: las MISMAS filas, escritas de una pasada y en orden de clave
    // ascendente sobre una base nueva. Es el mejor caso posible del árbol, y
    // comparar contra él evita que el umbral dependa de cuántas páginas
    // internas tenga esta carga o de la media de bytes por fila.
    let ctl_path = tmp("inro-agg-fill-control.inro");
    let _ = std::fs::remove_file(&ctl_path);
    let ctl = Db::create(
        Box::new(FileStorage::open(&ctl_path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();
    {
        let mut tx = ctl.begin_write().unwrap();
        // Ya vienen en orden de clave: `scan` recorre el árbol ordenado.
        for (k, v) in &final_rows {
            tx.put(0x02, k, v).unwrap();
        }
        tx.commit().unwrap();
    }
    let ctl_pages = pages_in_use(&ctl);
    drop(ctl);
    let _ = std::fs::remove_file(&ctl_path);

    let ratio = f64::from(pages) / f64::from(ctl_pages);
    println!(
        "agregado: {rows} filas y {bytes} B escritos · {pages} páginas vivas · \
         control en orden de clave {ctl_pages} · {ratio:.2}× del mejor caso"
    );
    assert!(
        ratio < 1.25,
        "el volcado gasta {ratio:.2}× las páginas del mismo juego de filas escrito en orden de \
         clave ({pages} contra {ctl_pages}): el sesgo de anexado no se está disparando (ver \
         `write_cell` y `WriteTxn::put_within`)"
    );
}
