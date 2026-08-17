//! Banco de RAM por base abierta — la línea base que la fase 2 necesita
//! antes de empezar.
//!
//! **Por qué existe.** El criterio de salida de la fase 2 (sección 16 de la
//! especificación) es "RAM por base abierta en 40 KB o menos para un nodo pro
//! y 8 KB o menos para uno micro". Hasta esta prueba, la columna de RAM de la
//! tabla de fases **no tenía ni una sola medición en ninguna fase**: los
//! ~832 KB de la fila de la fase 1 son una estimación de diseño, y la única
//! cifra de memoria que llegó a medirse (la comparativa con SQLite de la
//! sección 17.1) resultó no ser válida — medía el pico del PROCESO completo
//! con `VmHWM`, que es monótono, con los dos motores corriendo dentro del
//! mismo proceso. Empezar la fase 2 sin línea base sería repetir el error de
//! la tarea 21 con los bytes por entrada: optimizar contra un número
//! calculado y descubrir al medir que el hueco estaba en otro sitio.
//!
//! **Qué mide, exactamente.** `VmRSS` de `/proc/self/status` — memoria
//! residente AHORA, no el pico histórico — en un proceso **hijo recién
//! arrancado** que no hace más que abrir `N` bases y recorrerlas, dividido
//! entre `N`. No es memoria virtual ni pico: es lo que de verdad ocupa en RAM
//! tener mil inquilinos abiertos, que es la pregunta del escenario
//! multi-tenant de la sección 1.
//!
//! **Un proceso por medición, y por qué NO es una precaución opcional.** La
//! primera versión de este banco medía las tres configuraciones dentro del
//! mismo proceso de pruebas, tomando la referencia justo antes de cada una.
//! Dio un resultado imposible —**96 bytes por base abierta** en la tercera
//! medición— y la prueba que debía atraparlo pasó, porque el número absurdo
//! caía del lado bueno de su umbral. El motivo: el asignador no devuelve al
//! sistema todo lo que libera, así que a la tercera medición la arena ya
//! estaba caliente y `VmRSS` apenas crecía; lo que se medía no era la memoria
//! de las bases, era cuánta arena sobraba de la fase anterior. Ese sesgo
//! **subestima sin cota**, así que ningún umbral generoso protege de él.
//!
//! La corrección es la misma que la sección 17.1 concluyó para comparar RSS
//! entre motores, y aquí sí se ejecuta: **un proceso por configuración**. El
//! padre construye los ficheros y lanza un hijo (`std::process::Command` sobre
//! `current_exe`, sin dependencias nuevas) que arranca limpio, toma su propia
//! referencia, abre las bases y publica el número por su salida estándar. El
//! padre no mide nada; solo suma y divide.
//!
//! **Frío y caliente, que son dos números distintos y los dos importan.**
//! Recién abierta, una base solo tiene su estructura: la caché de páginas está
//! vacía porque se llena perezosamente. Tras recorrerla, la caché llega a su
//! presupuesto y la base ocupa su techo. El compromiso de la sección 1 —"RAM
//! constante y configurable por base abierta"— habla del techo, así que es el
//! caliente el que se compara contra los 40 KB de la fase 2.
//!
//! **Lo que sigue sin medir aquí**: la memoria de las capas de encima
//! (diccionarios de interning, buckets de agregación en curso), que la sección
//! 1 contabiliza aparte y que la fase 2 también tiene que atacar. Aquí solo
//! hay `Db`.
//!
//! Todo va `#[ignore]`: construye cientos de ficheros, lanza procesos y
//! depende de `/proc`. Es un banco de mano cuyo resultado se anota en la
//! especificación, no una prueba de regresión de cada `cargo test`.
#![cfg(feature = "std")]

use inro::storage::FileStorage;
use inro::{Db, Options, Sync};

/// Bases abiertas a la vez en el hijo. Con una sola, el ruido del asignador
/// es del orden del dato buscado; con 128, cada byte de ruido se reparte
/// entre 128.
const N: usize = 128;

/// Registros por base. Suficientes para que el árbol tenga varios niveles y
/// para que un recorrido complete el presupuesto de caché.
const ENTRIES: u32 = 20_000;

/// Memoria residente ACTUAL del proceso, en bytes. `None` fuera de Linux o si
/// `/proc` no está montado — las pruebas se saltan solas en ese caso en vez
/// de fallar, porque lo que faltaría es el instrumento, no la propiedad.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

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

/// Un registro con la forma del log del edge, igual que en `tests/size.rs`
/// pero recortado: lo que este banco mide es memoria, no bytes en disco.
fn synthetic(i: u32) -> (Vec<u8>, Vec<u8>) {
    let ts = 1_760_000_000_000u64 + i as u64 * 520;
    let mut key = Vec::with_capacity(10);
    key.extend_from_slice(&ts.to_be_bytes());
    key.extend_from_slice(&((i % 8) as u16).to_be_bytes());
    let mut v = Vec::with_capacity(24);
    push_varint(&mut v, (i % 400) as u64);
    push_varint(&mut v, 500 + (i % 9000) as u64);
    push_varint(&mut v, (i % 200) as u64);
    push_varint(&mut v, (i % 5_000) as u64);
    push_varint(&mut v, (i % 10_000) as u64);
    (key, v)
}

/// Directorio propio por corrida y configuración: el hijo solo recibe la
/// ruta y reconstruye los nombres, sin que padre e hijo tengan que ponerse
/// de acuerdo en nada más.
fn dir_for(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("inro-ram-{}-{tag}", std::process::id()))
}

fn path_in(dir: &std::path::Path, i: usize) -> std::path::PathBuf {
    dir.join(format!("{i}.inro"))
}

/// Construye `N` bases con `entries` registros y las cierra. Lo hace el
/// PADRE: el hijo tiene que arrancar limpio, sin haber asignado nada más que
/// lo suyo.
fn build_all(dir: &std::path::Path, entries: u32, page_size: u32) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    for i in 0..N {
        let path = path_in(dir, i);
        let db = Db::create(
            Box::new(FileStorage::open(&path).unwrap()),
            Options { page_size, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        let mut tx = db.begin_write().unwrap();
        for j in 0..entries {
            let (k, v) = synthetic(j);
            tx.put(0x01, &k, &v).unwrap();
        }
        tx.commit().unwrap();
    }
}

/// Recorre la base entera para que la caché de páginas llegue a su
/// presupuesto: es lo que separa el número frío del caliente.
fn warm_up(db: &Db) {
    let tx = db.begin_read();
    let mut cursor = tx.scan(0x01, &[], &[0xff; 16]).unwrap();
    let mut seen = 0u64;
    while let Some((_k, _v)) = cursor.next().unwrap() {
        seen += 1;
    }
    assert!(seen > 0, "el recorrido no vio ni una entrada; la base no se construyó");
}

/// Bytes por base abierta, en frío y en caliente, medidos en un proceso
/// recién arrancado. `None` si no hay `/proc`.
///
/// Lanza `current_exe` —el propio binario de pruebas— filtrando por el nombre
/// de `ram_measurement_child`, con las variables de entorno que le dicen qué
/// medir. Sin ellas ese test no hace nada, así que una corrida normal de
/// `cargo test -- --ignored` no lanza procesos ni mide memoria.
fn measure_in_child(dir: &std::path::Path, page_size: u32, cache_pages: usize) -> Option<(f64, f64)> {
    let exe = std::env::current_exe().expect("current_exe");
    let out = std::process::Command::new(exe)
        .args(["--ignored", "--exact", "ram_measurement_child", "--nocapture", "--test-threads", "1"])
        .env("INRO_RAM_DIR", dir)
        .env("INRO_RAM_PAGE", page_size.to_string())
        .env("INRO_RAM_CACHE", cache_pages.to_string())
        .output()
        .expect("lanzar el hijo");
    let text = String::from_utf8_lossy(&out.stdout);
    // `contains`, no `starts_with`: `libtest` antepone "test
    // ram_measurement_child ... " al `println!` del hijo EN LA MISMA LÍNEA,
    // así que buscar por prefijo no encuentra nada aunque el número esté ahí
    // — costó una corrida entera descubrirlo.
    let line = text
        .lines()
        .find_map(|l| l.split_once("INRO_RAM_RESULT ").map(|(_, rest)| rest))
        .unwrap_or_else(|| {
            panic!(
                "el hijo ({}) no publicó resultado.\n--- stdout ---\n{}\n--- stderr ---\n{}",
                out.status,
                text,
                String::from_utf8_lossy(&out.stderr)
            )
        });
    let mut cold = None;
    let mut warm = None;
    for field in line.split_whitespace() {
        if let Some(v) = field.strip_prefix("cold=") {
            cold = v.parse::<u64>().ok();
        } else if let Some(v) = field.strip_prefix("warm=") {
            warm = v.parse::<u64>().ok();
        }
    }
    Some((cold? as f64 / N as f64, warm? as f64 / N as f64))
}

/// El proceso hijo. **No es una prueba**: sin `INRO_RAM_DIR` en el entorno
/// termina sin hacer nada. Vive aquí, y no en un binario aparte, porque
/// `current_exe` es la única forma de relanzarse a sí mismo sin añadir un
/// target de Cargo ni una dependencia.
#[test]
#[ignore]
fn ram_measurement_child() {
    let Ok(dir) = std::env::var("INRO_RAM_DIR") else { return };
    let page_size: u32 = std::env::var("INRO_RAM_PAGE").unwrap().parse().unwrap();
    let cache_pages: usize = std::env::var("INRO_RAM_CACHE").unwrap().parse().unwrap();
    let dir = std::path::PathBuf::from(dir);

    let before = rss_bytes().expect("sin /proc");
    let dbs: Vec<Db> = (0..N)
        .map(|i| {
            Db::open(
                Box::new(FileStorage::open(&path_in(&dir, i)).unwrap()),
                Options { page_size, cache_pages, ..Options::default() },
            )
            .unwrap()
        })
        .collect();
    let cold = rss_bytes().unwrap();
    for db in &dbs {
        warm_up(db);
    }
    let warm = rss_bytes().unwrap();
    // Las tres lecturas solo significan algo si las `N` bases siguen vivas
    // cuando se toman.
    std::hint::black_box(&dbs);
    println!(
        "INRO_RAM_RESULT cold={} warm={}",
        cold.saturating_sub(before),
        warm.saturating_sub(before)
    );
}

/// Línea base con la configuración de un nodo micro: páginas de 512 B y 32 de
/// caché, que son los valores por defecto de `Options`. Presupuesto de caché:
/// 16.384 B.
///
/// **Medido** (17-08-2026, `--release`, glibc, 128 bases de 20.000 entradas,
/// proceso propio): ver el informe que imprime. El techo del `assert` es
/// generoso a propósito — lo que esta prueba defiende es el orden de magnitud,
/// no un byte exacto que el asignador puede mover entre versiones de la libc.
#[test]
#[ignore]
fn ram_per_open_database_with_micro_defaults() {
    if rss_bytes().is_none() {
        eprintln!("sin /proc: banco omitido");
        return;
    }
    let dir = dir_for("micro");
    build_all(&dir, ENTRIES, 512);
    let (cold, warm) = measure_in_child(&dir, 512, 32).expect("el hijo no publicó resultado");
    let _ = std::fs::remove_dir_all(&dir);
    let budget = 32.0 * 512.0;
    println!(
        "micro (512 B/página, 32 de caché = {budget:.0} B de presupuesto): \
         {cold:.0} B/base en frío, {warm:.0} B/base en caliente \
         ({:.2}× el presupuesto)",
        warm / budget
    );
    assert!(
        warm < 512.0 * 1024.0,
        "{warm:.0} B por base abierta: medio megabyte por inquilino invalidaría el escenario \
         multi-tenant entero, revisar antes de seguir"
    );
}

/// La misma medición con la configuración de un nodo pro: páginas de 4 KB y 64
/// de caché, presupuesto de 262.144 B. Es la fila de la tabla de fases que
/// dice "~832 KB, sin medir".
#[test]
#[ignore]
fn ram_per_open_database_with_pro_defaults() {
    if rss_bytes().is_none() {
        eprintln!("sin /proc: banco omitido");
        return;
    }
    let dir = dir_for("pro");
    build_all(&dir, ENTRIES, 4096);
    let (cold, warm) = measure_in_child(&dir, 4096, 64).expect("el hijo no publicó resultado");
    let _ = std::fs::remove_dir_all(&dir);
    let budget = 64.0 * 4096.0;
    println!(
        "pro (4 KB/página, 64 de caché = {budget:.0} B de presupuesto): \
         {cold:.0} B/base en frío, {warm:.0} B/base en caliente \
         ({:.2}× el presupuesto)",
        warm / budget
    );
}

/// **La curva entera, que es lo que de verdad hay que mirar.**
///
/// Los dos bancos de arriba miden un punto cada uno, y el punto lo elige una
/// constante. El tamaño de página SÍ lo fija la especificación por tier
/// (§12.4: 512 B en micro y starter, 4 KB en pro y enterprise, decidido al
/// crear el fichero), pero **`cache_pages` no aparece por ningún lado**: el
/// único valor que la especificación menciona es el `32` del ejemplo de API,
/// que es el de `Options::default()`. Llamar "configuración de un nodo pro" a
/// `64` era una invención de este banco.
///
/// Así que en vez de defender un número inventado, esta prueba barre el
/// presupuesto y publica la tabla: cuánta RAM por base cuesta cada valor, con
/// los dos tamaños de página que la especificación sí fija. Con eso, elegir
/// `cache_pages` por tier pasa a ser una decisión con datos delante — y el
/// coste en LECTURAS de cada opción, que es la otra mitad de esa decisión,
/// es la primera tarea de la fase 2.
#[test]
#[ignore]
fn ram_across_cache_budgets() {
    if rss_bytes().is_none() {
        eprintln!("sin /proc: banco omitido");
        return;
    }
    for (tag, page_size) in [("micro", 512u32), ("pro", 4096u32)] {
        let dir = dir_for(&format!("sweep-{tag}"));
        build_all(&dir, ENTRIES, page_size);
        println!("--- páginas de {page_size} B ---");
        for cache_pages in [0usize, 4, 8, 16, 32, 64, 128] {
            let (cold, warm) =
                measure_in_child(&dir, page_size, cache_pages).expect("el hijo no publicó");
            let budget = (cache_pages as f64) * (page_size as f64);
            println!(
                "cache_pages={cache_pages:3}  presupuesto={budget:8.0} B  \
                 frío={cold:8.0} B/base  caliente={warm:8.0} B/base"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// **El suelo fijo por base abierta**, medido con `cache_pages = 0`: la
/// estructura que existe aunque no se cachee ni una página — `Pager`,
/// `Freelist`, catálogo, geometría, los cerrojos, el `Box<dyn Storage>` y el
/// descriptor de fichero.
///
/// Es el número que decide si el criterio de la fase 2 es alcanzable. Los
/// otros dos bancos miden presupuesto de caché MÁS suelo, y el presupuesto se
/// baja con una constante; el suelo, no. Si el suelo por sí solo ya rozara los
/// 8 KB del objetivo micro, recortar la caché no serviría de nada y la fase 2
/// tendría que atacar la estructura, no el cacheo.
#[test]
#[ignore]
fn the_fixed_floor_per_open_database_without_any_cache() {
    if rss_bytes().is_none() {
        eprintln!("sin /proc: banco omitido");
        return;
    }
    let dir = dir_for("floor");
    build_all(&dir, ENTRIES, 512);
    let (cold, warm) = measure_in_child(&dir, 512, 0).expect("el hijo no publicó resultado");
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "suelo (512 B/página, caché 0): {cold:.0} B/base recién abierta, {warm:.0} B/base tras \
         recorrerla entera"
    );
    // Con presupuesto cero, recorrer la base no puede dejar páginas
    // retenidas: si el número caliente se dispara sobre el frío, algo cachea
    // por su cuenta y la RAM por base deja de ser constante.
    assert!(
        warm < cold.max(1.0) * 4.0 + 8.0 * 1024.0,
        "sin caché, recorrer la base entera pasa de {cold:.0} a {warm:.0} B/base: algo retiene \
         páginas fuera del presupuesto"
    );
}

/// **La propiedad, no el número**: la RAM por base abierta la fija el
/// presupuesto de caché, no el tamaño del fichero.
///
/// Es la mitad de la promesa de la sección 1 que decide si el escenario
/// multi-tenant se sostiene —"constante y configurable"— y la que ninguna
/// prueba vigilaba. Compara dos poblaciones con el MISMO presupuesto de caché
/// y **veinte veces** de diferencia en número de entradas, cada una en su
/// propio proceso: si el consumo siguiera al tamaño del fichero, mil
/// inquilinos grandes reventarían el nodo aunque el presupuesto dijera otra
/// cosa.
///
/// El umbral es de DOS lados, no de uno. Uno solo fue exactamente el defecto
/// de la primera versión de este banco: midiendo las dos poblaciones en el
/// mismo proceso, la segunda dio 96 B/base —un resultado imposible— y el
/// `assert` de "no crece" pasó tan contento. Un cociente demasiado BAJO no es
/// una buena noticia, es una medición rota.
#[test]
#[ignore]
fn ram_per_open_database_follows_the_cache_budget_and_not_the_file_size() {
    if rss_bytes().is_none() {
        eprintln!("sin /proc: banco omitido");
        return;
    }
    let small_dir = dir_for("small");
    build_all(&small_dir, 2_000, 512);
    let (_, warm_small) =
        measure_in_child(&small_dir, 512, 32).expect("el hijo no publicó resultado");
    let _ = std::fs::remove_dir_all(&small_dir);

    let big_dir = dir_for("big");
    build_all(&big_dir, 40_000, 512);
    let (_, warm_big) = measure_in_child(&big_dir, 512, 32).expect("el hijo no publicó resultado");
    let _ = std::fs::remove_dir_all(&big_dir);

    let ratio = warm_big / warm_small.max(1.0);
    println!(
        "mismo presupuesto de caché, 20× de diferencia de tamaño: {warm_small:.0} B/base con \
         2.000 entradas, {warm_big:.0} B/base con 40.000 — cociente {ratio:.2}"
    );
    assert!(
        ratio < 1.5,
        "cociente {ratio:.2}: veinte veces más datos suben la RAM por base abierta, así que el \
         consumo NO lo fija el presupuesto de caché — la promesa de RAM constante por base de la \
         sección 1 no se sostiene"
    );
    assert!(
        ratio > 0.5,
        "cociente {ratio:.2}: la población grande mide MENOS de la mitad que la pequeña con el \
         mismo presupuesto de caché, lo cual es imposible — la medición está rota, no el motor \
         (ver el comentario del módulo sobre el sesgo del asignador)"
    );
}
