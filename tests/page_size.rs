//! Qué cuesta cada tamaño de página, medido en las tres monedas que decide.
//!
//! La sección 12.4 de la especificación fija el tamaño de página por tier
//! —512 B en micro y starter, 4 KB en pro y enterprise— con dos frases de
//! argumento: el suelo por base manda en los pequeños, y en los grandes 512 B
//! implicarían "cientos de miles de páginas y demasiadas lecturas por
//! recorrido". Las dos son plausibles y **ninguna estaba medida**, así que
//! tampoco lo estaban los valores intermedios: nadie había mirado qué pasa con
//! 1 KB o 2 KB, que es la pregunta natural en cuanto se ve que la RAM por base
//! abierta escala con el presupuesto de caché en BYTES y no en páginas.
//!
//! Se elige al crear el fichero y no se puede cambiar después, así que
//! equivocarse aquí se paga durante toda la vida de la base.
//!
//! **Las tres monedas**, medidas para cada tamaño con la misma carga:
//!
//! 1. **Bytes por entrada en disco.** Cada página paga 20 bytes de cabecera y
//!    un array de slots; con páginas grandes eso se reparte entre más
//!    entradas. La compresión de prefijo también rinde más en una página
//!    llena.
//! 2. **Lecturas físicas por búsqueda puntual**, con la caché desactivada
//!    (`cache_pages = 0`), que es la altura efectiva del árbol: lo que la
//!    especificación llamaba "demasiadas lecturas por recorrido" sin ponerle
//!    número.
//! 3. **Suelo del fichero vacío**: tres páginas, sea cual sea el tamaño.
//!
//! La cuarta moneda —RAM por base abierta— no se mide aquí porque ya está en
//! `tests/ram_size.rs`, y su resultado es que **escala con el presupuesto de
//! caché en bytes**, no con el número de páginas: a igualdad de bytes de
//! caché, el tamaño de página no cambia la RAM, solo cuántas páginas caben en
//! ese presupuesto.
//!
//! `#[ignore]`: construye una base por tamaño de página.
#![cfg(feature = "std")]

use inro::storage::FileStorage;
use inro::{Db, Options, Storage, Sync};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cuenta lecturas al nivel del `Storage`, la capa más baja: cualquier byte
/// que el motor lea del medio pasa por aquí, venga del camino que venga.
/// Mismo patrón que `CountingStorage` en `tests/size.rs`, reimplementado
/// porque los binarios de integración no comparten código.
struct Counting<S> {
    inner: S,
    reads: AtomicU64,
    writes: AtomicU64,
    written_bytes: AtomicU64,
    syncs: AtomicU64,
    /// Offsets distintos escritos desde el último `reset_offsets`. Es lo que
    /// separa "cuántas escrituras" de "cuántas páginas".
    offsets: std::sync::Mutex<std::collections::BTreeSet<u64>>,
}

impl<S: Storage> Counting<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            written_bytes: AtomicU64::new(0),
            syncs: AtomicU64::new(0),
            offsets: std::sync::Mutex::new(Default::default()),
        }
    }
    fn count(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
    fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }
    fn written_bytes(&self) -> u64 {
        self.written_bytes.load(Ordering::Relaxed)
    }
    fn syncs(&self) -> u64 {
        self.syncs.load(Ordering::Relaxed)
    }
    fn reset_offsets(&self) {
        self.offsets.lock().unwrap().clear();
    }
    fn distinct_offsets(&self) -> usize {
        self.offsets.lock().unwrap().len()
    }
}

impl<S: Storage> Storage for Counting<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> inro::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> inro::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.written_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.offsets.lock().unwrap().insert(offset);
        self.inner.write_at(offset, buf)
    }
    fn sync(&self) -> inro::Result<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        self.inner.sync()
    }
    fn len(&self) -> inro::Result<u64> {
        self.inner.len()
    }
    fn truncate(&self, len: u64) -> inro::Result<()> {
        self.inner.truncate(len)
    }
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

/// La misma forma de registro que `tests/size.rs`: el log del edge de quota.
fn synthetic(i: u32) -> (Vec<u8>, Vec<u8>) {
    let ts = 1_760_000_000_000u64 + i as u64 * 520;
    let mut key = Vec::with_capacity(10);
    key.extend_from_slice(&ts.to_be_bytes());
    key.extend_from_slice(&((i % 8) as u16).to_be_bytes());
    let mut v = Vec::with_capacity(32);
    v.push(if i.is_multiple_of(7) { 1 } else { 0 });
    v.push(if i.is_multiple_of(97) { 2 } else { 0 });
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

/// Entradas por base. 200.000 por defecto —unos 7 MB, segundos por tamaño de
/// página— y ajustable por entorno (`INRO_PAGE_N`) porque **la escala cambia
/// la respuesta**: la altura del árbol crece con el número de entradas, así
/// que un tamaño de página que a 200.000 empata con otro puede perder a los
/// 2,5 millones de la ventana caliente de un nodo pro (sección 12.2). Medir
/// solo a la escala pequeña y extrapolar sería exactamente el error que la
/// tarea 21 cometió con los bytes por entrada.
fn entries() -> u32 {
    std::env::var("INRO_PAGE_N").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000)
}

const LOOKUPS: u32 = 1_000;

#[test]
#[ignore]
fn what_each_page_size_costs() {
    let n = entries();
    println!(
        "{:>7}  {:>12}  {:>10}  {:>9}  {:>10}  {:>9}",
        "página", "fichero", "B/entrada", "abrir", "lecturas/búsqueda", "vacía"
    );
    println!("(carga: {n} entradas)");
    for page_size in [512u32, 1024, 2048, 4096, 8192] {
        let path =
            std::env::temp_dir().join(format!("inro-page-{}-{page_size}.inro", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // Suelo del fichero recién creado, con este tamaño de página.
        let empty_path = std::env::temp_dir()
            .join(format!("inro-page-empty-{}-{page_size}.inro", std::process::id()));
        let _ = std::fs::remove_file(&empty_path);
        {
            let _db = Db::create(
                Box::new(FileStorage::open(&empty_path).unwrap()),
                Options { page_size, sync: Sync::Never, ..Options::default() },
            )
            .unwrap();
        }
        let empty = std::fs::metadata(&empty_path).unwrap().len();
        let _ = std::fs::remove_file(&empty_path);

        // La carga: 200.000 registros en lotes de mil, como el escritor
        // agrupado del edge.
        {
            let db = Db::create(
                Box::new(FileStorage::open(&path).unwrap()),
                Options { page_size, sync: Sync::Never, ..Options::default() },
            )
            .unwrap();
            for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
                let mut tx = db.begin_write().unwrap();
                for &i in chunk {
                    let (k, v) = synthetic(i);
                    tx.put(0x01, &k, &v).unwrap();
                }
                tx.commit().unwrap();
            }
        }
        let size = std::fs::metadata(&path).unwrap().len();

        // Lecturas de apertura y por búsqueda puntual, SIN caché: con caché
        // por medio se mediría el acierto de caché, no la altura del árbol.
        let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
        let db = Db::open(
            Box::new(counting.clone()),
            Options { page_size, cache_pages: 0, ..Options::default() },
        )
        .unwrap();
        let open_reads = counting.count();

        let tx = db.begin_read();
        // Claves repartidas por todo el espacio, no consecutivas: una
        // búsqueda tras otra sobre claves vecinas mediría localidad, no
        // profundidad.
        let stride = n / LOOKUPS;
        for j in 0..LOOKUPS {
            let (k, _) = synthetic(j * stride);
            let got = tx.get(0x01, &k).unwrap();
            assert!(got.is_some(), "falta una clave que se acaba de escribir");
        }
        let lookup_reads = counting.count() - open_reads;
        drop(tx);
        drop(db);
        let _ = std::fs::remove_file(&path);

        println!(
            "{page_size:>7}  {size:>12}  {:>10.2}  {open_reads:>9}  {:>17.2}  {empty:>9}",
            size as f64 / n as f64,
            lookup_reads as f64 / LOOKUPS as f64,
        );
    }
}

/// **La curva que abre la fase 2**: qué cuesta en LECTURAS cada presupuesto de
/// caché.
///
/// `tests/ram_size.rs` mide la otra mitad —lo que cada presupuesto cuesta en
/// RAM— y sale que la RAM por base es el suelo fijo (1.856 B) más la caché.
/// De ahí salía la tentación evidente: bajar `cache_pages` a 8 y cumplir el
/// criterio de la fase 2 sin escribir una línea. Esta prueba pone el precio a
/// esa tentación, que es el número que faltaba para poder decidir.
///
/// Mide lecturas FÍSICAS al nivel del `Storage`, que es donde se cuenta lo que
/// de verdad toca el medio, sobre dos cargas distintas:
///
/// - **Búsqueda puntual** con claves repartidas por todo el espacio: sin
///   localidad, cada una desciende el árbol entero. Es el peor caso para la
///   caché y el que enseña la altura efectiva.
/// - **Recorrido de rango**, que es lo que hace de verdad un informe del edge:
///   claves contiguas, localidad máxima.
///
/// La hipótesis de la fase 2 —"caché limitada a nodos internos"— predice que
/// un presupuesto pequeño se lleva casi todo el ahorro, porque los nodos
/// internos son pocos y se reusan en cada descenso mientras que las hojas no
/// se repiten. Si la curva se aplana pronto, `cache_pages` bajo es gratis; si
/// no, la fase 2 tiene que trabajar.
#[test]
#[ignore]
fn what_each_cache_budget_costs_in_reads() {
    // Escala ajustable (`INRO_PAGE_N`) por el mismo motivo que en el banco de
    // tamaño de página: el árbol crece de altura con las entradas, y lo que
    // esta curva mide es justo cuántos niveles caben en la caché.
    let n = entries();
    const LOOKUPS: u32 = 500;
    const PAGE: u32 = 4096;

    let path = std::env::temp_dir().join(format!("inro-cachecurve-{}.inro", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let db = Db::create(
            Box::new(FileStorage::open(&path).unwrap()),
            Options { page_size: PAGE, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic(i);
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
    }

    println!("(carga: {n} entradas)");
    println!(
        "{:>12}  {:>10}  {:>20}  {:>18}",
        "cache_pages", "RAM aprox", "lecturas/búsqueda", "lecturas/1000 filas"
    );
    for cache_pages in [0usize, 4, 8, 16, 32, 64, 128, 256] {
        let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
        let db = Db::open(
            Box::new(counting.clone()),
            Options { page_size: PAGE, cache_pages, ..Options::default() },
        )
        .unwrap();

        let base = counting.count();
        {
            let tx = db.begin_read();
            let stride = n / LOOKUPS;
            for j in 0..LOOKUPS {
                let (k, _) = synthetic(j * stride);
                assert!(tx.get(0x01, &k).unwrap().is_some());
            }
        }
        let lookup_reads = counting.count() - base;

        let base = counting.count();
        {
            let tx = db.begin_read();
            let (from, _) = synthetic(n / 2);
            let (to, _) = synthetic(n / 2 + 1000);
            let mut c = tx.scan(0x01, &from, &to).unwrap();
            let mut seen = 0;
            while c.next().unwrap().is_some() {
                seen += 1;
            }
            assert!(seen > 900, "el recorrido solo vio {seen} filas");
        }
        let scan_reads = counting.count() - base;
        drop(db);

        // RAM: el suelo fijo medido en `ram_size.rs` más la caché a su coste
        // real (unos 100 B de contabilidad por página, también medido).
        let ram = 1_856.0 + cache_pages as f64 * (f64::from(PAGE) + 100.0);
        println!(
            "{cache_pages:>12}  {:>8.0} KB  {:>20.2}  {scan_reads:>18}",
            ram / 1024.0,
            f64::from(lookup_reads as u32) / f64::from(LOOKUPS),
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// La otra mitad de la curva: qué cuesta cada presupuesto de caché **en el
/// camino de escritura**.
///
/// `what_each_cache_budget_costs_in_reads` mide lecturas y sale que cuatro
/// páginas bastan. De ahí salía la conclusión tentadora —bajar el defecto a 4
/// y cumplir el criterio de RAM de la fase 2 sin tocar el motor— pero medida
/// solo sobre lectura. Una caché pequeña puede salir cara al escribir: el
/// copy-on-write reescribe el camino raíz-hoja en cada commit, y dentro de un
/// mismo commit ese camino se toca una vez por fila.
///
/// Si la amplificación de escritura sube al bajar la caché, bajar el defecto
/// sería cambiar un criterio de salida de la fase 2 por el otro. Esta prueba
/// es la que lo dice.
#[test]
#[ignore]
fn what_each_cache_budget_costs_in_writes() {
    let n = entries();
    const PAGE: u32 = 4096;

    println!("(carga: {n} entradas en lotes de mil, páginas de {PAGE} B)");
    println!(
        "{:>12}  {:>14}  {:>14}  {:>16}  {:>12}",
        "cache_pages", "escrituras", "MB escritos", "amplificación", "lecturas"
    );
    for cache_pages in [0usize, 4, 8, 32, 64] {
        let path = std::env::temp_dir()
            .join(format!("inro-wcurve-{}-{cache_pages}.inro", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
        let db = Db::create(
            Box::new(counting.clone()),
            Options { page_size: PAGE, sync: Sync::Never, cache_pages, ..Options::default() },
        )
        .unwrap();

        let mut useful = 0u64;
        for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic(i);
                useful += (k.len() + v.len()) as u64;
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
        let writes = counting.writes();
        let bytes = counting.written_bytes();
        let reads = counting.count();
        drop(db);
        let _ = std::fs::remove_file(&path);

        println!(
            "{cache_pages:>12}  {writes:>14}  {:>14.1}  {:>16.2}  {reads:>12}",
            bytes as f64 / 1e6,
            bytes as f64 / useful as f64,
        );
    }
}

/// Cuántas páginas DISTINTAS toca un commit, contra cuántas escrituras emite.
///
/// El cociente entre las dos es exactamente lo que se ahorraría bufferizando
/// las páginas sucias hasta el commit en vez de escribir a través en cada
/// `put`: una página tocada mil veces se escribiría una. Sin este número, "el
/// arreglo baja la amplificación a ~2×" es aritmética de servilleta.
#[test]
#[ignore]
fn how_many_distinct_pages_a_commit_touches() {
    use std::collections::BTreeSet;
    const PAGE: u32 = 4096;
    const BATCH: u32 = 1_000;

    let path = std::env::temp_dir().join(format!("inro-distinct-{}.inro", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
    let db = Db::create(
        Box::new(counting.clone()),
        Options { page_size: PAGE, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();

    // Se calienta con unos cuantos lotes para que el árbol tenga profundidad y
    // el commit medido no sea el de un árbol de una página.
    for chunk in (0..20_000u32).collect::<Vec<_>>().chunks(BATCH as usize) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            let (k, v) = synthetic(i);
            tx.put(0x01, &k, &v).unwrap();
        }
        tx.commit().unwrap();
    }

    println!(
        "{:>8}  {:>12}  {:>16}  {:>14}  {:>12}",
        "filas", "escrituras", "páginas distintas", "escrituras/pág", "útil"
    );
    for batch in [10u32, 100, 1_000, 5_000] {
        counting.reset_offsets();
        let before = counting.writes();
        let mut useful = 0u64;
        let mut tx = db.begin_write().unwrap();
        for i in 100_000..100_000 + batch {
            let (k, v) = synthetic(i);
            useful += (k.len() + v.len()) as u64;
            tx.put(0x01, &k, &v).unwrap();
        }
        tx.commit().unwrap();
        let writes = counting.writes() - before;
        let distinct = counting.distinct_offsets();
        println!(
            "{batch:>8}  {writes:>12}  {distinct:>16}  {:>14.1}  {:>9} KB",
            writes as f64 / distinct as f64,
            useful / 1024,
        );
        println!(
            "          amplificación {:>6.2}×   ·   suelo de granularidad {:>5.2}×",
            (writes as u64 * u64::from(PAGE)) as f64 / useful as f64,
            (distinct as u64 * u64::from(PAGE)) as f64 / useful as f64,
        );
        // **La propiedad**: una página tocada mil veces en una transacción se
        // escribe UNA. El copy-on-write obliga a copiar el camino raíz-hoja en
        // cada `put`, pero no obliga a mandarlo al medio cada vez: eso era
        // escribir a través, y costaba 154 escrituras por página viva.
        //
        // El margen de 1,5 no es holgura arbitraria: el cierre del commit
        // escribe además la meta y las páginas de la lista de libres, que sí
        // pueden tocarse dos veces si el volcado de la lista crece mientras se
        // serializa.
        assert!(
            writes as f64 <= distinct as f64 * 1.5,
            "un commit de {batch} filas emitió {writes} escrituras para {distinct} páginas \
             distintas: las páginas sucias se están mandando al medio en cada `put` en vez de \
             acumularse hasta el commit"
        );
    }
    drop(db);
    let _ = std::fs::remove_file(&path);
}

/// Qué parte del FICHERO es basura transitoria del propio commit.
///
/// El desperdicio de escritura (2.009 escrituras para 13 páginas vivas) no se
/// traduce automáticamente en disco: las páginas que un `put` supera dentro de
/// la misma transacción vuelven a la lista de libres y se reutilizan. Esta
/// prueba separa las tres cifras que hay que mirar antes de decidir si
/// bufferizar el commit ahorra ESPACIO además de escrituras:
///
/// - **fichero**: el máximo histórico, que es contra lo que mide el tope por
///   inquilino (`Options::max_pages`).
/// - **páginas vivas**: lo que el árbol de verdad necesita.
/// - **la diferencia**: basura reciclable más holgura de lista de libres.
#[test]
#[ignore]
fn how_much_of_the_file_is_transient_garbage() {
    const PAGE: u32 = 4096;
    let n = entries();

    println!(
        "{:>10}  {:>12}  {:>13}  {:>13}  {:>12}  {:>10}",
        "lote", "fichero KB", "páginas fich.", "páginas vivas", "basura", "B/entrada"
    );
    for batch in [100u32, 1_000, 5_000] {
        let path =
            std::env::temp_dir().join(format!("inro-garbage-{}-{batch}.inro", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::create(
            Box::new(FileStorage::open(&path).unwrap()),
            Options { page_size: PAGE, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(batch as usize) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic(i);
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
        let live = {
            let mut tx = db.begin_write().unwrap();
            tx.pages_in_use()
        };
        let bytes = std::fs::metadata(&path).unwrap().len();
        let file_pages = (bytes / u64::from(PAGE)) as u32;
        drop(db);
        let _ = std::fs::remove_file(&path);

        println!(
            "{batch:>10}  {:>12}  {file_pages:>13}  {live:>13}  {:>11.1}%  {:>10.2}",
            bytes / 1024,
            f64::from(file_pages - live) / f64::from(file_pages) * 100.0,
            bytes as f64 / f64::from(n),
        );
    }
}

/// La curva de caché con una carga que SÍ tiene localidad.
///
/// `what_each_cache_budget_costs_in_reads` mide el peor caso a propósito:
/// claves repartidas por todo el espacio, sin reutilizar ninguna hoja. Sobre
/// esa curva se decidió bajar el defecto a 4 páginas, y la decisión tiene un
/// punto ciego evidente: una carga con claves calientes —el panel del edge
/// pidiendo una y otra vez las últimas horas— sí podría aprovechar una caché
/// mayor, y con 4 páginas se estaría pagando en lecturas lo que se ahorra en
/// RAM.
///
/// Esta prueba cierra ese hueco. Mismo fichero, misma medición, pero las
/// búsquedas se concentran: el 90% caen sobre el 1% más reciente del espacio
/// de claves, que es la forma real de un panel mirando "lo de ahora".
#[test]
#[ignore]
fn what_each_cache_budget_costs_with_a_hot_working_set() {
    let n = entries();
    const PAGE: u32 = 4096;
    const LOOKUPS: u32 = 2_000;

    let path = std::env::temp_dir().join(format!("inro-hotset-{}.inro", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let db = Db::create(
            Box::new(FileStorage::open(&path).unwrap()),
            Options { page_size: PAGE, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic(i);
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
    }

    println!("(carga: {n} entradas · 90% de las búsquedas sobre el 1% más reciente)");
    println!("{:>12}  {:>10}  {:>22}", "cache_pages", "RAM aprox", "lecturas/búsqueda");
    for cache_pages in [0usize, 4, 8, 16, 32, 64] {
        let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
        let db = Db::open(
            Box::new(counting.clone()),
            Options { page_size: PAGE, cache_pages, ..Options::default() },
        )
        .unwrap();
        let base = counting.count();
        {
            let tx = db.begin_read();
            let hot_from = n - n / 100;
            for j in 0..LOOKUPS {
                // Permutación multiplicativa dentro de la zona caliente, y un
                // 10% de las búsquedas fuera de ella: una carga 100% caliente
                // sería tan poco realista como una 100% dispersa.
                let i = if j % 10 == 0 {
                    j.wrapping_mul(2_654_435_761) % n
                } else {
                    hot_from + (j.wrapping_mul(48_271) % (n / 100))
                };
                assert!(tx.get(0x01, &synthetic(i).0).unwrap().is_some());
            }
        }
        let reads = counting.count() - base;
        drop(db);
        let ram = 1_856.0 + cache_pages as f64 * (f64::from(PAGE) + 100.0);
        println!(
            "{cache_pages:>12}  {:>8.0} KB  {:>22.2}",
            ram / 1024.0,
            f64::from(reads as u32) / f64::from(LOOKUPS)
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// `Sync::Never` contra `Sync::Commit`: qué cuesta cada política de verdad.
///
/// La medición anterior (`docs/agregacion.md` §8.6) daba **+38% de fichero**
/// para `Never` en un nodo micro: las páginas liberadas no se pueden reutilizar
/// hasta que el punto durable las alcanza, y sin `fsync` ese punto no avanza.
/// Se midió **antes del buffer de páginas sucias**, que cambió cuándo llegan
/// las páginas al medio, así que hay que rehacerla antes de decidir con ella.
///
/// Lo que decide es real: el edge tiene que elegir una, y las dos cifras que
/// importan —fichero y `fsync` por unidad de trabajo— van en direcciones
/// opuestas.
#[test]
#[ignore]
fn what_each_sync_policy_costs() {
    let n = entries();
    const PAGE: u32 = 4096;

    println!("(carga: {n} entradas en lotes de mil, páginas de {PAGE} B)");
    println!("{:>10}  {:>12}  {:>12}  {:>14}  {:>12}", "política", "fichero KB", "escrituras", "sync", "B/entrada");
    for (label, sync) in [("Never", Sync::Never), ("Commit", Sync::Commit)] {
        let path =
            std::env::temp_dir().join(format!("inro-sync-{}-{label}.inro", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let counting = Arc::new(Counting::new(FileStorage::open(&path).unwrap()));
        let db = Db::create(
            Box::new(counting.clone()),
            Options { page_size: PAGE, sync, ..Options::default() },
        )
        .unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
            let mut tx = db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic(i);
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
        let bytes = std::fs::metadata(&path).unwrap().len();
        let writes = counting.writes();
        let syncs = counting.syncs();
        drop(db);
        let _ = std::fs::remove_file(&path);
        println!(
            "{label:>10}  {:>12}  {writes:>12}  {syncs:>14}  {:>12.2}",
            bytes / 1024,
            bytes as f64 / f64::from(n)
        );
    }
}
