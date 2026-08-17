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
}

impl<S: Storage> Counting<S> {
    fn new(inner: S) -> Self {
        Self { inner, reads: AtomicU64::new(0) }
    }
    fn count(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl<S: Storage> Storage for Counting<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> inro::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> inro::Result<()> {
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
