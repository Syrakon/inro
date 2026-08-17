//! Qué dimensiones escribe cada resolución.
//!
//! Hasta ahora era una constante: `Resolution::dimensions()` decía "el minuto
//! guarda estado, todo lo demás guarda las cuatro", y no había forma de
//! elegir. La decisión de producto del 17-08-2026 (sección 12.3 de la
//! especificación) exige justo eso:
//!
//! - **El día guarda solo totales.** Mantener el top-32 de cuatro dimensiones
//!   noventa días es mantener noventa días de todo: 10.080 filas, el 55% de la
//!   meseta de agregado, para responder preguntas que nadie hace sobre un
//!   martes de hace dos meses.
//! - **`User` no se escribe.** No por espacio —son 225 KB— sino por inútil:
//!   con 32 huecos y del orden de diez mil usuarios distintos, el desglose por
//!   usuario solo nombra a los más pesados. No sirve para facturar ni para dar
//!   a cada cliente su informe, y para detectar al que abusa está el crudo,
//!   que es exacto.
//!
//! Lo que NO cambia y estas pruebas fijan: los totales diarios siguen ahí, con
//! sus percentiles, noventa días.
#![cfg(all(feature = "std", feature = "rollup"))]

use inro::rollup::{Config, Dimension, Observation, Resolution, Rollup, read_dimension, read_total};
use inro::storage::MemStorage;
use inro::{Db, Options, Sync};

/// Instante unix **en segundos**, que es lo que `Observation::ts` documenta.
/// La primera versión de estas pruebas pasaba milisegundos y cada observación
/// caía en un cubo distinto: la hora acababa con una petición y el día con 55
/// de 300. El error era de la prueba, pero el pie del que se tropieza es real
/// — el resto de la pila de quota mide en milisegundos.
const T0: u64 = 1_760_000_000;

fn db() -> Db {
    Db::create(
        Box::new(MemStorage::new()),
        Options { page_size: 512, sync: Sync::Never, ..Options::default() },
    )
    .unwrap()
}

/// Observa `n` peticiones repartidas por la primera hora y vuelca.
fn observe_an_hour(db: &Db, rollup: &mut Rollup, n: u32) {
    let mut tx = db.begin_write().unwrap();
    for i in 0..n {
        let endpoint = format!("/e{}", i % 7);
        let user = format!("u{}", i % 40);
        rollup
            .observe(
                &mut tx,
                &Observation {
                    ts: T0 + u64::from(i),
                    endpoint: endpoint.as_bytes(),
                    user: user.as_bytes(),
                    country: b"ES",
                    status: 200,
                    latency_ms: 10 + i % 50,
                    bytes_in: 100,
                    bytes_out: 900,
                    error: false,
                },
            )
            .unwrap();
    }
    rollup.flush(&mut tx).unwrap();
    tx.commit().unwrap();
}

fn hour_bucket() -> u32 {
    Resolution::Hour.bucket_of(T0).unwrap()
}

fn day_bucket() -> u32 {
    Resolution::Day.bucket_of(T0).unwrap()
}

#[test]
fn the_day_keeps_only_totals() {
    let db = db();
    let mut rollup = Rollup::new(Config::default());
    observe_an_hour(&db, &mut rollup, 300);

    let rd = db.begin_read();
    let total = read_total(&rd, Resolution::Day, day_bucket()).unwrap();
    assert!(total.is_some(), "el total del día tiene que seguir escribiéndose");
    assert_eq!(total.unwrap().requests, 300);

    for dim in [Dimension::Endpoint, Dimension::Country, Dimension::Status, Dimension::User] {
        let rows = read_dimension(&rd, Resolution::Day, day_bucket(), dim).unwrap();
        assert!(
            rows.is_empty(),
            "a resolución de día no debe escribirse ninguna dimensión, y {dim:?} tiene \
             {} filas",
            rows.len()
        );
    }
}

#[test]
fn the_hour_keeps_the_breakdown_except_the_user() {
    let db = db();
    let mut rollup = Rollup::new(Config::default());
    observe_an_hour(&db, &mut rollup, 300);

    let rd = db.begin_read();
    for dim in [Dimension::Endpoint, Dimension::Country, Dimension::Status] {
        let rows = read_dimension(&rd, Resolution::Hour, hour_bucket(), dim).unwrap();
        assert!(!rows.is_empty(), "la hora tiene que conservar el desglose por {dim:?}");
    }
    let users = read_dimension(&rd, Resolution::Hour, hour_bucket(), Dimension::User).unwrap();
    assert!(
        users.is_empty(),
        "la dimensión User ya no se escribe: 32 huecos para diez mil usuarios no dan el \
         informe de nadie, y salieron {} filas",
        users.len()
    );
}

#[test]
fn realtime_still_writes_every_dimension() {
    let db = db();
    let mut rollup = Rollup::new(Config::realtime());
    observe_an_hour(&db, &mut rollup, 300);

    let rd = db.begin_read();
    for dim in [Dimension::Endpoint, Dimension::Country, Dimension::Status, Dimension::User] {
        let rows = read_dimension(&rd, Resolution::Hour, hour_bucket(), dim).unwrap();
        assert!(
            !rows.is_empty(),
            "el perfil de tiempo real conserva las cuatro dimensiones, y {dim:?} salió vacía"
        );
    }
    let rows = read_dimension(&rd, Resolution::Day, day_bucket(), Dimension::Endpoint).unwrap();
    assert!(!rows.is_empty(), "y el día con desglose, que es lo que ese perfil describe");
}

/// El número que motivó el recorte, comprobado de punta a punta.
#[test]
fn the_default_profile_writes_far_fewer_rows_than_the_full_breakdown() {
    let lean = {
        let db = db();
        let mut r = Rollup::new(Config::default());
        observe_an_hour(&db, &mut r, 300);
        let rd = db.begin_read();
        let mut n = 0;
        for res in [Resolution::Hour, Resolution::Day] {
            let b = if res == Resolution::Hour { hour_bucket() } else { day_bucket() };
            for dim in [Dimension::Endpoint, Dimension::Country, Dimension::Status, Dimension::User]
            {
                n += read_dimension(&rd, res, b, dim).unwrap().len();
            }
        }
        n
    };
    let full = {
        let db = db();
        let mut r = Rollup::new(Config::realtime());
        observe_an_hour(&db, &mut r, 300);
        let rd = db.begin_read();
        let mut n = 0;
        for res in [Resolution::Hour, Resolution::Day] {
            let b = if res == Resolution::Hour { hour_bucket() } else { day_bucket() };
            for dim in [Dimension::Endpoint, Dimension::Country, Dimension::Status, Dimension::User]
            {
                n += read_dimension(&rd, res, b, dim).unwrap().len();
            }
        }
        n
    };
    assert!(
        lean * 2 <= full,
        "el perfil por defecto escribió {lean} filas de desglose contra {full} del completo: \
         se esperaba menos de la mitad"
    );
}
