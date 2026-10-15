//! Lectores concurrentes con un escritor: prueba de estrés de las dos
//! carreras que cerró la 0.5.1.
//!
//! 1. `Db::begin_read` leía la meta confirmada bajo un candado y se apuntaba
//!    en la tabla de lectores bajo otro. Un commit en medio dejaba al lector
//!    con un snapshot que el suelo de reutilización ya no contaba, y el
//!    siguiente escritor reciclaba sus páginas: `Corrupt { kind: PageType }`
//!    en el lector. Ver `docs/invariantes.md` §25.
//! 2. Dos fallos de caché simultáneos sobre la misma página dejaban DOS
//!    entradas en la caché; `Pager::write` invalidaba solo una y la otra,
//!    obsoleta, se servía después al escritor: claves confirmadas perdidas.
//!    Ver `docs/invariantes.md` §16.
//!
//! No hay gancho determinista para ninguna de las dos desde fuera del
//! crate (las pruebas deterministas de la segunda viven en `pager.rs`): esto
//! repite la carga hasta un número de vueltas que, sobre el código de la
//! 0.5.0, fallaba en todas las ejecuciones medidas. `INRO_STRESS_ITERS`
//! cambia ese número.
//!
//! Cada lector comprueba algo más fuerte que «no hay error»: como cada commit
//! añade exactamente una clave, el número de claves que ve un snapshot es
//! función exacta de su `txn_id`. Un lector que viera páginas recicladas o
//! una hoja obsoleta de la caché contaría otra cosa.
#![cfg(feature = "std")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use inro::storage::MemStorage;
use inro::{Db, Options};

const END: [u8; 8] = [0xFF; 8];
/// Cuatro, no más: medido en una máquina de cuatro núcleos, con más lectores
/// el escritor se queda sin CPU, hace menos commits por vuelta y la carrera
/// se da MENOS, no más.
const READERS: usize = 4;
const WRITERS: usize = 2;
/// Vueltas cortas y muchas, no largas y pocas: casi todos los fallos medidos
/// caen en los primeros commits de una base nueva, cuando el árbol es una
/// sola hoja y la página que se recicla es justo la raíz de algún lector.
const PUTS_PER_WRITER: usize = 10;
/// Con 3 000 vueltas el código de la 0.5.0 falló en todas las ejecuciones
/// medidas: 9-19 vueltas rotas de 3 000 sin caché, 166-181 con caché (unos
/// 4,5 s por prueba en `--release`). En `debug` cada vuelta es bastante más
/// lenta, así que ahí se recorta para que `cargo test` no se eternice.
const ROUNDS: usize = if cfg!(debug_assertions) { 2000 } else { 3000 };

fn iterations(default: usize) -> usize {
    std::env::var("INRO_STRESS_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn count(tx: &inro::ReadTxn<'_>) -> inro::Result<u64> {
    let mut c = tx.scan(1, b"w", &END)?;
    let mut n = 0;
    while c.next()?.is_some() {
        n += 1;
    }
    Ok(n)
}

/// Una vuelta: lectores en bucle, escritores serializados por un `Mutex`, un
/// `put` por commit. Devuelve los errores vistos (vacío = vuelta limpia).
fn one_round(cache_pages: usize) -> Vec<String> {
    let opts = Options {
        cache_pages,
        ..Options::default()
    };
    let db = Arc::new(Db::create(Box::new(MemStorage::new()), opts).unwrap());
    let base = db.begin_read().txn_id();
    let stop = Arc::new(AtomicBool::new(false));
    let errs = Arc::new(Mutex::new(Vec::new()));
    let wmu = Arc::new(Mutex::new(()));

    let readers: Vec<_> = (0..READERS)
        .map(|r| {
            let (db, stop, errs) = (db.clone(), stop.clone(), errs.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let tx = db.begin_read();
                    let want = tx.txn_id() - base;
                    match count(&tx) {
                        Ok(n) if n == want => {}
                        Ok(n) => {
                            errs.lock().unwrap().push(format!(
                                "reader {r}: snapshot {} saw {n} keys, want {want}",
                                tx.txn_id()
                            ));
                            return;
                        }
                        Err(e) => {
                            errs.lock().unwrap().push(format!("reader {r}: {e:?}"));
                            return;
                        }
                    }
                }
            })
        })
        .collect();

    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (db, errs, wmu) = (db.clone(), errs.clone(), wmu.clone());
            thread::spawn(move || {
                for i in 0..PUTS_PER_WRITER {
                    let _m = wmu.lock().unwrap();
                    let r = (|| -> inro::Result<()> {
                        let mut tx = db.begin_write()?;
                        tx.put(1, format!("w{w}-{i:04}").as_bytes(), b"x")?;
                        tx.commit()
                    })();
                    if let Err(e) = r {
                        errs.lock().unwrap().push(format!("writer {w}: {e:?}"));
                        return;
                    }
                }
            })
        })
        .collect();

    for h in writers {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for h in readers {
        h.join().unwrap();
    }

    let mut errs = errs.lock().unwrap().clone();
    let want = (WRITERS * PUTS_PER_WRITER) as u64;
    match count(&db.begin_read()) {
        Ok(n) if n == want => {}
        Ok(n) => errs.push(format!("final: found {n} keys, want {want}")),
        Err(e) => errs.push(format!("final: {e:?}")),
    }
    #[cfg(feature = "audit")]
    if errs.is_empty() && !db.audit_pages().unwrap() {
        errs.push("final: audit_pages found a page owned twice".into());
    }
    errs
}

fn stress(cache_pages: usize) {
    let iters = iterations(ROUNDS);
    let mut failed = Vec::new();
    for i in 0..iters {
        let e = one_round(cache_pages);
        if !e.is_empty() {
            failed.push((i, e));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {iters} rounds failed: {:?}",
        failed.len(),
        &failed[..failed.len().min(5)]
    );
}

/// Sin caché: aísla la carrera de `begin_read` (la segunda necesita caché).
#[test]
fn readers_never_see_pages_recycled_under_their_snapshot() {
    stress(0);
}
