//! El tope de tamaño por base (`Options::max_pages`).
//!
//! **Por qué vive en el motor y no en el llamante.** En el despliegue real de
//! quota cada inquilino es un fichero en un disco compartido con los otros
//! 2.699, y los volúmenes de `local-path` no imponen cuota ninguna: son
//! directorios en el disco del host. El único sitio donde puede existir un
//! límite por inquilino es dentro de `inro`, y sin él una sola ráfaga larga
//! llena el disco entero y tira a toda la flota. Ver la sección 12.2 de la
//! especificación para los topes por tier y de dónde salen.
//!
//! **Se mide sobre `n_pages`, el máximo histórico, no sobre las páginas
//! vivas.** El fichero no encoge solo: al podar, las páginas vuelven a la
//! lista de libres y se reutilizan, pero `n_pages` no baja (lo baja
//! `reclaim_tail`, y en régimen permanente devuelve 0-4 KB, medido). Un tope
//! contra el espacio en uso daría por bueno un fichero que ya ocupa el doble
//! en disco.
//!
//! **Y la reserva no es un adorno.** El copy-on-write reescribe el camino
//! raíz-hoja en cada commit, así que borrar TAMBIÉN asigna. Con un tope a
//! secas, una base que llega al límite no puede podarse: el remedio exige
//! justo lo que el problema impide. Las últimas `RESERVE_PAGES` páginas solo
//! las puede gastar una operación que reduce el árbol.
#![cfg(feature = "std")]

use inro::storage::MemStorage;
use inro::{Db, Error, Options, Sync};
use std::sync::Arc;

/// Páginas de 512 B y sin caché: lo que se mide aquí son páginas, no
/// rendimiento.
fn opts(max_pages: Option<u32>) -> Options {
    Options { page_size: 512, sync: Sync::Never, cache_pages: 0, max_pages, ..Options::default() }
}

fn value(i: u32) -> Vec<u8> {
    // 200 bytes: con páginas de 512 B, unas dos entradas por hoja, así que el
    // fichero crece rápido y las pruebas son cortas.
    let mut v = vec![0u8; 200];
    v[..4].copy_from_slice(&i.to_be_bytes());
    v
}

/// Escribe hasta que el motor diga que no cabe más, y devuelve cuántas
/// entradas entraron. Un commit por entrada: es el caso que más asigna, y el
/// que antes choca contra el tope.
fn fill_until_full(db: &Db, ns: u8, from: u32) -> (u32, Option<Error>) {
    let mut written = 0;
    for i in from..from + 100_000 {
        let mut tx = db.begin_write().unwrap();
        match tx.put(ns, &i.to_be_bytes(), &value(i)) {
            Ok(()) => {}
            Err(e) => return (written, Some(e)),
        }
        match tx.commit() {
            Ok(()) => written += 1,
            Err(e) => return (written, Some(e)),
        }
    }
    (written, None)
}

#[test]
fn writing_past_the_cap_fails_with_full() {
    let db = Db::create(Box::new(MemStorage::new()), opts(Some(200))).unwrap();
    let (written, err) = fill_until_full(&db, 0x01, 0);
    assert!(written > 0, "no entró ni una fila: el tope de 200 páginas es demasiado apretado");
    assert!(
        matches!(err, Some(Error::Full)),
        "escribir por encima del tope tiene que dar Error::Full, dio {err:?} tras {written} filas"
    );
}

#[test]
fn without_a_cap_nothing_changes() {
    let db = Db::create(Box::new(MemStorage::new()), opts(None)).unwrap();
    let (written, err) = fill_until_full(&db, 0x01, 0);
    assert!(err.is_none(), "sin tope no debe fallar ninguna escritura, falló con {err:?}");
    assert_eq!(written, 100_000);
}

#[test]
fn the_data_written_before_the_cap_survives_it() {
    // `Arc` para conservar un asa tras entregar el almacenamiento a `Db`:
    // `storage.rs` implementa `Storage` para cualquier `Arc<S>` justo para
    // este caso.
    let storage = Arc::new(MemStorage::new());
    let db = Db::create(Box::new(storage.clone()), opts(Some(200))).unwrap();
    let (written, _) = fill_until_full(&db, 0x01, 0);
    drop(db);

    // Reabrir SIN tope: el tope es una política de escritura, no una
    // propiedad del fichero, y una base que llegó a su límite tiene que
    // seguir siendo perfectamente legible.
    let db = Db::open(Box::new(storage), opts(None)).unwrap();
    let rd = db.begin_read();
    for i in 0..written {
        assert_eq!(
            rd.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
            Some(&value(i)[..]),
            "la fila {i} se confirmó antes del tope y ya no está"
        );
    }
}

#[test]
fn a_full_database_can_still_be_pruned() {
    let db = Db::create(Box::new(MemStorage::new()), opts(Some(200))).unwrap();
    let (written, err) = fill_until_full(&db, 0x01, 0);
    assert!(matches!(err, Some(Error::Full)), "la base tenía que llenarse primero");

    // La mitad más vieja fuera. Esto es lo que la reserva existe para
    // permitir: si `delete_range` fallara con `Full`, una base llena sería
    // irrecuperable salvo borrando el fichero.
    let cut = written / 2;
    let mut tx = db.begin_write().unwrap();
    tx.delete_range(0x01, &0u32.to_be_bytes(), &cut.to_be_bytes())
        .expect("podar una base llena tiene que funcionar: para eso está la reserva");
    tx.commit().expect("y el commit de la poda también");

    let rd = db.begin_read();
    assert!(rd.get(0x01, &0u32.to_be_bytes()).unwrap().is_none(), "la poda no borró nada");
    assert!(rd.get(0x01, &cut.to_be_bytes()).unwrap().is_some(), "la poda se llevó de más");
}

#[test]
fn pruning_gives_the_space_back_for_new_writes() {
    let db = Db::create(Box::new(MemStorage::new()), opts(Some(200))).unwrap();
    let (written, _) = fill_until_full(&db, 0x01, 0);

    let cut = written / 2;
    let mut tx = db.begin_write().unwrap();
    tx.delete_range(0x01, &0u32.to_be_bytes(), &cut.to_be_bytes()).unwrap();
    tx.commit().unwrap();

    // Las páginas liberadas se reciclan sin que el fichero crezca, así que
    // volver a escribir tiene que funcionar. Es el ciclo entero del edge:
    // llenar, podar, seguir escribiendo, sin que el tope se toque nunca.
    let (again, err) = fill_until_full(&db, 0x02, 0);
    assert!(
        again > 0,
        "tras podar la mitad no entró ni una fila nueva ({err:?}): las páginas liberadas no se \
         están reciclando y el tope se convierte en una condena"
    );
}

#[test]
fn the_cap_counts_the_high_water_mark_and_not_the_live_pages() {
    let db = Db::create(Box::new(MemStorage::new()), opts(Some(200))).unwrap();
    let (written, _) = fill_until_full(&db, 0x01, 0);

    // Borrarlo TODO deja el árbol casi vacío, pero el fichero conserva su
    // tamaño: las páginas están libres, no devueltas. Escribir de nuevo debe
    // reutilizarlas —y por tanto funcionar— sin que el tope suba.
    let mut tx = db.begin_write().unwrap();
    tx.delete_range(0x01, &0u32.to_be_bytes(), &u32::MAX.to_be_bytes()).unwrap();
    tx.commit().unwrap();

    let (again, _) = fill_until_full(&db, 0x02, 0);
    assert!(
        again >= written / 2,
        "tras vaciar la base entera solo entraron {again} filas contra las {written} de la \
         primera vuelta: el reciclaje no está devolviendo el espacio"
    );
}

/// Cuánto de la reserva se come el cierre de `commit`.
///
/// No es una prueba de invariante, es una MEDICIÓN con umbral: `alloc` se para
/// en `cap - 64`, pero la serialización de la lista de libres al cerrar el
/// commit extiende el fichero por su cuenta, y lo único que la contiene es esa
/// reserva. Si algún día se acerca a las 64 páginas, la reserva se queda corta
/// y hay que subirla o comprobar el tope también ahí.
#[test]
fn how_much_of_the_reserve_the_commit_path_spends() {
    const CAP: u32 = 200;
    let storage = Arc::new(MemStorage::new());
    let db = Db::create(Box::new(storage.clone()), opts(Some(CAP))).unwrap();
    let (written, _) = fill_until_full(&db, 0x01, 0);
    let after_fill = inro::Storage::len(&*storage).unwrap() / 512;

    let mut tx = db.begin_write().unwrap();
    tx.delete_range(0x01, &0u32.to_be_bytes(), &(written / 2).to_be_bytes()).unwrap();
    tx.commit().unwrap();
    let after_prune = inro::Storage::len(&*storage).unwrap() / 512;

    let stop = u64::from(CAP - 64);
    println!(
        "tope {CAP} páginas · alloc se para en {stop} · fichero tras llenar {after_fill} · \
         tras podar {after_prune} · reserva gastada {}",
        after_prune.saturating_sub(stop)
    );
    assert!(
        after_prune <= u64::from(CAP),
        "la poda dejó el fichero en {after_prune} páginas, por encima del tope de {CAP}:          algún camino extiende el fichero sin mirar el tope"
    );
    // El umbral que de verdad avisa. Medido el 17-08-2026: 5 páginas de 64.
    // Si esto llega a 32, la reserva se ha quedado a la mitad y toca o subirla
    // o comprobar el tope también en el cierre de `commit` — que hoy no lo
    // comprueba a propósito, porque fallar a mitad de un commit es peor que
    // pasarse cinco páginas.
    assert!(
        after_prune.saturating_sub(stop) < 32,
        "el cierre de commit se comió {} páginas de las 64 de reserva",
        after_prune.saturating_sub(stop)
    );
}
