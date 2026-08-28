//! El camino rápido de anexado (`page::append_in_place`) visto desde fuera del
//! motor: lo que se anexa en el sitio tiene que leerse exactamente igual que
//! lo que se escribe reconstruyendo la página.
//!
//! Las pruebas unitarias de `page.rs` cubren la mutación de una página suelta.
//! Éstas cubren lo que esa mutación cambia en el árbol: que el nivel de arriba
//! ya no reconstruye (la hoja conserva su número de página), que el camino
//! lento sigue atendiendo lo que el rápido rechaza —reemplazos, inserciones
//! por el medio, divisiones— y que mezclarlos en la misma transacción no deja
//! el árbol inconsistente.
#![cfg(feature = "std")]

use inro::storage::MemStorage;
use inro::{Db, Options};

/// Clave de 12 bytes creciente, como las del registro del edge
/// (`[ts_millis u64 BE][seq u32 BE]`): el caso para el que existe el camino
/// rápido.
fn key(i: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(12);
    k.extend_from_slice(&(1_700_000_000_000u64 + i).to_be_bytes());
    k.extend_from_slice(&(i as u32).to_be_bytes());
    k
}

fn db() -> Db {
    Db::create(
        Box::new(MemStorage::new()),
        Options {
            page_size: 512,
            ..Options::default()
        },
    )
    .unwrap()
}

/// Valor por encima del umbral de overflow de una página de 512 B
/// (`page_size / 4` = 128), que es el caso real del edge: toda fila del
/// registro supera el umbral, así que la celda de hoja es una referencia de
/// tamaño fijo.
fn big_value(i: u64) -> Vec<u8> {
    let mut v = alloc_pattern(400);
    v[..8].copy_from_slice(&i.to_be_bytes());
    v
}

fn alloc_pattern(n: usize) -> Vec<u8> {
    (0..n).map(|j| (j % 251) as u8).collect()
}

#[test]
fn sequential_appends_read_back_in_full() {
    let db = db();
    const N: u64 = 5_000;

    let mut tx = db.begin_write().unwrap();
    for i in 0..N {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    tx.commit().unwrap();

    let r = db.begin_read();
    for i in 0..N {
        assert_eq!(
            r.get(0x01, &key(i)).unwrap(),
            Some(big_value(i)),
            "fila {i}"
        );
    }

    // Y el recorrido las devuelve todas, en orden y sin repetir: un slot mal
    // colocado se vería aquí aunque cada `get` suelto acertara.
    let mut cur = r.scan(0x01, b"", b"\xff").unwrap();
    let mut seen = 0u64;
    let mut prev: Option<Vec<u8>> = None;
    while let Some((k, _v)) = cur.next().unwrap() {
        if let Some(p) = &prev {
            assert!(p < &k, "el recorrido tiene que ir en orden estricto");
        }
        prev = Some(k);
        seen += 1;
    }
    assert_eq!(seen, N);
}

/// Valores pequeños: la celda va en línea y el camino rápido tampoco cambia
/// la condición de "hoja plana" de la página.
#[test]
fn sequential_appends_of_inline_values_read_back() {
    let db = db();
    const N: u64 = 2_000;

    let mut tx = db.begin_write().unwrap();
    for i in 0..N {
        tx.put(0x01, &key(i), &i.to_be_bytes()).unwrap();
    }
    tx.commit().unwrap();

    let r = db.begin_read();
    for i in 0..N {
        assert_eq!(
            r.get(0x01, &key(i)).unwrap(),
            Some(i.to_be_bytes().to_vec()),
            "fila {i}"
        );
    }
}

/// Lo que el camino rápido NO cubre tiene que seguir funcionando, y mezclado
/// con lo que sí cubre dentro de la misma transacción: reemplazar una clave
/// existente (el anexado la rechaza porque `ascending` es estricto), insertar
/// por el medio (rompería el orden de los offsets de celda) y volver a anexar
/// después de las dos cosas.
#[test]
fn replacements_and_middle_inserts_still_work_between_appends() {
    let db = db();

    let mut tx = db.begin_write().unwrap();
    for i in (0..2_000).step_by(2) {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    // Por el medio, en los huecos impares.
    for i in (1..2_000).step_by(2) {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    // Reemplazos sobre claves que ya están.
    for i in (0..2_000).step_by(37) {
        tx.put(0x01, &key(i), &big_value(i + 1_000_000)).unwrap();
    }
    // Y más anexados detrás de todo lo anterior.
    for i in 2_000..2_500 {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    tx.commit().unwrap();

    let r = db.begin_read();
    for i in 0..2_500u64 {
        let expected = if i < 2_000 && i % 37 == 0 {
            big_value(i + 1_000_000)
        } else {
            big_value(i)
        };
        assert_eq!(r.get(0x01, &key(i)).unwrap(), Some(expected), "fila {i}");
    }
}

/// Anexar en el sitio y borrar en la misma transacción: el borrado sí
/// reconstruye, así que esto comprueba que una página anexada en el sitio es
/// una entrada válida para el camino que la reconstruye.
#[test]
fn deleting_after_appending_in_place_leaves_a_consistent_tree() {
    let db = db();

    let mut tx = db.begin_write().unwrap();
    for i in 0..3_000u64 {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    tx.commit().unwrap();

    let mut tx = db.begin_write().unwrap();
    tx.delete_range(0x01, &key(0), &key(1_000)).unwrap();
    for i in 3_000..3_200u64 {
        tx.put(0x01, &key(i), &big_value(i)).unwrap();
    }
    tx.commit().unwrap();

    let r = db.begin_read();
    for i in 0..1_000u64 {
        assert_eq!(r.get(0x01, &key(i)).unwrap(), None, "fila {i} borrada");
    }
    for i in 1_000..3_200u64 {
        assert_eq!(
            r.get(0x01, &key(i)).unwrap(),
            Some(big_value(i)),
            "fila {i}"
        );
    }
}

/// Varias transacciones seguidas: la primera deja la hoja de la derecha
/// aparcada y confirmada; la segunda empieza con esa hoja YA en disco, no en
/// el buffer de páginas pendientes, así que su primer anexado tiene que caer
/// al camino lento y el resto volver al rápido.
#[test]
fn appends_across_transactions_read_back() {
    let db = db();

    for round in 0..10u64 {
        let mut tx = db.begin_write().unwrap();
        for i in round * 200..(round + 1) * 200 {
            tx.put(0x01, &key(i), &big_value(i)).unwrap();
        }
        tx.commit().unwrap();
    }

    let r = db.begin_read();
    for i in 0..2_000u64 {
        assert_eq!(
            r.get(0x01, &key(i)).unwrap(),
            Some(big_value(i)),
            "fila {i}"
        );
    }
}
