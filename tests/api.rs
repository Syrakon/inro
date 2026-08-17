//! El ejemplo de API del documento de diseño, compilado.
//!
//! La sección 10 de
//! `docs/superpowers/specs/2026-08-10-inro-motor-kv-design.md` mostraba un
//! bloque `rust` que **no compilaba y nunca compiló**: `Db::open` tomando una
//! ruta, `Db::create` ausente, rangos de Rust donde la firma pide `(ns, from,
//! to)`, `begin_read` devolviendo `Result`, `scan` iterándose con un `for`.
//! Nada de eso lo detecta nadie: un bloque de código en un `.md` no lo compila
//! ni el CI ni `cargo test`, así que envejeció tres semanas sin que se notara.
//!
//! Este fichero es el mismo ejemplo, palabra por palabra, en un sitio donde el
//! compilador lo mira. Si cambia una firma pública, esto rompe la compilación y
//! el diseño se corrige a la vez que el código, que es la única forma de que
//! deje de desviarse.
//!
//! **Al editar este fichero hay que copiar el cuerpo a la sección 10 del
//! diseño**, y al revés. Es un contrato de dos direcciones a mano, no un
//! generador — pero un contrato que falla ruidosamente en una de las dos.
#![cfg(feature = "std")]

use inro::storage::MemStorage;
use inro::{Db, IndexDef, Options, Sync};

/// Índice por el primer byte del valor, que en el ejemplo es el código de
/// estado. `extract` devuelve una clave de índice por cada entrada que la
/// fila deba producir; devolver el vector vacío es «esta fila no se indexa».
fn by_status(_key: &[u8], value: &[u8]) -> Vec<Vec<u8>> {
    match value.first() {
        Some(&status) => vec![vec![status]],
        None => Vec::new(),
    }
}

#[test]
fn the_api_example_of_the_design_compiles_and_runs() {
    // --- inicio del bloque que reproduce la sección 10 del diseño ---
    let db = Db::create(
        Box::new(MemStorage::new()), // un `Box<dyn Storage>`, no una ruta
        Options {
            page_size: 512,
            sync: Sync::Commit,
            cache_pages: 4, // 32 hasta el 17-08-2026 — ver la curva de la sección 16
            encryption: None,
            max_pages: None, // tope en páginas — ver la sección 12.2
        },
    )
    .unwrap();

    db.define_index(IndexDef {
        id: 1,
        name: "por_estado",
        version: 1,
        ns: 0x02,
        unique: false,
        extract: by_status,
    })
    .unwrap();

    let mut tx = db.begin_write().unwrap(); // exclusivo, uno a la vez
    tx.put(0x01, b"k", b"v").unwrap();
    tx.put(0x02, b"fila", &[200, 0, 0]).unwrap();
    tx.delete(0x01, b"k").unwrap(); // `true` si existía
    tx.delete_range(0x01, b"", b"cutoff").unwrap(); // (ns, from, to), no rangos de Rust
    tx.commit().unwrap(); // páginas, fsync, meta, fsync

    let r = db.begin_read(); // sin bloqueo, snapshot inmutable; NO devuelve Result
    assert_eq!(r.get(0x02, b"fila").unwrap(), Some(vec![200, 0, 0]));

    let mut cur = r.scan(0x02, b"", b"\xff").unwrap(); // cursor perezoso y falible
    while let Some((_k, _v)) = cur.next().unwrap() {
        // ...
    }

    let pks = r.scan_index(1, &[200], &[201]).unwrap(); // Vec ya materializado
    assert_eq!(pks, vec![b"fila".to_vec()]);
    // --- fin del bloque ---
}

/// El otro medio contrato: que las firmas que el diseño enumera en su sección
/// 11 sigan existiendo con el nombre con el que las enumera.
#[test]
fn the_operations_the_design_names_still_exist() {
    let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();

    // Recuperar espacio es del motor, no del llamante (la sección 12.4 del
    // diseño decía lo contrario hasta el 17-08-2026).
    let freed = db.reclaim_tail().unwrap();
    assert_eq!(freed, 0, "una base recién creada no tiene cola que devolver");

    // Y la auditoría de páginas existe, tras la feature `audit`.
    #[cfg(feature = "audit")]
    assert!(db.audit_pages().unwrap(), "una base recién creada está sana");
}

/// La métrica que la sección 5 del diseño exige para diagnosticar el único
/// modo de fallo operativo del diseño copy-on-write: un lector que no suelta
/// su snapshot impide reciclar todo lo liberado desde entonces y el fichero
/// crece sin que nada esté roto.
#[test]
fn a_long_lived_reader_shows_up_in_the_retention_floor() {
    let db = Db::create(
        Box::new(MemStorage::new()),
        Options { page_size: 512, sync: Sync::Commit, ..Options::default() },
    )
    .unwrap();

    let mut tx = db.begin_write().unwrap();
    tx.put(0x10, b"a", b"1").unwrap();
    tx.commit().unwrap();

    let old = db.begin_read(); // y no lo suelta
    let pinned = old.txn_id();

    for i in 0..5u8 {
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, &[i], b"x").unwrap();
        tx.commit().unwrap();
    }
    let now = db.begin_read().txn_id();
    assert!(now > pinned, "los cinco commits tienen que haber avanzado el txn_id");

    assert_eq!(
        db.oldest_retained_txn(),
        pinned,
        "el lector viejo fija el suelo de reutilización, y eso es lo que hay que poder ver"
    );

    drop(old);
    assert_eq!(
        db.oldest_retained_txn(),
        now,
        "soltado el lector, el suelo sube al último commit duradero"
    );
}
