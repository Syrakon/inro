//! Pruebas basadas en propiedades (tarea 19): un `BTreeMap` de la biblioteca
//! estándar hace de oráculo, y secuencias aleatorias de operaciones se
//! comparan contra él tras cada paso. Es aquí donde han aparecido los
//! defectos más caros de este proyecto — la división de nodo interno que
//! perdía el par separador/hijo equivocado, o los internos que se quedaban
//! sin separadores — porque las pruebas escritas a mano ejercitan el orden
//! que a quien las escribe se le ocurre pensar, y esos dos defectos concretos
//! solo aparecían con una MEZCLA de órdenes de inserción que nadie escribió
//! a mano.
//!
//! **Todo el fichero vive tras `feature = "std"`** (abajo, `#![cfg(...)]`):
//! `Db`/`WriteTxn`/`ReadTxn`/`storage::MemStorage` no existen sin ella (ver
//! `lib.rs`), así que bajo `cargo test --no-default-features` este fichero
//! se compila vacío en vez de fallar. `Db::audit_pages` (propiedad 3, más
//! abajo) exige además la feature `audit` — no hace falta comprobarla
//! aparte: `audit` forma parte de `default` (ver `Cargo.toml`), y ninguna de
//! las combinaciones de compilación que verifica esta tarea activa `std`
//! sin ella.
#![cfg(feature = "std")]

use inro::storage::MemStorage;
use inro::{Db, IndexDef, Options, Storage};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
enum Op {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    DeleteRange(Vec<u8>, Vec<u8>),
}

/// Claves cortas de alfabeto reducido (0..6): así colisionan prefijos y se
/// ejercita de verdad la compresión por página, en vez de que cada clave
/// caiga en su propia hoja. Valores de hasta 300 bytes: con páginas de 512
/// bytes por defecto el umbral de overflow es `page_size / 4` = 128 (ver
/// `tree::overflow_threshold`), así que una fracción sustancial de los
/// valores generados cruza a una cadena de overflow — la ruta de tamaño
/// variable, no solo el caso en línea.
fn op_strategy() -> impl Strategy<Value = Op> {
    let key = proptest::collection::vec(0u8..6, 0..6);
    let value = proptest::collection::vec(any::<u8>(), 0..300);
    prop_oneof![
        3 => (key.clone(), value).prop_map(|(k, v)| Op::Put(k, v)),
        2 => key.clone().prop_map(Op::Delete),
        1 => (key.clone(), key).prop_map(|(a, b)| {
            if a <= b { Op::DeleteRange(a, b) } else { Op::DeleteRange(b, a) }
        }),
    ]
}

/// Igual que `op_strategy`, pero sin `DeleteRange` (2 ramas, no 3): lo usa
/// la propiedad del índice secundario (más abajo), porque `delete_range`
/// sobre un `ns` con algún índice definido siempre devuelve
/// `Error::DeleteRangeIndexed` — es una regla propia del motor (tarea 16,
/// ver el comentario de `WriteTxn::delete_range`), no un defecto, así que
/// generarlo ahí solo desperdiciaría casos de `proptest` en una rama que
/// jamás progresa.
fn put_delete_strategy() -> impl Strategy<Value = Op> {
    let key = proptest::collection::vec(0u8..6, 0..6);
    let value = proptest::collection::vec(any::<u8>(), 0..300);
    prop_oneof![
        3 => (key.clone(), value).prop_map(|(k, v)| Op::Put(k, v)),
        2 => key.prop_map(Op::Delete),
    ]
}

fn apply(model: &mut BTreeMap<Vec<u8>, Vec<u8>>, op: &Op) {
    match op {
        Op::Put(k, v) => {
            model.insert(k.clone(), v.clone());
        }
        Op::Delete(k) => {
            model.remove(k);
        }
        Op::DeleteRange(a, b) => {
            let doomed: Vec<_> = model.range(a.clone()..b.clone()).map(|(k, _)| k.clone()).collect();
            for k in doomed {
                model.remove(&k);
            }
        }
    }
}

/// Cubo derivado del primer byte del valor (0 si está vacío) — usado por la
/// propiedad del índice secundario, más abajo, como `extract` de un índice
/// NO único. Con valores aleatorios de hasta 300 bytes y solo 256 cubos
/// posibles, un centenar de `Put` basta para que varias claves primarias
/// distintas caigan en el mismo cubo: es la forma que de verdad ejercita la
/// mitad no única de `index::index_key` (primaria + longitud al final para
/// desambiguar), no solo el caso trivial de "cada entrada de índice resulta
/// única de casualidad" que daría un índice único.
fn bucket_of(_key: &[u8], value: &[u8]) -> Vec<Vec<u8>> {
    std::vec![std::vec![value.first().copied().unwrap_or(0)]]
}

const BUCKET_INDEX: IndexDef = IndexDef {
    id: 1,
    name: "bucket",
    version: 1,
    ns: 0x01,
    unique: false,
    extract: bucket_of,
};

/// Casos por propiedad. `200` de fondo (el valor del brief) hace que las
/// cuatro propiedades juntas tarden 100-160 s — tolerable en CI, pero no
/// para `cargo test` en el ciclo normal de desarrollo (medido: hace que la
/// invocación completa de la suite pase de segundos a minutos). `proptest`
/// ya lee `PROPTEST_CASES` para su propio valor por defecto, pero
/// `ProptestConfig::with_cases(n)` fija `n` de forma incondicional y dejaba
/// esa variable sin ningún efecto aquí — este `fn` es lo que la reconecta:
/// por defecto corre solo 20 casos (rápido, sigue ejerciendo las cuatro
/// formas de secuencia aleatoria en cada `cargo test` normal), y
/// `PROPTEST_CASES=200 cargo test --test props` (o más) recupera la
/// búsqueda profunda que de verdad encontró los defectos de la tarea 19 —
/// el nivel que conviene en CI o antes de fusionar, no en cada guardado.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(20)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    /// Propiedad 1 del brief: tras CADA operación, un recorrido completo del
    /// árbol (por `scan`, así que también ejercita `Cursor`) debe coincidir
    /// entrada por entrada con el `BTreeMap` de referencia.
    #[test]
    fn the_tree_always_matches_a_btreemap(ops in proptest::collection::vec(op_strategy(), 1..300)) {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut model = BTreeMap::new();

        for op in &ops {
            let mut tx = db.begin_write().unwrap();
            match op {
                Op::Put(k, v) => tx.put(0x01, k, v).unwrap(),
                Op::Delete(k) => { tx.delete(0x01, k).unwrap(); }
                Op::DeleteRange(a, b) => tx.delete_range(0x01, a, b).unwrap(),
            }
            tx.commit().unwrap();
            apply(&mut model, op);

            let r = db.begin_read();
            // `scan` devuelve `Result<Cursor>`, no `Cursor` a secas (desviación
            // deliberada del brief original, ver el comentario de
            // `ReadTxn::scan` en `tx.rs`: un `.expect()` ahí convertiría
            // corrupción detectada en el descenso inicial en un panic de la
            // API pública).
            let mut cursor = r.scan(0x01, b"", b"\xff\xff\xff\xff\xff\xff\xff").unwrap();
            let mut actual = Vec::new();
            while let Some(entry) = cursor.next().unwrap() {
                actual.push(entry);
            }
            let expected: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(actual, expected, "divergencia tras {:?}", op);
        }
    }

    /// Propiedad 2 del brief: cada clave de un lote insertado en una sola
    /// transacción se recupera individualmente con su valor exacto —
    /// valores de hasta 2000 bytes, muy por encima del umbral de overflow,
    /// así que ejercita tanto el camino en línea como el de overflow dentro
    /// del mismo lote.
    #[test]
    fn every_key_is_individually_retrievable(
        entries in proptest::collection::hash_map(
            proptest::collection::vec(0u8..8, 1..10),
            proptest::collection::vec(any::<u8>(), 0..2000),
            1..200,
        )
    ) {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for (k, v) in &entries {
            tx.put(0x01, k, v).unwrap();
        }
        tx.commit().unwrap();

        let r = db.begin_read();
        for (k, v) in &entries {
            let stored = r.get(0x01, k).unwrap();
            prop_assert_eq!(stored.as_ref(), Some(v));
        }
    }

    /// Propiedad 3 del brief: ninguna página del fichero se pierde ni se
    /// cuenta dos veces. `Db::audit_pages` (tarea 19, `tx.rs`) recorre el
    /// árbol desde la raíz y la lista de libres y comprueba que cada página
    /// por debajo de `n_pages` tiene exactamente un dueño.
    #[test]
    fn pages_are_never_lost_or_double_allocated(
        ops in proptest::collection::vec(op_strategy(), 1..200)
    ) {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        for op in &ops {
            let mut tx = db.begin_write().unwrap();
            match op {
                Op::Put(k, v) => tx.put(0x01, k, v).unwrap(),
                Op::Delete(k) => { tx.delete(0x01, k).unwrap(); }
                Op::DeleteRange(a, b) => tx.delete_range(0x01, a, b).unwrap(),
            }
            tx.commit().unwrap();
        }
        prop_assert!(db.audit_pages().unwrap(), "pagina perdida o contada dos veces");
    }

    /// Propiedad añadida sobre el brief (tarea 19): la combinación de índice
    /// secundario + valores de overflow + `Cursor` interno de
    /// `scan_index`, que ninguna de las tres propiedades de arriba ejercita
    /// — `put`/`delete` con índices SIEMPRE recorren una ruta extra
    /// (`WriteTxn::put`/`delete`, `tx.rs`) que las tres de arriba nunca
    /// tocan, porque ahí nunca hay ningún índice definido. Los hallazgos
    /// más caros de este proyecto vinieron de interacciones, no de
    /// funciones sueltas — ver el comentario de cabecera de este fichero —
    /// y un índice secundario es la interacción más grande que las tres
    /// propiedades del brief dejan totalmente sin cubrir.
    ///
    /// Sin `DeleteRange` en el generador (`put_delete_strategy`, arriba):
    /// esta propiedad define un índice sobre `ns = 0x01` desde el principio,
    /// y `delete_range` sobre un `ns` indexado siempre falla por diseño.
    ///
    /// Tras cada operación se comprueban DOS cosas: que `scan_index`
    /// coincide con el índice recalculado a mano desde el modelo (mismo
    /// orden de bytes que produce `index::index_key` para un índice no
    /// único — reconstruido aquí porque esa función es `pub(crate)`), y que
    /// `audit_pages` sigue en verde — el árbol del índice es un árbol más
    /// bajo la misma raíz que el de datos (tarea 16), así que cualquier fuga
    /// de páginas específica de mantener un índice también aparecería aquí.
    #[test]
    fn the_secondary_index_matches_a_recomputed_index_after_every_op(
        ops in proptest::collection::vec(put_delete_strategy(), 1..300)
    ) {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(BUCKET_INDEX).unwrap();
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        for op in &ops {
            let mut tx = db.begin_write().unwrap();
            match op {
                Op::Put(k, v) => tx.put(0x01, k, v).unwrap(),
                Op::Delete(k) => { tx.delete(0x01, k).unwrap(); }
                Op::DeleteRange(..) => unreachable!("put_delete_strategy no genera DeleteRange"),
            }
            tx.commit().unwrap();
            apply(&mut model, op);

            // `index::index_key` para un índice NO único, reconstruida a
            // mano: cubo (1 byte) ++ primaria ++ longitud de la primaria en
            // dos bytes little-endian.
            let mut expected: Vec<(Vec<u8>, Vec<u8>)> = model
                .iter()
                .map(|(k, v)| {
                    let mut entry = std::vec![v.first().copied().unwrap_or(0)];
                    entry.extend_from_slice(k);
                    entry.extend_from_slice(&(k.len() as u16).to_le_bytes());
                    (entry, k.clone())
                })
                .collect();
            expected.sort();
            let expected_pks: Vec<Vec<u8>> = expected.into_iter().map(|(_, k)| k).collect();

            let r = db.begin_read();
            // Límite superior de sobra: una entrada real mide como mucho
            // 1 (cubo) + 5 (clave, alfabeto 0..6 de hasta 5 bytes) + 2
            // (longitud) = 8 bytes, siempre por debajo de 32 bytes `0xff`.
            let actual_pks = r.scan_index(BUCKET_INDEX.id, b"", &[0xffu8; 32]).unwrap();
            prop_assert_eq!(actual_pks, expected_pks, "el indice diverge tras {:?}", op);

            prop_assert!(
                db.audit_pages().unwrap(),
                "pagina perdida o contada dos veces tras {:?} (con indice secundario)",
                op
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    /// Propiedad añadida con la recuperación de la cola: **intercalar
    /// `Db::reclaim_tail` en una secuencia aleatoria de operaciones no
    /// puede cambiar ni una sola respuesta del árbol, ni dejar ninguna
    /// página sin dueño, ni sobrevivir mal a un cierre.**
    ///
    /// Es la propiedad que le corresponde comprobar a este fichero y no a
    /// una prueba escrita a mano: un recorte decide qué páginas dejan de
    /// existir a partir de la lista de libres, y las formas de lista que
    /// dan problemas —tramos intermedios sin traer, grupos no servibles
    /// mezclados con servibles, contenedores reciclándose entre sí— salen
    /// de secuencias que a nadie se le ocurre escribir a propósito. Las
    /// tres comprobaciones van tras CADA recorte, no solo al final, para
    /// que la reducción de `proptest` señale la operación exacta.
    ///
    /// El `reopen` importa tanto como el resto: recortar mal no siempre se
    /// nota en la sesión que recorta —el estado en memoria puede seguir
    /// siendo coherente— sino al volver a montar desde el fichero, que es
    /// donde `n_pages`, la cadena de libres y la longitud real tienen que
    /// cuadrar entre sí.
    #[test]
    fn reclaiming_the_tail_never_changes_what_the_tree_answers(
        ops in proptest::collection::vec(op_strategy(), 1..200)
    ) {
        let s = Arc::new(MemStorage::new());
        let mut db = Db::create(Box::new(Arc::clone(&s)), Options::default()).unwrap();
        let mut model = BTreeMap::new();

        for (i, op) in ops.iter().enumerate() {
            let mut tx = db.begin_write().unwrap();
            match op {
                Op::Put(k, v) => tx.put(0x01, k, v).unwrap(),
                Op::Delete(k) => { tx.delete(0x01, k).unwrap(); }
                Op::DeleteRange(a, b) => tx.delete_range(0x01, a, b).unwrap(),
            }
            tx.commit().unwrap();
            apply(&mut model, op);

            if i % 7 != 6 {
                continue;
            }
            let before = s.len().unwrap();
            let freed = db.reclaim_tail().unwrap();
            let after = s.len().unwrap();
            prop_assert_eq!(
                before - after, freed,
                "los bytes que dice devolver no son los que el fichero ha perdido"
            );
            prop_assert!(db.audit_pages().unwrap(), "pagina perdida o contada dos veces");

            let r = db.begin_read();
            let mut cursor = r.scan(0x01, b"", b"\xff\xff\xff\xff\xff\xff\xff").unwrap();
            let mut actual = Vec::new();
            while let Some(entry) = cursor.next().unwrap() {
                actual.push(entry);
            }
            let expected: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(actual, expected, "divergencia tras recortar en la operacion {}", i);
            drop(r);

            // Y desde el fichero, no desde la memoria de esta sesión.
            drop(db);
            db = Db::open(Box::new(Arc::clone(&s)), Options::default()).unwrap();
            prop_assert!(db.audit_pages().unwrap(), "contabilidad rota tras reabrir");
        }

        let r = db.begin_read();
        for (k, v) in &model {
            let stored = r.get(0x01, k).unwrap();
            prop_assert_eq!(stored.as_ref(), Some(v));
        }
    }
}

/// **Cobertura de cifrado de este fichero.**
///
/// Hasta el cambio de diseño a nonces aleatorios, `tests/props.rs` no tocaba
/// el cifrado en absoluto: las cuatro propiedades de arriba corren sobre
/// `Options::default()`, sin clave. Eso dejaba sin cubrir justo lo que este
/// motor tiene de particular bajo cifrado — que el tamaño de página LÓGICA
/// (`page_size` menos `crypto::CIPHER_PREFIX`) es el que gobierna cuántas
/// entradas caben en una hoja, el umbral de overflow y el límite de tamaño
/// de clave. Un descuido ahí no se manifiesta como un fallo de descifrado,
/// que sería obvio, sino como un árbol que diverge del modelo en cargas
/// concretas: exactamente lo que una propiedad contra un oráculo
/// `BTreeMap` está para encontrar y una prueba escrita a mano no.
///
/// Cubre los DOS algoritmos, no solo el de por defecto: el prefijo de
/// cifrado mide 40 bytes para ambos, así que los dos tienen la misma
/// geometría lógica y ninguno merece menos cobertura que el otro.
///
/// Casos reducidos frente a las propiedades de arriba (`cases() / 2`,
/// secuencias de hasta 120 operaciones en vez de 300): cada operación paga
/// aquí un sellado y un descifrado reales por página tocada, y el objetivo
/// es cubrir la geometría lógica en las dos vías criptográficas sin
/// convertir `cargo test --features encryption` en un banco de minutos.
#[cfg(feature = "encryption")]
mod encrypted {
    use super::*;
    use inro::{Algorithm, Encryption};

    /// Los algoritmos que este build compila. `Vec` y no un `const`
    /// array, porque su longitud depende de la feature `aes`.
    fn algorithms() -> Vec<Algorithm> {
        // `unused_mut` sin la feature `aes`: ahí el `push` de abajo no se
        // compila y el vector nace ya completo. El `allow` es más honesto
        // que construir el vector de dos formas distintas según la feature.
        #[allow(unused_mut)]
        let mut v = vec![Algorithm::XChaCha20Poly1305];
        #[cfg(feature = "aes")]
        v.push(Algorithm::Aes256GcmSiv);
        v
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: std::cmp::max(1, cases() / 2),
            ..ProptestConfig::default()
        })]

        #[test]
        fn an_encrypted_tree_always_matches_a_btreemap(
            ops in proptest::collection::vec(op_strategy(), 1..120)
        ) {
            for algorithm in algorithms() {
                let opts = Options {
                    encryption: Some(Encryption { key: [0x5c; 32], algorithm }),
                    ..Options::default()
                };
                let db = Db::create(Box::new(MemStorage::new()), opts).unwrap();
                let mut model = BTreeMap::new();

                for op in &ops {
                    let mut tx = db.begin_write().unwrap();
                    match op {
                        Op::Put(k, v) => tx.put(0x01, k, v).unwrap(),
                        Op::Delete(k) => { tx.delete(0x01, k).unwrap(); }
                        Op::DeleteRange(a, b) => tx.delete_range(0x01, a, b).unwrap(),
                    }
                    tx.commit().unwrap();
                    apply(&mut model, op);

                    let r = db.begin_read();
                    let mut cursor =
                        r.scan(0x01, b"", b"\xff\xff\xff\xff\xff\xff\xff").unwrap();
                    let mut actual = Vec::new();
                    while let Some(entry) = cursor.next().unwrap() {
                        actual.push(entry);
                    }
                    let expected: Vec<_> =
                        model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    prop_assert_eq!(
                        actual, expected,
                        "{:?}: divergencia tras {:?}", algorithm, op
                    );
                }

                // Y ninguna página perdida ni contada dos veces: el
                // reciclado de páginas es donde el cifrado y la lista de
                // libres se cruzan (`Freelist::flush` sella sus propias
                // páginas con el mismo flujo de nonces que el árbol).
                prop_assert!(
                    db.audit_pages().unwrap(),
                    "{:?}: pagina perdida o contada dos veces", algorithm
                );
            }
        }
    }
}
