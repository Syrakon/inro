//! Inyección sistemática de fallos (tarea 20): la prueba que decide si el
//! esquema de dos meta-ranuras es correcto o solo suena bien. El protocolo
//! de commit es "escribe páginas, sincroniza, escribe la ranura de meta
//! INACTIVA, sincroniza otra vez" — un corte que desgarra esa escritura de
//! meta debe dejar esa ranura ilegible (CRC roto) y montar desde la otra,
//! sin perder nada del commit anterior ni dejar nada del que se estaba
//! confirmando.
//!
//! **Todo el fichero vive tras `feature = "std"`** (abajo, `#![cfg(...)]`),
//! igual que `tests/props.rs`: `Db`/`WriteTxn`/`storage::{FaultStorage,
//! MemStorage}` no existen sin ella, así que bajo `cargo test
//! --no-default-features` este fichero se compila vacío en vez de fallar.
//!
//! ## Reconciliación con el brief y con el arnés existente
//!
//! El brief describe `FaultStorage`/`Fault` y sugiere que
//! `WriteTxn::pending_writes` (ver `tx.rs`) devuelva `self.written.len()` —
//! el mismo campo que ya usa el guardián de reutilización de nonces. Eso NO
//! sirve aquí: `written` solo se puebla si la base está cifrada (ver su
//! comentario en `tx.rs`), y las tres pruebas de este fichero usan
//! `Options::default()`, sin cifrado — con esa definición,
//! `pending_writes()` devolvería 0 siempre y la aritmética
//! `pending_writes() + 1` del brief para localizar la escritura de la meta
//! apuntaría a la escritura EQUIVOCADA (la primera página de árbol de la
//! transacción, no la meta). `WriteTxn::pending_writes` se implementó en su
//! lugar como un contador propio (`write_count`), incrementado
//! incondicionalmente en `write_page` — ver su comentario — y aun así este
//! fichero NO calcula la escritura de la meta como `pending_writes() + 1`:
//! `Freelist::flush` (llamado desde `commit`, no desde `write_page`) casi
//! siempre añade sus propias escrituras entre el último `put` y la meta
//! (cualquier `put`/`delete` libera al menos la raíz y la hoja antiguas por
//! COW), así que "+1" solo sería exacto por casualidad. En su lugar, cada
//! prueba que necesita apuntar a la meta MIDE cuántas escrituras añade un
//! commit de referencia idéntico sobre un medio aparte — la escritura de la
//! meta es SIEMPRE la última de un commit (`WriteTxn::commit`: tras la
//! lista de libres solo quedan dos `sync()` y la propia escritura de la
//! meta), así que el total medido apunta exactamente a ella, sin adivinar.
//! `pending_writes()` en sí queda cubierto por su propia prueba dedicada en
//! `tx.rs` (`pending_writes_counts_every_physical_write_issued_so_far`).
//!
//! `FaultStorage` (`src/storage.rs`) es deliberadamente MÁS SIMPLE que
//! `crypto::tests::PowerLossStorage` (tarea 17/18): aquella modela cifrado y
//! necesita distinguir ranuras de meta/cabecera para revertir solo esas al
//! último `sync()`. Esta pregunta no necesita esa distinción — solo poder
//! fallar o desgarrar la escritura N-ésima de la secuencia completa, sea lo
//! que sea — así que no es una duplicación accidental, ver el comentario de
//! `FaultStorage` en `storage.rs`.
#![cfg(feature = "std")]

use inro::storage::{Fault, FaultStorage, MemStorage};
use inro::{Db, Options, Storage, Sync};
use std::sync::Arc;

/// Estado conocido bueno: diez claves confirmadas.
fn seed(db: &Db) {
    let mut tx = db.begin_write().unwrap();
    for i in 0..10u32 {
        tx.put(0x01, &i.to_be_bytes(), b"confirmado").unwrap();
    }
    tx.commit().unwrap();
}

/// Las diez claves de `seed`, y solo ellas, deben seguir presentes. Válido
/// siempre que nada más se haya escrito jamás en el espacio `0x01` — que es
/// el caso de las pruebas 1 y 2 de este fichero (la transacción bajo prueba
/// usa claves DISTINTAS, `100..200` o `b"perdida"`), pero NO el de la
/// tercera, que sí añade más claves confirmadas al mismo espacio — ver
/// `assert_seed_is_intact`, que esa prueba usa en su lugar.
fn assert_is_the_committed_state(db: &Db) {
    let r = db.begin_read();
    for i in 0..10u32 {
        assert_eq!(
            r.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
            Some(b"confirmado".as_slice()),
            "clave {i}"
        );
    }
    let mut c = r.scan(0x01, b"", b"\xff\xff\xff\xff").unwrap();
    let mut n = 0;
    while c.next().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 10, "no aparecen claves de mas ni de menos de las diez confirmadas");
}

/// Solo las diez claves de `seed` siguen presentes — sin afirmar que sean
/// las ÚNICAS del espacio `0x01` (a diferencia de `assert_is_the_committed_state`),
/// para poder usarse cuando otras transacciones confirmadas conviven en el
/// mismo espacio.
fn assert_seed_is_intact(db: &Db) {
    let r = db.begin_read();
    for i in 0..10u32 {
        assert_eq!(
            r.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
            Some(b"confirmado".as_slice()),
            "clave {i} de seed"
        );
    }
}

/// Barre `N` (el punto de aborto) sobre TODA la secuencia de escrituras de
/// una transacción de 100 `put` — desde la primera página de árbol hasta la
/// propia escritura de la meta, inclusive — y tras cada aborto reabre y
/// comprueba que el contenido es exactamente el del commit anterior
/// (`seed`), sin excepción alguna: es la propiedad central del diseño de
/// dos ranuras.
///
/// **Ruptura deliberada que prueba que esto muerde**: `Fault::AbortAt`
/// nunca deja bytes a medias (o la escritura entera llega, o no llega
/// nada) — así que, con SOLO este fallo, incluso escribir la meta en la
/// ranura ACTIVA en vez de la inactiva sobrevive el barrido: un abort que
/// cae justo en esa escritura la deja sin tocar en absoluto, sin importar
/// qué ranura fuera. Lo que este barrido SÍ demuestra es la propiedad más
/// básica de la que depende el diseño de dos ranuras: "escrituras que nunca
/// llegan no deben cambiar nada". Se comprobó invirtiendo el desempate de
/// `Meta::load` (`meta.txn_id > b.txn_id` a `<`, en `meta.rs`) — monta
/// siempre por la ranura MÁS VIEJA en vez de la más nueva — y el barrido
/// falla en el primer punto (`n = 0`, la clave `0` de `seed` ya no aparece)
/// porque hasta un commit que llegó COMPLETO dejó de ganarle a lo que había
/// antes. Revertido tras confirmar; ver `a_torn_write_of_the_meta_page_falls_back_to_the_other_slot`
/// (más abajo) para la ruptura que sí distingue ranura activa de inactiva —
/// esa necesita una escritura a medias (`Fault::TearAt`), no un simple
/// aborto.
#[test]
fn aborting_at_any_write_of_a_transaction_leaves_the_previous_commit_intact() {
    // Primero se mide cuántas escrituras hace la transacción, y luego se
    // aborta en cada una de ellas.
    let total = {
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
        seed(&db);
        let before = s.write_count();
        let mut tx = db.begin_write().unwrap();
        for i in 100..200u32 {
            tx.put(0x01, &i.to_be_bytes(), b"nuevo").unwrap();
        }
        tx.commit().unwrap();
        s.write_count() - before
    };
    assert!(total > 0, "la transaccion de referencia deberia emitir al menos una escritura");

    // `audit_pages` puede fallar de verdad en un punto MUY concreto y ya
    // documentado, sin que sea un defecto de ESTA tarea: `WriteTxn::commit`
    // llama a `relocate_meta_b` (tarea 18) ANTES de escribir la lista de
    // libres y la meta de este commit, y esa función sincroniza su propia
    // cabecera de forma incondicional — duradera aunque el resto del
    // commit no llegue a confirmar. Si el corte cae DESPUÉS de esa
    // sincronización pero ANTES de que la meta de ESTE commit se escriba, la
    // página vieja de meta B queda huérfana para siempre: el propio
    // comentario de `relocate_meta_b` en `tx.rs` lo documenta y lo acepta
    // ("Peor que 'nunca perderla', mejor que 'perderla siempre'"). Esa
    // ventana son, como mucho, las dos ÚLTIMAS escrituras de la
    // transacción — confirmado abajo, no solo asumido: cualquier fallo de
    // `audit_pages` fuera de esa ventana hace fallar la prueba igual, para
    // no confundir este hueco ya conocido con un defecto nuevo del diseño
    // de dos ranuras que SÍ es responsabilidad de esta tarea.
    let mut audit_failures: Vec<u64> = Vec::new();

    for n in 0..total {
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
        seed(&db);
        let base = s.write_count();
        s.set_fault(Some(Fault::AbortAt(base + n + 1)));

        let _ = (|| -> inro::Result<()> {
            let mut tx = db.begin_write()?;
            for i in 100..200u32 {
                tx.put(0x01, &i.to_be_bytes(), b"nuevo")?;
            }
            tx.commit()
        })();
        drop(db);

        s.set_fault(None);
        let db = Db::open(Box::new(s.clone()), Options::default()).unwrap();
        assert_is_the_committed_state(&db);
        if !db.audit_pages().unwrap() {
            audit_failures.push(n);
        }
        // Ninguna clave de la transacción abortada (100..200) debe
        // sobrevivir a NINGÚN punto de corte: o el commit entero pasó (y
        // entonces esta rama de la sentencia if de más abajo ni se toca
        // porque `n` cubre solo puntos DENTRO de la transacción de
        // referencia) o no pasó nada de él.
        let r = db.begin_read();
        for i in 100..200u32 {
            assert_eq!(
                r.get(0x01, &i.to_be_bytes()).unwrap(),
                None,
                "clave {i} de la transaccion abortada en la escritura {n} sobrevivio"
            );
        }
    }

    for &n in &audit_failures {
        assert!(
            n + 2 >= total,
            "auditoria de paginas fallo en la escritura {n} de {total}, fuera de la \
             ventana de las 2 ultimas escrituras que explica el hueco YA documentado \
             de relocate_meta_b (ver el comentario de mas arriba): esto es un defecto \
             nuevo, no el conocido"
        );
    }
}

/// Localiza, entre las dos posiciones posibles de una ranura de meta con
/// `Options::default()` (página 1 → offset 512, página 2 → offset 1024;
/// ninguna prueba de este fichero cruza los 4 KB que disparan la
/// reubicación de la tarea 18), la que quedó ILEGIBLE tras un desgarro —
/// o `None` si ninguna lo está.
fn find_torn_meta_slot(s: &FaultStorage) -> Option<u64> {
    use inro::meta::Meta;
    for &offset in &[512u64, 1024u64] {
        let mut buf = [0u8; 512];
        s.read_at(offset, &mut buf).unwrap();
        if Meta::decode(&buf).is_err() {
            return Some(offset);
        }
    }
    None
}

/// Desgarra específicamente la escritura de la meta (no cualquier otra) y
/// comprueba que el commit se cae por completo — no se ve "medio commit" —
/// y que reabrir monta desde la ranura superviviente, con el contenido
/// exacto de `seed`.
///
/// **Ruptura deliberada que prueba que esto muerde**: sin la comprobación
/// de premisa de más abajo, un `bytes` que por accidente dejara la ranura
/// desgarrada BYTE A BYTE IDÉNTICA a un contenido válido (el mismo tipo de
/// fallo que ya sufrió `TORN_PREFIX` en `crypto.rs`, corregido de 56 a 104)
/// pasaría esta prueba sin haber desgarrado nada de verdad. Se comprobó
/// bajando `bytes` a valores que SÍ dejan la ranura legible (p. ej. `0`,
/// que no toca ningún byte) y confirmando que la aserción de premisa lo
/// atrapa antes de llegar a la parte que importa.
#[test]
fn a_torn_write_of_the_meta_page_falls_back_to_the_other_slot() {
    // La escritura de la meta es SIEMPRE la última de un commit (ver el
    // comentario de cabecera de este fichero): basta con medir cuántas
    // escrituras hace un commit de referencia IDÉNTICO sobre un medio
    // aparte y usar el total como ordinal.
    let meta_write = {
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
        seed(&db);
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"perdida", b"x").unwrap();
        tx.commit().unwrap();
        s.write_count()
    };

    let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
    seed(&db);
    // 40 bytes: dentro de `txn_id` (0..8, que SIEMPRE cambia de un commit a
    // otro) y muy por debajo del CRC (108..112, `meta::META_SIZE` = 112),
    // así que el contenido mezclado que queda en el plato jamás puede
    // coincidir por casualidad con lo que el CRC viejo certificaba.
    s.set_fault(Some(Fault::TearAt { write: meta_write, bytes: 40 }));
    let mut tx = db.begin_write().unwrap();
    tx.put(0x01, b"perdida", b"x").unwrap();
    let commit_result = tx.commit();
    assert!(commit_result.is_err(), "un commit cuya meta se desgarra debe reportar el fallo, no ocultarlo");
    drop(db);
    s.set_fault(None);

    // Premisa del propio arnés (ver el comentario de la prueba): el
    // desgarro tiene que dejar de verdad una ranura ilegible, o esto no
    // está comprobando nada.
    assert!(
        find_torn_meta_slot(&s).is_some(),
        "el desgarro de {} bytes no dejo ninguna ranura de meta ilegible: \
         esta prueba no esta desgarrando nada",
        40
    );

    let db = Db::open(Box::new(s.clone()), Options::default()).unwrap();
    assert_is_the_committed_state(&db);
    assert_eq!(db.begin_read().get(0x01, b"perdida").unwrap(), None);
    assert!(db.audit_pages().unwrap());
}

/// La sincronización relajada (`Sync::Never`) puede perder commits enteros
/// tras un corte — es la garantía que ofrece, no un defecto — pero nunca
/// debe dejar el fichero corrupto: ni una página huérfana o con dos dueños
/// (`audit_pages`), ni un hueco en medio de la secuencia de commits (una
/// clave posterior presente sin que todas las anteriores también lo
/// estén, que delataría un commit aplicado a medias).
///
/// **A diferencia del brief**: la versión original de esta prueba
/// reabría sin haber armado NINGÚN fallo — con `FaultStorage` respaldado
/// por `MemStorage`, que no tiene búfer de sistema operativo que perder,
/// eso significa que las 50 transacciones sobreviven siempre enteras, y
/// "puede perder commits" queda sin ejercitar: pasaría igual si `commit`
/// nunca sincronizara nada en absoluto. Esta versión SÍ corta la corriente
/// — `Fault::AbortAt` en un barrido de puntos a lo largo de las 50
/// transacciones relajadas, incluida la mitad de una transacción
/// individual — y comprueba la propiedad de verdad.
///
/// **Sobre la comprobación de "sin huecos", honestamente**: no se encontró
/// ninguna ruptura de una línea que SOLO ella atrape — dos candidatas
/// probadas (escribir la meta en la ranura activa; invertir el desempate de
/// `Meta::load` para preferir el `txn_id` más bajo) las atrapa antes
/// `assert_seed_is_intact`, porque cada ranura de meta describe el árbol
/// COMPLETO hasta ese punto, nunca un delta — así que una ranura con CRC
/// válido no puede, por construcción, describir un estado con huecos: o
/// describe un commit entero, o (con `Fault::AbortAt`, que nunca deja bytes
/// a medias) sigue describiendo el anterior. La comprobación se queda de
/// todos modos como defensa en profundidad, barata, para el día en que
/// `Fault::TearAt` — que sí deja bytes a medias — se combine con esta misma
/// prueba y pueda producir un estado que las comprobaciones más simples no
/// atrapen.
#[test]
fn relaxed_sync_loses_commits_but_never_corrupts() {
    const N: u32 = 50;
    let opts = Options { sync: Sync::Never, ..Options::default() };

    // Referencia: cuántas escrituras hacen falta para las N transacciones
    // relajadas completas, sobre un medio aparte.
    let total = {
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(s.clone()), opts).unwrap();
        seed(&db);
        let base = s.write_count();
        for i in 0..N {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &(1000 + i).to_be_bytes(), b"relajado").unwrap();
            tx.commit().unwrap();
        }
        s.write_count() - base
    };
    assert!(total > 0);

    // Barrido representativo, no exhaustivo (ver el comentario sobre el
    // reloj en la cabecera del fichero): 25 puntos repartidos a lo largo
    // de TODA la secuencia bastan para cruzar límites de transacción y
    // caer también a mitad de una — la propiedad no depende de cuántos
    // puntos se prueben, solo de que el barrido cubra ambos casos.
    let samples = 25u64.min(total);
    for k in 0..samples {
        let n = if samples <= 1 { 0 } else { k * (total - 1) / (samples - 1) };
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(s.clone()), opts).unwrap();
        seed(&db);
        let base = s.write_count();
        s.set_fault(Some(Fault::AbortAt(base + n + 1)));

        for i in 0..N {
            let mut tx = match db.begin_write() {
                Ok(tx) => tx,
                Err(_) => break,
            };
            if tx.put(0x01, &(1000 + i).to_be_bytes(), b"relajado").is_err() {
                break;
            }
            if tx.commit().is_err() {
                break;
            }
        }
        drop(db);
        s.set_fault(None);

        let db = Db::open(Box::new(s.clone()), opts).unwrap();
        // Solo `seed` — no `assert_is_the_committed_state`: esta prueba SÍ
        // añade más claves confirmadas al mismo espacio `0x01`, así que la
        // comprobación de "diez y ni una más" de aquella no aplica aquí
        // (ver el comentario de `assert_seed_is_intact`).
        assert_seed_is_intact(&db);
        // Mismo hueco YA documentado que en la primera prueba (ventana de
        // `relocate_meta_b`, ver su comentario ahí): se tolera SOLO dentro
        // de las 2 últimas escrituras de la secuencia completa, nunca en
        // ningún otro punto.
        if !db.audit_pages().unwrap() {
            assert!(
                n + 2 >= total,
                "auditoria de paginas fallo en la escritura {n} de {total}, fuera de la \
                 ventana ya documentada de relocate_meta_b: defecto nuevo, no el conocido"
            );
        }

        let r = db.begin_read();
        let mut gap_seen = false;
        let mut present_count = 0u32;
        for i in 0..N {
            let present = r.get(0x01, &(1000 + i).to_be_bytes()).unwrap().is_some();
            if gap_seen {
                assert!(!present, "clave relajada {i} presente tras un hueco en la escritura {n}: no es un prefijo");
            }
            if present {
                present_count += 1;
            } else {
                gap_seen = true;
            }
        }
        // Cierra el hueco que el brief original dejaba sin cubrir: no basta
        // con que las presentes formen un prefijo, tampoco puede haber
        // ninguna clave de MÁS colgando en el espacio `0x01` fuera de las
        // diez de `seed` y ese prefijo — lo comprueba contando TODO el
        // espacio con `scan`, no solo consultando las claves que la propia
        // prueba conoce.
        let mut c = r.scan(0x01, b"", b"\xff\xff\xff\xff").unwrap();
        let mut total_in_ns = 0u32;
        while c.next().unwrap().is_some() {
            total_in_ns += 1;
        }
        assert_eq!(
            total_in_ns,
            10 + present_count,
            "el espacio 0x01 tiene claves de mas o de menos tras cortar en la escritura {n}"
        );
    }
}
