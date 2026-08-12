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
//! comentario en `tx.rs`), y las pruebas de este fichero usan
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
//!
//! ## Ronda de revisión (tras la primera entrega): dos hallazgos MEDIUM
//!
//! **El guardián de premisa podía pasar en vacío.** La primera versión de
//! `find_torn_meta_slot` (ya eliminada) codificaba a mano los offsets 512 y
//! 1024 — válidos SOLO mientras la meta B no se haya reubicado (tarea 18).
//! En una base que ya cruzó los 4 KB y recicló la página 2 como dato
//! corriente, esos offsets fijos hacían que el guardián reportara "ranura
//! ilegible" sobre una base perfectamente SANA — la página 2 ya no
//! contiene una meta en absoluto, así que `Meta::decode` falla ahí por una
//! razón que no tiene nada que ver con ningún desgarro. Es el hueco de
//! `TORN_PREFIX` (`crypto.rs`, 56→104) por TERCERA vez en el código y
//! CUARTA en el proyecto. Corregido derivando los offsets de la cabecera
//! (`header::Geometry::read`, la única fuente de verdad sobre dónde viven
//! las ranuras AHORA MISMO) en vez de una lista fija — ver `geometry` y
//! `assert_meta_tear_left_the_previous_commit_recoverable`, más abajo — y
//! reforzado para exigir que la ranura superviviente decodifique CON el
//! `txn_id` del último commit confirmado, no solo que "alguna ranura no
//! lea". El caso vacío exacto que encontró la revisión está reproducido y
//! bloqueado en
//! `the_meta_tear_guard_is_not_satisfied_by_an_ordinary_healthy_database_past_relocation`.
//!
//! Nótese que `crypto::tests::PowerLossStorage::META_OFFSETS` SÍ mantiene
//! una lista fija de tres posiciones (512, 1024, 4096) — y NO es la misma
//! clase de error: ese arnés necesita conocer TODAS las posiciones que una
//! ranura ocupó alguna vez durante la vida del fichero, porque su pregunta
//! es "¿se reutilizó algún nonce de cifrado en cualquier momento?", una
//! pregunta sobre HISTORIA de escritura, no sobre estado actual. La
//! pregunta de este fichero — "¿qué ranura sigue viva AHORA?" — solo
//! necesita el estado actual, y por eso se deriva de la cabecera en vez de
//! mantener una segunda lista fija que pueda desincronizarse de la primera.
//!
//! **La ventana de tolerancia de `audit_pages` en la prueba de
//! `Sync::Never` estaba anclada al evento equivocado.** Toleraba fallos de
//! `audit_pages` solo en las 2 últimas escrituras de TODA la secuencia de
//! 50 transacciones — pero `relocate_meta_b` puede disparar (y de hecho
//! dispara) en CUALQUIERA de esas 50 transacciones, normalmente mucho antes
//! del final, no en la última. Un barrido exhaustivo de los 182 puntos de
//! corte (la revisión lo corrió; reproducido aquí) encuentra fallos reales
//! de `audit_pages` en `n=79` y `n=80` — la transacción que de verdad cruza
//! los 4 KB — fuera de la ventana tolerada y fuera del muestreo de 25
//! puntos que hacía la versión anterior. Corregido en dos frentes: el
//! barrido ahora es EXHAUSTIVO (no un muestreo, que es precisamente lo que
//! escondió el hallazgo), y la tolerancia se ancla a la transacción que
//! REALMENTE reubica (detectada comparando `meta_b_page` de la cabecera
//! antes y después de cada una de las 50, no a "cerca del final") — ver
//! `measure_relaxed_reference`.
#![cfg(feature = "std")]

use inro::header::Geometry;
use inro::meta::Meta;
use inro::storage::{Fault, FaultStorage, MemStorage};
use inro::{Db, Options, Storage, Sync};
use std::sync::{Arc, Mutex};

/// Estado conocido bueno: diez claves confirmadas.
fn seed(db: &Db) {
    let mut tx = db.begin_write().unwrap();
    for i in 0..10u32 {
        tx.put(0x01, &i.to_be_bytes(), b"confirmado").unwrap();
    }
    tx.commit().unwrap();
}

/// Geometría actual del fichero, leída de la cabecera — la única fuente de
/// verdad sobre dónde viven las ranuras de meta AHORA MISMO (ver el
/// comentario de cabecera de este fichero, sección de la ronda de
/// revisión).
fn geometry(s: &FaultStorage) -> Geometry {
    Geometry::read(s).unwrap()
}

/// Las diez claves de `seed`, y solo ellas, deben seguir presentes. Válido
/// siempre que nada más se haya escrito jamás en el espacio `0x01` — que es
/// el caso de las pruebas de esta primera sección (la transacción bajo
/// prueba usa claves DISTINTAS, `100..200`), pero NO el de la prueba de
/// sincronización relajada, que sí añade más claves confirmadas al mismo
/// espacio — ver `assert_seed_is_intact`, que esa prueba usa en su lugar.
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

// ---------------------------------------------------------------------
// Prueba 1: barrido exhaustivo de `Fault::AbortAt` sobre una transacción.
// ---------------------------------------------------------------------

/// Ejecuta `seed` + 100 `put` (`100..200`) + `commit` contra un medio
/// fresco, con `fault` ya armado ANTES de empezar la segunda transacción —
/// simula un corte/desgarro exactamente en la escritura que `fault`
/// describe. Comprueba que, tras reabrir, el contenido es EXACTAMENTE el
/// de `seed` (ninguna clave `100..200` sobrevive, sea cual sea el punto de
/// corte) y devuelve si `audit_pages` fue limpio, para que el llamante
/// decida si un `false` cae dentro de la ventana ya conocida de
/// `relocate_meta_b` (ver el comentario de cabecera).
///
/// Compartida entre el barrido de `AbortAt` y el de `TearAt`: el
/// mecanismo — cuántas escrituras exitosas preceden al commit — es el
/// mismo para los dos tipos de fallo, solo cambia CÓMO falla la última.
fn run_one_hundred_put_transaction_under_fault(fault: Fault) -> bool {
    let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
    seed(&db);
    s.set_fault(Some(fault));

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
    let r = db.begin_read();
    for i in 100..200u32 {
        assert_eq!(
            r.get(0x01, &i.to_be_bytes()).unwrap(),
            None,
            "clave {i} de la transaccion bajo fallo sobrevivio"
        );
    }
    db.audit_pages().unwrap()
}

/// Cuántas escrituras físicas hace `seed` + 100 `put` + `commit`, medido
/// sobre un medio de usar y tirar, sin ningún fallo armado. La escritura de
/// la meta es SIEMPRE la última (`WriteTxn::commit`: tras la lista de
/// libres solo quedan dos `sync()` y la propia escritura de la meta, sin
/// nada más después), así que el total apunta exactamente a ella.
fn measure_hundred_put_reference() -> u64 {
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
}

/// Ordinal (1-based, relativo a justo-después-de-`seed`) de la reescritura
/// de la cabecera PRINCIPAL (offset `0`, `header::HEADER_SIZE` bytes)
/// dentro de la transacción de 100 `put` de referencia, si
/// `relocate_meta_b` (tarea 18) llega a dispararse — `None` si no.
///
/// **Por qué la cabecera principal, y no "las 2 últimas escrituras"**
/// (ronda de revisión: la primera versión de esta tolerancia era "n + 2 >=
/// total", una distancia al FINAL de la secuencia sin relación con el
/// mecanismo real). `relocate_meta_b` escribe, en orden: la copia de la
/// meta en su posición nueva, el ESPEJO de la cabecera, y solo entonces la
/// cabecera PRINCIPAL — cada una con su propia sincronización. Mientras la
/// PRINCIPAL siga intacta con su contenido VIEJO, `Geometry::read` la usa
/// tal cual (decodifica bien, así que nunca cae al espejo) y reporta la
/// posición VIEJA de la meta B — estable y autocorregible: la PRÓXIMA
/// transacción que intente `relocate_meta_b` la reintentará desde cero,
/// sin fuga permanente. El punto sin retorno es la PRIMERA vez que la
/// PRINCIPAL queda con contenido NUEVO de forma duradera — desde ahí,
/// cualquier corte que impida que ESTE commit complete dejaría la página
/// vieja de meta B huérfana para siempre (`self.free(geometry.meta_b_page)`
/// en `relocate_meta_b`, `tx.rs`, es solo en memoria: no sobrevive a un
/// commit que no confirma) — el propio comentario de `relocate_meta_b`
/// documenta y acepta esa pérdida ("Peor que 'nunca perderla', mejor que
/// 'perderla siempre'"). No es un defecto de esta tarea, es deuda ya
/// aceptada de la tarea 18.
///
/// **Por qué esto también cubre `Fault::TearAt`, no solo `Fault::AbortAt`**
/// (el hallazgo concreto de esta ronda): un desgarro cuyo `bytes` sea `>=
/// header::HEADER_SIZE` (64) deposita la cabecera COMPLETA — el resto de
/// la página física ya era relleno a cero en ambos lados — así que la
/// principal queda duradera con el contenido NUEVO aunque `write_at`
/// devuelva `Err` (ver el comentario de `Fault::TearAt` en `storage.rs`).
/// Con el prefijo de 104 bytes que usa esta suite, tearing la reescritura
/// de la cabecera principal (64 bytes) hace justo eso — confirmado: el
/// barrido de `TearAt` con ese prefijo encontró un fallo real de
/// `audit_pages` EXACTAMENTE en esa escritura, fuera de la ventana vieja de
/// "2 últimas" (era la antepenúltima de 175, no de las 2 últimas) y dentro
/// de la nueva, correctamente anclada al mecanismo.
///
/// Detectado grabando el `(offset, longitud)` de cada escritura física de
/// un medio de referencia SIN ningún fallo armado: es la única reescritura
/// de cabecera que existe en este motor (`Geometry::write`, solo desde
/// `relocate_meta_b`), así que localizarla por FORMA (offset `0`, longitud
/// exacta de una cabecera) no deja ambigüedad posible con ninguna otra
/// escritura del commit.
fn measure_header_primary_rewrite_ordinal() -> Option<u64> {
    struct Recording {
        inner: MemStorage,
        writes: Mutex<Vec<(u64, usize)>>,
    }
    impl Storage for Recording {
        fn read_at(&self, o: u64, b: &mut [u8]) -> inro::Result<()> {
            self.inner.read_at(o, b)
        }
        fn write_at(&self, o: u64, b: &[u8]) -> inro::Result<()> {
            self.writes.lock().unwrap().push((o, b.len()));
            self.inner.write_at(o, b)
        }
        fn sync(&self) -> inro::Result<()> {
            self.inner.sync()
        }
        fn len(&self) -> inro::Result<u64> {
            self.inner.len()
        }
    }

    let s = Arc::new(Recording { inner: MemStorage::new(), writes: Mutex::new(Vec::new()) });
    let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
    seed(&db);
    s.writes.lock().unwrap().clear();
    let mut tx = db.begin_write().unwrap();
    for i in 100..200u32 {
        tx.put(0x01, &i.to_be_bytes(), b"nuevo").unwrap();
    }
    tx.commit().unwrap();
    let writes = s.writes.lock().unwrap();
    writes
        .iter()
        .position(|&(o, l)| o == 0 && l == inro::header::HEADER_SIZE)
        .map(|idx| (idx + 1) as u64)
}

/// Reporta cualquier fallo de `audit_pages` en una escritura ANTERIOR a la
/// reescritura de la cabecera principal (o, si `relocate_meta_b` nunca
/// dispara para esta transacción de referencia, cualquier fallo en
/// absoluto) — es decir, un defecto NUEVO, no el ya documentado de
/// `relocate_meta_b`. Común a `AbortAt` y `TearAt`: el mecanismo (qué
/// escritura durable deja el hueco sin retorno) no depende de CÓMO falla
/// esa escritura.
fn assert_all_audit_failures_are_within_the_known_window(
    failures: &[u64],
    header_primary_ordinal: Option<u64>,
    total: u64,
    label: &str,
) {
    for &n in failures {
        let write_ord = n + 1;
        let tolerated = header_primary_ordinal.is_some_and(|start| write_ord >= start);
        assert!(
            tolerated,
            "{label}: auditoria de paginas fallo en la escritura {n} (ordinal {write_ord}) de \
             {total}, fuera de la ventana de relocate_meta_b (cabecera principal en \
             {header_primary_ordinal:?}): esto es un defecto nuevo, no el conocido"
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
/// antes. Revertido tras confirmar; ver
/// `a_torn_write_of_the_meta_page_falls_back_to_the_other_slot` (más abajo)
/// para la ruptura que sí distingue ranura activa de inactiva — esa
/// necesita una escritura a medias (`Fault::TearAt`), no un simple aborto.
#[test]
fn aborting_at_any_write_of_a_transaction_leaves_the_previous_commit_intact() {
    let total = measure_hundred_put_reference();
    assert!(total > 0, "la transaccion de referencia deberia emitir al menos una escritura");

    let s0 = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db0 = Db::create(Box::new(s0.clone()), Options::default()).unwrap();
    seed(&db0);
    let base = s0.write_count();
    drop(db0);

    let header_primary_ordinal = measure_header_primary_rewrite_ordinal();

    let mut audit_failures = Vec::new();
    for n in 0..total {
        let ok = run_one_hundred_put_transaction_under_fault(Fault::AbortAt(base + n + 1));
        if !ok {
            audit_failures.push(n);
        }
    }
    assert_all_audit_failures_are_within_the_known_window(&audit_failures, header_primary_ordinal, total, "AbortAt");
}

/// Igual que la prueba anterior, pero con `Fault::TearAt` en vez de
/// `Fault::AbortAt`: cada punto de corte de la MISMA transacción se
/// desgarra (no se aborta limpiamente) a dos profundidades distintas.
/// Sube la cobertura de "sistemática" de "un solo punto con un solo
/// prefijo" (la primera versión de esta tarea) a "todo punto con más de un
/// prefijo" — lo que el nombre de la tarea promete.
///
/// **Por qué 40 y 104, no cualquier par de prefijos**: los dos están por
/// DEBAJO de `meta::META_SIZE` (112) — deliberado. Un prefijo `>= 112`
/// deposita una ranura de meta COMPLETA y válida (el resto de la página es
/// relleno a cero en ambos lados, ver el comentario de `TearAt` en
/// `storage.rs`), así que el commit queda DURADERO de verdad aunque
/// `commit()` devuelva `Err` — comportamiento correcto pero especial, que
/// esta prueba deliberadamente NO ejercita para mantener una sola
/// aserción uniforme en los 2×total puntos ("ninguna clave de la
/// transacción bajo fallo sobrevive"); ver
/// `a_torn_write_of_the_meta_page_with_a_prefix_at_or_above_meta_size_lands_a_full_commit_anyway`,
/// más abajo, para ese caso por separado, documentado, no mezclado aquí.
/// 104 coincide a propósito con `TORN_PREFIX` en `crypto.rs` (tarea 18,
/// endurecido en una ronda de revisión anterior): reutiliza sabiduría ya
/// establecida sobre dónde cae un desgarro "de verdad" dentro de una
/// ranura de meta, en vez de inventar un segundo valor sin relación con el
/// primero.
///
/// **Efecto secundario del mismo prefijo sobre la CABECERA, no solo la
/// meta** (hallazgo de la ronda de revisión): 104 es mayor que
/// `header::HEADER_SIZE` (64), así que al caer sobre la reescritura de la
/// cabecera principal que hace `relocate_meta_b` (tarea 18), este mismo
/// prefijo la deposita COMPLETA — sin desgarrar nada de su contenido —
/// aunque `write_at` siga devolviendo `Err`. Es precisamente lo que expuso
/// el hallazgo que corrigió `measure_header_primary_rewrite_ordinal`, más
/// abajo: un fallo de `audit_pages` real, fuera de la ventana vieja de "2
/// últimas escrituras", dentro de la nueva (anclada a esa reescritura de
/// cabecera). Ver también
/// `a_torn_write_of_the_meta_page_with_a_prefix_at_or_above_meta_size_lands_a_full_commit_anyway`.
#[test]
fn tearing_any_write_of_a_transaction_at_two_depths_never_leaks_partial_effects() {
    let total = measure_hundred_put_reference();
    assert!(total > 0);

    let s0 = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db0 = Db::create(Box::new(s0.clone()), Options::default()).unwrap();
    seed(&db0);
    let base = s0.write_count();
    drop(db0);

    let header_primary_ordinal = measure_header_primary_rewrite_ordinal();

    let mut audit_failures = Vec::new();
    for &prefix in &[40usize, 104usize] {
        for n in 0..total {
            let ok = run_one_hundred_put_transaction_under_fault(Fault::TearAt {
                write: base + n + 1,
                bytes: prefix,
            });
            if !ok {
                audit_failures.push(n);
            }
        }
    }
    assert_all_audit_failures_are_within_the_known_window(&audit_failures, header_primary_ordinal, total, "TearAt");
}

// ---------------------------------------------------------------------
// Prueba 2: desgarro dirigido a la escritura de la meta, con verificación
// reforzada de premisa.
// ---------------------------------------------------------------------

/// Comprueba que el desgarro dejó EXACTAMENTE una ranura de meta ilegible y
/// que la OTRA sigue decodificando con el `txn_id` del último commit
/// confirmado — no solo "alguna ranura no lee", que es un guardián más
/// débil, satisfecho por accidente si `s` no está desgarrado en absoluto
/// (dos ranuras válidas con el mismo `txn_id` viejo, por ejemplo). "Una
/// ranura se rompió" es más débil que "la otra sigue teniendo el último
/// commit"; la segunda es la garantía que el diseño de dos ranuras
/// promete de verdad.
///
/// Los offsets se derivan de la cabecera (`geometry`), NO de una lista
/// fija — ver el comentario de cabecera de este fichero, sección de la
/// ronda de revisión, y
/// `the_meta_tear_guard_is_not_satisfied_by_an_ordinary_healthy_database_past_relocation`
/// para el caso vacío exacto que esto corrige.
fn assert_meta_tear_left_the_previous_commit_recoverable(s: &FaultStorage, expected_txn_id: u64) {
    let g = geometry(s);
    let offsets = [
        g.meta_a_page as u64 * g.page_size as u64,
        g.meta_b_page as u64 * g.page_size as u64,
    ];
    let mut torn = 0u32;
    let mut survivor_txn_id = None;
    for &offset in &offsets {
        let mut buf = vec![0u8; g.page_size as usize];
        s.read_at(offset, &mut buf).unwrap();
        match Meta::decode(&buf) {
            Ok(m) => survivor_txn_id = Some(m.txn_id),
            Err(_) => torn += 1,
        }
    }
    assert_eq!(
        torn, 1,
        "el desgarro deberia dejar EXACTAMENTE una ranura de meta ilegible (offsets {offsets:?}), \
         no {torn}: esta prueba no esta desgarrando lo que cree que desgarra"
    );
    assert_eq!(
        survivor_txn_id,
        Some(expected_txn_id),
        "la ranura de meta superviviente no decodifica con el txn_id del ultimo commit confirmado"
    );
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
/// atrapa antes de llegar a la parte que importa — con el mensaje de error
/// interpolando el `bytes` real usado, no un literal repetido a mano.
#[test]
fn a_torn_write_of_the_meta_page_falls_back_to_the_other_slot() {
    const TORN_PREFIX: usize = 40;

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
    // El txn_id del último commit confirmado ANTES de intentar (y perder)
    // la transacción bajo prueba — lo que la ranura superviviente debe
    // seguir llevando tras el desgarro.
    let expected_txn_id = db.begin_read().txn_id();
    // `TORN_PREFIX` bytes: dentro de `txn_id` (0..8, que SIEMPRE cambia de
    // un commit a otro) y muy por debajo del CRC (108..112,
    // `meta::META_SIZE` = 112), así que el contenido mezclado que queda en
    // el plato jamás puede coincidir por casualidad con lo que el CRC
    // viejo certificaba.
    s.set_fault(Some(Fault::TearAt { write: meta_write, bytes: TORN_PREFIX }));
    let mut tx = db.begin_write().unwrap();
    tx.put(0x01, b"perdida", b"x").unwrap();
    let commit_result = tx.commit();
    assert!(commit_result.is_err(), "un commit cuya meta se desgarra debe reportar el fallo, no ocultarlo");
    drop(db);
    s.set_fault(None);

    // Premisa del propio arnés, reforzada (ver el comentario de la
    // función): no basta con que ALGUNA ranura falle, la OTRA tiene que
    // seguir teniendo el último commit confirmado.
    assert_meta_tear_left_the_previous_commit_recoverable(&s, expected_txn_id);

    let db = Db::open(Box::new(s.clone()), Options::default()).unwrap();
    assert_is_the_committed_state(&db);
    assert_eq!(db.begin_read().get(0x01, b"perdida").unwrap(), None);
    assert!(db.audit_pages().unwrap());
}

/// Regresión directa de la ronda de revisión: reproduce el caso VACÍO
/// exacto que encontró — una base perfectamente SANA, sin ningún fallo
/// armado, que ya cruzó los 4 KB y recicló la posición VIEJA de la meta B
/// (página 2, offset 1024 con `page_size` 512) como página de datos
/// corriente — y confirma dos cosas a la vez:
///
/// 1. Los offsets FIJOS que usaba la primera versión del guardián (512,
///    1024) SÍ habrían reportado "ilegible" en el offset 1024, porque ahí
///    ya no hay una meta en absoluto — confirma que el hueco era real, no
///    hipotético.
/// 2. Los offsets DERIVADOS de la cabecera (`geometry`) no caen en la
///    trampa: las dos ranuras LIVE decodifican perfectamente, así que
///    `assert_meta_tear_left_the_previous_commit_recoverable` ya no puede
///    satisfacerse con una base sana.
#[test]
fn the_meta_tear_guard_is_not_satisfied_by_an_ordinary_healthy_database_past_relocation() {
    let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db = Db::create(Box::new(s.clone()), Options::default()).unwrap();
    // Suficientes puts para cruzar los 4 KB y que la reubicación se
    // confirme de verdad, reciclando la posición vieja de la meta B.
    for batch in 0..20u32 {
        let mut tx = db.begin_write().unwrap();
        for i in 0..10u32 {
            tx.put(0x01, &(batch * 10 + i).to_be_bytes(), &[7u8; 40]).unwrap();
        }
        tx.commit().unwrap();
    }
    assert!(s.len().unwrap() > 4096, "la prueba necesita cruzar los 4 KB para reproducir el caso");
    assert!(db.audit_pages().unwrap(), "la base deberia estar perfectamente sana");

    let g = geometry(&s);
    assert_ne!(
        g.meta_b_page as u64 * g.page_size as u64,
        1024,
        "la reubicacion deberia haber movido ya la meta B fuera de la pagina 2"
    );

    // (1): el offset FIJO viejo (1024) ya no contiene una meta — confirma
    // que el hueco de la primera version era real.
    let mut stale = vec![0u8; g.page_size as usize];
    s.read_at(1024, &mut stale).unwrap();
    assert!(
        Meta::decode(&stale).is_err(),
        "si esto decodificase, el caso vacio de la revision no se habria reproducido aqui"
    );

    // (2): las dos ranuras LIVE, derivadas de la cabecera, SÍ decodifican
    // — el guardian corregido ya no puede confundir esto con un desgarro.
    for &offset in &[g.meta_a_page as u64 * g.page_size as u64, g.meta_b_page as u64 * g.page_size as u64] {
        let mut buf = vec![0u8; g.page_size as usize];
        s.read_at(offset, &mut buf).unwrap();
        assert!(
            Meta::decode(&buf).is_ok(),
            "ranura de meta LIVE en offset {offset} deberia decodificar en una base sana"
        );
    }
}

/// Documenta el comportamiento "digno de registrar, no de corregir" que
/// señaló la ronda de revisión: un `Fault::TearAt` cuyo `bytes` es `>=
/// meta::META_SIZE` (112) deposita una ranura de meta COMPLETA y VÁLIDA —
/// el resto de la página física ya era relleno a cero en ambos lados, así
/// que un prefijo así de largo no desgarra nada de contenido real — pero
/// `write_at` sigue devolviendo `Err` (así lo define `Fault::TearAt`: "falla
/// a partir de ahí", ver `storage.rs`). El resultado es que el COMMIT
/// QUEDA DURADERO DE VERDAD (la clave nueva es recuperable tras reabrir)
/// aunque `tx.commit()` haya devuelto `Err` — comportamiento correcto (los
/// bytes llegaron), pero sorprendente para quien solo mire el `Result` de
/// `commit()`. Ver también el comentario de `Fault::TearAt` en
/// `storage.rs`.
#[test]
fn a_torn_write_of_the_meta_page_with_a_prefix_at_or_above_meta_size_lands_a_full_commit_anyway() {
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
    s.set_fault(Some(Fault::TearAt { write: meta_write, bytes: 256 }));
    let mut tx = db.begin_write().unwrap();
    tx.put(0x01, b"perdida", b"x").unwrap();
    let commit_result = tx.commit();
    assert!(commit_result.is_err(), "write_at devuelve Err por definicion de Fault::TearAt");
    drop(db);
    s.set_fault(None);

    let db = Db::open(Box::new(s.clone()), Options::default()).unwrap();
    // Solo `seed` — no `assert_is_the_committed_state`: a diferencia de la
    // prueba hermana con un desgarro genuino, aquí "perdida" SÍ sobrevive a
    // propósito (ver más abajo), así que la comprobación de "diez y ni una
    // más" de aquella no aplica.
    assert_seed_is_intact(&db);
    // A diferencia de un desgarro real (prefijo < META_SIZE): la clave SÍ
    // sobrevive, porque el prefijo de 256 bytes ya cubría los 112 bytes
    // utiles de la meta — el commit quedo duradero pese al `Err`.
    assert_eq!(
        db.begin_read().get(0x01, b"perdida").unwrap().as_deref(),
        Some(b"x".as_slice()),
        "con bytes >= META_SIZE el commit deberia quedar duradero pese a que commit() devolvio Err"
    );
    assert!(db.audit_pages().unwrap());
}

// ---------------------------------------------------------------------
// Prueba 3: sincronización relajada bajo un corte real, barrido exhaustivo.
// ---------------------------------------------------------------------

/// Ejecuta `seed` + `n` transacciones relajadas (`Sync::Never`) de
/// referencia sobre un medio aparte, sin ningún fallo armado, y devuelve:
/// el total de escrituras físicas, y — si alguna de las `n` transacciones
/// disparó `relocate_meta_b` (tarea 18) — el rango de escrituras
/// `[antes, despues)` de ESA transacción concreta, en ordinal RELATIVO a
/// justo-después-de-`seed`.
///
/// Se detecta comparando `meta_b_page` de la cabecera antes y después de
/// cada una de las `n` transacciones: es la única reescritura de cabecera
/// que existe en este motor (`Geometry::write`/`write_mirror`, solo desde
/// `relocate_meta_b`), así que un cambio ahí ES la reubicación — no hace
/// falta adivinar por tamaño de fichero ni por cercanía al final de la
/// secuencia, que es precisamente lo que dejaba la ventana anterior
/// (ver el comentario de cabecera de este fichero) anclada al evento
/// equivocado.
fn measure_relaxed_reference(n: u32, opts: Options) -> (u64, Option<(u64, u64)>) {
    let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db = Db::create(Box::new(s.clone()), opts).unwrap();
    seed(&db);
    let base = s.write_count();
    let mut meta_b_page = geometry(&s).meta_b_page;
    let mut relocating_window = None;
    for i in 0..n {
        let before = s.write_count() - base;
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, &(1000 + i).to_be_bytes(), b"relajado").unwrap();
        tx.commit().unwrap();
        let after = s.write_count() - base;
        let new_meta_b_page = geometry(&s).meta_b_page;
        if relocating_window.is_none() && new_meta_b_page != meta_b_page {
            relocating_window = Some((before, after));
        }
        meta_b_page = new_meta_b_page;
    }
    (s.write_count() - base, relocating_window)
}

/// La sincronización relajada (`Sync::Never`) puede perder commits enteros
/// tras un corte — es la garantía que ofrece, no un defecto — pero nunca
/// debe dejar el fichero corrupto: ni una página huérfana o con dos dueños
/// (`audit_pages`), ni un hueco en medio de la secuencia de commits (una
/// clave posterior presente sin que todas las anteriores también lo
/// estén, que delataría un commit aplicado a medias).
///
/// **A diferencia del brief**: la versión original de esta prueba reabría
/// sin haber armado NINGÚN fallo — con `FaultStorage` respaldado por
/// `MemStorage`, que no tiene búfer de sistema operativo que perder, eso
/// significa que las 50 transacciones sobreviven siempre enteras, y "puede
/// perder commits" queda sin ejercitar: pasaría igual si `commit` nunca
/// sincronizara nada en absoluto. Esta versión SÍ corta la corriente —
/// `Fault::AbortAt` en un barrido EXHAUSTIVO de la secuencia completa de 50
/// transacciones relajadas, no un muestreo — y comprueba la propiedad de
/// verdad.
///
/// **Ronda de revisión**: la versión anterior muestreaba 25 puntos y
/// toleraba fallos de `audit_pages` solo en las 2 últimas escrituras de
/// TODA la secuencia. Un barrido exhaustivo de los 182 puntos reales
/// encuentra el hueco YA CONOCIDO de `relocate_meta_b` en `n=79` y `n=80`
/// — la transacción que de verdad cruza los 4 KB, muy lejos del final de
/// la secuencia y fuera del muestreo de 25 puntos. Corregido quitando el
/// muestreo (barrido completo) y anclando la tolerancia a la transacción
/// que REALMENTE reubica (`measure_relaxed_reference`), no a la distancia
/// al final.
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

    let (total, relocating_window) = measure_relaxed_reference(N, opts);
    assert!(total > 0);
    // No es obligatorio que ESTE fixture concreto llegue a reubicar (si
    // `seed`/`N`/los tamaños cambiaran, podría no cruzar los 4 KB), pero
    // con los valores actuales sí lo hace — y si algún día deja de
    // hacerlo, `audit_failures` de más abajo simplemente estará vacío y la
    // aserción final no tendrá nada que comprobar.

    let mut audit_failures = Vec::new();
    for n in 0..total {
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
        if !db.audit_pages().unwrap() {
            audit_failures.push(n);
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

    for &n in &audit_failures {
        let write_ord = n + 1;
        let tolerated = relocating_window
            .map(|(_, end)| write_ord == end || write_ord + 1 == end)
            .unwrap_or(false);
        assert!(
            tolerated,
            "auditoria de paginas fallo en la escritura {n} (ordinal {write_ord}) de {total}, \
             fuera de la ventana de relocate_meta_b ({relocating_window:?}): defecto nuevo, no \
             el conocido"
        );
    }
}
