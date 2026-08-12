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
        fn truncate(&self, len: u64) -> inro::Result<()> {
            self.inner.truncate(len)
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

    // La ventana tolerada es la transacción que reubica ENTERA, no sus dos
    // últimas escrituras.
    //
    // **Las "dos últimas" eran otra constante cocinada a mano.** El hueco
    // conocido es este: `relocate_meta_b` reescribe la cabecera y la
    // sincroniza SIN CONDICIONES —así que esa parte queda duradera pase lo
    // que pase— pero quien devuelve la página vieja de la meta B a la
    // lista de libres es el `self.free(...)` del final de esa misma
    // función, y eso solo llega a disco si la transacción CONFIRMA. Un
    // corte en cualquier punto entre la reescritura de cabecera y el final
    // del commit deja la cabecera nueva (meta B ya en su sitio definitivo)
    // y a la página vieja sin dueño: `audit_pages` la ve como fuga.
    // Comprobado en caja blanca durante esta corrección: la única página
    // sin marcar en los tres puntos de corte que fallaban era la 2, la
    // posición inicial de la meta B.
    //
    // Cuántas escrituras hay entre la reescritura de cabecera y el final
    // del commit depende de cuántos contenedores necesite `Freelist::flush`
    // en esa transacción concreta — un número que cambia con cualquier
    // ajuste de la lista de libres o de la política de reciclado. Anclarlo
    // a "las dos últimas" era, por tanto, una foto de una versión concreta
    // del motor: al pasar el suelo de reutilización a la meta durable, esa
    // misma transacción pasó a tener una escritura más y la ventana dejó
    // de encajar. Lo que sí es estable es el hecho estructural — la fuga
    // solo puede aparecer dentro de la transacción que reubica — y eso es
    // lo que se comprueba ahora, con los límites MEDIDOS por
    // `measure_relaxed_reference`, no supuestos.
    for &n in &audit_failures {
        let write_ord = n + 1;
        let tolerated = relocating_window
            .map(|(start, end)| write_ord > start && write_ord <= end)
            .unwrap_or(false);
        assert!(
            tolerated,
            "auditoria de paginas fallo en la escritura {n} (ordinal {write_ord}) de {total}, \
             fuera de la transaccion que reubica la meta B ({relocating_window:?}): defecto \
             nuevo, no el conocido"
        );
    }
}

// ---------------------------------------------------------------------
// Prueba 6: corte de corriente CON escrituras sin sincronizar (el único
// escenario en el que vive la sincronización relajada).
// ---------------------------------------------------------------------

/// Una operación emitida contra el medio, con su ordinal global.
///
/// **Dos variantes, no una** (recuperación de la cola libre): hasta que
/// existió `Storage::truncate`, toda operación que cambiaba el medio era una
/// escritura, y bastaba con guardar `(offset, bytes)`. Un recorte no es una
/// escritura: no deposita bytes, hace desaparecer los que había del final. Si
/// el arnés lo dejara pasar directamente a `inner` sin registrarlo, el corte
/// de corriente NO PODRÍA perderlo — y perderlo es exactamente el caso que
/// hay que probar, porque el recorte es lo último que hace `reclaim_tail` y
/// por tanto lo primero que un corte se lleva. Registrado aquí, `cut` decide
/// si llegó al plato igual que con cualquier escritura.
enum PendingOp {
    Write { ordinal: u64, offset: u64, bytes: Vec<u8> },
    Truncate { ordinal: u64, len: u64 },
}

impl PendingOp {
    fn ordinal(&self) -> u64 {
        match self {
            PendingOp::Write { ordinal, .. } | PendingOp::Truncate { ordinal, .. } => *ordinal,
        }
    }
}

/// Medio que modela un corte de corriente DE VERDAD: `sync()` marca un
/// punto de durabilidad y `cut` descarta un subconjunto ARBITRARIO de las
/// escrituras emitidas desde ese punto.
///
/// **Por qué hace falta un tercer arné, habiendo ya dos.** Ninguno de los
/// dos que ya existían puede expresar la única condición en la que vive la
/// sincronización relajada — "escrito pero todavía no sincronizado":
///
/// - `FaultStorage` (`src/storage.rs`, usado por todo el resto de este
///   fichero) tiene un `sync()` que es un no-op y un `Fault::AbortAt` que
///   deja DURADERA toda escritura anterior al punto de corte. Su modelo es
///   "el proceso murió": las escrituras se pierden en sufijo, nunca de
///   forma desordenada. Bajo él, `Sync::Never` y `Sync::Commit` se
///   comportan exactamente igual — de hecho
///   `relaxed_sync_loses_commits_but_never_corrupts` (arriba) PASA sin
///   tocar nada si se le cambia `Sync::Never` por `Sync::Commit`, que es
///   la señal de que la política de sincronización no entra en lo que esa
///   prueba mide.
/// - `tx::tests::PowerLossStorage` sí modela la pérdida de lo no
///   sincronizado, pero solo para las ranuras de meta y de cabecera, cuyos
///   offsets lleva CODIFICADOS A MANO — y su prueba nunca vuelve a leer
///   ninguna clave después de reabrir, así que no puede detectar que el
///   árbol que la meta superviviente describe se haya quedado sin páginas.
///
/// Este combina las dos mitades y no codifica ningún offset: no sabe —ni
/// necesita saber— qué escritura es una meta, cuál una página de árbol y
/// cuál una de lista de libres. Solo sabe lo que el contrato de `Storage`
/// promete de verdad (ver el trait): tras un `sync()` correcto, lo escrito
/// hasta ese momento está en el medio; de lo escrito DESPUÉS, nada está
/// prometido.
struct PowerCutStorage {
    inner: MemStorage,
    /// Contenido del medio tal como quedaría si la corriente se fuera
    /// ahora mismo y no sobreviviera ninguna escritura pendiente: la foto
    /// del último `sync()` correcto.
    durable: Mutex<Vec<u8>>,
    /// Operaciones emitidas desde ese `sync()`, en orden.
    pending: Mutex<Vec<PendingOp>>,
    writes: std::sync::atomic::AtomicU64,
    syncs: std::sync::atomic::AtomicU64,
    /// Ordinales de las operaciones que fueron un RECORTE, en toda la vida
    /// del medio — a diferencia de `pending`, esto no lo borra ningún
    /// `sync()`. Es lo que deja a una prueba decir "el cambio de tamaño sí
    /// llegó al plato, lo demás no" sin codificar a mano en qué posición de
    /// la secuencia cae el recorte: se MIDE, igual que `Acked::last_write`
    /// mide dónde acaba cada commit.
    truncations: Mutex<Vec<u64>>,
}

impl PowerCutStorage {
    fn new() -> Self {
        Self {
            inner: MemStorage::new(),
            durable: Mutex::new(Vec::new()),
            pending: Mutex::new(Vec::new()),
            writes: std::sync::atomic::AtomicU64::new(0),
            syncs: std::sync::atomic::AtomicU64::new(0),
            truncations: Mutex::new(Vec::new()),
        }
    }

    /// Ordinales de todos los recortes emitidos hasta ahora.
    fn truncations(&self) -> Vec<u64> {
        self.truncations.lock().unwrap().clone()
    }

    /// Ordinal de la última escritura emitida (1 en adelante). La prueba lo
    /// consulta tras cada `commit` para saber DÓNDE acaba ese commit en la
    /// secuencia física, sin necesitar saber qué contiene esa escritura.
    fn writes(&self) -> u64 {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `fsync` emitidos contra el medio desde su creación. Es la medida de
    /// coste de la sincronización bajo demanda que la recuperación de
    /// espacio necesita (ver el informe de esta tarea).
    fn syncs(&self) -> u64 {
        self.syncs.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Corta la corriente: de las operaciones emitidas desde el último
    /// `sync()`, sobreviven exactamente aquellas cuyo ordinal acepta
    /// `keep`; el resto no llegó nunca al plato. Tras esto, el medio
    /// contiene un estado que un `Db::open` real podría encontrarse.
    ///
    /// Se reproducen EN ORDEN, escrituras y recortes mezclados: un recorte
    /// que sobrevive acorta la imagen, y una escritura posterior que
    /// también sobreviva vuelve a extenderla — igual que en un fichero de
    /// verdad. Reproducir solo las escrituras y aplicar los recortes al
    /// final (o al revés) inventaría estados que ningún disco produce.
    fn cut(&self, keep: &mut dyn FnMut(u64) -> bool) {
        let mut image = self.durable.lock().unwrap().clone();
        let mut pending = self.pending.lock().unwrap();
        for op in pending.iter() {
            if !keep(op.ordinal()) {
                continue;
            }
            match op {
                PendingOp::Write { offset, bytes, .. } => {
                    let start = *offset as usize;
                    let end = start + bytes.len();
                    if image.len() < end {
                        image.resize(end, 0);
                    }
                    image[start..end].copy_from_slice(bytes);
                }
                PendingOp::Truncate { len, .. } => {
                    let len = *len as usize;
                    if len < image.len() {
                        image.truncate(len);
                    }
                }
            }
        }
        pending.clear();
        self.inner.restore(image.clone());
        *self.durable.lock().unwrap() = image;
    }
}

impl Storage for PowerCutStorage {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> inro::Result<()> {
        self.inner.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> inro::Result<()> {
        let ordinal = self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.pending.lock().unwrap().push(PendingOp::Write {
            ordinal,
            offset,
            bytes: buf.to_vec(),
        });
        self.inner.write_at(offset, buf)
    }

    fn sync(&self) -> inro::Result<()> {
        self.inner.sync()?;
        // El orden importa: primero se congela la foto, y solo entonces se
        // olvidan las pendientes. Al revés, un corte concurrente vería un
        // instante sin ninguna de las dos cosas.
        *self.durable.lock().unwrap() = self.inner.snapshot();
        self.pending.lock().unwrap().clear();
        self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn len(&self) -> inro::Result<u64> {
        self.inner.len()
    }

    /// Consume un ordinal de la MISMA secuencia que las escrituras (igual
    /// que `FaultStorage::truncate`, ver su comentario en `storage.rs`): así
    /// una prueba puede decir "pierde la operación número N" sin saber si N
    /// es una página, una meta o el recorte.
    fn truncate(&self, len: u64) -> inro::Result<()> {
        let ordinal = self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.truncations.lock().unwrap().push(ordinal);
        self.pending.lock().unwrap().push(PendingOp::Truncate { ordinal, len });
        self.inner.truncate(len)
    }
}

/// Generador determinista para elegir subconjuntos de escrituras
/// supervivientes: xorshift64*, tres líneas, sin dependencias nuevas. La
/// semilla viaja en el mensaje de fallo, así que cualquier corrida que
/// falle se reproduce tal cual.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// `true` con probabilidad `percent`/100.
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// Un commit confirmado y reconocido al llamante: su `txn_id` y la clave
/// que escribió.
struct Acked {
    txn: u64,
    key: u32,
    /// Ordinal de la ÚLTIMA escritura física de ese commit. Medido, no
    /// supuesto: la prueba no sabe qué es esa escritura, solo que después
    /// de ella `commit()` ya devolvió `Ok` (ver el comentario de cabecera
    /// de este fichero sobre por qué la meta es siempre la última).
    last_write: u64,
}

/// Confirma `commits` transacciones de una clave cada una contra un medio
/// que va registrando lo pendiente de sincronizar, y devuelve el registro
/// de lo que el motor RECONOCIÓ como confirmado.
fn commit_acknowledged_keys(s: &Arc<PowerCutStorage>, opts: Options, commits: u32) -> Vec<Acked> {
    let db = Db::create(Box::new(Arc::clone(s)), opts).unwrap();
    let mut acked = Vec::new();
    for key in 0..commits {
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, &key.to_be_bytes(), b"confirmado").unwrap();
        let txn = tx.txn_id();
        tx.commit().unwrap();
        acked.push(Acked { txn, key, last_write: s.writes() });
    }
    drop(db);
    acked
}

/// Reabre tras el corte y comprueba la única propiedad que un motor
/// copy-on-write con dos ranuras de meta puede y debe garantizar sea cual
/// sea la política de sincronización: **lo que sobrevive es un SNAPSHOT
/// ENTERO**. Si la base reabierta dice estar en la transacción `T`, tienen
/// que estar TODAS las claves de los commits con `txn <= T` y NINGUNA de
/// los posteriores. Perder commits está permitido (es lo que la
/// sincronización relajada compra); devolver medio commit, o el árbol de
/// `T` con páginas ya reescritas por un commit posterior, no.
fn assert_the_surviving_state_is_a_whole_snapshot(
    s: &Arc<PowerCutStorage>,
    opts: Options,
    acked: &[Acked],
    scenario: &str,
) -> u64 {
    let db = Db::open(Box::new(Arc::clone(s)), opts)
        .unwrap_or_else(|e| panic!("{scenario}: reabrir tras el corte falló con {e:?}"));
    let r = db.begin_read();
    let survived = r.txn_id();
    for a in acked {
        let got = r.get(0x01, &a.key.to_be_bytes()).unwrap();
        if a.txn <= survived {
            assert_eq!(
                got.as_deref(),
                Some(b"confirmado".as_slice()),
                "{scenario}: la base reabierta dice estar en la transaccion {survived}, pero la \
                 clave {} —confirmada y reconocida en la transaccion {}, {} commits antes— ya no \
                 esta: el snapshot superviviente no esta entero",
                a.key,
                a.txn,
                survived.saturating_sub(a.txn)
            );
        } else {
            assert_eq!(
                got, None,
                "{scenario}: la base reabierta dice estar en la transaccion {survived} pero \
                 devuelve la clave {}, escrita {} commits DESPUES: eso no es ningun estado que \
                 este motor haya confirmado jamas",
                a.key,
                a.txn - survived
            );
        }
    }
    // Y ninguna clave de más: `get` solo mira las que la prueba conoce.
    let mut c = r.scan(0x01, b"", b"\xff\xff\xff\xff").unwrap();
    let mut seen = 0u32;
    while c.next().unwrap().is_some() {
        seen += 1;
    }
    let expected = acked.iter().filter(|a| a.txn <= survived).count() as u32;
    assert_eq!(
        seen, expected,
        "{scenario}: el espacio 0x01 tiene {seen} claves tras reabrir en la transaccion \
         {survived}, no las {expected} de los commits <= {survived}"
    );
    drop(r);
    assert!(
        db.audit_pages().unwrap(),
        "{scenario}: la contabilidad de paginas no cuadra tras reabrir"
    );
    survived
}

/// El defecto, en su forma más nítida: **las escrituras de datos llegan al
/// plato, las últimas metas no.**
///
/// Es el caso clásico de un corte de corriente con caché de escritura: las
/// páginas de árbol se emiten antes y son muchas; la meta es una escritura
/// de 512 B emitida al final de cada commit y es justo la que se queda en
/// la caché volátil. `tx::tests::PowerLossStorage` modela exactamente esto
/// —revierte solo las ranuras de meta— pero con los offsets codificados a
/// mano y sin volver a leer ninguna clave. Aquí las metas se identifican
/// MIDIENDO (`Acked::last_write`: el ordinal de la última escritura de
/// cada commit reconocido), no por su posición en el fichero.
///
/// Con las metas posteriores al último `sync()` descartadas, `Meta::load`
/// no tiene más remedio que montar por la última meta DURADERA — y el
/// árbol de esa meta tiene que seguir entero, porque ninguna transacción
/// posterior tenía derecho a reescribir ni una de sus páginas.
#[test]
fn a_power_cut_that_keeps_data_pages_but_loses_the_last_metas_leaves_a_whole_snapshot() {
    let opts = Options { sync: Sync::Never, ..Options::default() };
    let s = Arc::new(PowerCutStorage::new());
    let acked = commit_acknowledged_keys(&s, opts, 60);
    let metas: std::collections::BTreeSet<u64> = acked.iter().map(|a| a.last_write).collect();

    s.cut(&mut |ordinal| !metas.contains(&ordinal));

    let survived = assert_the_surviving_state_is_a_whole_snapshot(
        &s,
        opts,
        &acked,
        "corte que conserva las paginas de datos y pierde las metas",
    );
    assert!(
        survived < acked.last().unwrap().txn,
        "el corte no llegó a perder ningún commit: la prueba no está ejercitando nada"
    );
}

/// El mismo corte, pero descartando además un subconjunto ARBITRARIO de las
/// escrituras que no son la última de su commit. Un disco real no pierde
/// las escrituras en orden: lo que quede en la caché volátil cuando se va
/// la corriente es cualquier cosa. Diez semillas deterministas.
///
/// Las metas siguen descartándose siempre, y no por comodidad: es lo que
/// mantiene la afirmación JUSTA. Si una meta posterior sobreviviera sin
/// que sobrevivieran las páginas que su árbol referencia, el motor
/// devolvería basura sin tener ninguna forma de evitarlo — bajo
/// sincronización relajada nadie promete que la meta llegue después que sus
/// páginas, y esa es una limitación del MODO, no un defecto del motor (ver
/// el informe: es la razón de que `Sync::Interval` no pueda prometer
/// "nunca corrompe" sin más matices). Descartando todas las metas no
/// duraderas, la que monta es siempre una que ya estaba en disco antes del
/// último `sync()`, y de esa sí se puede exigir el árbol entero.
#[test]
fn a_power_cut_that_loses_an_arbitrary_subset_of_the_unsynced_writes_leaves_a_whole_snapshot() {
    let opts = Options { sync: Sync::Never, ..Options::default() };
    for seed in 1..=10u64 {
        let s = Arc::new(PowerCutStorage::new());
        let acked = commit_acknowledged_keys(&s, opts, 60);
        let metas: std::collections::BTreeSet<u64> = acked.iter().map(|a| a.last_write).collect();

        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        s.cut(&mut |ordinal| !metas.contains(&ordinal) && rng.chance(90));

        assert_the_surviving_state_is_a_whole_snapshot(
            &s,
            opts,
            &acked,
            &format!("corte aleatorio con semilla {seed}"),
        );
    }
}

/// Guardián de premisa, del mismo tipo que
/// `the_meta_tear_guard_is_not_satisfied_by_an_ordinary_healthy_database_past_relocation`
/// (arriba): esta sección solo prueba algo si la política de sincronización
/// entra de verdad en el resultado.
///
/// **Falla si alguien cambia `Sync::Never` por `Sync::Commit`.** Bajo
/// `Sync::Commit` cada commit sincroniza después de escribir su meta, así
/// que al llegar el corte no hay NADA pendiente que perder y la base
/// reabre en el último commit reconocido; el arné entero quedaría
/// midiendo el vacío, que es exactamente lo que le pasaba a
/// `relaxed_sync_loses_commits_but_never_corrupts` (ver el comentario de
/// `PowerCutStorage`).
#[test]
fn the_power_cut_harness_only_says_anything_because_sync_is_relaxed() {
    let s = Arc::new(PowerCutStorage::new());
    let strict = Options { sync: Sync::Commit, ..Options::default() };
    let acked = commit_acknowledged_keys(&s, strict, 60);
    let metas: std::collections::BTreeSet<u64> = acked.iter().map(|a| a.last_write).collect();
    s.cut(&mut |ordinal| !metas.contains(&ordinal));
    let db = Db::open(Box::new(Arc::clone(&s)), strict).unwrap();
    assert_eq!(
        db.begin_read().txn_id(),
        acked.last().unwrap().txn,
        "bajo Sync::Commit el corte no puede perder nada: si esta prueba falla, alguien ha \
         hecho que Sync::Commit deje commits sin sincronizar"
    );
    drop(db);

    let s = Arc::new(PowerCutStorage::new());
    let relaxed = Options { sync: Sync::Never, ..Options::default() };
    let acked = commit_acknowledged_keys(&s, relaxed, 60);
    let metas: std::collections::BTreeSet<u64> = acked.iter().map(|a| a.last_write).collect();
    s.cut(&mut |ordinal| !metas.contains(&ordinal));
    let db = Db::open(Box::new(Arc::clone(&s)), relaxed).unwrap();
    assert!(
        db.begin_read().txn_id() < acked.last().unwrap().txn,
        "bajo Sync::Never el corte TIENE que perder commits reconocidos: si no los pierde, este \
         arné no está ejercitando la sincronización relajada y todo lo que esta sección afirma \
         pasaría igual con Sync::Commit"
    );
}

/// Coste MEDIDO de la sincronización relajada tras la corrección, y su
/// cota. Es la contrapartida de `Db::durable`: gatear el reciclado por la
/// meta durable obliga a retener las páginas liberadas desde el último
/// `fsync`, así que el fichero ocupa más y hay que comprobar CUÁNTO más.
///
/// Carga de churn: 2 000 commits sobre 200 claves, `page_size` 512. El
/// conjunto vivo es constante, así que un motor que recicle bien deja el
/// fichero plano — cualquier crecimiento que dependa del número de
/// commits sale aquí.
///
/// Cifras medidas al escribir esta prueba (las cotas de abajo dejan
/// margen sobre ellas):
///
/// | modo                          | páginas | escrituras | `fsync` |
/// |-------------------------------|---------|-----------:|--------:|
/// | `Sync::Commit`                |      24 |      7 996 |   4 004 |
/// | `Sync::Never`                 |      84 |      9 845 |     128 |
///
/// Es decir: 60 páginas de más (30 KB), CONSTANTES —con 1 000, 2 000,
/// 4 000 y 8 000 commits el fichero se queda en 84 páginas—, un 23 % más
/// de escrituras físicas, y un `fsync` cada ~16 commits en vez de dos por
/// commit: 31 veces menos. Ver el informe de esta tarea para el detalle y
/// para las cifras sin la fusión de grupos de `Freelist::flush`, que era
/// lo que hacía el retraso cuadrático.
#[test]
fn relaxed_sync_costs_bounded_space_and_far_fewer_fsyncs() {
    fn run(sync: Sync, commits: u32) -> (u64, u64, u64) {
        let s = Arc::new(PowerCutStorage::new());
        let opts = Options { sync, ..Options::default() };
        let db = Db::create(Box::new(Arc::clone(&s)), opts).unwrap();
        for i in 0..commits {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &(i % 200).to_be_bytes(), b"valor-de-prueba").unwrap();
            tx.commit().unwrap();
        }
        assert!(db.audit_pages().unwrap(), "la contabilidad de paginas no cuadra");
        (s.len().unwrap() / 512, s.writes(), s.syncs())
    }

    let (strict_pages, strict_writes, strict_syncs) = run(Sync::Commit, 2000);
    let (pages, writes, syncs) = run(Sync::Never, 2000);

    assert_eq!(strict_syncs, 2 * 2000 + 4, "Sync::Commit debe sincronizar dos veces por commit");
    assert!(
        pages <= strict_pages + 128,
        "sincronización relajada: {pages} páginas frente a {strict_pages} con Sync::Commit — el          margen por retener lo liberado desde el último fsync debe estar acotado por          MAX_DURABLE_LAG, no crecer con el número de commits"
    );
    assert!(
        writes <= strict_writes * 3 / 2,
        "sincronización relajada: {writes} escrituras físicas frente a {strict_writes}"
    );
    assert!(
        syncs * 15 <= strict_syncs,
        "sincronización relajada: {syncs} fsync frente a {strict_syncs} — el ahorro tiene que          seguir siendo de al menos un orden de magnitud, o el modo no sirve para lo que existe"
    );

    // Plano: cuatro veces más commits, el mismo fichero. Es la propiedad
    // que de verdad importa (crecimiento acotado, no proporcional al
    // trabajo), y la que un `MAX_DURABLE_LAG` mal puesto rompe.
    let (long_pages, _, _) = run(Sync::Never, 8000);
    assert_eq!(
        long_pages, pages,
        "con cuatro veces más commits sobre las mismas claves el fichero no debe crecer"
    );
}

// ---------------------------------------------------------------------
// Prueba 7: recuperación de la cola libre del fichero (`Db::reclaim_tail`).
//
// Un recorte es una escritura de una clase que ninguno de los dos arneses
// modelaba: no deposita bytes, hace desaparecer los que había. Los dos se
// han extendido para poder perderlo o conservarlo como cualquier otra
// operación —`FaultStorage::truncate` consume un ordinal de la misma
// secuencia que las escrituras, `PowerCutStorage` lo registra como
// `PendingOp::Truncate`— así que las dos preguntas de este fichero siguen
// pudiendo hacerse sobre él sin codificar a mano dónde cae.
//
// La propiedad que se exige es la misma de siempre, y no se relaja ni un
// milímetro por el hecho de que ahora el fichero pueda encoger: **toda
// clave que el motor reconoció como confirmada tiene que seguir ahí tras
// reabrir**, muera el proceso donde muera.
// ---------------------------------------------------------------------

/// Carga que deja el fichero con una cola libre que devolver: lastre
/// escrito y borrado en `0x02`, que es lo que crea el espacio muerto, más
/// las claves de verdad en `0x01`.
fn ballast(db: &Db, n: u32, batch: usize) {
    for chunk in (0..n).collect::<Vec<_>>().chunks(batch) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            tx.put(0x02, &i.to_be_bytes(), &[9u8; 40]).unwrap();
        }
        tx.commit().unwrap();
    }
    for chunk in (0..n).collect::<Vec<_>>().chunks(batch) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            tx.delete(0x02, &i.to_be_bytes()).unwrap();
        }
        tx.commit().unwrap();
    }
}

/// Deja una base con `keys` claves confirmadas en `0x01` y una cola libre
/// bien gorda, y devuelve el fichero listo para que la llame `reclaim_tail`.
fn seeded_with_dead_tail(s: &Arc<FaultStorage>, opts: Options, keys: u32) -> Db {
    let db = Db::create(Box::new(Arc::clone(s)), opts).unwrap();
    let mut tx = db.begin_write().unwrap();
    for i in 0..keys {
        tx.put(0x01, &i.to_be_bytes(), b"confirmado").unwrap();
    }
    tx.commit().unwrap();
    ballast(&db, 400, 100);
    db
}

/// Cuántas operaciones físicas emite un `reclaim_tail` de referencia sobre
/// esta carga, y a partir de qué ordinal. **Medido, no supuesto**: el
/// número de páginas de cadena que hay que reescribir, cuántas pasadas
/// hacen falta y en qué posición cae el recorte dependen de la forma que
/// tenga la lista de libres, y codificar cualquiera de esas cosas a mano
/// es el error que este proyecto ya ha cometido seis veces. La corrida de
/// referencia usa un medio aparte, sin ningún fallo armado.
fn measure_reclaim_reference(opts: Options, keys: u32) -> (u64, u64) {
    let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
    let db = seeded_with_dead_tail(&s, opts, keys);
    let first = s.write_count() + 1;
    let freed = db.reclaim_tail().unwrap();
    assert!(freed > 0, "la carga de referencia no libera nada: no habría nada que cortar");
    (first, s.write_count())
}

/// **El barrido de cortes del recorte.** Para CADA operación física que
/// emite un `reclaim_tail` —páginas de lista de libres, las dos ranuras de
/// meta y el recorte en sí—, mata el proceso justo ahí y en todas las
/// posteriores (`Fault::AbortAt`), reabre y exige que la base siga entera.
///
/// Es el barrido que decide si el orden del recorte es correcto. Con el
/// orden invertido —recortar antes de que la meta con el `n_pages`
/// reducido esté sincronizada— el corte en el punto intermedio deja una
/// meta superviviente que declara más páginas de las que el fichero tiene:
/// su raíz y su cadena de libres apuntan más allá del final, y `Db::open`
/// falla con `UnexpectedEof` (que, a diferencia de `Corrupt`, no se degrada
/// con gracia) o `audit_pages` denuncia el desajuste. Ver el informe de
/// esta tarea para la salida exacta de esa corrida.
#[test]
fn aborting_at_any_operation_of_a_reclaim_leaves_the_database_readable() {
    const KEYS: u32 = 40;
    let opts = Options::default();
    let (first, last) = measure_reclaim_reference(opts, KEYS);
    assert!(last >= first, "el recorte de referencia no emitió ninguna operación");

    for n in first..=last {
        let s = Arc::new(FaultStorage::new(MemStorage::new(), None));
        let db = seeded_with_dead_tail(&s, opts, KEYS);
        s.set_fault(Some(Fault::AbortAt(n)));
        // Puede fallar o no: si el corte cae después del último recorte
        // efectivo, `reclaim_tail` termina bien. Lo que importa es lo que
        // queda en el medio, no lo que devuelve.
        let _ = db.reclaim_tail();
        drop(db);

        s.set_fault(None);
        let db = Db::open(Box::new(Arc::clone(&s)), opts)
            .unwrap_or_else(|e| panic!("corte en la operación {n}: reabrir falló con {e:?}"));
        let r = db.begin_read();
        for i in 0..KEYS {
            assert_eq!(
                r.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
                Some(b"confirmado".as_slice()),
                "corte en la operación {n}: la clave {i}, confirmada mucho antes del recorte, \
                 ya no está"
            );
        }
        assert_eq!(
            r.get(0x02, &0u32.to_be_bytes()).unwrap(),
            None,
            "corte en la operación {n}: reapareció lastre ya borrado"
        );
        drop(r);
        assert!(
            db.audit_pages().unwrap(),
            "corte en la operación {n}: la contabilidad de páginas no cuadra tras reabrir"
        );
        // Y la base sigue siendo escribible: si el recorte hubiera dejado
        // la lista de libres con entradas más allá del final del fichero,
        // el primer `alloc` que las sirviera escribiría fuera.
        let mut tx = db.begin_write().unwrap();
        for i in 0..20u32 {
            tx.put(0x03, &i.to_be_bytes(), &[3u8; 60]).unwrap();
        }
        tx.commit().unwrap();
        assert!(
            db.audit_pages().unwrap(),
            "corte en la operación {n}: escribir tras reabrir rompe la contabilidad"
        );
    }
}

/// Prepara, sobre un medio que registra lo pendiente de sincronizar, una
/// base que: confirma lastre, lo borra, DEVUELVE LA COLA con
/// `reclaim_tail`, y después sigue confirmando claves con normalidad sobre
/// el espacio recién recuperado. Devuelve el registro de lo reconocido.
fn commit_reclaim_then_commit_more(
    s: &Arc<PowerCutStorage>,
    opts: Options,
    before: u32,
    after: u32,
) -> Vec<Acked> {
    let db = Db::create(Box::new(Arc::clone(s)), opts).unwrap();
    let mut acked = Vec::new();
    for key in 0..before {
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, &key.to_be_bytes(), b"confirmado").unwrap();
        let txn = tx.txn_id();
        tx.commit().unwrap();
        acked.push(Acked { txn, key, last_write: s.writes() });
    }
    // Lotes de 10, no de 100: 80 commits de lastre bastan para que el
    // motor pague por su cuenta el `fsync` de recuperación de espacio
    // (`MAX_DURABLE_LAG`), así que la foto duradera con la que trabaja el
    // corte es un fichero GRANDE con una meta que declara muchas páginas
    // — el único estado desde el que un recorte mal ordenado hace daño. Con
    // lotes grandes el retraso nunca llega a 16, la foto duradera se queda
    // en la base recién creada, y un corte que lo tirase todo caería en un
    // estado vacío pero coherente: la prueba pasaría sin haber mirado nada.
    ballast(&db, 400, 10);
    let before_pages = s.len().unwrap() / 512;
    let freed = db.reclaim_tail().unwrap();
    assert!(
        freed > 0 && s.len().unwrap() / 512 < before_pages,
        "el recorte no devolvió nada: esta prueba no estaría ejercitando nada"
    );
    for key in before..before + after {
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, &key.to_be_bytes(), b"confirmado").unwrap();
        let txn = tx.txn_id();
        tx.commit().unwrap();
        acked.push(Acked { txn, key, last_write: s.writes() });
    }
    drop(db);
    acked
}

/// **El corte que se lleva todo lo no sincronizado pero deja el recorte.**
/// Es el reparto más hostil que un disco real puede hacer con esta
/// operación: el cambio de tamaño llega al plato y las escrituras que lo
/// preceden se quedan en la caché volátil.
///
/// Para el motor tal como está, `keep` no puede quitar ninguna de las
/// escrituras del propio recorte: están sincronizadas antes de que el
/// recorte se emita, así que ya forman parte de la foto duradera y el
/// corte no las alcanza. Eso es exactamente lo que esta prueba comprueba —
/// que el orden hace inalcanzable el estado malo—, y por eso NO es una
/// tautología: si las dos sincronizaciones de `commit_maybe_shrinking`
/// desaparecieran (o pasaran a ser `maybe_sync`, que bajo `Sync::Never` no
/// sincroniza nada), esas escrituras seguirían pendientes, este mismo
/// `keep` las tiraría, y lo que quedaría en el medio sería una meta con el
/// `n_pages` de antes del recorte sobre un fichero ya recortado.
#[test]
fn a_power_cut_that_keeps_only_the_truncate_leaves_a_whole_snapshot() {
    let opts = Options { sync: Sync::Never, ..Options::default() };
    let s = Arc::new(PowerCutStorage::new());
    // CERO commits después del recorte, y es lo que da filo a la prueba: el
    // corte cae en la ventana que va del recorte al siguiente `fsync`. Con
    // commits de por medio, el `fsync` de recuperación de espacio
    // (`MAX_DURABLE_LAG`) acabaría congelando por su cuenta una foto ya
    // recortada y coherente, y el corte no tendría nada que romper ni en un
    // motor que recortara antes de sincronizar.
    let acked = commit_reclaim_then_commit_more(&s, opts, 20, 0);
    let truncations = s.truncations();
    assert!(!truncations.is_empty(), "el arnés no registró ningún recorte");

    s.cut(&mut |ordinal| truncations.contains(&ordinal));

    assert_the_surviving_state_is_a_whole_snapshot(
        &s,
        opts,
        &acked,
        "corte que conserva el recorte y pierde todo lo no sincronizado",
    );
}

/// El mismo escenario con el reparto ALEATORIO que ya usa la prueba 6:
/// diez semillas, cada una tirando un subconjunto arbitrario de lo
/// pendiente. Aquí sí hay commits de verdad en vuelo —los 40 posteriores
/// al recorte, que reutilizan el espacio recuperado—, así que el corte
/// tiene material que perder y la afirmación de "snapshot entero" trabaja.
///
/// Las metas se descartan siempre, por el mismo motivo que en la prueba 6
/// (ver su comentario): bajo sincronización relajada nadie promete que una
/// meta llegue después que las páginas que referencia, así que exigirle al
/// motor que sobreviva a una meta sin sus páginas sería exigirle algo que
/// el modo no promete.
#[test]
fn a_power_cut_after_a_reclaim_still_leaves_a_whole_snapshot() {
    let opts = Options { sync: Sync::Never, ..Options::default() };
    for seed in 1..=10u64 {
        let s = Arc::new(PowerCutStorage::new());
        let acked = commit_reclaim_then_commit_more(&s, opts, 10, 40);
        let metas: std::collections::BTreeSet<u64> = acked.iter().map(|a| a.last_write).collect();
        let truncations = s.truncations();

        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        s.cut(&mut |ordinal| {
            truncations.contains(&ordinal) || (!metas.contains(&ordinal) && rng.chance(90))
        });

        assert_the_surviving_state_is_a_whole_snapshot(
            &s,
            opts,
            &acked,
            &format!("corte aleatorio tras un recorte, semilla {seed}"),
        );
    }
}
