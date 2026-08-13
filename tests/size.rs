//! Bancos de tamaño de la tarea 21: los cinco criterios de salida de la fase
//! 1 que hasta ahora eran estimaciones de la especificación (sección 12.2,
//! "37 bytes por entrada") se sustituyen aquí por mediciones reales sobre
//! un millón de registros con la forma exacta de `request_logs` del edge de
//! quota.
//!
//! **Todo el fichero vive tras `feature = "std"`** (abajo, `#![cfg(...)]`),
//! igual que `tests/props.rs` y `tests/faults.rs`: `Db`/`WriteTxn`/
//! `storage::FileStorage` no existen sin ella, así que bajo `cargo test
//! --no-default-features` este fichero se compila vacío en vez de fallar.
//!
//! ## Desviación deliberada del brief: `tests/size.rs`, no `benches/size.rs`
//!
//! El brief (paso 1) lista `benches/size.rs` entre los ficheros a crear,
//! pero cada orden que el propio brief (pasos 3, 5 y 6) usa para ejecutarlo
//! es `cargo test --test size` / `cargo test --release --test size`. Cargo
//! solo registra un target `--test <nombre>` a partir de un fichero en
//! `tests/<nombre>.rs` — un fichero en `benches/` se convierte en un target
//! `--bench`, que necesita el arnés de bancos (inestable en Rust estable
//! sin una dependencia externa, que este proyecto no tiene) o
//! `harness = false` con un `main` propio, ninguno de los dos presente
//! aquí. Colocarlo en `benches/` haría que `cargo test --test size` fallara
//! con "no test target named `size`". Se sigue la instrucción ejecutable
//! (los comandos, repetidos cuatro veces en el propio brief) sobre la
//! instrucción declarativa (la lista de ficheros a crear), que es
//! justamente el tipo de conocimiento de disposición que hay que derivar,
//! no copiar a ciegas — ver el contexto de la tarea sobre harnesses que
//! reportaban cobertura que no tenían.
//!
//! ## `push_varint`: reimplementado aquí, no importado
//!
//! `crate::varint` es `pub(crate)` (ver `lib.rs`): invisible desde un
//! binario de integración, que enlaza `libinro` compilada normalmente, sin
//! acceso a nada que no sea `pub`. La función de abajo genera la MISMA
//! forma de bytes que `varint::write` (LEB128 sin signo, grupos de 7 bits,
//! bit de continuación en la posición 8) porque el objetivo es medir el
//! tamaño de un registro con la forma real del edge de quota, no ejercitar
//! el varint del motor — eso ya lo cubre `varint::tests` dentro del crate.
//!
//! ## Qué prueba cada banco, y qué NO prueba
//!
//! - `bytes_per_log_entry_stay_under_the_threshold` mide el tamaño del
//!   FICHERO completo entre el número de entradas — incluye cabecera,
//!   las dos meta-páginas, la holgura de páginas libres del copy-on-write
//!   agrupado en lotes de mil, y el árbol de datos completo. NO mide el
//!   tamaño de una fila aislada ni el de un `put` individual sin agrupar
//!   (la sección 12.4 de la especificación ya documenta que un commit por
//!   fila cuesta bastante más).
//!
//!   **Medido: 34,14 bytes por entrada, por debajo del umbral de 40.** No
//!   siempre lo estuvo, y la historia importa: la primera medición de este
//!   banco (tarea 21) dio 67,72 B/entrada y la prueba fallaba a propósito,
//!   sin subir el umbral para taparlo ("si el número medido supera 40, no
//!   se ajusta el umbral"). El hueco era el llenado real de página: el
//!   cálculo de la especificación (34-38 B, sección 12.2) es sobre el
//!   payload LÓGICO — clave más valor, con compresión de prefijo y sin
//!   códigos de tipo — asumiendo páginas casi llenas, mientras que una hoja
//!   construida por inserciones ascendentes con partición por el punto
//!   medio se congelaba al 49,5% de llenado medio. Lo cerró `SplitBias`
//!   (`tree.rs`): partir sesgado al anexar cuando la clave que entra es la
//!   mayor del árbol, que sube el llenado medio de hoja al 99,5%. Que de
//!   verdad mide bytes en disco y no una cifra calculada sobre los
//!   registros se demuestra en
//!   `bytes_per_entry_reacts_to_shuffled_insertion_order`, más abajo:
//!   cambiar SOLO el orden de inserción (mismo volumen, mismo lote, mismos
//!   registros) multiplica el cociente medido por 8,16 — si no se moviera,
//!   esta prueba no estaría midiendo el llenado real de las páginas.
//! - `pruning_a_days_worth_is_orders_of_magnitude_cheaper_than_a_scan` mide
//!   páginas LEÍDAS por el `Pager` durante un `delete_range` que descarta
//!   la mitad más vieja de las entradas, contra páginas liberadas. No mide
//!   tiempo de reloj — la tarea 15 ya estableció que contar páginas es más
//!   estable entre máquinas que medir microsegundos.
//! - `opening_costs_the_same_at_thirty_kilobytes_and_at_two_hundred_thousand_entries`
//!   mide lecturas físicas hechas por `Db::open` sola, antes de cualquier
//!   `get`/`scan`, contadas por `CountingStorage` (más abajo) al nivel del
//!   `Storage` — NO de `Pager::read`/`Db::pages_read()`, como hacía una
//!   versión anterior de este banco. **Corrección de una ronda de revisión
//!   posterior**: contar solo `Pager::read` deja invisible la cabecera y
//!   las dos meta-páginas — `Db::open` las lee directamente del `Storage`
//!   (`Geometry::read_reporting_fallback`, `Meta::load`), antes incluso de
//!   construir el `Pager` — así que ese contador certificaba que abrir no
//!   recorre el árbol, pero no habría atrapado una regresión que hiciera
//!   depender del tamaño del fichero justo a ESE camino, que ni siquiera
//!   toca el `Pager`. Contar en el `Storage`, la capa más baja de todas, sí
//!   lo hace: cualquier byte que `Db::open` lea del medio, por el camino
//!   que sea, pasa por ahí. Lo único que de verdad varía con el contenido
//!   del fichero es la carga perezosa de la lista de libres
//!   (`Freelist::load`, como mucho DOS páginas físicas — cabeza y cola, si
//!   son distintas — ver su comentario en `freelist.rs`), y solo si esa
//!   lista no está vacía. No mide el coste de recorrer el árbol después de
//!   abrir. El caso "grande" es 200.000 entradas, no ~2 GB/50 millones — ver
//!   el comentario de la propia prueba sobre por qué eso basta.
#![cfg(feature = "std")]

use inro::storage::FileStorage;
use inro::{Db, Options, Storage, Sync};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Añade `v` a `buf` en LEB128 sin signo — misma forma que `varint::write`
/// del motor (ver el comentario del módulo), reimplementada porque ese
/// módulo es `pub(crate)` y este fichero es un binario de integración
/// externo al crate.
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

/// Genera un registro con la forma real de `request_logs` del edge de
/// quota y comprueba los bytes por entrada en disco.
///
/// Distribución tomada del esquema real: 200 endpoints distintos, 5.000
/// user agents, 40 países, 10.000 usuarios, y la inmensa mayoría de las
/// respuestas con código 200.
fn synthetic_log(i: u32) -> (Vec<u8>, Vec<u8>) {
    let ts = 1_760_000_000_000u64 + i as u64 * 520; // ~2 req/s
    let mut key = Vec::with_capacity(10);
    key.extend_from_slice(&ts.to_be_bytes());
    key.extend_from_slice(&((i % 8) as u16).to_be_bytes());

    let mut v = Vec::with_capacity(32);
    v.push(if i.is_multiple_of(7) { 1 } else { 0 }); // method
    v.push(if i.is_multiple_of(97) { 2 } else { 0 }); // status
    push_varint(&mut v, (i % 400) as u64); // latency_ms
    push_varint(&mut v, 500 + (i % 9000) as u64); // bytes_sent
    push_varint(&mut v, 100 + (i % 900) as u64); // bytes_received
    v.extend_from_slice(&((192u32 << 24) | (i % 65_536)).to_le_bytes()); // client_ip
    v.push((i % 40) as u8); // country
    v.push(0); // query_string vacía
    push_varint(&mut v, (i % 200) as u64); // path_id
    push_varint(&mut v, (i % 5_000) as u64); // user_agent_id
    push_varint(&mut v, (i % 300) as u64); // referer_id
    push_varint(&mut v, (i % 1_200) as u64); // city_id
    push_varint(&mut v, (i % 10_000) as u64); // quota_user_id
    push_varint(&mut v, (i % 10_000) as u64); // client_user_id
    (key, v)
}

/// Escribe `n` registros sintéticos en `path` en lotes de `batch`, como el
/// escritor agrupado del edge.
fn write_synthetic_log(db: &Db, n: u32, batch: usize) {
    write_synthetic_log_in(db, n, batch, 0x01);
}

/// Igual, pero eligiendo el espacio de claves. Lo necesita
/// `a_row_in_a_higher_namespace_does_not_double_the_file`, que compara la
/// misma carga escrita con y sin algo por encima de ella: el espacio ya no es
/// un detalle sin consecuencias del banco, es una de las dos variables que
/// deciden el tamaño del fichero (ver `tree::SplitBias`).
fn write_synthetic_log_in(db: &Db, n: u32, batch: usize, ns: u8) {
    for chunk in (0..n).collect::<Vec<_>>().chunks(batch) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            let (k, v) = synthetic_log(i);
            tx.put(ns, &k, &v).unwrap();
        }
        tx.commit().unwrap();
    }
}

/// Marcada `#[ignore]` (medido en esta misma tarea): un millón de
/// registros en modo `debug` — el que usan los cinco comandos de
/// verificación de este proyecto, ninguno con `--release` — no llegó a
/// terminar en dos minutos de reloj. El brief no marcaba esta prueba como
/// `#[ignore]`, solo la de apertura a 2 GB, pero "que el binario compile
/// sin `--cfg test`" (el problema que obligó a destapar `pages_read`/
/// `pages_in_use`, ver `tx.rs`) no es el único requisito de disposición que
/// hay que derivar en vez de copiar: el coste real de ejecutarla también
/// hay que medirlo, no asumirlo del texto del brief. La etapa `bench` de
/// `.gitlab-ci.yml` la ejecuta en `--release`, donde sí es rápida (ver el
/// informe de la tarea 21 para el tiempo medido).
#[test]
#[ignore]
fn bytes_per_log_entry_stay_under_the_threshold() {
    const N: u32 = 1_000_000;
    let path = std::env::temp_dir().join("inro-bench-size.inro");
    let _ = std::fs::remove_file(&path);
    let db = Db::create(
        Box::new(FileStorage::open(&path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();

    write_synthetic_log(&db, N, 1000);
    drop(db);

    let size = std::fs::metadata(&path).unwrap().len();
    let per_entry = size as f64 / N as f64;
    println!("inro: {size} bytes, {per_entry:.2} por entrada");
    let _ = std::fs::remove_file(&path);
    assert!(per_entry <= 40.0, "{per_entry:.2} bytes por entrada supera el umbral de 40");
}

/// Escribe `order` (una permutación de índices para `synthetic_log`) en
/// `path`, en lotes de mil, y devuelve el tamaño de fichero resultante en
/// bytes por entrada — la misma métrica que
/// `bytes_per_log_entry_stay_under_the_threshold`, parametrizada por orden.
fn size_per_entry_for_order(path: &std::path::Path, order: &[u32]) -> f64 {
    let _ = std::fs::remove_file(path);
    let db = Db::create(
        Box::new(FileStorage::open(path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();
    for chunk in order.chunks(1000) {
        let mut tx = db.begin_write().unwrap();
        for &i in chunk {
            let (k, v) = synthetic_log(i);
            tx.put(0x01, &k, &v).unwrap();
        }
        tx.commit().unwrap();
    }
    drop(db);
    let size = std::fs::metadata(path).unwrap().len();
    let _ = std::fs::remove_file(path);
    size as f64 / order.len() as f64
}

/// Prueba de control: demuestra que la medición de arriba mide de verdad
/// el llenado de página en disco, no una cifra calculada sobre el tamaño
/// lógico de los registros — cambiando el ORDEN de inserción, con el mismo
/// volumen (`N` = 16 384, para que la corrida sea rápida), el mismo tamaño
/// de lote y los mismos registros que `synthetic_log`. **Construye los DOS
/// órdenes dentro de esta misma prueba** y compara su COCIENTE, en vez de
/// fijar el resultado secuencial como una constante de otra corrida:
/// codificar el número secuencial del día como umbral fijo convertiría un
/// arreglo futuro del llenado de página (que baje ESE número) en un fallo
/// de esta prueba de control con el mensaje "la medición no está
/// reaccionando al orden" — exactamente lo contrario de lo que debe
/// reportar una mejora real. Y no es hipotético: la llegada de
/// `SplitBias::Append` (`tree.rs`) bajó el lado secuencial de 82,00 a
/// 49,50 B/entrada sin mover el barajado ni un byte, que es justo el caso
/// que un umbral fijo habría reportado como avería. El cociente entre los
/// dos, medidos en la misma corrida, no tiene ese problema: se mueve con
/// cualquier cambio real de llenado, en cualquier dirección.
///
/// **La hipótesis inicial de quien escribió este banco era la contraria a
/// lo medido** — que la inserción ascendente de `synthetic_log` (con `ts`
/// creciente, la forma real de una clave de log) sería la PEOR, porque
/// `tree.rs` divide un nodo siempre por el punto medio (ver su comentario
/// junto a `Split`: "...deja la mitad izquierda llena y la derecha
/// con...") y con inserción estrictamente ascendente la mitad izquierda de
/// cada partición queda congelada para siempre, sin que ningún `put`
/// futuro caiga ya en ese rango. Medido, ES AL REVÉS, y por un margen que
/// no deja lugar a dudas: a igual `N`, secuencial da 49,50 B/entrada y
/// barajado 404,00 — 8,16 veces peor, no mejor. (Antes de que
/// `SplitBias::Append` corrigiera la patología ascendente eran 82,00 y
/// 404,00, cociente 4,93: el sesgo al anexar mejoró el lado secuencial y
/// dejó el barajado intacto, que es exactamente lo que promete.) El
/// mecanismo del lado barajado queda sin aislar (candidatos: la compresión
/// de prefijo aprovecha mucho mejor un `ts` que crece por pasos pequeños
/// que una dispersión uniforme sobre todo el rango, o el patrón de
/// escritura simultánea a hojas muy separadas del árbol interactúa peor con
/// la política de partición) — lo que sí está confirmado, y es lo único que
/// esta prueba necesita establecer, es que el cociente medido REACCIONA al
/// orden de inserción: si no reaccionara, la prueba de arriba no estaría
/// midiendo el llenado real de las páginas en absoluto, sino algún
/// artefacto fijo.
///
/// El barajado es una permutación multiplicativa sobre una potencia de
/// dos: con un multiplicador impar, `j ↦ (j·a) mod N` es una biyección de
/// `0..N` sobre sí mismo — determinista, reproducible entre corridas, y sin
/// tirar de ninguna dependencia de aleatoriedad.
#[test]
#[ignore]
fn bytes_per_entry_reacts_to_shuffled_insertion_order() {
    const N: u32 = 16_384; // potencia de dos: la biyección de abajo lo exige
    let sequential: Vec<u32> = (0..N).collect();
    let shuffled: Vec<u32> = (0..N).map(|j| j.wrapping_mul(2_654_435_761) & (N - 1)).collect();

    let seq_path = std::env::temp_dir().join("inro-bench-size-sequential.inro");
    let shuf_path = std::env::temp_dir().join("inro-bench-size-shuffled.inro");
    let seq_per_entry = size_per_entry_for_order(&seq_path, &sequential);
    let shuf_per_entry = size_per_entry_for_order(&shuf_path, &shuffled);
    println!("inro (secuencial, N={N}): {seq_per_entry:.2} B/entrada");
    println!("inro (barajado,   N={N}): {shuf_per_entry:.2} B/entrada");

    // Cociente, no una constante fija: cualquier lado puede moverse en el
    // futuro, y ya se movió — el `emit` sesgado a anexar (`SplitBias`,
    // `tree.rs`) subió el llenado secuencial al 99,5% y bajó ese lado de
    // 82,00 a 49,50 B/entrada. Lo único que esta prueba necesita es que los
    // dos números difieran de forma sustancial — un 10% de margen sobre 1.0
    // en cualquier dirección — no que el secuencial gane ni que valga una
    // cifra concreta.
    let ratio = shuf_per_entry / seq_per_entry;
    assert!(
        !(0.9..=1.1).contains(&ratio),
        "cociente barajado/secuencial = {ratio:.3} (secuencial {seq_per_entry:.2} B/entrada, \
         barajado {shuf_per_entry:.2} B/entrada) — el orden de inserción no está moviendo la \
         medición de forma sustancial, así que `bytes_per_log_entry_stay_under_the_threshold` \
         podría no estar midiendo el llenado real de las páginas"
    );
}

/// **La única prueba de este fichero que NO va `#[ignore]`, y el motivo por
/// el que existe.**
///
/// `bytes_per_log_entry_stay_under_the_threshold`, arriba, escribe todos sus
/// registros en un solo espacio de claves (`0x01`) y nada más en ninguna
/// parte. Eso la dejaba ciega a la regresión de disco más cara que ha tenido
/// este motor: el motor antepone el byte del espacio a cada clave
/// (`tx::scoped`), así que el orden de los espacios ES el orden del árbol, y
/// el sesgo de división que baja el crudo a ~34 B/entrada dependía de que la
/// clave que entra fuera la mayor del ÁRBOL ENTERO. Con UNA sola fila en un
/// espacio superior —una fila de agregado en `0x02`, una entrada de índice
/// secundario en `0x80 | id`— ninguna clave del espacio inferior vuelve a
/// serlo, el sesgo deja de dispararse y el llenado de hoja cae al ~50%.
/// **Medido antes de la corrección, 200.000 registros y páginas de 4 KB:
/// 34,98 B/entrada solo, 80,26 B/entrada con una fila en `0x02` — 2,29x, muy
/// por encima del umbral de 40 que vigila la integración continua, y con
/// TODOS los bancos en verde.**
///
/// Por eso esta prueba mide los DOS ficheros en la misma corrida y compara su
/// COCIENTE, igual que `bytes_per_entry_reacts_to_shuffled_insertion_order`:
/// una constante fija convertiría cualquier mejora futura del llenado en un
/// fallo, mientras que el cociente solo se mueve si las dos disposiciones
/// dejan de costar lo mismo, que es justo la propiedad que hay que defender.
///
/// **No lleva `#[ignore]`, a diferencia de las cuatro de arriba**: está
/// dimensionada para caber en modo `debug`, que es el que usan los cinco
/// comandos de verificación de este proyecto y las cuatro invocaciones de
/// `cargo test` de la etapa `test`. Ponerla en la etapa `bench` la habría
/// dejado corriendo una sola vez, después de la etapa que de verdad cierra el
/// paso a una fusión — y el defecto que vigila se introduce escribiendo en un
/// espacio de claves nuevo, algo que puede pasar en cualquier commit.
/// 6.000 registros bastan, y está comprobado que bastan en vez de supuesto:
/// con la corrección revertida esta prueba mide un cociente de **1,868**
/// contra el umbral de 1,15 (51,88 → 96,94 B/entrada), así que discrimina con
/// margen de sobra. Cuestan 4,5 s en modo `debug`, que es lo que la deja
/// caber en los cinco comandos de verificación.
#[test]
fn a_row_in_a_higher_namespace_does_not_double_the_file() {
    const N: u32 = 6_000;

    /// Escribe `N` registros en `raw_ns` y devuelve los bytes por entrada.
    /// Si `higher`, planta antes UNA entrada en un espacio POR ENCIMA de
    /// `raw_ns` — una sola, para aislar el efecto sobre la política de
    /// división del volumen de lo que se guarde ahí.
    fn per_entry(path: &std::path::Path, raw_ns: u8, higher: bool) -> f64 {
        let _ = std::fs::remove_file(path);
        let db = Db::create(
            Box::new(FileStorage::open(path).unwrap()),
            Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        if higher {
            let mut tx = db.begin_write().unwrap();
            tx.put(raw_ns + 1, b"", b"una fila cualquiera").unwrap();
            tx.commit().unwrap();
        }
        write_synthetic_log_in(&db, N, 1000, raw_ns);
        drop(db);
        let size = std::fs::metadata(path).unwrap().len();
        let _ = std::fs::remove_file(path);
        size as f64 / N as f64
    }

    let solo = per_entry(&std::env::temp_dir().join("inro-ns-solo.inro"), 0x01, false);
    let con_fila = per_entry(&std::env::temp_dir().join("inro-ns-fila.inro"), 0x01, true);
    println!("inro (crudo en 0x01, sin nada encima): {solo:.2} B/entrada");
    println!("inro (crudo en 0x01, UNA fila en 0x02): {con_fila:.2} B/entrada");

    // 1,15 y no 1,00: desgajar el bloque que queda por encima de la cota
    // cuesta UNA hoja por frontera (ver `tree::SplitBias`), más el commit
    // extra de plantar la fila. Medido tras la corrección: 34,98 contra 35,16
    // B/entrada a 200.000 registros (cociente 1,005) y 51,88 contra 53,25 a
    // los 6.000 de aquí (1,026 — a este volumen la holgura fija del fichero
    // pesa más y el cociente se mueve algo en las dos direcciones). El margen
    // deja sitio de sobra a esa constante sin dejar pasar nada que se parezca
    // a perder el sesgo, que costaba 1,868 en esta misma prueba.
    let ratio = con_fila / solo;
    assert!(
        ratio <= 1.15,
        "una sola fila en el espacio 0x02 encarece el crudo de 0x01 de {solo:.2} a \
         {con_fila:.2} B/entrada (cociente {ratio:.3}): el espacio inferior ha perdido su \
         sesgo de anexado por existir algo por encima. Ver `tree::SplitBias` y la cota \
         `upper` que `WriteTxn::put_raw` le pasa"
    );
}

/// `#[ignore]`, mismo motivo que `bytes_per_log_entry_stay_under_the_threshold`:
/// 833.000 registros en modo `debug` no cabe en el presupuesto de los cinco
/// comandos de verificación.
#[test]
#[ignore]
fn pruning_a_days_worth_is_orders_of_magnitude_cheaper_than_a_scan() {
    const N: u32 = 833_000; // un día de retención de un nodo pro
    let path = std::env::temp_dir().join("inro-bench-prune.inro");
    let _ = std::fs::remove_file(&path);
    let db = Db::create(
        Box::new(FileStorage::open(&path).unwrap()),
        Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
    )
    .unwrap();

    write_synthetic_log(&db, N, 1000);

    let (cutoff, _) = synthetic_log(N / 2);
    let reads_before = db.pages_read();
    let mut tx = db.begin_write().unwrap();
    let in_use_before = tx.pages_in_use();
    tx.delete_range(0x01, b"", &cutoff).unwrap();
    let freed = in_use_before - tx.pages_in_use();
    tx.commit().unwrap();
    let read = db.pages_read() - reads_before;

    println!("poda: {read} páginas leídas, {freed} liberadas");
    drop(db);
    let _ = std::fs::remove_file(&path);
    assert!(freed > 3_000, "solo se liberaron {freed} páginas");
    assert!(read < 500, "se leyeron {read} páginas; las hojas no deben abrirse");
}

/// Envoltorio de `Storage` que cuenta llamadas a `read_at` — a diferencia
/// de `Db::pages_read()`/`Pager::pages_read()`, que solo cuentan lecturas
/// que pasan por `Pager::read`. `Db::open` lee la cabecera y las dos
/// meta-páginas directamente del `Storage`, ANTES de construir el `Pager`
/// (`Geometry::read_reporting_fallback`, `Meta::load`) — esas lecturas son
/// invisibles para `Db::pages_read()`, así que un contador anclado ahí
/// certifica que abrir no recorre el árbol, pero no atraparía una
/// regresión que hiciera depender del tamaño del fichero justo a ese
/// camino de cabecera/metas. Contar en el `Storage`, la capa más baja de
/// todas, no deja ningún camino sin cubrir: cualquier lectura física que
/// `Db::open` haga, por el camino interno que sea, incrementa `reads`.
///
/// Envuelto en `Arc` (no solo `Box`) para conservar un asa legible después
/// de entregar la propiedad a `Db::open`, que exige `Box<dyn Storage>` —
/// el mismo patrón que usan `FaultStorage`/`Recording` en `tests/faults.rs`,
/// posible porque `storage.rs` implementa `Storage` para cualquier
/// `Arc<S: Storage>` (ver su comentario ahí, sobre este caso exacto: un
/// arnés de pruebas que necesita conservar acceso tras la entrega).
struct CountingStorage<S> {
    inner: S,
    reads: AtomicU64,
}

impl<S: Storage> CountingStorage<S> {
    fn new(inner: S) -> Self {
        Self { inner, reads: AtomicU64::new(0) }
    }

    fn read_count(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl<S: Storage> Storage for CountingStorage<S> {
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

/// Confirma que el coste de `Db::open` (medido en lecturas físicas al
/// nivel del `Storage`, ver `CountingStorage` arriba) no depende del
/// tamaño del fichero: como mucho la carga perezosa de la lista de libres
/// — cabeza y cola, si son distintas — encima de la cabecera y las dos
/// meta-páginas, que se leen siempre, nunca el árbol de datos ni el resto
/// de la lista.
///
/// **El caso "grande" es 200.000 entradas, no ~2 GB (50 millones)** —
/// corregido en la ronda de revisión que cerró la tarea 21: la versión
/// anterior de este banco dejaba la cifra grande sin rellenar en el
/// informe (`[PENDIENTE]`) porque construir ~2 GB tarda del orden de DOS
/// HORAS de reloj, y esa corrida nunca llegó a completarse. El mecanismo
/// que este banco verifica — que `Db::open` no toca el árbol de datos, y
/// que la lista de libres se carga perezosa con como mucho dos lecturas —
/// no depende de cuán grande sea el árbol: un fichero de 200.000 entradas
/// (decenas de MB, con el llenado real medido en la sección 12.2) ya tiene
/// un árbol de varios niveles y ejercita el mismo camino de apertura que
/// uno de 2 GB, en segundos en vez de horas. Marcar el criterio de la
/// especificación como cumplido a 2 GB exactos seguiría siendo una
/// extrapolación del mecanismo, no una medición a esa escala — la
/// especificación lo dice así explícitamente (sección 1 y 16).
///
/// Marcada `#[ignore]`, igual que sus vecinas de este fichero: no entra en
/// los cinco comandos de verificación. La integración continua la ejecuta
/// aparte, filtrada por nombre (`-- --ignored opening_costs`, ver
/// `.gitlab-ci.yml`) — **antes** del resto de la etapa `bench`, no
/// después: el primer comando de esa etapa falla a propósito (el umbral de
/// 40 B/entrada, ver `bytes_per_log_entry_stay_under_the_threshold`), y
/// una orden de `script` que falla detiene las que le siguen — si la de
/// apertura fuera la segunda orden, nunca se ejecutaría en una corrida
/// real de integración continua, solo en local.
#[test]
#[ignore]
fn opening_costs_the_same_at_thirty_kilobytes_and_at_two_hundred_thousand_entries() {
    fn reads_to_open(entries: u32) -> u64 {
        let path = std::env::temp_dir().join(format!("inro-bench-open-{entries}.inro"));
        let _ = std::fs::remove_file(&path);
        {
            let db = Db::create(
                Box::new(FileStorage::open(&path).unwrap()),
                Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
            )
            .unwrap();
            write_synthetic_log(&db, entries, 1000);
        }
        let counting = Arc::new(CountingStorage::new(FileStorage::open(&path).unwrap()));
        let db =
            Db::open(Box::new(counting.clone()), Options { page_size: 4096, ..Options::default() })
                .unwrap();
        let reads = counting.read_count();
        drop(db);
        let _ = std::fs::remove_file(&path);
        reads
    }

    let small = reads_to_open(500); // decenas de KB
    let large = reads_to_open(200_000); // decenas de MB — ver el comentario de arriba
    println!("apertura: {small} lecturas (Storage) en pequeño, {large} en grande");
    assert_eq!(
        small, large,
        "la apertura debe costar lo mismo — si difiere, no es por el TAMAÑO del \
         fichero (`Freelist::load` no depende de él), sino porque uno de los dos \
         ficheros acumuló actividad de lista de libres y el otro no; ver el \
         comentario del módulo"
    );
    assert!(
        small <= 4,
        "cabecera, dos meta-páginas y como mucho cabeza/cola de la lista de libres — \
         nunca más; ver `Db::open`, `Meta::load` y `Freelist::load` en freelist.rs"
    );
}

/// Comparativa con SQLite (tarea 21, sección 17.1 de la especificación).
/// Solo compila tras `--features bench-sqlite` (ver `Cargo.toml`): la
/// dependencia `rusqlite` nunca la ven los cinco comandos de verificación
/// de este proyecto.
#[cfg(feature = "bench-sqlite")]
mod sqlite_comparison {
    use super::synthetic_log;
    use inro::storage::FileStorage;
    use inro::{Db, Options, Sync};
    use rusqlite::Connection;
    use std::time::Instant;

    /// Esquema normalizado, con tablas de diccionario, para que SQLite
    /// almacene la MISMA información que inro y no un texto crudo más caro
    /// de guardar por decisión de esquema en vez de por el motor en sí:
    /// inro también usa identificadores de diccionario para path/user
    /// agent/referer/city (ver `synthetic_log`), así que darle a SQLite una
    /// tabla `logs` con esas mismas columnas enteras small-int es la
    /// comparación justa — una columna `TEXT` de ruta repetida un millón de
    /// veces penalizaría a SQLite por una decisión de esquema, no por ser
    /// SQLite.
    const SCHEMA: &str = "
        CREATE TABLE logs (
            ts          INTEGER NOT NULL,
            seq         INTEGER NOT NULL,
            method      INTEGER NOT NULL,
            status      INTEGER NOT NULL,
            latency_ms  INTEGER NOT NULL,
            bytes_sent  INTEGER NOT NULL,
            bytes_recv  INTEGER NOT NULL,
            client_ip   INTEGER NOT NULL,
            country     INTEGER NOT NULL,
            path_id     INTEGER NOT NULL,
            ua_id       INTEGER NOT NULL,
            referer_id  INTEGER NOT NULL,
            city_id     INTEGER NOT NULL,
            quota_uid   INTEGER NOT NULL,
            client_uid  INTEGER NOT NULL,
            PRIMARY KEY (ts, seq)
        ) WITHOUT ROWID;
    ";

    /// Mismos catorce campos que `synthetic_log` (más `ts`/`seq`, la
    /// clave), en una fila con nombre en vez de una tupla de quince
    /// posiciones: una tupla así de larga es exactamente el tipo de cosa
    /// que clippy (`type_complexity`) marca con razón — nadie distingue de
    /// un vistazo cuál de dos `u64` seguidos es `bytes_sent` y cuál
    /// `bytes_recv`.
    struct SyntheticRow {
        ts: u64,
        seq: u16,
        method: u8,
        status: u8,
        latency_ms: u64,
        bytes_sent: u64,
        bytes_recv: u64,
        client_ip: u32,
        country: u8,
        path_id: u64,
        ua_id: u64,
        referer_id: u64,
        city_id: u64,
        quota_uid: u64,
        client_uid: u64,
    }

    fn synthetic_row(i: u32) -> SyntheticRow {
        SyntheticRow {
            ts: 1_760_000_000_000u64 + i as u64 * 520,
            seq: (i % 8) as u16,
            method: if i.is_multiple_of(7) { 1 } else { 0 },
            status: if i.is_multiple_of(97) { 2 } else { 0 },
            latency_ms: (i % 400) as u64,
            bytes_sent: 500 + (i % 9000) as u64,
            bytes_recv: 100 + (i % 900) as u64,
            client_ip: (192u32 << 24) | (i % 65_536),
            country: (i % 40) as u8,
            path_id: (i % 200) as u64,
            ua_id: (i % 5_000) as u64,
            referer_id: (i % 300) as u64,
            city_id: (i % 1_200) as u64,
            quota_uid: (i % 10_000) as u64,
            client_uid: (i % 10_000) as u64,
        }
    }

    /// Lee `VmHWM` de `/proc/self/status` — Linux, texto plano, sin
    /// dependencia. **Es el pico residente del PROCESO ENTERO desde que
    /// arrancó, no de ningún motor aislado, y es MONÓTONO: solo puede
    /// subir, nunca bajar**, incluida memoria que ya se liberó (confirmado
    /// en una ronda de revisión: liberar 64 MB deliberadamente deja el
    /// `VmHWM` exactamente igual). Dentro de este mismo proceso de prueba,
    /// la fase de inro corre primero y la de SQLite después — así que
    /// `inro_rss` (leído tras la fase de inro) y `sqlite_rss` (leído tras
    /// la fase de SQLite, que ya incluye todo lo que dejó la de inro) NO
    /// son comparables como "RSS de cada motor": `sqlite_rss >= inro_rss`
    /// está GARANTIZADO por construcción, sea SQLite más o menos pesado que
    /// inro — invertir el orden de las dos fases (confirmado en la misma
    /// ronda) da el mismo número redondo para las dos lecturas, lo que
    /// termina de confirmar que lo que se mide es "el proceso hasta este
    /// punto", no "este motor". Lo único que SÍ es legítimo leer de estos
    /// dos números es su DIFERENCIA cuando inro corre primero: cuánto pico
    /// adicional añade la fase de SQLite encima de lo que la fase de inro
    /// ya había establecido — ver `compare_against_sqlite_on_the_same_workload`,
    /// donde se imprime así, marcado como lo que es, no como "RSS de
    /// SQLite" ni "RSS de inro" aislados.
    fn max_rss_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                return rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// Marcada `#[ignore]`, mismo motivo medido que las cuatro pruebas del
    /// módulo padre (`bytes_per_log_entry_stay_under_the_threshold` y
    /// vecinas): un millón de registros — aquí, además, en LOS DOS motores,
    /// más la compilación de SQLite si `--features bench-sqlite` no se
    /// había activado antes — no cabe en el presupuesto de los cinco
    /// comandos de verificación. **Esta era la prueba que se quedaba sin
    /// `#[ignore]`**: como solo compila tras `--features bench-sqlite`, no
    /// aparecía en ninguno de los cinco comandos de verificación de rutina
    /// (que no activan esa *feature*), pero SÍ en `cargo test
    /// --all-features`, que la activa junto con todas las demás y la
    /// ejecuta sin filtrar — en modo `debug`, sin límite de tiempo visible,
    /// indistinguible de un cuelgue para quien no supiera que ahí dentro
    /// hay un millón de filas en dos motores a la vez.
    #[test]
    #[ignore]
    fn compare_against_sqlite_on_the_same_workload() {
        const N: u32 = 1_000_000;

        // --- inro ---
        let inro_path = std::env::temp_dir().join("inro-bench-sqlite-cmp.inro");
        let _ = std::fs::remove_file(&inro_path);
        let inro_db = Db::create(
            Box::new(FileStorage::open(&inro_path).unwrap()),
            Options { page_size: 4096, sync: Sync::Never, ..Options::default() },
        )
        .unwrap();
        for chunk in (0..N).collect::<Vec<_>>().chunks(1000) {
            let mut tx = inro_db.begin_write().unwrap();
            for &i in chunk {
                let (k, v) = synthetic_log(i);
                tx.put(0x01, &k, &v).unwrap();
            }
            tx.commit().unwrap();
        }
        let inro_size = std::fs::metadata(&inro_path).unwrap().len();
        let cutoff_ts = 1_760_000_000_000u64 + (N as u64 / 2) * 520;
        let prune_start = Instant::now();
        let mut tx = inro_db.begin_write().unwrap();
        let mut cutoff_key = Vec::with_capacity(10);
        cutoff_key.extend_from_slice(&cutoff_ts.to_be_bytes());
        cutoff_key.extend_from_slice(&0u16.to_be_bytes());
        tx.delete_range(0x01, b"", &cutoff_key).unwrap();
        tx.commit().unwrap();
        let inro_prune = prune_start.elapsed();
        drop(inro_db);
        let inro_rss = max_rss_kb();
        let _ = std::fs::remove_file(&inro_path);

        // --- SQLite ---
        // page_size=4096, IGUAL que inro arriba — no los 512 que proponía
        // el brief. A esta escala (un millón de registros, del orden de la
        // ventana de un nodo "pro" de cinco días, sección 12.2) la propia
        // especificación fija inro en páginas de 4 KB, no 512 — comparar a
        // inro-4096 contra sqlite-512 habría sido darle a inro la
        // configuración que de verdad usaría y a SQLite una más pequeña de
        // la que su propio proyecto recomienda por defecto desde la 3.12
        // precisamente para este tipo de carga. cache_size en el valor por
        // defecto de SQLite (~2 MB, `-2000`) en vez de un mínimo forzado:
        // reducirlo solo podría penalizar la lectura/poda de SQLite, nunca
        // inro, así que dejarlo en su valor de fábrica no favorece a
        // ninguno de los dos motores.
        let sqlite_path = std::env::temp_dir().join("inro-bench-sqlite-cmp.sqlite");
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", sqlite_path.display()));
        }
        let conn = Connection::open(&sqlite_path).unwrap();
        conn.pragma_update(None, "page_size", 4096).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "cache_size", -2000).unwrap();
        conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        {
            let mut stmt = conn
                .prepare(
                    "INSERT INTO logs (ts, seq, method, status, latency_ms, bytes_sent, \
                     bytes_recv, client_ip, country, path_id, ua_id, referer_id, city_id, \
                     quota_uid, client_uid) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                )
                .unwrap();
            for chunk in (0..N).collect::<Vec<_>>().chunks(1000) {
                conn.execute_batch("BEGIN IMMEDIATE").unwrap();
                for &i in chunk {
                    let r = synthetic_row(i);
                    stmt.execute(rusqlite::params![
                        r.ts,
                        r.seq,
                        r.method,
                        r.status,
                        r.latency_ms,
                        r.bytes_sent,
                        r.bytes_recv,
                        r.client_ip,
                        r.country,
                        r.path_id,
                        r.ua_id,
                        r.referer_id,
                        r.city_id,
                        r.quota_uid,
                        r.client_uid,
                    ])
                    .unwrap();
                }
                conn.execute_batch("COMMIT").unwrap();
            }
        }
        // Checkpoint para que el tamaño reportado incluya lo que ya se
        // volcó del WAL al fichero principal, igual que se contaría en
        // producción tras una ventana tranquila.
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE").unwrap();

        let prune_start = Instant::now();
        conn.execute("DELETE FROM logs WHERE ts < ?1", rusqlite::params![cutoff_ts]).unwrap();
        conn.execute_batch("COMMIT").ok(); // no-op si no hay transacción abierta
        let sqlite_prune = prune_start.elapsed();
        // Segundo checkpoint, FUERA del tiempo medido arriba (igual que la
        // poda de inro no incluye ningún "asentamiento" posterior): el
        // `DELETE` mismo escribe al WAL, así que sin este segundo
        // checkpoint el tamaño de fichero que se mide más abajo incluiría
        // ese WAL sin volcar y el fichero de SQLite se vería más grande de
        // lo que quedaría tras una ventana tranquila — la comparación de
        // tamaño debe coger a los dos motores en un estado asentado, no a
        // SQLite a mitad de escribir su WAL.
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE").unwrap();

        let sqlite_main = std::fs::metadata(&sqlite_path).unwrap().len();
        let sqlite_wal = std::fs::metadata(format!("{}-wal", sqlite_path.display()))
            .map(|m| m.len())
            .unwrap_or(0);
        let sqlite_shm = std::fs::metadata(format!("{}-shm", sqlite_path.display()))
            .map(|m| m.len())
            .unwrap_or(0);
        let sqlite_total = sqlite_main + sqlite_wal + sqlite_shm;
        drop(conn);
        let sqlite_rss = max_rss_kb();
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", sqlite_path.display()));
        }

        println!(
            "inro:   {inro_size} bytes ({:.2} B/entrada), poda {:?}",
            inro_size as f64 / N as f64,
            inro_prune
        );
        println!(
            "sqlite: {sqlite_total} bytes = {sqlite_main} main + {sqlite_wal} wal + \
             {sqlite_shm} shm ({:.2} B/entrada), poda {:?}",
            sqlite_total as f64 / N as f64,
            sqlite_prune
        );
        // NO se imprime "RSS de inro" ni "RSS de SQLite" como si fueran
        // cifras comparables por separado — ver el comentario de
        // `max_rss_kb`, arriba: `VmHWM` es del proceso completo y monótono,
        // así que `sqlite_rss >= inro_rss` está garantizado por
        // construcción sin importar qué motor pese más. Lo único que se
        // imprime es la DIFERENCIA entre las dos lecturas — cuánto pico
        // adicional añade la fase de SQLite encima de lo que ya había
        // dejado la fase de inro, que corrió primero — etiquetada como lo
        // que es, no como una comparación de "RSS por motor". La cifra
        // aislada de cada motor (RAM por base abierta, sección 1 y 17.1 de
        // la especificación) sigue sin medirse: haría falta un proceso
        // separado por motor, con su propio `VmHWM`, y esta prueba no lo
        // hace.
        let sqlite_phase_delta_kb = sqlite_rss.saturating_sub(inro_rss);
        println!(
            "RSS de pico del proceso: {inro_rss} KB tras la fase inro, {sqlite_rss} KB tras la \
             fase SQLite — +{sqlite_phase_delta_kb} KB de pico ATRIBUIBLE A LA FASE SQLITE \
             (encima de lo que ya había dejado inro; NO es \"RSS de SQLite\" ni \"RSS de inro\" \
             aislados, ver el comentario de `max_rss_kb`)"
        );

        // Sin umbral: es una medición para la especificación (sección
        // 17.1), no una puerta de integración continua. El propio banco
        // deja constancia de que corrió hasta el final imprimiendo las
        // cifras arriba.
    }
}
