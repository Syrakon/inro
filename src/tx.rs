use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
// Solo en pruebas desde que la caché del `Pager` guarda páginas validadas:
// el único `Arc` que queda en este fichero es el de `ReadTxn::read_page`
// (gateado igual) y el de los `Storage` compartidos de los módulos de
// prueba de más abajo, que lo toman de aquí por `use super::*`.
#[cfg(test)]
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};
use std::time::Instant;

use crate::freelist::Freelist;
use crate::header::{Geometry, FORMAT_MAJOR, MAX_PAGE_SIZE, MIN_PAGE_SIZE, FLAG_ENCRYPTED};
use crate::index::{index_key, primary_of, IndexDef, CATALOG_NS, INDEX_NS_BASE};
use crate::meta::{Meta, MetaSlot};
use crate::page::ValidPage;
use crate::pager::Pager;
use crate::{Error, PageNo, Result, Storage, TxnId};

// Reexportado para que el resto del crate (y las pruebas de `crypto.rs`,
// que lo importan como `crate::tx::Encryption`) puedan nombrarlo sin
// conocer que en realidad vive en `crypto`. `Encryption` es un tipo simple
// (ver su comentario en `crypto.rs`), así que reexportarlo aquí sin
// condicionarlo a la feature `encryption` no compila nada de más — el
// reexport PÚBLICO desde la raíz del crate (`lib.rs`) sí está tras esa
// feature, que es el sitio que de verdad importa para "quien no cifra no
// puede ni nombrar el tipo desde fuera".
pub use crate::crypto::Encryption;

/// Política de sincronización a disco.
///
/// # Lo que cada modo promete de verdad
///
/// Los tres modos comparten una garantía, y es la que el motor SÍ puede
/// dar: **ninguna página que la meta superviviente referencie ha sido
/// reescrita por una transacción posterior.** El reciclado de páginas
/// libres está anclado a la última meta DEMOSTRADA en disco, no a la
/// última escrita (ver el campo `Db::durable`), así que el árbol que monta
/// tras un corte es el de un commit real y completo, nunca uno con
/// agujeros.
///
/// Lo que cambia entre modos es CUÁNTO se pierde y CUÁNTOS `fsync` se
/// pagan:
///
/// - `Commit`: dos `fsync` por commit. Pérdida máxima: el commit en vuelo.
/// - `Interval(d)`: `fsync` como mucho cada `d`. Pérdida máxima: los
///   commits de la última ventana.
/// - `Never`: ningún `fsync` por commit. Pérdida máxima: todo lo
///   confirmado desde el último `fsync` que el motor haya emitido por su
///   cuenta.
///
/// # Los dos `fsync` que el motor emite pase lo que pase
///
/// Ni `Interval` ni `Never` significan "cero `fsync`":
///
/// - **Para recuperar espacio.** Una página liberada no se puede volver a
///   repartir mientras la meta durable siga referenciándola, así que un
///   punto durable muy retrasado obliga a retener páginas libres — y bajo
///   `Never`, sin ningún `fsync`, a retenerlas para siempre: el fichero
///   crecería sin cota justo en el entorno donde el disco es más escaso.
///   El motor no deja que el punto durable se retrase más de
///   `MAX_DURABLE_LAG` transacciones: pasado ese punto paga UN `fsync` y
///   recupera de golpe todo lo liberado hasta ahí. Coste medido (2 000
///   commits sobre 200 claves, páginas de 512 B): 84 páginas frente a las
///   24 de `Sync::Commit` —un margen constante, no proporcional al
///   trabajo—, un 23 % más de escrituras físicas y 31 veces menos `fsync`.
///   Ver `relaxed_sync_costs_bounded_space_and_far_fewer_fsyncs` en
///   `tests/faults.rs`.
///
/// **Ya solo queda ese.** Hasta el cambio de diseño a nonces aleatorios
/// había un segundo `fsync` incondicional, uno por sesión: la reserva
/// duradera de contadores de nonce de una base cifrada. Con un prefijo
/// aleatorio nuevo en cada apertura no hay nada que reservar, así que una
/// base cifrada paga hoy exactamente las mismas sincronizaciones que una
/// sin cifrar — ver `a_reopened_encrypted_database_pays_no_extra_sync_at_all`
/// en `crypto.rs`.
///
/// # El límite que ningún modo relajado puede superar
///
/// Con `Interval`/`Never`, entre las páginas de un commit y su meta puede
/// no haber ningún `fsync`, así que nada impide que el sistema operativo
/// escriba la meta ANTES que las páginas que esa meta referencia. Si el
/// corte cae justo ahí, la base monta por una meta cuyas páginas nunca
/// llegaron al medio, y eso el motor no lo puede evitar: ordenar las dos
/// cosas es exactamente lo que hace el primer `fsync` de `Sync::Commit`.
/// Dicho al derecho: **el modo relajado no promete que el último commit
/// sobreviva entero; promete que lo que sobreviva no lo habrá estropeado
/// una transacción posterior.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sync {
    /// Un `fsync` de páginas y otro de meta por commit. Pérdida máxima en un
    /// corte: el commit en vuelo. Único modo que ordena las páginas de un
    /// commit por delante de su meta — ver el comentario del enum.
    Commit,
    /// Agrupa sincronizaciones. Pérdida máxima: los commits de la última
    /// ventana. Pensado para IoT, donde sincronizar cada escritura desgasta la
    /// memoria flash. Emite además el `fsync` de recuperación de espacio
    /// descrito en el comentario del enum si el ritmo de commits deja el
    /// punto durable más de `MAX_DURABLE_LAG` transacciones por detrás.
    Interval(Duration),
    /// Sin `fsync` por commit: solo los que el motor necesita para
    /// recuperar espacio — ver el comentario del enum. Una base cifrada paga
    /// exactamente los mismos que una sin cifrar: el `fsync` extra por
    /// contadores de nonce desapareció al pasar a nonces por apertura
    /// (`crypto::NonceStream`). Pensado para pruebas y bancos.
    Never,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub page_size: u32,
    pub sync: Sync,
    pub cache_pages: usize,
    /// Clave maestra y algoritmo para el cifrado por página (tarea 17).
    /// `None` (el valor por defecto): base sin cifrar, formato idéntico al
    /// de antes de esta tarea. Con la feature `encryption` desactivada, el
    /// tipo `Encryption` no es alcanzable fuera del crate (ver `lib.rs`),
    /// así que en la práctica solo puede llegar aquí `None` — `Db::create`/
    /// `open` fallan alto con `Error::BadFormat` si alguna vez no fuera
    /// así (ver su comentario), en vez de cifrar en silencio con una
    /// implementación que no está compilada.
    pub encryption: Option<Encryption>,
    /// Tope de tamaño de la base, en PÁGINAS. `None` (el valor por defecto)
    /// es el comportamiento de siempre: el único límite es el contador de
    /// 32 bits, 2 TB con páginas de 512 B.
    ///
    /// **En páginas y no en bytes** porque es la única unidad que el motor
    /// cuenta: `Meta::n_pages` ya existe y ya es el número contra el que se
    /// comprueba el desbordamiento. Un tope en bytes habría que redondearlo
    /// a la baja al múltiplo de página en cada asignación.
    ///
    /// **Se compara contra el máximo histórico, no contra las páginas
    /// vivas.** El fichero no encoge al podar: las páginas vuelven a la
    /// lista de libres y se reutilizan, pero `n_pages` solo lo baja
    /// `Db::reclaim_tail`. Un tope contra el espacio en uso daría por bueno
    /// un fichero que ya ocupa el doble en disco.
    ///
    /// Reciclar nunca choca contra el tope: solo lo comprueba la rama de
    /// `WriteTxn::alloc` que extiende el fichero. Ver ahí la reserva que
    /// mantiene podable una base llena.
    pub max_pages: Option<u32>,
}

impl Default for Options {
    fn default() -> Self {
        // `cache_pages: 4`, no 32 (17-08-2026). Medida la curva entera en
        // `tests/page_size.rs`, de la cuarta página en adelante la caché no
        // evita ni una sola lectura más —1,02 por búsqueda con 200.000
        // entradas, 1,26 con 2,5 millones, iguales con 4 que con 256— porque
        // las hojas no se reutilizan y los nodos internos que sí caben en
        // cuatro páginas. Y en el camino de escritura el tamaño de caché no
        // cambia nada, ni un byte: el copy-on-write escribe cada página en un
        // número nuevo, así que no hay nada que cachear.
        //
        // Con 4, la RAM por base baja de 21,9 a 4,9 KB con páginas de 512 B y
        // de 271 a 19,3 KB con las de 4 KB (medido, no derivado del modelo),
        // que es lo que pone los dos
        // criterios de salida de RAM de la fase 2 por debajo del tope sin
        // tocar una línea de motor. Ver `the_default_cache_is_four_pages`.
        Self { page_size: 512, sync: Sync::Commit, cache_pages: 4, encryption: None, max_pages: None }
    }
}

/// Transacciones que el punto durable (`Db::durable`) puede quedarse por
/// detrás de la meta confirmada antes de que el motor pague UN `fsync`
/// para ponerlo al día. Ver `Db::reclaim_needs_a_sync`.
const MAX_DURABLE_LAG: TxnId = 16;

pub struct Db {
    pager: Pager,
    /// La meta CONFIRMADA y la ranura donde vive, siempre fieles byte a
    /// byte a lo que hay en el fichero: esto es exactamente lo que
    /// devolvería un `Meta::load` ahora mismo, nunca un estado "mejorado"
    /// en memoria.
    ///
    /// **No es una sutileza de estilo** (tarea 17, tercera ronda de
    /// revisión, hallazgo MEDIUM). Lo era menos aún cuando existía la
    /// extensión del techo de contador de nonce, que copiaba esta meta y la
    /// ESCRIBÍA en el fichero a mitad de una transacción, sin ningún commit
    /// de por medio: cualquier campo que aquí valiera más de lo que hay en
    /// disco se publicaba como si estuviera confirmado. Eso es justo lo que
    /// pasaba con `n_pages`: `Db::open` lo subía hasta la extensión real
    /// del fichero (las páginas recuperadas de una transacción
    /// interrumpida) y lo guardaba aquí, mientras esas páginas vivían solo
    /// en la lista de libres EN MEMORIA — así que una extensión seguida de
    /// un aborto dejaba en disco un `n_pages` alto con una lista de libres
    /// que no poseía la diferencia, y esas páginas se perdían para siempre.
    /// Doce ciclos abrir-extender-abortar: `n_pages` de 10 a 22, doce
    /// páginas fugadas, sin cota.
    ///
    /// Esa escritura de meta fuera de un commit ya no existe, así que el
    /// campo no puede publicar nada por ese camino; la invariante se
    /// mantiene igual porque sigue siendo la que hace que `Db::committed`
    /// signifique lo que dice — y porque el siguiente camino que escriba
    /// meta fuera de un commit volvería a necesitarla. La extensión
    /// recuperada
    /// vive ahora en `WriterState::n_pages_floor`, que es donde de verdad
    /// pertenece: es el punto de partida de la PRÓXIMA transacción, no algo
    /// que ya esté confirmado.
    committed: RwLock<(Meta, MetaSlot)>,
    /// Punto DURABLE: el último `txn_id` cuya meta se ha demostrado en
    /// disco, con la extensión que tenía el fichero en ese instante.
    ///
    /// **No es `committed`, y confundirlos era el defecto que esta
    /// corrección cierra.** `committed` es la última meta ESCRITA; bajo
    /// `Sync::Interval`/`Never` una escritura de meta puede llevar mucho
    /// tiempo sin sincronizarse, así que la meta que un corte de corriente
    /// deja como superviviente puede ir varias transacciones por detrás.
    /// La regla de reutilización de la lista de libres — una página
    /// liberada en la transacción N sigue viva para cualquier lector cuyo
    /// snapshot sea anterior a N — cuenta la meta confirmada como lector
    /// implícito, y ese lector implícito es el que MONTARÍA tras un corte:
    /// el durable, no el escrito. Con el escrito como suelo, `alloc`
    /// repartía páginas que el árbol durable seguía referenciando y el
    /// escritor las sobrescribía; tras el corte, la meta superviviente
    /// describía un árbol con agujeros — claves confirmadas y reconocidas
    /// decenas de commits antes devueltas como `None`, y claves de commits
    /// muy posteriores devueltas como si fueran suyas. Ver
    /// `a_power_cut_that_keeps_data_pages_but_loses_the_last_metas_leaves_a_whole_snapshot`
    /// (`tests/faults.rs`).
    ///
    /// **Era exactamente el mismo razonamiento que `counter_ceiling`**, el
    /// techo de contador de nonce que vivía en `WriterState` hasta el
    /// cambio a nonces aleatorios: aquel campo se negaba a avanzar con la
    /// escritura de meta de un commit normal porque «bajo
    /// `Sync::Interval`/`Never` puede no haberse hecho durable todavía», y
    /// solo aceptaba avances ya demostrados en disco. Este campo es esa
    /// misma regla aplicada a la reutilización de páginas: solo avanza tras
    /// un `sync()` que devolvió `Ok` (ver `Db::sync_upto`, el ÚNICO sitio
    /// que lo mueve). Aquel desapareció con su aparato entero; este sigue,
    /// porque la corrección del reciclado de páginas no tiene nada que ver
    /// con el cifrado.
    ///
    /// `n_pages` es la extensión del fichero en el momento de ese avance:
    /// es la base contra la que `reclaim_needs_a_sync` mide cuánto ha
    /// crecido el fichero por no poder reciclar todavía. Ver ahí el
    /// porqué de que exista un presupuesto en vez de sincronizar en cuanto
    /// haga falta una página.
    durable: AtomicU64,
    write_lock: Mutex<Option<WriterState>>,
    readers: Mutex<BTreeMap<TxnId, u32>>,
    sync: Sync,
    /// Tope de páginas de esta apertura (`Options::max_pages`). Es política
    /// del proceso que abre, no del fichero: no se escribe en la meta ni se
    /// hereda al reabrir, así que una base que llegó a su tope se puede
    /// abrir sin él —para leerla, para migrarla, para subirle el plan— sin
    /// tocar un solo byte del formato.
    ///
    /// **`page_cap` y no `max_pages`**, aunque la opción pública se llame
    /// así: `PageSource::max_pages` ya existe en este mismo fichero y
    /// significa lo contrario —cuántas páginas TIENE el fichero, la cota
    /// para leer— y dos campos con el mismo nombre y sentidos opuestos es
    /// una trampa que alguien pisa.
    page_cap: Option<u32>,
    last_sync: Mutex<Instant>,
    /// Índices registrados en este proceso (tarea 16). Vacío hasta que el
    /// llamante invoca `define_index`; nunca se relee solo de disco — cada
    /// apertura debe volver a registrar sus índices, porque el extractor es
    /// código del llamante y no vive en el fichero.
    ///
    /// Que esté vacío **no** significa que la base no tenga índices, y
    /// confundir las dos cosas era el defecto que cierra `catalog_indexes`,
    /// justo debajo.
    indexes: Mutex<Vec<IndexDef>>,
    /// Pares `(id, ns)` que el catálogo DURABLE declara, leídos del fichero
    /// —no de `indexes`— la primera vez que alguien escribe. `None` mientras
    /// no se hayan leído todavía.
    ///
    /// **Por qué existe.** `indexes` arranca vacío en CADA apertura y solo
    /// lo puebla `define_index`, que exige un `extract` que el fichero no
    /// puede guardar. Un proceso que abre la base sin declarar nada tenía,
    /// hasta esta corrección, una lista vacía indistinguible de "esta base
    /// no tiene índices": `put` se iba por `put_raw` y guardaba la fila sin
    /// entrada de índice, `delete` borraba la fila y dejaba la suya
    /// huérfana, y `delete_range` huerfanaba el rango entero de una vez —
    /// su rechazo `DeleteRangeIndexed` (tarea 16) no llegaba a dispararse
    /// jamás. Nada de eso fallaba ni se notaba en el momento: la divergencia
    /// aparecía en OTRA apertura, la que sí declara sus índices, como una
    /// respuesta equivocada de `scan_index` en las dos direcciones — claves
    /// primarias de filas ya borradas, y ausencia de filas ya insertadas.
    /// `audit_pages` no lo ve y no puede verlo: cada página sigue teniendo
    /// exactamente un dueño; lo que está muerto es el SIGNIFICADO de las
    /// entradas, no su contabilidad de espacio. El caso de uso donde más
    /// duele es el que este motor prioriza: un podador por retención no
    /// tiene ningún motivo para declarar índices —no tiene el extractor— y
    /// es justo el que borra a diario.
    ///
    /// El catálogo no basta para MANTENER un índice (falta `extract`), pero
    /// sí para saber que existe; con eso el motor puede negarse — ver
    /// `WriteTxn::refuse_undeclared`.
    ///
    /// **Perezoso a propósito, no por comodidad.** Leerlo en `Db::open`
    /// costaría un descenso hasta la hoja más a la izquierda del árbol (el
    /// catálogo es `ns` 0x00, las claves más pequeñas que existen), y ese
    /// descenso crece con la PROFUNDIDAD del árbol, es decir con el tamaño
    /// de la base — exactamente lo que el criterio de salida de la
    /// especificación prohíbe y lo que fijan
    /// `open_costs_the_same_on_a_small_and_a_large_file` (aquí abajo,
    /// `read_count() <= 4`) y `opening_costs_the_same_at_thirty_kilobytes_..`
    /// (`tests/size.rs`, `assert_eq!(small, large)` con 500 y 200 000
    /// entradas). Leyéndolo perezosamente, abrir cuesta exactamente lo mismo
    /// que antes de esta corrección: cero lecturas de más, medido en
    /// `opening_a_database_never_reads_the_catalog`. Quien solo lee no lo
    /// paga nunca; quien escribe lo paga UNA vez por apertura.
    ///
    /// **Y además resuelve la apertura degradada.** `Db::open` ya degrada
    /// con gracia una lista de libres ilegible en vez de negarle la entrada
    /// a un fichero por lo demás legible (ver su comentario). Un catálogo
    /// ilegible en `open` no admitiría ese trato: degradar a "asumo que no
    /// hay índices" es literalmente el defecto que esto corrige, y negarse a
    /// abrir contradiría esa política. Leyéndolo aquí, la disyuntiva
    /// desaparece — la apertura no lo toca (los lectores siguen abriendo y
    /// leyendo), y si el catálogo no se deja leer, el error sale por donde
    /// tiene que salir: la ESCRITURA que necesitaba saberlo falla, y este
    /// campo se queda en `None` para que la siguiente lo reintente.
    catalog_indexes: Mutex<Option<Vec<(u8, u8)>>>,
}

/// Estado que sobrevive entre transacciones de escritura: la lista de libres
/// no se relee de disco en cada una.
struct WriterState {
    freelist: Freelist,
    /// Flujo de nonces de ESTA apertura: el prefijo aleatorio de 16 bytes
    /// que se sorteó al abrir más el contador de escrituras desde entonces
    /// (`crypto::NonceStream`). `None` en una base sin cifrar, donde no se
    /// sella ninguna página.
    ///
    /// **Estado de la BASE, no de una transacción** — vive aquí, no en
    /// `WriteTxn`, precisamente para que sobreviva a un aborto sin
    /// rebobinar: `WriteTxn::Drop` restaura `freelist` desde
    /// `pre_freelist`, pero NUNCA toca esto. Es justo esa propiedad — el
    /// contador no retrocede ni cuando una transacción se descarta sin
    /// `commit` — la que impide que un aborto vuelva a repartir un nonce
    /// que una transacción muerta ya usó para sellar páginas que sí
    /// llegaron al medio.
    ///
    /// **Y ya no hace falta nada más que esto.** Hasta el cambio a nonces
    /// aleatorios, aquí vivían DOS campos: el contador vivo y un
    /// `counter_ceiling`, el techo hasta el que podía crecer sin otra
    /// escritura duradera, respaldado por `Meta::write_counter` en disco y
    /// extendido por `Db::extend_counter_ceiling` con dos escrituras de
    /// meta y dos `fsync` incondicionales. Todo aquello existía por una
    /// sola razón: tras una caída no había forma de saber cuántos
    /// contadores había quemado la sesión muerta, y reiniciar en cero
    /// habría repetido nonces. Con un prefijo aleatorio nuevo en cada
    /// apertura, la sesión siguiente vive en otro espacio de nonces por
    /// completo, así que reiniciar el contador en cero es seguro por
    /// construcción y no queda nada que persistir, extender ni sincronizar.
    nonce_stream: Option<crate::crypto::NonceStream>,
    /// Suelo de `n_pages` para la próxima transacción: la extensión REAL
    /// del fichero tal como la vio `Db::open`, incluidas las páginas que
    /// dejó una transacción interrumpida y que la recuperación metió en
    /// `freelist` (tarea 17, tercera ronda de revisión — ver el comentario
    /// del campo `Db::committed`).
    ///
    /// Vive aquí, y no en la meta confirmada, porque describe el estado del
    /// FICHERO, no el del último commit: `alloc` no puede repartir por
    /// extensión desde un `n_pages` que ya se quedó corto — entregaría por
    /// segunda vez una página que la lista de libres en memoria también va
    /// a ofrecer — pero tampoco puede escribirse en disco como si estuviera
    /// confirmado mientras la lista de libres que lo respalda solo existe
    /// en memoria. `begin_write` toma el máximo de los dos, así que la
    /// transacción arranca con la cota correcta y solo un commit real —
    /// que sí vuelca la lista de libres a disco a la vez — llega a
    /// grabarla.
    n_pages_floor: u32,
}

/// Última página del prefijo FIJO reservado del fichero: la cabecera es la
/// página `0` y la meta A la `1`, y ninguna de las dos cambia jamás de sitio
/// ni vuelve nunca a la circulación. Ninguna página `<= 1` es, por tanto, un
/// número de página legítimo en NINGÚN sitio donde el motor lea uno del
/// disco: ni como hijo de un nodo interno (`tree::validate_child`), ni como
/// entrada de la lista de libres (`freelist::PageDomain`), ni como raíz
/// (`Db::check_meta_against_file`).
///
/// Constante y no solo el método `WriteTxn::last_reserved_page` (que ahora
/// la devuelve): los otros dos sitios que la necesitan no tienen —ni deben
/// tener— un `WriteTxn` a mano; la lista de libres se decodifica con un
/// `Pager` y la meta se valida antes de que exista ninguna transacción.
pub(crate) const LAST_RESERVED_PAGE: PageNo = 1;

/// Páginas que `Db::open` acepta reconciliar por encima de las que la meta
/// declara — la cola que dejó una transacción interrumpida (ver el bucle de
/// recuperación en `open`).
///
/// **Existe porque ese bucle cuesta memoria proporcional a un número que
/// sale del medio de almacenamiento**, no del motor: una entrada de lista de
/// libres manipulada que hiciera escribir a un offset de terabytes deja el
/// fichero (disperso, sin ocupar disco de verdad) con miles de millones de
/// páginas, y reabrirlo pedía una entrada de lista de libres por cada una —
/// del orden de 10 GB de `VecDeque` para un fichero con 15 páginas de datos
/// reales. El proceso moría en el `Db::open`, así que la base quedaba
/// inservible para siempre: ninguna herramienta del propio motor
/// (`audit_pages` incluida) llegaba a ejecutarse, porque `open` es la
/// puerta.
///
/// **Por qué 2^20 y no una cota derivada.** No hay ninguna cota estructural:
/// una transacción legítima puede extender el fichero tanto como pida el
/// valor que esté escribiendo, así que cualquier número aquí es una
/// decisión de ingeniería y no un teorema. 1 048 576 páginas son 512 MB con
/// páginas de 512 B (4 GB con páginas de 4 KB) de extensión NO confirmada, y
/// como mucho 4 MB de `VecDeque` mientras dura la reconciliación. El banco
/// más grande que este proyecto se mide a sí mismo (un millón de registros,
/// `tests/size.rs`) ocupa del orden de 66 000 páginas: quince veces por
/// debajo de esta cota, así que una carga masiva interrumpida a mitad se
/// reconcilia entera sin acercarse. Por encima, la desproporción entre lo
/// que la meta declara y lo que el fichero mide deja de ser plausible como
/// "transacción interrumpida" y se trata como lo que es: corrupción, con
/// `Err`, que es el desenlace que el motor promete para una entrada corrupta.
const MAX_RECOVERABLE_TAIL: u32 = 1 << 20;

/// Página de la meta B al crear la base (tarea 18). Siempre la página 2, sin
/// importar `page_size`: es el suelo de 1,5 KB (cabecera + meta A + meta B,
/// tres páginas). Con páginas de 4 KB o más eso YA cae en un sector físico
/// distinto al de la meta A (página 1) — ver `WriteTxn::final_meta_b_page` —
/// así que esas bases nunca reubican. Con páginas más pequeñas comparte
/// sector con la meta A hasta que el fichero crece más allá de 4 KB, momento
/// en el que `WriteTxn::relocate_meta_b` la traslada a su sitio definitivo.
const INITIAL_META_B_PAGE: PageNo = 2;

impl Db {
    pub fn create(storage: Box<dyn Storage>, opts: Options) -> Result<Self> {
        if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&opts.page_size)
            || !opts.page_size.is_power_of_two()
        {
            return Err(Error::BadFormat);
        }
        // Fijo en la creación (ver `header::FLAG_ENCRYPTED`): activar el
        // cifrado más tarde exigiría reescribir todas las páginas ya
        // existentes, así que la decisión se toma aquí y no se revisita.
        let flags = if opts.encryption.is_some() { FLAG_ENCRYPTED } else { 0 };
        let geometry = Geometry {
            page_size: opts.page_size,
            format_major: FORMAT_MAJOR,
            format_minor: 0,
            flags,
            db_id: db_id(),
            created_unix: now_unix(),
            meta_a_page: 1,
            meta_b_page: INITIAL_META_B_PAGE,
        };
        geometry.write(storage.as_ref())?;

        let mut meta = Meta {
            txn_id: 1,
            root: 0,
            catalog_root: 0,
            freelist_head: 0,
            freelist_tail: 0,
            n_pages: INITIAL_META_B_PAGE + 1,
            page_size_log2: opts.page_size.trailing_zeros() as u8,
            format_major: FORMAT_MAJOR,
            flags,
            wrapped_key: None,
        };
        // Genera la clave de datos y la envuelve con la maestra ANTES de
        // guardar la meta: `meta.wrapped_key` tiene que estar ya poblado
        // para que las dos ranuras se escriban con él.
        let encryption = Self::init_data_key(&opts, &mut meta)?;

        // El prefijo de nonce se sortea aquí, una vez, exactamente igual
        // que en `Db::open`: una base recién creada y una reabierta son la
        // misma situación desde el punto de vista del cifrado — cada
        // apertura estrena su propio espacio de nonces y arranca el
        // contador en cero. Ver `WriterState::nonce_stream`.
        //
        // **Antes de escribir las metas, no después** (lo era hasta la meta
        // autenticada): el sellado de cada ranura saca su nonce de este
        // mismo flujo, así que tiene que existir ya. Los dos primeros
        // nonces de la vida del fichero se van en las dos ranuras de aquí
        // abajo; la primera página sellada estrena el tercero.
        let mut writer_state = WriterState {
            freelist: Freelist::empty(),
            nonce_stream: Self::new_nonce_stream(encryption.is_some())?,
            // Fichero recién creado: no hay ninguna página más allá de lo
            // que la meta ya declara, así que el suelo coincide con ella.
            n_pages_floor: meta.n_pages,
        };

        // Ambas ranuras se inicializan para que la primera apertura encuentre
        // una meta válida pase lo que pase. Con el MISMO contenido pero
        // sellados DISTINTOS: cada tag ata su ranura a su letra (ver
        // `MetaSlot::index`), así que las dos son idénticas byte a byte en
        // 0..108 y distintas en 108..152.
        for slot in [MetaSlot::A, MetaSlot::B] {
            let seal = Self::seal_meta_for(
                encryption.as_ref(),
                writer_state.nonce_stream.as_mut(),
                &geometry,
                &meta,
                slot,
            )?;
            meta.store(storage.as_ref(), &geometry, slot, seal.as_ref())?;
        }
        storage.sync()?;
        Ok(Self::assemble(storage, geometry, meta, MetaSlot::A, opts, writer_state, encryption))
    }

    pub fn open(storage: Box<dyn Storage>, opts: Options) -> Result<Self> {
        let (geometry, used_mirror) = Geometry::read_reporting_fallback(storage.as_ref())?;
        // Repara la principal cuando hubo que caer al espejo (ronda de
        // revisión posterior a la corrección del hallazgo HIGH de la tarea
        // 18): sin esto, sobrevivir a UN desgarro de cabecera gasta la
        // redundancia entera y no la devuelve — la base sigue abriendo, pero
        // desde ese momento corre sobre una sola copia legible de la
        // geometría para siempre, sin que nadie lo note, hasta que un
        // segundo fallo (un sector malo, otro corte que también alcance a
        // la principal si algún día volviera a escribirse) la deja
        // inservible sin ningún aviso previo. Reparar aquí restaura la
        // redundancia de inmediato, en la sesión que la descubre, no "algún
        // día si hay suerte y llega otra escritura de cabecera" — que
        // podría no llegar nunca (la cabecera no vuelve a tocarse tras la
        // única reubicación de la vida del fichero).
        //
        // Sincroniza DE INMEDIATO, no "a caballo del próximo commit": una
        // sesión de solo lectura puede no hacer ningún commit jamás, y
        // dejar la reparación sin sincronizar hasta un commit que quizá
        // nunca llegue es exactamente la misma ventana de vulnerabilidad
        // que esta reparación existe para cerrar — solo que trasladada de
        // "para siempre" a "hasta que alguien escriba, si alguien lo hace".
        // El coste es una escritura y un `sync` MÁS, solo en esta ruta de
        // excepción (un desgarro de cabecera es un evento raro, no el
        // camino común que sí importa mantener a coste constante — ver
        // `open_costs_the_same_on_a_small_and_a_large_file`, que sigue
        // midiendo el camino SIN reparación).
        //
        // **Oportunista, nunca de carga (regresión hallada tras la entrega
        // de esta ronda, corregida aquí).** La base ya es plenamente
        // usable con la geometría que se acaba de leer del espejo — no
        // hace falta nada más para abrir. La primera versión de esto
        // propagaba el error de `write`/`sync` con `?`, así que un medio de
        // solo lectura (o cualquier fallo de E/S en esa escritura, sector
        // dañado en la posición de la principal incluido) convertía una
        // apertura que antes funcionaba — sin reparación, esta ruta nunca
        // escribía nada — en un `Err` que le niega la base entera a quien
        // llama, aunque el fichero sea perfectamente legible y el espejo ya
        // haya dado una geometría válida. Un motor que se niega a abrir un
        // fichero legible porque no puede REPARARLO es peor que el defecto
        // que la reparación soluciona (gastar la redundancia sin
        // devolverla, ver más arriba). Si falla, el fichero se queda en el
        // mismo estado degradado de una sola copia legible en el que ya
        // estaba un instante antes — ni mejor ni peor que no haber
        // intentado nada — y la reparación se reintenta en la próxima
        // apertura, con las mismas condiciones.
        //
        // No se registra el fallo en ningún sitio: este crate no tiene
        // ninguna facilidad de log y añadir una solo para este caso sería
        // una mecánica nueva por una señal sin nadie que la consuma —
        // `Db::open` ya devuelve `Ok`, que es toda la información que
        // quien llama puede accionar (la base abrió), y el propio diseño
        // ya garantiza convergencia eventual (se reintenta sola) sin que
        // ninguna parte del motor necesite saber que el intento anterior
        // falló para seguir funcionando.
        if used_mirror {
            let _ = geometry.write(storage.as_ref()).and_then(|()| storage.sync());
        }
        // **La selección de ranura y el desenvolvimiento de la clave son el
        // MISMO paso desde la meta autenticada**, y tienen que serlo: una
        // ranura no es aceptable hasta que su tag valida, y su tag no se
        // puede comprobar sin la clave que ella misma lleva envuelta. Ver
        // `Meta::load_verified` para el orden completo y para por qué eso no
        // es un círculo vicioso.
        //
        // La clave se desenvuelve además ANTES de construir el `Pager`
        // provisional que lee la lista de libres, no solo el definitivo de
        // `assemble`: si la base está cifrada, sus páginas de lista de
        // libres también lo están (`Freelist::flush` usa
        // `Pager::write_encrypted`, ver `freelist.rs`), así que ese `Pager`
        // provisional necesita la misma clave para poder leerlas.
        //
        // Coste: se desenvuelve UNA vez —exactamente las mismas que antes
        // de este cambio, porque `accept` corre sobre la ranura ganadora y
        // sobre ninguna otra— y se verifica UN tag sobre 108 bytes de datos
        // asociados. Ni una lectura de más: `load_verified` lee las dos
        // ranuras, que es lo que `Meta::load` ya leía. El criterio de
        // `open_costs_the_same_on_a_small_and_a_large_file` no se mueve.
        let mut encryption = None;
        let (mut meta, slot) =
            Meta::load_verified(storage.as_ref(), &geometry, &mut |meta, raw, slot| {
                let enc = Self::open_data_key(&opts, meta)?;
                Self::verify_meta_slot(enc.as_ref(), &geometry, raw, slot)?;
                encryption = enc;
                Ok(())
            })?;
        let pager = Pager::new(storage, geometry, opts.cache_pages).with_encryption(encryption);

        // **LA FRONTERA DE VALIDACIÓN DE LA META.** Se toma la extensión
        // REAL del fichero UNA vez, aquí, antes de que ningún campo de la
        // meta se use para dimensionar nada ni para direccionar nada, y se
        // contrasta la meta contra ella (`check_meta_against_file`, ver su
        // comentario para qué se comprueba y por qué).
        //
        // Antes de esto, `file_pages` se leía DESPUÉS de montar la lista de
        // libres y se usaba en una sola dirección: subir `n_pages` hasta la
        // extensión real cuando el fichero tenía más páginas de las que la
        // meta declaraba. La dirección contraria —la meta declara MÁS
        // páginas de las que el fichero tiene— no se miraba, y era la que
        // sostenía media clase de defectos: `alloc` repartía `n_pages` como
        // página nueva y `Pager::write` escribía a `n_pages * page_size`,
        // a terabytes del dato real, mientras `audit_pages` reservaba un
        // `Vec` de `n_pages` entradas. Ninguna de las dos cosas necesitaba
        // más que este `>` para cerrarse.
        //
        // **Aquí, y no en cada uso.** El coste es una llamada a
        // `Storage::len` (que esta función ya hacía unas líneas más abajo,
        // para otra cosa) y tres comparaciones, una sola vez por apertura:
        // no crece con el tamaño de la base, así que el criterio de salida
        // que fija `open_costs_the_same_on_a_small_and_a_large_file` sigue
        // intacto — no se lee ni una página de más. Y a partir de aquí
        // `meta.n_pages` es un número CONTRASTADO con el fichero, no un
        // dato de disco cualquiera: eso es lo que deja que el resto del
        // motor lo use como cota sin volver a tocar el medio (ver
        // `PageSource::max_pages` y `tree::read_overflow`).
        let file_pages = pager.file_pages()?;
        Self::check_meta_against_file(&meta, file_pages, slot.page(&geometry))?;

        // Degrada con gracia si la cadena heredada no decodifica, en vez de
        // propagar el error con `?` (tarea 19, autorrevisión tras el hallazgo
        // de las pruebas basadas en propiedades).
        //
        // **El escenario que motivó esto ya está cerrado en origen.** Se
        // escribió porque `Freelist::flush` reciclaba, dentro de la misma
        // sesión, el contenedor físico que su propio `flush` anterior había
        // escrito (ver `written_head` en `freelist.rs`) más rápido de lo que
        // una meta antigua todavía "vigente" podía tolerar: bajo
        // `Sync::Never` o un `Sync::Interval` largo, la meta que sobrevive a
        // un corte puede quedarse varias transacciones atrás de la última
        // escrita, y esa meta vieja seguía señalando como
        // `freelist_head`/`freelist_tail` una página cuyo contenedor físico
        // una transacción posterior —nunca sincronizada, así que invisible
        // para esta apertura— ya había reasignado como página de datos. La
        // pérdida no era pequeña: un caso real medido dejó 27 de 56 páginas
        // (48 %) huérfanas para siempre tras degradar. Eso ya no puede
        // ocurrir: el suelo de reutilización es la meta DURABLE, no la
        // última escrita (ver el campo `Db::durable`), así que nada de lo
        // que la meta que montaría tras un corte referencia —cadena de
        // libres incluida— se reparte.
        //
        // Se conserva como defensa en profundidad, no como red de un
        // reciclado que se sabía imprudente: una cadena puede dejar de
        // decodificar por un medio que devuelve basura o un fichero
        // manipulado, y negarse a abrir por eso sería el mismo error que la
        // reparación de cabecera de más arriba existe para evitar — un
        // fichero por lo demás legible al que el motor le niega la entrada
        // porque una pieza de contabilidad no cuadra. Cubierto por su
        // prueba directa,
        // `an_unreadable_freelist_chain_does_not_keep_the_database_from_opening`
        // (abajo), que ataca la cadena a propósito: las pruebas de corte de
        // corriente que antes llegaban aquí de rebote ya no lo hacen, y
        // dejar la rama sin cobertura confiando en que sí lo hacen sería el
        // patrón de siempre. Solo `Corrupt` se trata así — un `IoError` del
        // medio subyacente (lectura fallida de verdad, no una página con el
        // tipo cambiado) sigue siendo fatal, porque ahí no hay ninguna base
        // razonable para asumir contabilidad en vez de un fallo real del
        // almacenamiento.
        let mut freelist = match Freelist::load(&pager, meta.freelist_head, meta.freelist_tail) {
            Ok(f) => f,
            Err(Error::Corrupt { .. }) => {
                // Pone a cero `freelist_head`/`freelist_tail` en la META EN
                // MEMORIA, no solo la variable local `freelist` (hallazgo
                // HIGH de la ronda de revisión de la tarea 19): esta `meta`
                // es la que `Self::assemble`, más abajo, publica tal cual en
                // `Db::committed` — sin este ajuste, `self.committed`
                // seguiría señalando la cadena irrecuperable aunque
                // `freelist` (la estructura en memoria) ya la hubiera dado
                // por perdida, y `db.audit_pages()` —llamado justo después
                // de un `open` que acaba de tener éxito— fallaría con
                // `Err(Corrupt)` al intentar recorrer esa misma cadena
                // muerta desde disco: la comprobación de integridad
                // reportando corrupción sobre un fichero que `open` acaba
                // de aceptar como bueno. `n_pages` no se toca: las páginas
                // de esa cadena siguen contando para él (son físicamente
                // reales), solo dejan de estar señaladas como "la lista de
                // libres" — la reconciliación de la sección de abajo (que
                // ya barre `[meta.n_pages, file_pages)`) no las alcanza
                // porque siguen por DEBAJO de `n_pages`, así que quedan
                // perdidas de verdad — hasta el 48 % del fichero en el caso
                // medido que documenta el comentario de más arriba, no un
                // puñado de páginas — pero no corruptas.
                meta.freelist_head = 0;
                meta.freelist_tail = 0;
                Freelist::empty()
            }
            Err(e) => return Err(e),
        };

        // Recuperación: las páginas más allá de `n_pages` las escribió una
        // transacción que nunca confirmó. Nadie las referencia y ningún lector
        // puede verlas, así que son reutilizables de inmediato — etiqueta 0.
        //
        // Salta la página destino de la reubicación de la meta B (tarea 18,
        // hallazgo BLOCKER de revisión): este bucle es un TERCER sitio que
        // reparte números de página — además de `alloc` y del cierre de
        // `commit` que serializa la lista de libres, los dos ya protegidos
        // con `skip_meta_b_target` — y la propia escritura de
        // `relocate_meta_b` en la posición nueva extiende el fichero hasta
        // esa página (offset `final_meta_b_page * page_size`) antes de que
        // la cabecera cambie o la transacción confirme. Un corte justo ahí
        // dejaba `meta.n_pages` (de la última confirmación real) a
        // `file_pages` (que ya incluye la página destino) apuntando de lleno
        // a ella: sin este salto, la recuperación la mete en la lista de
        // libres, `alloc` la reparte con normalidad, el árbol la usa como
        // dato, y la siguiente reubicación le escribe meta encima —
        // corrupción silenciosa que sobrevive a la reapertura. Confirmado de
        // punta a punta con
        // `reopening_after_a_crash_during_relocation_never_recovers_the_relocation_target_into_the_freelist`.
        //
        // El recorrido está acotado por `check_meta_against_file`, más
        // arriba: sin esa cota, este bucle es trabajo Y memoria
        // proporcionales a `file_pages`, un número que sale del medio de
        // almacenamiento — una entrada de lista de libres sin validar que
        // hiciera escribir a 1,37 TB dejaba el fichero con 2,7×10^9
        // páginas, y esta reconciliación pedía del orden de 10 GB de
        // `VecDeque` para reabrirlo. Ver `MAX_RECOVERABLE_TAIL`.
        let relocation_target = WriteTxn::final_meta_b_page(geometry.page_size);
        for p in meta.n_pages..file_pages {
            if p == relocation_target {
                continue;
            }
            freelist.push(p, 0);
        }

        // `n_pages` tiene que avanzar hasta la extensión real del fichero, y no
        // solo por higiene. Sin esto, en cuanto la lista de libres agote esas
        // páginas recuperadas, el camino de extensión de `alloc` volvería a
        // repartir desde el `n_pages` viejo y entregaría por segunda vez una
        // página que ya está en uso. Es corrupción silenciosa, no una fuga.
        //
        // Pero ese avance NO va a `meta` (tarea 17, tercera ronda de
        // revisión): la meta que se guarda en `self.committed` tiene que
        // seguir siendo byte a byte la que está en disco, porque
        // `Db::committed` tiene que seguir siendo byte a byte la meta que
        // hay en disco — ver su comentario y el de
        // `WriterState::n_pages_floor`. El suelo viaja en `WriterState` y
        // `begin_write` lo aplica.
        let n_pages_floor = core::cmp::max(meta.n_pages, file_pages);

        // Prefijo de nonce nuevo y contador desde cero, sin mirar nada de
        // lo que quedó en disco. **Es el cambio que hace innecesario todo
        // el aparato de techo de contador**: antes había que leer un techo
        // persistido y arrancar justo ahí, asumiendo el peor caso, porque
        // no había forma de saber cuánto del margen había quemado la sesión
        // anterior antes de morir. Ahora esta apertura estrena un espacio
        // de nonces propio —128 bits aleatorios de separación respecto a
        // CUALQUIER sesión anterior de este fichero, incluida la de una
        // copia de seguridad restaurada— así que lo que hiciera la sesión
        // previa no puede colisionar con lo que haga esta. Ver
        // `WriterState::nonce_stream` y el comentario del módulo `crypto`.
        let writer_state = WriterState {
            freelist,
            nonce_stream: Self::new_nonce_stream(encryption.is_some())?,
            n_pages_floor,
        };

        let storage = pager.into_storage();
        Ok(Self::assemble(storage, geometry, meta, slot, opts, writer_state, encryption))
    }

    /// Contrasta la meta recién leída con lo que el fichero ES: su longitud
    /// real, medida ahora mismo. Única frontera de validación de la meta,
    /// igual que `PageRef::parse` lo es de una página — y por el mismo
    /// motivo: todo lo que hay más abajo (`alloc`, `audit_pages`,
    /// `read_overflow`, la propia reconciliación de `open`) usa estos
    /// campos como si fueran números de página y cuentas de página de ESTE
    /// fichero, sin volver a preguntar.
    ///
    /// Lo que se comprueba, y por qué cada cosa:
    ///
    /// - **`n_pages > file_pages`**: un fichero no encoge por su cuenta. La
    ///   meta que dice tener más páginas de las que hay solo puede venir de
    ///   una manipulación (el CRC de la meta lo cubre, así que la
    ///   podredumbre de bits se detiene antes) o de un medio que miente. Es
    ///   el campo más peligroso de los cinco: `alloc` reparte `n_pages`
    ///   como página nueva por el camino de extensión, y `Pager::write`
    ///   calcula `page_no * page_size` sin más, así que un solo byte
    ///   cambiado aquí hacía que el primer `put` escribiera a cientos de
    ///   gigabytes del dato real (sobre un fichero de verdad, un fichero
    ///   DISPERSO que el commit acepta sin quejarse y que ya no se puede
    ///   reabrir); y `audit_pages` reservaba `vec![false; n_pages]`, 4,29 GB
    ///   de golpe con `n_pages = u32::MAX`. La comprobación vale para
    ///   bases CIFRADAS igual que para las demás, y sigue haciendo falta en
    ///   las dos aunque desde el formato 3 la meta de una base cifrada esté
    ///   autenticada: **esta frontera es la ÚNICA defensa de una base sin
    ///   cifrar**, donde no hay clave y por tanto no hay nada que
    ///   autenticar. En una base cifrada pasa a ser la segunda línea —el tag
    ///   rechaza la ranura antes de llegar aquí— pero cada una atrapa lo que
    ///   la otra no puede: el tag no sabe si un valor es plausible, y esta
    ///   comprobación no sabe si un valor plausible es auténtico. Ver
    ///   `tampering_tests::authenticated_meta`.
    ///
    /// - **`root` / `catalog_root` fuera del fichero**: una raíz que no
    ///   direcciona ninguna página real. Hoy degradan solas (leerla da
    ///   `UnexpectedEof` del medio, o `Corrupt` si esos bytes existen pero
    ///   no son una página del tipo esperado), así que esto no cierra
    ///   ningún fallo abierto — pero deja el criterio en un solo sitio en
    ///   vez de repartido entre "lo que pasa cuando alguien intenta leerla",
    ///   y convierte un `IoError` (que quien llama tiene que interpretar
    ///   como problema del disco) en `Corrupt` (que es lo que de verdad
    ///   es). `0` es el árbol vacío, y se acepta como tal.
    ///
    /// - **La cola por reconciliar**: ver `MAX_RECOVERABLE_TAIL`.
    ///
    /// `freelist_head`/`freelist_tail` NO se comprueban aquí a propósito:
    /// los valida `Freelist::load` contra su propio dominio de páginas (ver
    /// `PageDomain` en `freelist.rs`) para que un puntero de cadena
    /// imposible entre por la degradación con gracia que `open` ya tiene
    /// para una cadena ilegible —abrir la base y perder la lista— en vez de
    /// negarle la entrada a un fichero cuyo árbol está perfectamente sano.
    fn check_meta_against_file(meta: &Meta, file_pages: PageNo, meta_page: PageNo) -> Result<()> {
        let corrupt =
            Err(Error::Corrupt { page: meta_page, kind: crate::CorruptKind::MetaMismatch });
        if meta.n_pages > file_pages {
            return corrupt;
        }
        if file_pages - meta.n_pages > MAX_RECOVERABLE_TAIL {
            return corrupt;
        }
        for root in [meta.root, meta.catalog_root] {
            if root != 0 && (root <= LAST_RESERVED_PAGE || root >= file_pages) {
                return corrupt;
            }
        }
        Ok(())
    }

    /// Toma `WriterState` ya construido, no sus campos sueltos
    /// (`cargo clippy`, `too_many_arguments`: eran 8 parámetros cuando el
    /// contador de nonce vivía en dos campos aparte — agruparlos en el
    /// `WriterState` que de todos modos iban a formar los deja en 7).
    fn assemble(
        storage: Box<dyn Storage>,
        geometry: Geometry,
        meta: Meta,
        slot: MetaSlot,
        opts: Options,
        writer_state: WriterState,
        encryption: Option<Encryption>,
    ) -> Self {
        Self {
            pager: Pager::new(storage, geometry, opts.cache_pages).with_encryption(encryption),
            committed: RwLock::new((meta, slot)),
            // La meta con la que se monta ESTÁ en disco por definición —
            // `Db::create` la sincroniza antes de llegar aquí y `Db::open`
            // acaba de leerla del fichero — así que el punto durable
            // arranca exactamente ahí, sin necesitar ninguna
            // sincronización de más. (En `open`, `meta` puede llevar
            // `freelist_head`/`tail` puestos a cero por la degradación con
            // gracia; lo que este campo mira, `txn_id` y `n_pages`, sigue
            // siendo byte a byte lo que hay en el fichero.)
            durable: AtomicU64::new(meta.txn_id),
            write_lock: Mutex::new(Some(writer_state)),
            readers: Mutex::new(BTreeMap::new()),
            sync: opts.sync,
            page_cap: opts.max_pages,
            last_sync: Mutex::new(Instant::now()),
            indexes: Mutex::new(Vec::new()),
            // `None`, no `Some(Vec::new())`: "todavía no lo he leído" y "lo
            // he leído y no hay ningún índice" son estados distintos, y
            // confundirlos aquí sería repetir en pequeño el defecto que
            // `catalog_indexes` corrige — ver su comentario. Ni `create` ni
            // `open` tocan el catálogo: se lee en la primera escritura.
            catalog_indexes: Mutex::new(None),
        }
    }

    /// Genera una clave de datos nueva y la envuelve con la maestra de
    /// `opts.encryption`, si la hay; deja `meta.wrapped_key` lista para
    /// guardarse. Devuelve la clave de datos (ya en claro, para que el
    /// `Pager` de esta misma apertura pueda usarla) o `None` si `opts` no
    /// pide cifrado.
    #[cfg(feature = "encryption")]
    fn init_data_key(opts: &Options, meta: &mut Meta) -> Result<Option<Encryption>> {
        let Some(master) = &opts.encryption else { return Ok(None) };
        let data_key = crate::crypto::generate_data_key()?;
        let wrap_nonce = crate::crypto::generate_wrap_nonce()?;
        meta.wrapped_key = Some(crate::crypto::wrap_key(&master.key, &data_key, wrap_nonce)?);
        Ok(Some(Encryption { key: data_key, algorithm: master.algorithm }))
    }

    /// Sin la feature `encryption` no hay forma de generar ni envolver una
    /// clave — `opts.encryption` solo puede ser `Some` aquí si algo dentro
    /// del propio crate lo coló sin pasar por la reexportación pública
    /// (gateada, ver `lib.rs`), porque fuera del crate el tipo `Encryption`
    /// ni siquiera es nombrable en este build. Falla alto en vez de crear
    /// una base sin cifrar en silencio cuando el llamante pidió cifrado.
    #[cfg(not(feature = "encryption"))]
    fn init_data_key(opts: &Options, _meta: &mut Meta) -> Result<Option<Encryption>> {
        if opts.encryption.is_some() {
            return Err(Error::BadFormat);
        }
        Ok(None)
    }

    /// Desenvuelve la clave de datos guardada en `meta` con la maestra de
    /// `opts.encryption`. Compara la intención del llamante (`opts`) contra
    /// lo que dice el fichero (`meta.flags & FLAG_ENCRYPTED`) en las cuatro
    /// combinaciones posibles: sin cifrar de los dos lados es el caso
    /// normal; pedir clave sobre un fichero sin cifrar, o abrir uno cifrado
    /// sin dar clave, son errores de uso — el segundo con el mismo
    /// `Error::Decrypt` que una clave incorrecta, porque para quien llama
    /// es la misma situación de fondo: "no puedo leer estas páginas sin la
    /// clave correcta".
    #[cfg(feature = "encryption")]
    fn open_data_key(opts: &Options, meta: &Meta) -> Result<Option<Encryption>> {
        let file_is_encrypted = meta.flags & FLAG_ENCRYPTED != 0;
        match (&opts.encryption, file_is_encrypted) {
            (None, false) => Ok(None),
            (None, true) => Err(Error::Decrypt { page: 0 }),
            (Some(_), false) => Err(Error::BadFormat),
            (Some(master), true) => {
                let wrapped = meta.wrapped_key.ok_or(Error::Decrypt { page: 0 })?;
                let data_key = crate::crypto::unwrap_key(&master.key, &wrapped)?;
                Ok(Some(Encryption { key: data_key, algorithm: master.algorithm }))
            }
        }
    }

    /// Mismo razonamiento que `init_data_key` sin la feature: si el fichero
    /// dice estar cifrado, o si `opts` trae una clave, no hay nada útil que
    /// hacer sin `chacha20poly1305`/`aes-gcm` compiladas — falla alto.
    #[cfg(not(feature = "encryption"))]
    fn open_data_key(opts: &Options, meta: &Meta) -> Result<Option<Encryption>> {
        if opts.encryption.is_some() || meta.flags & FLAG_ENCRYPTED != 0 {
            return Err(Error::BadFormat);
        }
        Ok(None)
    }

    /// Sortea el prefijo de nonce de esta apertura, si la base está
    /// cifrada. UNA lectura de `/dev/urandom` por apertura — no por
    /// escritura, que es justo lo que este diseño evita (ver el comentario
    /// del módulo `crypto`) — y ninguna en una base sin cifrar.
    ///
    /// La llaman `Db::create` y `Db::open` por igual: para el cifrado las
    /// dos son lo mismo, "empieza una sesión nueva".
    #[cfg(feature = "encryption")]
    fn new_nonce_stream(encrypted: bool) -> Result<Option<crate::crypto::NonceStream>> {
        match encrypted {
            true => Ok(Some(crate::crypto::NonceStream::random()?)),
            false => Ok(None),
        }
    }

    /// Sin la feature, `encrypted` solo puede ser `false`:
    /// `init_data_key`/`open_data_key` (arriba) ya han fallado alto si
    /// alguien pidió cifrado o si el fichero dice estarlo. Devolver `None`
    /// sin más es correcto, no una omisión silenciosa.
    #[cfg(not(feature = "encryption"))]
    fn new_nonce_stream(_encrypted: bool) -> Result<Option<crate::crypto::NonceStream>> {
        Ok(None)
    }

    /// El sellado que le toca a `slot` con el contenido de `meta`, o `None`
    /// si la base no está cifrada.
    ///
    /// **Un único sitio para las CINCO escrituras de meta que existen**
    /// (las dos de `Db::create`, la del commit, la del segundo `store_via`
    /// del recorte y la de `relocate_meta_b`): un sellado olvidado en
    /// cualquiera de ellas produce una ranura que la apertura siguiente
    /// rechaza como manipulada, así que la forma de no olvidarlo es que
    /// escribir una meta sin pasar por aquí no compile — `Meta::store`/
    /// `store_via` exigen el parámetro.
    ///
    /// `Err` si la base está cifrada pero no hay flujo de nonces: sería un
    /// fallo interno (los dos campos nacen juntos en `WriterState`), y
    /// sellar con un nonce inventado es exactamente lo que no se puede
    /// hacer — ver `crypto::seal_meta`.
    #[cfg(feature = "encryption")]
    fn seal_meta_for(
        encryption: Option<&Encryption>,
        stream: Option<&mut crate::crypto::NonceStream>,
        geometry: &Geometry,
        meta: &Meta,
        slot: MetaSlot,
    ) -> Result<Option<crate::meta::MetaSeal>> {
        match (encryption, stream) {
            (None, _) => Ok(None),
            (Some(enc), Some(stream)) => Ok(Some(crate::crypto::seal_meta(
                enc,
                stream,
                &geometry.db_id,
                slot.index(),
                &meta.payload(),
            )?)),
            (Some(_), None) => Err(Error::BadFormat),
        }
    }

    /// Sin la feature no hay nada que sellar: `init_data_key`/
    /// `open_data_key` ya han fallado alto si alguien pidió cifrado o si el
    /// fichero dice estarlo, así que `encryption` solo puede ser `None`.
    #[cfg(not(feature = "encryption"))]
    fn seal_meta_for(
        encryption: Option<&Encryption>,
        _stream: Option<&mut crate::crypto::NonceStream>,
        _geometry: &Geometry,
        _meta: &Meta,
        _slot: MetaSlot,
    ) -> Result<Option<crate::meta::MetaSeal>> {
        match encryption {
            None => Ok(None),
            Some(_) => Err(Error::BadFormat),
        }
    }

    /// La otra mitad de `seal_meta_for`, sobre los bytes CRUDOS de la
    /// ranura tal como están en el plato — no sobre una recodificación de
    /// los campos decodificados, que dejaría los dos huecos reservados
    /// (32..40 y 100..108) fuera de la autenticación de hecho. Ver
    /// `crypto::meta_associated_data`.
    #[cfg(feature = "encryption")]
    fn verify_meta_slot(
        encryption: Option<&Encryption>,
        geometry: &Geometry,
        raw: &[u8],
        slot: MetaSlot,
    ) -> Result<()> {
        let Some(enc) = encryption else { return Ok(()) };
        let mut payload = [0u8; crate::meta::META_AUTH_END];
        payload.copy_from_slice(&raw[..crate::meta::META_AUTH_END]);
        crate::crypto::verify_meta(
            enc,
            &geometry.db_id,
            slot.index(),
            &payload,
            &Meta::seal_of(raw),
        )
        .map_err(|_| Error::Corrupt {
            page: slot.page(geometry),
            kind: crate::CorruptKind::MetaAuth,
        })
    }

    /// Sin la feature, `encryption` solo puede ser `None` (ver
    /// `seal_meta_for`) y no hay nada que verificar. **Una base cifrada no
    /// llega aquí**: `open_data_key` la ha rechazado ya con `BadFormat`.
    #[cfg(not(feature = "encryption"))]
    fn verify_meta_slot(
        encryption: Option<&Encryption>,
        _geometry: &Geometry,
        _raw: &[u8],
        _slot: MetaSlot,
    ) -> Result<()> {
        match encryption {
            None => Ok(()),
            Some(_) => Err(Error::BadFormat),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Identificador único de la base. No hace falta un generador criptográfico:
/// solo debe distinguir ficheros, no resistir predicción.
fn db_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    id[..8].copy_from_slice(&nanos.to_le_bytes());
    let addr = &id as *const _ as usize as u64;
    id[8..].copy_from_slice(&addr.to_le_bytes());
    id
}

pub struct ReadTxn<'db> {
    db: &'db Db,
    meta: Meta,
}

impl Db {
    pub fn begin_read(&self) -> ReadTxn<'_> {
        let meta = self.committed.read().unwrap().0;
        *self.readers.lock().unwrap().entry(meta.txn_id).or_insert(0) += 1;
        ReadTxn { db: self, meta }
    }

    /// Snapshot del lector vivo más antiguo, o `None` si no hay lectores.
    /// Determina qué páginas libres puede reciclar el escritor.
    fn oldest_reader(&self) -> Option<TxnId> {
        self.readers.lock().unwrap().keys().next().copied()
    }

    /// Páginas leídas por el `Pager` desde que se abrió esta base. Pensado
    /// para pruebas y bancos: expone `Pager::pages_read` (ver su
    /// comentario) para la prueba de coste de la tarea 15
    /// (`it_reads_far_fewer_pages_than_it_frees`), que necesita contar
    /// páginas, no medir tiempo, y para `tests/size.rs` (tarea 21), que
    /// mide lecturas de apertura y de poda desde fuera del crate.
    ///
    /// **Sin `#[cfg(test)]`, a diferencia de `root`/`read_page`, más abajo
    /// en `impl<'db> ReadTxn`.** Esos dos solo los llaman pruebas unitarias
    /// DENTRO de este crate (`tree.rs`), compiladas con `--cfg test`, así
    /// que ese atributo sí las oculta correctamente fuera de una
    /// compilación de pruebas. `tests/size.rs`, en cambio, es un binario de
    /// integración: enlaza `libinro` compilada normalmente, SIN
    /// `--cfg test` — así compila cualquier dependencia externa del crate,
    /// también durante `cargo test` — así que un método marcado
    /// `#[cfg(test)]` aquí sería invisible para él aunque la orden que lo
    /// ejecuta sea `cargo test`. `pages_in_use` (`WriteTxn`, más abajo)
    /// tiene la misma nota y el mismo motivo.
    pub fn pages_read(&self) -> u64 {
        self.pager.pages_read()
    }
}

impl<'db> ReadTxn<'db> {
    pub fn txn_id(&self) -> TxnId {
        self.meta.txn_id
    }

    /// Raíz cruda del árbol de datos. Plomería de página (ronda 3 de
    /// revisión de la tarea 16, mismo motivo que `WriteTxn::root`/
    /// `set_root`/`read_page`/`alloc`/`free` más abajo): fuera del crate no
    /// hay nada legítimo que hacer con un número de página suelto, y
    /// tenerlo público era justo lo que le permitía a un llamante externo
    /// reconstruir un `Cursor` sobre esta raíz saltándose `scan`, o
    /// simplemente leer estructura interna que no forma parte del
    /// contrato — el contrato es `get`/`scan`/`scan_index`. Su único
    /// llamador hoy son las pruebas de bajo nivel de `tree.rs` que montan
    /// árboles a mano, compiladas dentro de este crate con `--cfg test`; de
    /// ahí el `#[cfg(test)]`. A diferencia de `pages_read`, arriba en este
    /// mismo `impl Db` (que la tarea 21 destapó para un binario de
    /// integración, ver su comentario), este método sigue sin llamador
    /// fuera de `tree.rs`, así que se queda gateado.
    #[cfg(test)]
    pub(crate) fn root(&self) -> PageNo {
        self.meta.root
    }

    /// Sin llamador, ni siquiera en pruebas: el catálogo de índices vive en
    /// el árbol normal bajo `CATALOG_NS` (tarea 16), no en un árbol aparte
    /// enraizado aquí. El campo `meta.catalog_root` en sí sigue siendo parte
    /// del formato en disco (lo pedía el brief de la tarea 9, ver
    /// `Meta::encode`/`decode`) y se queda reservado — este accesor, sin
    /// nada que lo use, se marca explícitamente en vez de dejar el aviso de
    /// código muerto sin explicar.
    #[allow(dead_code)]
    pub(crate) fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    /// Bytes crudos de una página por número. Plomería de página: ver el
    /// comentario de `root`, arriba. `ReadTxn` también implementa
    /// `PageSource` (también `pub(crate)`, mismo motivo) para que `tree.rs`
    /// pueda leer páginas sin saber si viene de un lector o un escritor —
    /// esa es la vía que usa el código de producción; este método inherente
    /// solo lo llaman pruebas que ya tienen un `&ReadTxn` concreto en la
    /// mano.
    #[cfg(test)]
    pub(crate) fn read_page(&self, page: PageNo) -> Result<Arc<[u8]>> {
        self.db.pager.read_bytes(page)
    }

    pub fn get(&self, ns: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        crate::tree::get(self, self.meta.root, &scoped(ns, key))
    }

    /// Recorrido de `[from, to)` dentro del espacio `ns`.
    ///
    /// **Desviación deliberada del brief**: la tarea proponía
    /// `pub fn scan(...) -> crate::tree::Cursor<'_, Self>`, construido con
    /// `Cursor::new(...).expect("el descenso inicial no falla en un árbol
    /// válido")`. Ese `.expect` convierte cualquier corrupción detectada
    /// durante el descenso inicial (`TreeLoop` de una pila corrupta,
    /// `PageType` de una página que no es la que dice ser, o un error de E/S
    /// del propio `read_page`) en un `panic!` de la API pública, justo la
    /// clase de fallo que este motor evita desde la tarea 5: "entrada
    /// corrupta se reporta como `Err`, nunca como una respuesta incorrecta
    /// silenciosa" (ver el comentario de `read_overflow`) — un panic es
    /// estrictamente peor que una respuesta silenciosa, porque además
    /// aborta el proceso. `get`, `put` y `delete` ya devuelven `Result` por
    /// esta misma razón; `scan` debe ser igual de consistente.
    ///
    /// `ns` se le pasa a `Cursor::new` en vez de escaparse aquí (ronda 1 de
    /// revisión, hallazgo 3): el propio cursor calcula `scoped(ns, from)` y
    /// `scoped(ns, to)` y recuerda con qué `ns` lo hizo, así que no hay
    /// forma de que el prefijo antepuesto al rango y el que se recorta de
    /// cada clave devuelta se desincronicen — antes eran dos decisiones
    /// separadas (`scoped(...)` aquí, `strip` allí) que nada obligaba a
    /// coincidir.
    pub fn scan(&self, ns: u8, from: &[u8], to: &[u8]) -> Result<crate::tree::Cursor<'_, Self>> {
        crate::tree::Cursor::new(self, self.meta.root, ns, from, to)
    }

    /// Claves primarias cuyas entradas de índice caen en `[from, to)`
    /// (tarea 16). `from`/`to` se comparan contra el valor indexado: en un
    /// índice no único eso es solo el prefijo de la entrada, nunca la clave
    /// primaria ni la longitud que le siguen, así que el orden que ve quien
    /// llama es el del valor indexado, aunque la clave real en el árbol
    /// lleve más bytes detrás.
    ///
    /// **Cuidado con el modismo `scan_index(id, v, v ++ [0xff])`** para "todo
    /// lo que vale exactamente `v`" (ronda 2 de revisión, hallazgo 9, sin
    /// arreglo — documentado): en un índice NO único la entrada completa es
    /// `v ++ primaria ++ longitud`, así que ese límite superior también es
    /// mayor que cualquier entrada cuya clave primaria empiece por el byte
    /// `0xff` — comparado byte a byte, `v` seguido de `0xff` es UN prefijo
    /// estricto de `v` seguido de `0xff` seguido de más bytes, y un prefijo
    /// estricto compara menor, así que esa fila cae fuera del rango
    /// `[from, to)` y `scan_index` no la devuelve, aunque su valor indexado
    /// sea `v` en todos los sentidos que importan. El límite en sí,
    /// `[from, to)`, es correcto y hace justo lo que dice; el problema es
    /// solo de este modismo concreto para construirlo. Quien necesite
    /// cubrir el rango entero de un valor indexado sin este hueco debe
    /// construir `to` con suficientes bytes `0xff` de sobra como para
    /// exceder cualquier clave primaria real posible, no solo uno.
    pub fn scan_index(&self, id: u8, from: &[u8], to: &[u8]) -> Result<Vec<Vec<u8>>> {
        let def = self
            .db
            .indexes
            .lock()
            .unwrap()
            .iter()
            .copied()
            .find(|d| d.id == id)
            .ok_or(Error::BadFormat)?;

        let mut out = Vec::new();
        let mut cursor = self.scan(def.index_ns(), from, to)?;
        while let Some((k, v)) = cursor.next()? {
            out.push(if def.unique { v } else { primary_of(&k)?.to_vec() });
        }
        Ok(out)
    }
}

/// Antepone el byte de espacio de claves. Es la única transformación entre la
/// clave que ve el usuario y la que vive en el árbol. `pub(crate)` porque
/// `tree::Cursor::new` también la necesita (ronda 1 de revisión, hallazgo 3):
/// el cursor calcula su propio prefijo internamente en vez de recibirlo ya
/// aplicado, así que esta es la única función que sabe construirlo.
pub(crate) fn scoped(ns: u8, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + key.len());
    k.push(ns);
    k.extend_from_slice(key);
    k
}

/// Acceso a páginas común a lectores y escritores, para que el árbol se
/// escriba una sola vez y sirva a ambos.
///
/// `pub(crate)` (ronda 3 de revisión de la tarea 16): si este trait fuera
/// público, un llamante externo podría invocar `read_page` a través de él
/// (`PageSource::read_page(&tx, pagina)`) igual que a través del método
/// inherente, sin que importara que ESE método inherente pasara a
/// `pub(crate)` — la visibilidad de un método de trait la fija el trait
/// entero, no cada implementación por separado, así que dejar el trait
/// público habría dejado la misma puerta abierta con otro nombre.
pub(crate) trait PageSource {
    /// Una página YA VALIDADA, no bytes crudos: quien la recibe no vuelve a
    /// llamar a `PageRef::parse`. La validación ocurre una sola vez, al
    /// entrar en la caché del `Pager` — ver `Pager::read`.
    fn read_page(&self, page: PageNo) -> Result<ValidPage>;

    /// Páginas que existen en el fichero según el snapshot de ESTA
    /// transacción: la cota superior del número de páginas DISTINTAS que
    /// cualquier recorrido legítimo puede visitar, y por tanto la cota con
    /// la que se acota un recorrido cuya longitud, si no, la fijaría un
    /// dato leído del disco. Es el mismo argumento —y el mismo número— que
    /// ya usa `tree::RangeBudget` a través de `WriteTxn::n_pages`, ahora
    /// disponible también para un lector.
    ///
    /// **Sale de la meta y no cuesta E/S**, que es justo lo que la hace
    /// utilizable en el camino caliente: `meta.n_pages` está en memoria
    /// desde `begin_read`/`begin_write`, y desde
    /// `Db::check_meta_against_file` es además un número ya contrastado
    /// contra la longitud real del fichero — sin esa comprobación al abrir,
    /// acotar con él sería acotar un dato de disco con otro dato de disco.
    fn max_pages(&self) -> PageNo;
}

impl PageSource for ReadTxn<'_> {
    fn read_page(&self, page: PageNo) -> Result<ValidPage> {
        self.db.pager.read(page)
    }

    fn max_pages(&self) -> PageNo {
        self.meta.n_pages
    }
}

impl PageSource for WriteTxn<'_> {
    fn read_page(&self, page: PageNo) -> Result<ValidPage> {
        self.db.pager.read(page)
    }

    fn max_pages(&self) -> PageNo {
        self.meta.n_pages
    }
}

/// Pares `(id, ns)` de todos los índices que el catálogo declara en `root`.
///
/// Es lo ÚNICO que se puede saber de un índice sin tener su `IndexDef`
/// completo: `IndexDef::encode` no guarda —no puede guardar— el puntero a
/// función `extract`, así que un registro del catálogo dice que un índice
/// existe y sobre qué espacio de claves, pero no alcanza para mantenerlo.
/// Ver `Db::catalog_indexes`.
///
/// El catálogo vive bajo `CATALOG_NS` en el árbol normal (tarea 16), con el
/// id como clave de un solo byte — así que esto es UN recorrido del rango
/// `[0x00, INDEX_NS_BASE)` de ese espacio, no una lectura por índice.
/// `INDEX_NS_BASE` como límite superior no es un número mágico prestado de
/// otro sitio: es exactamente el primer id que `define_index` rechaza,
/// porque el espacio de un índice es `INDEX_NS_BASE | id` y un id mayor
/// desbordaría sobre el de otro.
///
/// **Ignora lo que `define_index` no pudo haber escrito**, en vez de
/// tratarlo como catálogo corrupto y negar toda escritura: `CATALOG_NS` es
/// un espacio de claves reservado, pero nada impide que alguien escriba
/// bytes arbitrarios ahí con `tx.put(CATALOG_NS, ...)` — la misma puerta
/// que ya está documentada para el espacio de un índice (ver `primary_of`
/// en `index.rs`). La distinción es demostrable, no una suposición: la
/// clave que escribe `define_index` es SIEMPRE `&[id]`, un byte, y su
/// registro SIEMPRE mide 6 bytes o más (`IndexDef::encode`), así que nada
/// fuera de esa forma describe un índice y saltárselo no puede perderse
/// ninguno de verdad.
fn read_catalog_indexes<S: PageSource>(src: &S, root: PageNo) -> Result<Vec<(u8, u8)>> {
    let mut out = Vec::new();
    let mut cursor = crate::tree::Cursor::new(src, root, CATALOG_NS, &[], &[INDEX_NS_BASE])?;
    while let Some((key, record)) = cursor.next()? {
        let (&[id], Some(ns)) = (&key[..], IndexDef::stored_ns(&record)) else { continue };
        out.push((id, ns));
    }
    Ok(out)
}

impl Drop for ReadTxn<'_> {
    fn drop(&mut self) {
        let mut readers = self.db.readers.lock().unwrap();
        if let Some(n) = readers.get_mut(&self.meta.txn_id) {
            *n -= 1;
            if *n == 0 {
                readers.remove(&self.meta.txn_id);
            }
        }
    }
}

pub struct WriteTxn<'db> {
    db: &'db Db,
    guard: MutexGuard<'db, Option<WriterState>>,
    meta: Meta,
    slot: MetaSlot,
    /// Números de escritura (`crypto::NonceStream::issued`) ya consumidos
    /// por esta transacción (tarea 17). Comprobación defensiva, no la
    /// fuente real de la garantía de unicidad — esa la da la construcción
    /// de `WriterState::nonce_stream` (contador estrictamente creciente que
    /// no rebobina nunca, ver su comentario) — pero convierte esa
    /// construcción de una suposición no comprobada a algo que `write_page`
    /// verifica en cada escritura: si algún cambio futuro rompe el
    /// incremento, esto lo detecta con un error en vez de sellar dos
    /// páginas con el mismo nonce en silencio.
    ///
    /// **Sobre el número de escritura, no sobre el par `(página, contador)`
    /// de antes** (cambio a nonces aleatorios): el nonce ya no lleva el
    /// número de página, así que dos páginas distintas con el mismo
    /// contador serían una colisión real y el par no la detectaría. Y el
    /// número de escritura sigue siendo único aunque el prefijo se renueve
    /// a media apertura (agotamiento del contador de AES, ver
    /// `NonceStream::next`), porque `issued` no rebobina en esa renovación.
    ///
    /// **Solo se puebla si la base está cifrada** (segunda ronda de
    /// revisión posterior a la primera entrega, hallazgo sobre coste de
    /// memoria: en una transacción de 45 000 `put` esto llegaba a costar
    /// del orden de 1,6 MB, sin dar ninguna protección real a una base SIN
    /// cifrar, donde no se sella nada). Ver `write_page`.
    /// Reserva abierta: solo lo está mientras corre una operación que reduce
    /// el árbol (`with_reserve`). Ver `RESERVE_PAGES`.
    reserve: bool,
    /// Páginas sucias de esta transacción, sin sellar y sin escribir.
    ///
    /// **Por qué existe.** El copy-on-write obliga a copiar el camino
    /// raíz-hoja en cada `put` —eso no se negocia, es lo que da la seguridad
    /// ante cortes sin WAL y los lectores sin bloqueo—, pero NO obliga a
    /// mandar ese camino al medio en cada `put`. Escribiendo a través, un
    /// commit de mil filas emitía 2.009 escrituras para 13 páginas distintas:
    /// cada página viajaba al disco 154 veces y solo la última contaba.
    /// Medido en `how_many_distinct_pages_a_commit_touches`: 242× de
    /// amplificación física, plana con cualquier tamaño de lote.
    ///
    /// Acumular y escribir una vez al cerrar el commit lo deja en 1,57× con
    /// lotes de mil y 1,10× con lotes de cinco mil, y de paso hace que
    /// agrupar escrituras —que la sección 12.4 ya exige al llamante— por fin
    /// sirva de algo en el motor.
    ///
    /// `BTreeMap` y no `HashMap`: al volcar se escribe en orden de página, que
    /// es secuencial en el fichero.
    /// Tope del buffer. Al pasarlo se derrama la página más baja al medio,
    /// así que la RAM de una transacción sigue acotada pase lo que pase — que
    /// es la promesa de la sección 1 y el motivo por el que este buffer no
    /// existía. 512 páginas son 2 MB con páginas de 4 KB y 256 KB con las de
    /// 512 B; un commit del edge toca 13.
    spill_at: usize,
    written: BTreeSet<u64>,
    /// Escrituras físicas (`write_page`) emitidas por esta transacción hasta
    /// ahora — tarea 20. A diferencia de `written`, se lleva SIEMPRE, con o
    /// sin cifrado: es un `u64` que solo se incrementa, sin coste de memoria
    /// alguno, así que no aplica la misma razón que mantiene `written`
    /// condicional. Nace en cero y solo cuenta lo que pasa por
    /// `write_page` — ni la lista de libres que `commit` escribe
    /// directamente contra `self.db.pager` (`Freelist::flush`), ni la
    /// propia meta del commit, así que `pending_writes()` (más abajo) es
    /// "escrituras de árbol/lista-de-libres de ESTA transacción hasta el
    /// instante de la llamada", no "escrituras totales que este commit
    /// hará" — ver el comentario de `pending_writes`.
    write_count: u64,
    /// Copia de la lista de libres tal como estaba antes de esta
    /// transacción. `alloc`/`free` mutan `guard`'s `WriterState` en el
    /// sitio, no una copia local — es el mismo objeto que sobrevive entre
    /// transacciones (ver `WriterState`) — así que si esta transacción se
    /// descarta sin `commit`, `Drop` la restaura desde aquí. Barata: `Clone`
    /// de `Freelist` solo copia lo materializado en memoria.
    pre_freelist: Freelist,
    /// Se pone a `true` solo al final de un `commit` que ya tocó la meta
    /// confirmada. Mientras sea `false`, `Drop` deshace cualquier cambio que
    /// esta transacción le haya hecho a la lista de libres persistente.
    committed: bool,
    /// Todas las páginas que ESTA transacción ha asignado alguna vez, sin
    /// importar de dónde salieron (lista de libres persistente o extensión
    /// de fichero). `free` la consulta para decidir si una página liberada
    /// va al conjunto propio (`own_free`, reciclable de inmediato) o a la
    /// lista de libres persistente (protegida hasta el commit, ver
    /// `alloc`). `BTreeSet`, no un escaneo lineal: un lote de miles de
    /// operaciones asigna y libera del orden de miles de páginas, y una
    /// comprobación de pertenencia por página convertiría esa carga en
    /// cuadrática si fuera O(n).
    self_allocated: BTreeSet<PageNo>,
    /// Páginas que esta transacción asignó y ya liberó ella misma: nunca
    /// llegaron a formar parte del árbol confirmado, así que son
    /// reciclables de inmediato, sin esperar al commit. `alloc` las
    /// consume antes de tocar la lista de libres persistente. Puro LIFO
    /// (siempre se saca la última que se metió) y acotado por lo que esta
    /// transacción llega a asignar, así que un `Vec` con `push`/`pop`
    /// basta — no hace falta orden ni pertenencia sobre este conjunto, eso
    /// ya lo resuelve `self_allocated`.
    ///
    /// **Es precisamente lo que hace que reutilizar `txn_id` como nonce
    /// fuera inseguro** (primera ronda de revisión posterior a la primera
    /// entrega, hallazgo BLOCKER): una página que sale de aquí en `alloc` y
    /// se vuelve a escribir con `write_page` recibía un `txn_id` — el de
    /// ESTA transacción — idéntico al que ya tenía la primera vez que se
    /// escribió, dentro de la MISMA transacción. Con un lote de cientos de
    /// `put` en una sola transacción esto no es un caso raro: es el camino
    /// normal, y una sola página puede reciclarse así decenas o cientos de
    /// veces (121 veces sobre 200 `put`, medido). De ahí que el nonce ya no
    /// se derive de `txn_id`, sino del contador vivo de la base — ver
    /// `WriterState::nonce_stream`.
    own_free: Vec<PageNo>,
}

impl Db {
    pub fn begin_write(&self) -> Result<WriteTxn<'_>> {
        // `try_lock` distingue dos causas muy distintas de fallo (ronda 2 de
        // revisión, hallazgo 7): `WouldBlock` es un escritor legítimo en
        // curso — reintentar más tarde tiene sentido — pero `Poisoned`
        // significa que una transacción anterior entró en pánico con este
        // candado tomado (el sitio más probable: un extractor de índice
        // caprichoso, ver el comentario de `IndexDef::extract`) y el candado
        // de la biblioteca estándar queda envenenado PARA SIEMPRE, no solo
        // hasta que el otro escritor termine. Colapsar los dos casos en
        // `WriterBusy`, como hacía antes, convertía ese envenenamiento en un
        // ladrillo silencioso: cada apertura posterior fallaría con un
        // mensaje que invita a reintentar, cuando reintentar nunca
        // funcionará.
        let guard = match self.write_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Err(Error::WriterBusy),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::WriterPoisoned),
        };
        let (mut meta, slot) = *self.committed.read().unwrap();
        meta.txn_id += 1;
        let state = guard.as_ref().expect("el estado del escritor siempre está presente");
        let pre_freelist = state.freelist.clone();

        // La transacción arranca desde la extensión REAL del fichero, no
        // desde el `n_pages` de la meta confirmada (tarea 17, tercera ronda
        // de revisión): las páginas que `Db::open` recuperó de una
        // transacción interrumpida ya están en `state.freelist`, así que
        // extender desde el `n_pages` viejo entregaría por segunda vez una
        // página que la lista de libres también va a ofrecer. Es el mismo
        // avance que antes hacía `Db::open` sobre la meta confirmada; lo
        // que cambia es CUÁNDO se aplica — aquí, sobre la meta de esta
        // transacción, que solo llega a disco si esta transacción confirma
        // (y entonces la lista de libres viaja con ella) — ver
        // `WriterState::n_pages_floor`.
        meta.n_pages = core::cmp::max(meta.n_pages, state.n_pages_floor);

        // Sin nada que hacer con los nonces aquí: el flujo vive en
        // `WriterState`, sobrevive tal cual entre transacciones (abortadas
        // o no) y no necesita reservar ni extender nada. Ver
        // `WriterState::nonce_stream`.
        Ok(WriteTxn {
            db: self,
            guard,
            meta,
            slot,
            reserve: false,
            spill_at: 512,
            written: BTreeSet::new(),
            write_count: 0,
            pre_freelist,
            committed: false,
            self_allocated: BTreeSet::new(),
            own_free: Vec::new(),
        })
    }
}

/// Deshace, para una transacción de escritura abortada, cualquier mutación
/// que `alloc` (vía `pop_refill`) o `free` le hayan hecho ya a la lista de
/// libres persistente. Sin esto, una página liberada por una transacción que
/// nunca confirma queda marcada libre para siempre mientras la meta
/// confirmada la sigue señalando como viva — dos dueños a la vez — o una
/// página reciclada de la lista de libres por esa transacción se pierde para
/// siempre, porque ni la recuperación al abrir (que solo mira más allá de
/// `n_pages`) ni nada más vuelve a ofrecerla.
impl Drop for WriteTxn<'_> {
    fn drop(&mut self) {
        if !self.committed
            && let Some(state) = self.guard.as_mut()
        {
            state.freelist = core::mem::replace(&mut self.pre_freelist, Freelist::empty());
        }
        // Las páginas aparcadas se tiran SIEMPRE, se haya confirmado o no.
        //
        // Tras un commit el buffer ya está vacío (`flush_dirty` se lo lleva),
        // así que esto solo actúa cuando la transacción se abandona — y ahí es
        // obligatorio: una transacción abandonada no deja rastro, y con el
        // buffer «no dejar rastro» dejó de ser automático. Sin esto, la
        // transacción que se lleva un `Error::Full` deja sus páginas aparcadas
        // y la SIGUIENTE las lee como si fueran válidas: `Corrupt { PageType }`
        // en cuanto una de ellas cae donde antes había otra cosa. Lo cazaron
        // `pruning_gives_the_space_back_for_new_writes` y
        // `the_cap_counts_the_high_water_mark_and_not_the_live_pages` en
        // `tests/cap.rs`, que son las dos que abandonan transacciones a
        // propósito.
        self.db.pager.drop_pending();
    }
}

impl<'db> WriteTxn<'db> {
    pub fn txn_id(&self) -> TxnId {
        self.meta.txn_id
    }

    /// Plomería de página cruda (ronda 3 de revisión de la tarea 16, junto
    /// con `set_root`/`catalog_root`/`set_catalog_root`/`read_page`/
    /// `write_page`/`alloc`/`free` más abajo). Antes de esta ronda, esto era
    /// `pub`, y la revisión demostró exactamente el problema: con `set_root`
    /// y `write_page` públicos, cualquiera puede construir una página a
    /// mano, escribirla, y apuntar la raíz del árbol a ella sin pasar por
    /// `put`/`delete` — es decir, sin que ningún índice se entere. Esa es
    /// justo la garantía que la tarea 16 existe para dar, así que dejarla
    /// bypasseable por una vía pública la volvía condicional a que quien
    /// llama no usara una API que el propio crate anunciaba. `pub(crate)`
    /// cierra el camino sin tocar ni una sola prueba interna.
    ///
    /// El código de producción no llama ni siquiera a la versión
    /// `pub(crate)`: `put_raw`/`delete_raw` leen y escriben `self.meta.root`
    /// directamente (acceso de campo, mismo módulo), y las funciones de
    /// `tree.rs` reciben `root: PageNo` como parámetro explícito en vez de
    /// pedírselo a un `WriteTxn`. El único llamador real son las pruebas de
    /// bajo nivel de `tree.rs`, que montan árboles a mano página a página —
    /// de ahí el `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn root(&self) -> PageNo {
        self.meta.root
    }

    #[cfg(test)]
    pub(crate) fn set_root(&mut self, root: PageNo) {
        self.meta.root = root;
    }

    /// Sin llamador, ni siquiera en pruebas — ver el comentario gemelo en
    /// `ReadTxn::catalog_root`.
    #[allow(dead_code)]
    pub(crate) fn catalog_root(&self) -> PageNo {
        self.meta.catalog_root
    }

    #[allow(dead_code)]
    pub(crate) fn set_catalog_root(&mut self, root: PageNo) {
        self.meta.catalog_root = root;
    }

    fn state(&mut self) -> &mut WriterState {
        self.guard.as_mut().expect("el estado del escritor siempre está presente")
    }

    /// El sellado de `meta` para `slot` con la clave y el flujo de nonces
    /// de ESTA apertura, o `None` si la base no está cifrada.
    ///
    /// Toma `meta` por valor (es `Copy`) en vez de leer `self.meta`: las
    /// tres escrituras de meta de una transacción no siempre sellan la
    /// misma — `relocate_meta_b` sella la meta CONFIRMADA
    /// (`Db::committed`), que puede no ser la que esta transacción está
    /// construyendo.
    ///
    /// El flujo de nonces sale de `WriterState`, no de la transacción: es
    /// estado de la BASE, y no rebobina ni cuando una transacción se
    /// descarta sin confirmar (ver `WriterState::nonce_stream`). Es lo que
    /// impide que un aborto haga sellar dos metas distintas con el mismo
    /// nonce.
    fn seal_meta(
        &mut self,
        geometry: &Geometry,
        meta: Meta,
        slot: MetaSlot,
    ) -> Result<Option<crate::meta::MetaSeal>> {
        // `db` se copia fuera (es `&Db`, `Copy`) para que el préstamo de la
        // clave no compita con el préstamo mutable del flujo de nonces, que
        // vive en `self.guard`.
        let db = self.db;
        let encryption = db.pager.encryption();
        let stream = self.state().nonce_stream.as_mut();
        Db::seal_meta_for(encryption, stream, geometry, &meta, slot)
    }

    /// Tamaño FÍSICO de página fijado al crear la base. Nadie en `tree.rs`
    /// debe usar este método para decidir cuánto cabe en una página: eso es
    /// `logical_page_size`, más abajo. Se conserva `pub` porque sigue
    /// siendo información legítima (p. ej. para calcular el tamaño de
    /// fichero desde fuera), pero ya no lo llama ningún camino que
    /// construya páginas.
    pub fn page_size(&self) -> u32 {
        self.db.pager.geometry().page_size
    }

    /// Bytes útiles de una página lógica: lo que de verdad cabe en una
    /// página una vez descontado el prefijo de cifrado, si lo hay (tarea
    /// 17). `tree.rs` (`emit`, `write_overflow`, `free_overflow`, `put`) y
    /// `freelist.rs` (`Freelist::flush`) lo usan para construir páginas y
    /// para el límite de tamaño de clave — TODO lo que antes usaba
    /// `page_size()` para esos dos fines ahora usa este método. Sin cifrado
    /// coincide con `page_size()`.
    pub fn logical_page_size(&self) -> u32 {
        self.db.pager.logical_page_size()
    }

    /// Página destino definitiva de la meta B (tarea 18): el primer offset
    /// que cae en un sector físico de 4 KB distinto al de la meta A, que
    /// vive en la página 1. Con páginas de 4 KB o más, la página 2 (donde
    /// vive la meta B desde `Db::create`, ver `INITIAL_META_B_PAGE`) ya está
    /// en otro sector, así que esas bases nunca reubican: `relocate_meta_b`
    /// devuelve enseguida al ver que la geometría ya coincide con esto.
    pub(crate) fn final_meta_b_page(page_size: u32) -> PageNo {
        core::cmp::max(2, 4096 / page_size)
    }

    /// Salta la página destino final de la meta B (`final_meta_b_page`) si
    /// una extensión de fichero está a punto de entregarla como página de
    /// datos.
    ///
    /// **Sin esto, una reubicación exitosa —sin ningún corte de
    /// corriente— corrompería datos en vivo.** Sondeado con dos pruebas
    /// deliberadas, una por cada sitio que extiende el fichero
    /// (`allocation_never_hands_out_the_meta_b_relocation_target` y
    /// `freelist_serialization_never_hands_out_the_meta_b_relocation_target_either`,
    /// en `relocation_tests`, más abajo): antes de este salto, con páginas
    /// de 512 B la página 8 es una página de datos como cualquier otra
    /// mientras el fichero es pequeño — nada la distingue como "reservada"
    /// hasta que `relocate_meta_b` la reclama de verdad — así que si el
    /// árbol o la lista de libres la reciben de una extensión normal y la
    /// referencian en el estado confirmado (como raíz, como nodo interno,
    /// como página de lista de libres), y DESPUÉS el fichero crece más allá
    /// de 4 KB, `relocate_meta_b` escribe bytes de meta encima sin saber que
    /// había algo ahí. `relocate_meta_b` en sí no protege contra esto — solo
    /// comprueba que `n_pages` ya pasó de la página destino (ver su
    /// comentario), no que esa página concreta esté libre — así que la única
    /// defensa real es que NINGUNA extensión de fichero llegue a entregarla
    /// jamás. Dos sitios extienden el fichero con un número de página nuevo:
    /// el `else` de `alloc`, más abajo, y el cierre de `commit` que
    /// serializa la lista de libres — los dos tienen que saltarla por igual,
    /// porque una página de lista de libres viva es tan real como cualquier
    /// otra.
    fn skip_meta_b_target(p: PageNo, page_size: u32) -> Result<PageNo> {
        if p == Self::final_meta_b_page(page_size) {
            p.checked_add(1).ok_or(Error::Full)
        } else {
            Ok(p)
        }
    }

    /// Total de páginas que ha llegado a tener el fichero hasta ahora
    /// (vivas o libres). Cota superior del número de páginas DISTINTAS
    /// alcanzables desde cualquier raíz de un árbol legítimo: en un árbol
    /// propiamente dicho — sin aliasing, cada página con un único padre —
    /// nunca hace falta visitar más páginas internas de las que existen en
    /// el fichero. `free_subtree` y `delete_range_rec` (`tree.rs`, tarea
    /// 15) la usan para acotar su trabajo total frente a un DAG corrupto
    /// que comparte hijos entre nodos distintos: ver `RangeBudget` ahí para
    /// el razonamiento completo de por qué esta cota concreta no rechaza
    /// nunca un recorrido legítimo, por grande que sea.
    pub(crate) fn n_pages(&self) -> u32 {
        self.meta.n_pages
    }

    /// Última página del prefijo FIJO reservado del fichero: la cabecera es
    /// la página `0`, la meta A vive en la `1`, ninguna de las dos cambia
    /// jamás — así que ninguna página `<= 1` es nunca un hijo legítimo de un
    /// nodo interno, en NINGÚN momento de la vida del fichero.
    ///
    /// **Ya NO incluye a la meta B (tarea 18) — ni fija en `2` ni dinámica
    /// del todo.** Antes de la reubicación esto era `geometry().meta_b_page`
    /// directamente, válido mientras esa página era estática de por vida;
    /// una versión posterior lo cambió a la constante `2`
    /// (`INITIAL_META_B_PAGE`), asumiendo que la meta B en su posición
    /// inicial está reservada PARA SIEMPRE — cierto hasta que
    /// `relocate_meta_b` la libera de verdad (`self.free`, ver su
    /// comentario) una vez completa la reubicación, momento en el que esa
    /// página vuelve a la lista de libres como cualquier otra y SÍ puede
    /// volver a ser un hijo legítimo. Una constante fija la rechazaba para
    /// siempre incluso después de reciclarse — confirmado de punta a punta
    /// (`an_overflow_value_ever_written_costs_its_node_the_fast_path_permanently`,
    /// `it_does_not_touch_other_keyspaces`, en `tree.rs`, con árboles lo
    /// bastante grandes como para que la meta B reubicada se reciclara y
    /// volviera a usarse). La meta B —en cualquiera de sus dos posibles
    /// posiciones, la inicial o la final— se comprueba aparte y de verdad
    /// dinámica, en `current_meta_b_page`, justo abajo: en todo momento hay
    /// como mucho UNA página con ese papel, así que una sola comparación
    /// dinámica basta, sin falsos rechazos ni ventanas sin cubrir.
    ///
    /// `pub(crate)`: la usa `tree::validate_child` (tarea 15, ronda 2 de
    /// revisión, hallazgo 1) para rechazar un hijo corrupto que caiga en
    /// una de las ranuras de meta, no solo en la página `0`.
    pub(crate) fn last_reserved_page(&self) -> PageNo {
        LAST_RESERVED_PAGE
    }

    /// Página de la meta B AHORA MISMO: la `2` (`INITIAL_META_B_PAGE`)
    /// antes de que `relocate_meta_b` complete, `meta_b_relocation_target()`
    /// después — exactamente `geometry().meta_b_page`, sin más. Ningún hijo
    /// legítimo de un nodo interno puede tener este valor jamás, porque
    /// `alloc` nunca la reparte mientras cumple este papel — pero SÍ puede
    /// volver a repartir la posición VIEJA una vez `relocate_meta_b` la
    /// libera (ver su comentario), así que esta comprobación tiene que leer
    /// la geometría vigente en cada llamada, no memorizar un valor de una
    /// vez. `pub(crate)`: la usa `tree::validate_child`, junto con
    /// `last_reserved_page` y `meta_b_relocation_target`.
    pub(crate) fn current_meta_b_page(&self) -> PageNo {
        self.db.pager.geometry().meta_b_page
    }

    /// Página destino final de la reubicación de la meta B — SIEMPRE
    /// excluida como hijo legítimo, tanto si la reubicación ya sucedió como
    /// si no (tarea 18): ver el comentario de `skip_meta_b_target`, que es
    /// quien de verdad la reserva desde la primera vez que `alloc`/`commit`
    /// podrían haberla repartido, no `relocate_meta_b` cuando por fin la usa
    /// de verdad. Redundante con `current_meta_b_page` una vez completa la
    /// reubicación (las dos valen lo mismo entonces) — la redundancia es
    /// inofensiva; lo que hace falta es la cobertura ANTES, mientras
    /// `current_meta_b_page` todavía vale `INITIAL_META_B_PAGE` y esta es la
    /// única que ya excluye el destino futuro. `pub(crate)`: la usa
    /// `tree::validate_child`, junto con las dos anteriores.
    pub(crate) fn meta_b_relocation_target(&self) -> PageNo {
        Self::final_meta_b_page(self.page_size())
    }

    /// Páginas en uso ahora mismo: asignadas menos libres. Solo para
    /// pruebas, para poder afirmar sobre liberaciones (p. ej. que borrar o
    /// reemplazar un valor de overflow libera de verdad su cadena vieja).
    ///
    /// Cuenta las DOS bolsas de páginas libres, no solo `state().freelist`:
    /// una página que esta misma transacción asignó y ya liberó ella misma
    /// va a `own_free`, no a la lista persistente (ver `free`), así que
    /// contar solo la lista persistente sobrestima "en uso" en exactamente
    /// ese número — precisamente el patrón de todas las pruebas de esta
    /// función (`alloc` y `free` dentro de la misma transacción sin
    /// confirmar, como al sustituir o borrar un valor de overflow que la
    /// propia transacción acaba de escribir). Sin esto, ninguna de esas
    /// pruebas vería bajar el conteo nunca, con o sin fuga real.
    ///
    /// **Descuenta también la página destino de la reubicación de la meta B
    /// una vez `n_pages` la cruza** (tarea 18, autorrevisión). No es una
    /// fuga de datos: `skip_meta_b_target` la retira del espacio de
    /// numeración para siempre en cuanto `alloc`/`commit` la cruzan, tanto
    /// si la reubicación ya sucedió (entonces es meta legítima) como si no
    /// (entonces es, sencillamente, un hueco reservado a la espera) — pero
    /// nunca aparece en `free`, así que sin este descuento cualquier prueba
    /// que sustituya o borre valores lo bastante grandes como para cruzar
    /// esa página vería un `pages_in_use` una unidad más alto que antes de
    /// cruzarla, sin que put/delete/replace tuvieran ninguna fuga real —
    /// confirmado de punta a punta,
    /// `replacing_large_with_small_then_large_again_then_deleting_returns_to_baseline`
    /// en `tree.rs`. `target > INITIAL_META_B_PAGE` descarta `page_size` de
    /// 4 KB o más: ahí el destino ya ES la página `2` desde la creación —
    /// ver `final_meta_b_page` — y jamás hay salto que descontar, porque
    /// `alloc` nunca extiende el fichero hacia atrás, hasta la `2`.
    ///
    /// **Sin `#[cfg(test)]`** (tarea 21): lo necesita `tests/size.rs`, un
    /// binario de integración que enlaza `libinro` compilada sin
    /// `--cfg test` — ver la nota de `Db::pages_read`, arriba, mismo motivo
    /// exacto.
    /// **`saturating_sub`, no `-`.** `free` cuenta lo que la lista de libres
    /// trajo del disco, y aunque `PageDomain` (`freelist.rs`) ya garantiza
    /// que cada entrada direcciona una página que existe de verdad, no
    /// garantiza —ni puede, sin memoria proporcional a la lista entera— que
    /// no haya REPETIDAS entre páginas distintas de la cadena. Una cadena
    /// manipulada que liste cien veces la misma página válida deja `free`
    /// por encima de `n_pages`, y con la resta a pelo eso era un pánico
    /// («attempt to subtract with overflow») en depuración y un número
    /// silenciosamente falso en release (`4 294 967 183` páginas en uso en
    /// un fichero de 7). Saturando, un fichero manipulado da un número
    /// pequeño en vez de un pánico o una respuesta absurda; la duplicación
    /// en sí la denuncia `audit_pages`, que es la función que existe para
    /// eso — esto es contabilidad de diagnóstico, no una respuesta a una
    /// consulta.
    pub fn pages_in_use(&mut self) -> u32 {
        let n = self.meta.n_pages;
        let free = self.state().freelist.len() as u32 + self.own_free.len() as u32;
        let target = self.meta_b_relocation_target();
        let skip_gap = if target > INITIAL_META_B_PAGE && n > target { 1 } else { 0 };
        n.saturating_sub(free).saturating_sub(skip_gap)
    }

    /// Toma una página libre reutilizable o extiende el fichero.
    ///
    /// Dos fuentes, en orden. Primero el conjunto propio (`own_free`):
    /// páginas que esta misma transacción asignó y ya liberó ella misma.
    /// Nunca llegaron a formar parte del árbol confirmado — la meta vieja
    /// no las referencia — así que reutilizarlas no puede dañar nada tras
    /// un corte, y no hace falta esperar a ningún commit. Esta distinción
    /// no es un refinamiento opcional: el camino de inserción copy-on-write
    /// libera el camino raíz→hoja en cada `put`, así que un lote de mil
    /// registros asigna del orden de cuatro mil páginas y libera casi
    /// todas dentro de la misma transacción. Sin reciclarlas de inmediato,
    /// el fichero crecería unos 16 MB por lote con páginas de 4 KB — en un
    /// motor cuyo objetivo es justo el mínimo consumo de disco.
    ///
    /// Si `own_free` está vacío, la lista de libres persistente, con la
    /// meta DURABLE contando como lector — el más importante: si esta
    /// transacción no llega a confirmar, la recuperación monta por ella,
    /// así que hay un lector implícito en el último commit hasta que esta
    /// acabe. Sin ese suelo, una página liberada por esta transacción pero
    /// todavía viva en el árbol confirmado en N-1 se reutilizaría en
    /// cuanto no hay lectores reales, el escritor la sobrescribiría, y un
    /// corte antes del commit dejaría la meta N-1 apuntando a basura.
    /// `WriteTxn::Drop` no lo repara — deshace la lista de libres en
    /// memoria, no lo que ya se escribió en disco — y un corte de
    /// corriente nunca llega a ejecutar `Drop`. `min` con el lector real
    /// más antiguo (si lo hay) conserva ese límite tal cual: la meta
    /// durable nunca es más reciente que cualquier lector real vivo.
    ///
    /// **DURABLE, no confirmada** (ver el campo `Db::durable`): la meta que
    /// monta tras un corte no es la última escrita sino la última
    /// sincronizada, y bajo `Sync::Interval`/`Never` no son la misma. Con
    /// la confirmada como suelo, este método repartía páginas que el árbol
    /// durable seguía referenciando.
    ///
    /// Cualquier página que salga de aquí, sea cual sea la fuente, se
    /// registra en `self_allocated`: en cuanto esta transacción la posee,
    /// liberarla de nuevo (dentro de la misma transacción) es siempre
    /// seguro y debe ir a `own_free`, no a la lista persistente — ver
    /// `free`.
    /// Páginas que el tope se guarda para que una base llena todavía se
    /// pueda vaciar.
    ///
    /// **Sin esto, el tope es una condena.** El copy-on-write reescribe el
    /// camino raíz-hoja en cada commit, así que `delete`/`delete_range`
    /// ASIGNAN antes de liberar nada: una base clavada en su límite no
    /// podría podarse, y el remedio para estar llena exigiría justo lo que
    /// estar llena impide.
    ///
    /// 64 y no la altura exacta del árbol: el peor commit de poda son el
    /// camino raíz-hoja (5 niveles medidos en la sección 12.4 de la
    /// especificación, con 2,5 millones de entradas) más las páginas de
    /// lista de libres que toque y la meta. 64 cubre eso con holgura de
    /// sobra y cuesta 32 KiB con páginas de 512 B — entre el 0,03% y el
    /// 0,2% de los topes por tier. Ser tacaño aquí solo compra bytes y
    /// puede costar una base irrecuperable.
    pub(crate) const RESERVE_PAGES: u32 = 64;

    /// Rechaza el crecimiento que pasaría del tope de esta apertura.
    ///
    /// La reserva la abre `with_reserve`, que solo envuelve a las
    /// operaciones que REDUCEN el árbol. Todo lo demás se para
    /// `RESERVE_PAGES` antes del tope de verdad.
    fn check_page_cap(&self, grown: PageNo) -> Result<()> {
        let Some(cap) = self.db.page_cap else { return Ok(()) };
        let limit = if self.reserve { cap } else { cap.saturating_sub(Self::RESERVE_PAGES) };
        if grown > limit { Err(Error::Full) } else { Ok(()) }
    }

    /// Ejecuta `f` con la reserva abierta. Solo para operaciones que dejan
    /// el árbol más pequeño de lo que estaba.
    fn with_reserve<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let before = self.reserve;
        self.reserve = true;
        let out = f(self);
        self.reserve = before;
        out
    }

    pub(crate) fn alloc(&mut self) -> Result<PageNo> {
        if let Some(p) = self.own_free.pop() {
            return Ok(p);
        }

        let p = if let Some(p) = self.recycle()? {
            p
        } else {
            // Salta la página destino final de la meta B (tarea 18): ver el
            // comentario de `skip_meta_b_target`. Una página que nunca sale
            // de aquí tampoco puede volver más tarde por la lista de libres
            // (`pop_refill`, arriba) — nadie la libera nunca porque nadie la
            // recibió nunca — así que este único salto basta para que jamás
            // aparezca como dato en ningún camino que pase por `alloc`.
            let p = Self::skip_meta_b_target(self.meta.n_pages, self.page_size())?;
            let grown = p.checked_add(1).ok_or(Error::Full)?;
            if self.check_page_cap(grown).is_err() {
                // Antes de rendirse: forzar el `fsync` que desbloquea el
                // suelo de reutilización. Es caro, pero al llegar al tope
                // la alternativa no es crecer un poco más, es fallar — ver
                // `recycle_inner`.
                match self.recycle_inner(true)? {
                    Some(p) => {
                        self.self_allocated.insert(p);
                        return Ok(p);
                    }
                    None => return Err(Error::Full),
                }
            }
            self.meta.n_pages = grown;
            p
        };
        self.self_allocated.insert(p);
        Ok(p)
    }

    /// Sirve una página de la lista de libres persistente, o `None` si no
    /// hay ninguna reutilizable y el fichero tiene que crecer.
    ///
    /// Dos intentos, no uno. El primero usa el suelo de reutilización tal
    /// como está (`Db::reuse_floor`, con la meta DURABLE como lector
    /// implícito). Si no sirve nada y lo que retiene al suelo es el retraso
    /// del punto durable —no un lector real, ni una lista de libres
    /// vacía— entonces un `fsync` AQUÍ pone el punto durable al día y
    /// desbloquea de golpe todo lo liberado hasta la última meta escrita;
    /// `reclaim_needs_a_sync` decide si ya toca pagarlo o si todavía sale
    /// más barato dejar crecer el fichero (ver su comentario para el
    /// presupuesto y su porqué).
    ///
    /// **Es la respuesta a la única objeción seria contra usar el punto
    /// durable como suelo**: bajo `Sync::Never` nada se sincroniza jamás,
    /// así que un suelo durable «puro» no avanzaría nunca y ninguna página
    /// se reciclaría — el fichero crecería sin cota en el entorno donde el
    /// disco es más escaso. Con esto, `Sync::Never` deja de significar
    /// «sin `fsync` pase lo que pase» y pasa a significar «sin `fsync` por
    /// commit; solo los que hagan falta para recuperar espacio» — que es
    /// justo el trato que un proceso IoT de larga duración querría. No es
    /// una excepción sin precedente en el motor: la reserva duradera de
    /// contadores de nonce sincronizaba también sin condiciones bajo
    /// cualquier política, mientras existió.
    ///
    /// Sincronizar a mitad de una transacción no publica nada: lo único
    /// que hay escrito y sin confirmar son páginas que ninguna meta
    /// referencia todavía, y la meta de esta transacción aún no se ha
    /// escrito.
    fn recycle(&mut self) -> Result<Option<PageNo>> {
        self.recycle_inner(false)
    }

    /// `forced`: paga el `fsync` que desbloquea el suelo de reutilización
    /// aunque el presupuesto de `reclaim_needs_a_sync` diga que todavía sale
    /// más barato dejar crecer el fichero.
    ///
    /// **Existe por el tope de páginas, y el matiz importa.** Ese
    /// presupuesto compara el coste de un `fsync` contra el de dejar crecer
    /// el fichero unas páginas más — un intercambio que asume que crecer
    /// siempre es posible. Con `Options::max_pages` deja de serlo: al llegar
    /// al tope, "crecer un poco más" no es la alternativa barata, es la
    /// alternativa inexistente. Sin este camino, una base tope-llena
    /// devolvía `Full` con la lista de libres llena de páginas servibles y
    /// podar no servía de nada — lo detectaron
    /// `pruning_gives_the_space_back_for_new_writes` y
    /// `the_cap_counts_the_high_water_mark_and_not_the_live_pages` en
    /// `tests/cap.rs`, y es justo el modo (`Sync::Never`) que usa el edge.
    fn recycle_inner(&mut self, forced: bool) -> Result<Option<PageNo>> {
        let pager = &self.db.pager;
        let floor = self.db.reuse_floor();
        if let Some(p) = self.state().freelist.pop_refill(pager, Some(floor))? {
            return Ok(Some(p));
        }
        if !forced && !self.db.reclaim_needs_a_sync() {
            return Ok(None);
        }
        let upto = self.db.committed.read().unwrap().0.txn_id;
        self.db.sync_upto(upto)?;
        let floor = self.db.reuse_floor();
        self.state().freelist.pop_refill(pager, Some(floor))
    }

    /// Marca `page` como libre a partir de esta transacción.
    ///
    /// Si la asignó esta misma transacción (`self_allocated`), va al
    /// conjunto propio y vuelve a estar disponible de inmediato: nunca la
    /// vio la meta confirmada, así que no hay nada que proteger. Si venía
    /// de antes de esta transacción — del árbol confirmado — va a la lista
    /// de libres persistente etiquetada con esta transacción y no se
    /// reutiliza hasta que el commit la haga durable (ver `alloc`).
    pub(crate) fn free(&mut self, page: PageNo) {
        if self.self_allocated.contains(&page) {
            self.own_free.push(page);
        } else {
            let txn = self.meta.txn_id;
            self.state().freelist.push(page, txn);
        }
    }

    pub(crate) fn read_page(&self, page: PageNo) -> Result<ValidPage> {
        self.db.pager.read(page)
    }

    /// `bytes` debe medir `logical_page_size()`. Sella (si procede) con un
    /// nonce nuevo por cada llamada, sacado del flujo de la apertura
    /// (`WriterState::nonce_stream`) — NO derivado de `self.meta.txn_id`
    /// (primera ronda de revisión posterior a la primera entrega, hallazgo
    /// BLOCKER: `txn_id` es el mismo para toda la transacción, y
    /// `WriteTxn::alloc` recicla `own_free` — la MISMA página puede
    /// escribirse muchas veces dentro de una sola transacción, ver el
    /// comentario de `own_free`) — así que el nonce nunca se repite sin
    /// importar cuántas veces se reescriba la misma página.
    ///
    /// Sin cifrado no hay flujo, y esta función es una escritura normal:
    /// desde el cambio a nonces aleatorios, una base sin cifrar ya ni
    /// siquiera lleva un contador que avanzar.
    ///
    /// El guardián `written`, que sí cuesta memoria real en una transacción
    /// grande, solo se puebla si la base está cifrada (segunda ronda de
    /// revisión, hallazgo sobre coste de memoria — ver su comentario).
    /// Acumula una página sucia. Solo llega al medio en `flush_dirty`, al
    /// cerrar el commit — ver el campo `dirty`.
    pub(crate) fn write_page(&mut self, page: PageNo, bytes: &[u8]) -> Result<()> {
        self.db.pager.stage(page, bytes);
        self.write_count += 1;
        if self.db.pager.pending_len() > self.spill_at {
            // Derrame: la página más baja sale al medio para que el buffer no
            // crezca sin cota. Sigue siendo correcto —solo cambia CUÁNDO se
            // escribe, no qué— y una transacción normal no llega aquí.
            // Derrame: se vacía entero en vez de gota a gota. Vaciar una sola
            // página dejaría el buffer justo en el tope y derramaría en CADA
            // escritura posterior, que es exactamente el comportamiento que
            // este buffer viene a quitar.
            self.flush_dirty()?;
        }
        Ok(())
    }

    /// Vuelca al medio todo lo acumulado, en orden de página.
    ///
    /// Se llama al cerrar el commit, ANTES de la meta: la meta es lo que
    /// publica la transacción, así que todo lo que referencia tiene que estar
    /// ya en el fichero. Es el mismo orden que tenía el camino de escritura a
    /// través, solo que ahora cada página va una vez.
    pub(crate) fn flush_dirty(&mut self) -> Result<()> {
        for (page, bytes) in self.db.pager.take_pending() {
            self.write_page_through(page, &bytes)?;
        }
        Ok(())
    }

    fn write_page_through(&mut self, page: PageNo, bytes: &[u8]) -> Result<()> {
        let pager = &self.db.pager;
        let state = self.guard.as_mut().expect("el estado del escritor siempre está presente");
        // ANTES de sellar, no después: comprobarlo a posteriori llegaría
        // tarde, con la página ya escrita en el medio bajo el nonce
        // repetido. Matemáticamente inalcanzable si `NonceStream::next`
        // incrementa correctamente — comprobación defensiva, no la fuente
        // de la garantía. Ver el comentario de `written`.
        if let Some(stream) = state.nonce_stream.as_ref()
            && !self.written.insert(stream.issued())
        {
            return Err(Error::NonceReuse { page });
        }
        pager.write_encrypted(page, state.nonce_stream.as_mut(), bytes)?;
        Ok(())
    }

    /// Páginas escritas por esta transacción hasta ahora. La prueba de
    /// inyección de fallos la usa para localizar la escritura de la meta, que
    /// es siempre la última del commit.
    ///
    /// Cuenta únicamente lo que pasó por `write_page` — páginas de árbol,
    /// tarea 20 — no la lista de libres, que `commit` escribe aparte contra
    /// `self.db.pager` (`Freelist::flush`), ni la propia meta. Por eso
    /// `tests/faults.rs` no calcula la escritura de la meta como
    /// `pending_writes() + 1` a ciegas: mide cuántas escrituras físicas
    /// añade un `commit()` de referencia por encima de este valor y usa esa
    /// cifra, que en la práctica no siempre es 1 — cualquier `put`/`delete`
    /// libera al menos la raíz y la hoja antiguas (COW), así que
    /// `Freelist::flush` casi siempre tiene algo que serializar.
    pub fn pending_writes(&self) -> u64 {
        self.write_count
    }

    /// Ejecuta `f` sobre los pares `(id, ns)` que el CATÁLOGO declara,
    /// leyéndolo del fichero si esta apertura todavía no lo había hecho.
    ///
    /// Lee como mucho una vez por apertura y guarda el resultado en
    /// `Db::catalog_indexes` (ver su comentario para por qué aquí y no en
    /// `Db::open`). Recorre la raíz de ESTA transacción, la misma que va a
    /// recibir la escritura que hace la pregunta: así el catálogo que decide
    /// y el árbol que se muta son el mismo estado, sin una instantánea
    /// intermedia que pudiera diferir — el mismo criterio con el que `put`
    /// lee el valor anterior y comprueba la unicidad.
    ///
    /// Con `f` en vez de devolviendo los ids que le interesan a cada
    /// llamante: así ninguna de las dos preguntas asigna nada en el camino
    /// caliente. Todo `put` y todo `delete` pasan por aquí, también sobre
    /// espacios de claves sin ningún índice, y devolver un `Vec` de ids
    /// habría metido una asignación por escritura donde no hace ninguna
    /// falta — el filtro por `ns` se hace sobre el conjunto ya materializado
    /// y no sobrevive a la llamada.
    ///
    /// El `take`/devolver alrededor de la lectura no es un rodeo: deja el
    /// campo en `None` si la lectura falla, que es justo lo que hace falta
    /// para que la siguiente escritura vuelva a intentarlo en vez de
    /// quedarse con una respuesta que nunca llegó a existir. Y sostener el
    /// candado durante la lectura evita que dos escrituras la hagan a la
    /// vez; no puede haber bloqueo mutuo, porque nada por debajo (`Pager`,
    /// `tree`) conoce este campo.
    fn with_catalog<T>(&self, f: impl FnOnce(&[(u8, u8)]) -> Result<T>) -> Result<T> {
        let mut slot = self.db.catalog_indexes.lock().unwrap();
        let catalog = match slot.take() {
            Some(c) => c,
            None => read_catalog_indexes(self, self.meta.root)?,
        };
        let out = f(&catalog);
        *slot = Some(catalog);
        out
    }

    /// Rechaza la escritura si el catálogo declara sobre `ns` algún índice
    /// que `declared` —lo que `Db::indexes_for` devolvió para este mismo
    /// `ns`— no cubre. Es el guardián que convierte el defecto silencioso
    /// descrito en `Db::catalog_indexes` en un `Err` inmediato.
    ///
    /// **Por id, no por espacio de claves.** Bastaría con "hay índices
    /// declarados sobre `ns`" para el caso del encargo (un proceso que no
    /// declara NADA), pero deja escapar el intermedio: dos índices sobre el
    /// mismo `ns` y un llamante que solo registra uno mantendría el suyo y
    /// dejaría el otro divergiendo, con la lista de definiciones no vacía y
    /// por tanto sin sospecha ninguna. Comparar id a id cuesta lo mismo y no
    /// deja ese hueco.
    ///
    /// Una base sin índices no paga nada de esto más allá del recorrido
    /// único: el catálogo está vacío y el bucle no llega a ejecutarse.
    fn refuse_undeclared(&self, ns: u8, declared: &[IndexDef]) -> Result<()> {
        self.with_catalog(|catalog| {
            for (id, indexed_ns) in catalog {
                if *indexed_ns == ns && !declared.iter().any(|d| d.id == *id) {
                    return Err(Error::IndexNotDeclared { id: *id, ns });
                }
            }
            Ok(())
        })
    }

    /// ¿Declara el catálogo algún índice sobre `ns`, lo tenga registrado
    /// esta apertura o no? Es la pregunta que necesita `delete_range`, que
    /// rechaza igual en los dos casos — ver su comentario.
    fn catalog_indexes_namespace(&self, ns: u8) -> Result<bool> {
        self.with_catalog(|catalog| Ok(catalog.iter().any(|(_, n)| *n == ns)))
    }

    /// Escritura sin mantenimiento de índices. `put` (más abajo) la envuelve
    /// para actualizar también los índices secundarios dentro de la misma
    /// transacción; `define_index` también la usa directamente para escribir
    /// el catálogo, que nunca está indexado.
    /// `pub(crate)` y no privado: `index.rs` necesita plantar una entrada
    /// corrupta EN un espacio de índice para comprobar que `scan_index` la
    /// reporta en vez de entrar en pánico, y desde que `put` rechaza los
    /// espacios reservados (`Error::ReservedNamespace`) esa es la única vía
    /// dentro del crate. No amplía nada de cara al usuario: `put_raw` sigue
    /// sin ser `pub`.
    /// `put` con región de anexado acotada. Misma puerta que `put` —espacios
    /// reservados e índices sin declarar— y, si el espacio tiene índices, cae
    /// al camino normal: mantener el índice importa más que el llenado.
    pub(crate) fn put_within(
        &mut self,
        ns: u8,
        key: &[u8],
        value: &[u8],
        upper: &[u8],
    ) -> Result<()> {
        if ns == CATALOG_NS || ns >= INDEX_NS_BASE {
            return Err(Error::ReservedNamespace { ns });
        }
        let defs = self.db.indexes_for(ns);
        self.refuse_undeclared(ns, &defs)?;
        if !defs.is_empty() {
            return self.put(ns, key, value);
        }
        self.put_bounded(ns, key, value, upper)
    }

    /// Igual que `put_raw`, pero con una región de anexado MÁS FINA que el
    /// espacio de claves.
    ///
    /// `put_raw` acota la región a `[ns, ns+1)`, que es la traducción exacta
    /// de "el mayor de su espacio". Para el crudo basta: sus claves crecen y
    /// nada por encima comparte espacio. Para los agregados no, y el efecto
    /// es caro: hora y día conviven en `0x02`, las claves de día ordenan por
    /// encima de TODAS las de hora, y en cuanto existe una sola fila de día
    /// ninguna inserción horaria vuelve a ser la mayor de su espacio. El sesgo
    /// de anexado deja de dispararse y el llenado de hoja cae al 40% medido.
    ///
    /// Con esto, quien escribe declara la región dentro de la que su clave sí
    /// es la mayor —para el agregado, la celda `[res][ts_bucket]`— y el árbol
    /// vuelve a partir por el borde. `upper` va SIN el prefijo de espacio:
    /// se le antepone aquí, igual que a la clave.
    pub(crate) fn put_bounded(
        &mut self,
        ns: u8,
        key: &[u8],
        value: &[u8],
        upper: &[u8],
    ) -> Result<()> {
        let full = scoped(ns, key);
        let bound = scoped(ns, upper);
        let root = crate::tree::put(self, self.meta.root, &full, value, Some(&bound))?;
        self.meta.root = root;
        Ok(())
    }

    pub(crate) fn put_raw(&mut self, ns: u8, key: &[u8], value: &[u8]) -> Result<()> {
        let full = scoped(ns, key);
        // La cota de anexado del árbol (ver `tree::put`): el byte siguiente a
        // `ns`, solo. `scoped` antepone `ns`, así que toda clave de ESTE
        // espacio es `[ns] ++ algo` —estrictamente menor que `[ns + 1]`— y
        // toda clave de un espacio superior empieza por un byte `>= ns + 1`,
        // luego es mayor o igual que él. Es la traducción exacta de "el mayor
        // de su espacio" al único vocabulario que `tree.rs` tiene, que es el
        // de claves opacas ordenadas.
        //
        // `checked_add` y no `+ 1`: para `ns == 0xff` no existe cota (ninguna
        // cadena de bytes es mayor que todas las que empiezan por `0xff`), y
        // `None` es justo lo que `tree::put` entiende por "sin región", que
        // para el espacio más alto es además la respuesta correcta — sus
        // claves sí son las mayores del árbol.
        let upper: Option<[u8; 1]> = ns.checked_add(1).map(|next| [next]);
        let root = crate::tree::put(
            self,
            self.meta.root,
            &full,
            value,
            upper.as_ref().map(|b| b.as_slice()),
        )?;
        self.meta.root = root;
        Ok(())
    }

    /// Borrado sin mantenimiento de índices. Ver `put_raw`.
    fn delete_raw(&mut self, ns: u8, key: &[u8]) -> Result<bool> {
        let full = scoped(ns, key);
        let (root, existed) = crate::tree::delete(self, self.meta.root, &full)?;
        self.meta.root = root;
        Ok(existed)
    }

    /// Escribe `key`/`value` en `ns` y mantiene, dentro de la MISMA
    /// transacción, cualquier índice secundario definido sobre `ns` (tarea
    /// 16) — esa atomicidad es lo único que un índice mantenido a mano con
    /// prefijos de clave no puede dar.
    ///
    /// **Contrato de error, igual que `tree::put` (ver su comentario): si
    /// esta función devuelve `Err`, abandona la transacción — déjala caer
    /// sin `commit` — en vez de reintentar sobre el mismo `tx`.** No hace
    /// falta para el caso más peligroso, el que motivó este comentario: una
    /// clave de índice no único es `indexado + primaria + 2`, y ambas
    /// mitades pueden ser individualmente legales (`page_size / 4` cada una,
    /// tarea 11) y aun así superar el límite juntas. Ese caso, y una
    /// violación de unicidad, se comprueban ENTEROS antes de mutar ninguna
    /// página (ver el bucle de más abajo): si van a fallar, fallan limpio,
    /// sin haber tocado el dato ni ningún índice, exactamente como ya hace
    /// `tree::put` con una clave primaria de sobra. El contrato de abandonar
    /// la transacción cubre lo que queda: un error real de motor (`Corrupt`,
    /// `Full`) a mitad de aplicar las mutaciones ya planeadas, el mismo tipo
    /// de fallo catastrófico que ya obliga a abandonar cualquier `put`/
    /// `delete` de este motor.
    ///
    /// **Nota sobre `KeyTooLarge` (ronda 2 de revisión, hallazgo 8, sin
    /// arreglo — documentado):** esta función reutiliza la misma variante
    /// `Error::KeyTooLarge { len, max }` que usa `tree::put` para la clave
    /// primaria, así que un `Err` de este tipo no dice POR SÍ SOLO si lo
    /// rechazó la clave primaria o una entrada de algún índice, ni cuál. Es
    /// una limitación real, de prioridad baja: `len`/`max` siguen siendo
    /// correctos y suficientes para saber "esta escritura no cabe", que es
    /// la información que importa para decidir qué hacer a continuación
    /// (nada la vuelve a intentar igual). Distinguirlo exigiría o una nueva
    /// variante de error o añadir un campo a esta, cualquiera de las dos
    /// cosas un cambio de la forma pública de `Error` fuera del alcance de
    /// esta ronda.
    pub fn put(&mut self, ns: u8, key: &[u8], value: &[u8]) -> Result<()> {
        if ns == CATALOG_NS || ns >= INDEX_NS_BASE {
            return Err(Error::ReservedNamespace { ns });
        }
        let defs = self.db.indexes_for(ns);
        // Antes de decidir NADA, ni siquiera el atajo de "aquí no hay
        // índices": esa lista vacía puede significar que esta apertura no
        // declaró los suyos, y entonces el atajo es justo el que guarda la
        // fila sin indexar. Ver `Db::catalog_indexes`.
        self.refuse_undeclared(ns, &defs)?;
        if defs.is_empty() {
            return self.put_raw(ns, key, value);
        }

        // `logical_page_size`, no `page_size` (tarea 17): es el tamaño con
        // el que `tree::put` construye páginas de verdad (ver su propio
        // `max_key`), así que este límite tiene que coincidir con el suyo o
        // una base cifrada aceptaría aquí una clave de índice que
        // `tree::put` rechazaría después, ya con la entrada vieja borrada
        // (ver el comentario de la fase de aplicación, más abajo).
        let max_key = self.logical_page_size() / 4;

        // Clave primaria demasiado grande (ronda 2 de revisión, hallazgo 3):
        // en un índice único la entrada de índice es SOLO el valor indexado
        // — la clave primaria viaja como valor, nunca como parte de la
        // clave de índice — así que el chequeo de tamaño de más abajo, que
        // solo mira entradas de índice, no la ve nunca. Sin este chequeo
        // aparte, una clave primaria de sobra pasaba la fase de
        // planificación entera, la entrada de índice se llegaba a escribir
        // de verdad en la fase de aplicación, y solo el último paso
        // (`put_raw(ns, key, value)`) fallaba — dejando esa entrada huérfana
        // en memoria si quien llama no abandonaba la transacción, la misma
        // clase de mutación prematura que el resto de esta función existe
        // para evitar. `1 +` porque `scoped()` antepone el byte de `ns`
        // antes de que la clave llegue a `tree::put`, que es quien de verdad
        // aplica este límite (ver su comentario) — comprobarlo aquí sin ese
        // `+1` habría aceptado una clave que `tree::put` iba a rechazar de
        // todas formas, un byte más allá del límite real.
        let full_key_len = 1 + key.len() as u32;
        if full_key_len > max_key {
            return Err(Error::KeyTooLarge { len: full_key_len, max: max_key });
        }

        let previous = self.get(ns, key)?;

        // Fase de planificación: solo lecturas, ninguna página se toca
        // todavía. Recoge qué entradas de índice hay que borrar (las viejas,
        // derivadas del valor anterior — su tamaño ya se validó cuando se
        // insertaron, así que borrarlas nunca puede fallar por tamaño) y
        // cuáles insertar (las nuevas, derivadas de `value`), validando de
        // paso el tamaño de cada una nueva y, en un índice único, que no
        // colisione con la de OTRA fila.
        //
        // La comprobación de unicidad compara la clave primaria ALMACENADA,
        // no solo si la entrada existe: así una fila que se reescribe con el
        // mismo valor indexado que ya tenía (p. ej. solo cambió una parte no
        // indexada del valor) no se confunde consigo misma. Comparar solo
        // existencia obligaría a borrar la entrada vieja ANTES de comprobar
        // duplicados para que este caso no fallara — y borrar antes de
        // validar es exactamente la mutación prematura que este bloque
        // entero existe para evitar.
        let mut deletions: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut insertions: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();

        for def in &defs {
            if let Some(old) = &previous {
                for ik in (def.extract)(key, old) {
                    deletions.push((def.index_ns(), index_key(def, &ik, key)));
                }
            }
            for ik in (def.extract)(key, value) {
                let entry = index_key(def, &ik, key);
                // `+ 1`: mismo motivo que arriba — la entrada de índice
                // también pasa por `scoped()` (bajo `def.index_ns()`) antes
                // de llegar a `tree::put`, que mide la clave YA con ese
                // byte de más (ronda 2 de revisión, hallazgo 2). Sin el
                // `+ 1` una entrada de exactamente `page_size / 4` bytes
                // pasaba esta comprobación y fallaba después, en la fase de
                // aplicación, ya con la entrada vieja borrada.
                let full_entry_len = entry.len() as u32 + 1;
                if full_entry_len > max_key {
                    return Err(Error::KeyTooLarge { len: full_entry_len, max: max_key });
                }
                if def.unique
                    && let Some(existing_pk) = self.get(def.index_ns(), &ik)?
                    && existing_pk != key
                {
                    return Err(Error::DuplicateKey { id: def.id });
                }
                let payload = if def.unique { key.to_vec() } else { Vec::new() };
                insertions.push((def.index_ns(), entry, payload));
            }
        }

        // Fase de aplicación: todo lo de arriba ya validó limpio, así que de
        // aquí en adelante solo puede fallar por un error real de motor —
        // el caso que el contrato de "abandona la transacción" ya cubre.
        for (idx_ns, k) in &deletions {
            self.delete_raw(*idx_ns, k)?;
        }
        for (idx_ns, k, v) in &insertions {
            self.put_raw(*idx_ns, k, v)?;
        }
        self.put_raw(ns, key, value)
    }

    /// Borra `key` de `ns` y sus entradas de índice asociadas (tarea 16),
    /// dentro de la misma transacción. Mismo contrato de error que `put`:
    /// abandona la transacción si devuelve `Err`.
    pub fn delete(&mut self, ns: u8, key: &[u8]) -> Result<bool> {
        if ns == CATALOG_NS || ns >= INDEX_NS_BASE {
            return Err(Error::ReservedNamespace { ns });
        }
        let defs = self.db.indexes_for(ns);
        // Mismo guardián que en `put`, y por el mismo motivo: sin él, una
        // apertura que no declara sus índices borra la fila y deja su
        // entrada de índice apuntando a una clave primaria que ya no
        // existe. Ver `Db::catalog_indexes`.
        self.refuse_undeclared(ns, &defs)?;
        if !defs.is_empty()
            && let Some(old) = self.get(ns, key)?
        {
            for def in &defs {
                for ik in (def.extract)(key, &old) {
                    self.delete_raw(def.index_ns(), &index_key(def, &ik, key))?;
                }
            }
        }
        self.delete_raw(ns, key)
    }

    /// Borra todas las claves de `[from, to)` dentro del espacio `ns`.
    ///
    /// Es la operación que hace viable la poda diaria por retención: los
    /// números de página de las hojas viven en sus nodos padre, así que
    /// `delete_range` (`tree.rs`) nunca las lee — vuelca sus punteros a la
    /// lista de libres en bloque y desengancha el subárbol entero. El coste
    /// es proporcional al número de páginas internas, no al de entradas
    /// borradas.
    ///
    /// **Se rechaza sobre un `ns` con algún índice definido** (ronda 2 de
    /// revisión, hallazgo 1) — `Error::DeleteRangeIndexed`. Es justo la
    /// propiedad de arriba, "nunca lee las hojas", la que hace imposible
    /// mantener los índices aquí sin tirarla: no hay forma de saber qué
    /// entradas de índice retirar sin visitar cada valor borrado, y
    /// visitarlos todos vuelve a poner el coste en proporción al número de
    /// entradas, exactamente lo que esta función existe para evitar.
    ///
    /// Se consideraron tres caminos:
    /// 1. Enrutar por `delete` clave a clave cuando `ns` está indexado:
    ///    correcto, pero destruye la garantía de coste que justifica esta
    ///    función — precisamente para el caso de uso, poda por retención,
    ///    que más se beneficia de tener también un índice (la carga de
    ///    referencia de este proyecto es justo esa: cientos de miles de
    ///    entradas podadas por nodo y día).
    /// 2. Rechazar limpio con un error propio. Preserva la corrección Y la
    ///    garantía de coste sin ambigüedad, al precio de que quien llama
    ///    tenga que decidir explícitamente qué hacer en vez de que el motor
    ///    decida por él.
    /// 3. Aceptarlo SOLO cuando el índice declara que su clave empieza por
    ///    el mismo cubo temporal que la clave primaria que borra el rango
    ///    — entonces borrar el rango de datos `[from, to)` corresponde a
    ///    borrar también un rango CONTIGUO de entradas de índice, y el
    ///    camino rápido de `delete_range` serviría para ambos árboles. Es
    ///    la vía que anticipa la especificación del proyecto (sección 8).
    ///    Pero esa correspondencia depende de una propiedad de `extract`
    ///    que el motor no puede verificar — igual que la versión es la
    ///    única defensa posible contra un extractor que cambia, aquí solo
    ///    quien llama puede afirmar "mi extractor sí respeta esto", y
    ///    construir un mecanismo de declaración correcto (¿por qué campo se
    ///    marca?, ¿cómo se deriva el rango de índice a partir de `from`/
    ///    `to`?, ¿qué pasa si la declaración es falsa?) es una pieza de
    ///    diseño propia, no un arreglo de esta ronda.
    ///
    /// Se optó por (2): es la única de las tres que no puede divergir en
    /// silencio bajo ninguna circunstancia y no exige inventar superficie de
    /// API nueva sin el diseño y las pruebas que merece. (1) traiciona
    /// exactamente el caso de uso que este motor prioriza; (3) es el camino
    /// correcto a largo plazo, pero como tarea propia y deliberada, con su
    /// propio ciclo de revisión — no como parte de una ronda de correcciones
    /// sobre otro hallazgo.
    ///
    /// **"Con algún índice definido" se decide contra el CATÁLOGO**, no
    /// contra los `IndexDef` que esta apertura tenga registrados. Escrito
    /// solo contra los registrados, este rechazo no se disparaba jamás en el
    /// proceso donde de verdad hacía falta: el podador de retención —el caso
    /// de uso que motiva esta función entera— no llama a `define_index`
    /// porque no tiene el extractor que exige, así que su lista está vacía,
    /// el rechazo no saltaba, y cada poda diaria huerfanaba de golpe todas
    /// las entradas de índice del rango. Medido sobre la carga de retención
    /// de 14 días: con el índice registrado, la base se estabiliza en 328
    /// páginas del día 30 al 59; sin registrarlo, crece sin cota (+4,43
    /// páginas/día, 1557 al día 299) con 30 000 entradas de índice para 1400
    /// filas vivas — 95,3 % basura. Y `audit_pages` decía `true` todo el
    /// rato, con razón: la propiedad de las páginas estaba intacta; lo que
    /// estaba muerto era el significado de las entradas.
    ///
    /// El error sigue siendo `DeleteRangeIndexed` también cuando el índice
    /// existe pero no está declarado, y no `IndexNotDeclared`: declararlo no
    /// haría viable esta operación: seguiría rechazada por (2), de arriba.
    /// Un error que sugiere una acción correctora que no corrige nada es
    /// peor que ninguna sugerencia. Quien caiga aquí y enrute por `delete`
    /// clave a clave —el remedio que (1) describe— sí obtendrá entonces
    /// `IndexNotDeclared`, que es donde declarar el índice sí resuelve.
    pub fn delete_range(&mut self, ns: u8, from: &[u8], to: &[u8]) -> Result<()> {
        if ns == CATALOG_NS || ns >= INDEX_NS_BASE {
            return Err(Error::ReservedNamespace { ns });
        }
        if !self.db.indexes_for(ns).is_empty() || self.catalog_indexes_namespace(ns)? {
            return Err(Error::DeleteRangeIndexed { ns });
        }
        let (a, b) = (scoped(ns, from), scoped(ns, to));
        // Con la reserva abierta: desenganchar un subárbol reescribe el
        // camino hasta la raíz, así que esto ASIGNA aunque su efecto sea
        // liberar. Ver `RESERVE_PAGES`.
        let root = self.with_reserve(|tx| crate::tree::delete_range(tx, tx.meta.root, &a, &b))?;
        self.meta.root = root;
        Ok(())
    }

    pub fn get(&self, ns: u8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        crate::tree::get(self, self.meta.root, &scoped(ns, key))
    }

    /// Recorrido de `[from, to)` dentro de `ns`, sobre la raíz de **esta**
    /// transacción — es decir, viendo también lo que ella misma lleva escrito
    /// y todavía no ha confirmado. `ReadTxn::scan` no puede dar eso: su
    /// instantánea es la del último commit.
    ///
    /// Existe para el patrón leer-modificar-escribir sobre un RANGO dentro de
    /// una sola transacción, que `get` (puntual) no cubre cuando no se sabe
    /// de antemano qué claves hay. Su primer consumidor es la capa de
    /// agregación (`rollup`), que necesita releer una celda entera antes de
    /// sobrescribirla; sin este método esa capa tendría que abrir una lectura
    /// aparte y perdería justo lo que la hace correcta —ver el estado de la
    /// transacción en curso— o tendría que vivir dentro del motor con acceso
    /// privilegiado, que es peor.
    ///
    /// El `Cursor` toma prestada la transacción de forma **inmutable**, así
    /// que el compilador ya impide mutarla mientras el recorrido siga vivo:
    /// hay que recoger lo que interese y soltar el cursor antes de escribir.
    /// No hace falta ninguna regla de invalidación escrita a mano.
    ///
    /// Devuelve `Result` y no un `Cursor` a secas por la misma razón que
    /// `ReadTxn::scan` (ver su comentario): el descenso inicial puede toparse
    /// con corrupción, y un `.expect` ahí sería un pánico de la API pública.
    pub fn scan(&self, ns: u8, from: &[u8], to: &[u8]) -> Result<crate::tree::Cursor<'_, Self>> {
        crate::tree::Cursor::new(self, self.meta.root, ns, from, to)
    }

    /// Traslada la meta B a su posición definitiva (tarea 18). No hace nada
    /// si ya está ahí — bases con `page_size >= 4096` (ya en sectores
    /// distintos desde `Db::create`) o una reubicación anterior que ya
    /// completó, sea de esta sesión o de una previa.
    ///
    /// Es la ÚNICA operación de este motor que reescribe la cabecera —
    /// escrita una sola vez en el resto de la vida del fichero (tarea 3) — y
    /// por eso el orden importa tanto: primero se escribe una copia de la
    /// meta CONFIRMADA en su sitio nuevo y se sincroniza; luego el ESPEJO de
    /// la cabecera (`Geometry::write_mirror`) y se sincroniza; y solo
    /// entonces la cabecera PRINCIPAL, con otra sincronización final.
    ///
    /// **La copia es la meta CONFIRMADA (`self.db.committed`), nunca
    /// `self.meta`** — la de esta transacción, con su propio `root` todavía
    /// a medio construir. Mismo razonamiento que seguía la extensión del
    /// techo de contador de nonce, la otra escritura de meta fuera de un
    /// commit que llegó a existir: así, si el proceso muere en cualquier punto de
    /// esta función, lo único que puede llegar a verse como confirmado es el
    /// último estado que YA lo estaba antes de que esta transacción
    /// empezara — jamás un commit a medio hacer.
    ///
    /// **Corte entre el primer `sync` y las cabeceras**: ninguna de las dos
    /// copias de cabecera ha cambiado todavía — la principal sigue
    /// apuntando a la posición antigua, donde la meta también sigue estando
    /// intacta (nunca se toca) — se monta igual, y la reubicación se
    /// reintenta en el commit siguiente.
    ///
    /// **Corte a medio escribir el espejo o la principal — hallazgo HIGH de
    /// revisión, corregido en esta ronda.** Antes de este arreglo, la
    /// cabecera se escribía UNA sola vez aquí, sin ninguna copia de
    /// respaldo: un corte que aterrizara a medias (la nueva cabecera solo
    /// difiere de la vieja en `meta_b_page`, bytes 44..48, y el CRC, bytes
    /// 60..64 — cualquier corte entre el byte 45 y el 63 deja un
    /// `meta_b_page` actualizado con un CRC que no le corresponde) dejaba
    /// `Geometry::decode` fallando con `Corrupt { kind: Checksum }` PARA
    /// SIEMPRE — `Db::open` no podía volver a montar la base nunca más,
    /// aunque las dos metas y el árbol entero siguieran intactos. Justo la
    /// inmunidad que tenía la cabecera de escritura-única (tarea 3), que
    /// esta tarea le quita al convertirla en reescribible. Confirmado de
    /// punta a punta con `a_torn_header_rewrite_does_not_permanently_brick_the_database`
    /// (`relocation_tests`, siete prefijos de corte distintos dentro de la
    /// región que cambia) contra la versión sin espejo.
    ///
    /// El espejo va PRIMERO — mismo patrón que el resto de esta función:
    /// escribir la copia de respaldo
    /// primero y sincronizarla antes de tocar la que `Geometry::read` prueba
    /// primero. Con las dos sincronizadas por separado, un corte a medio
    /// escribir CUALQUIERA de las dos deja a la otra — ya sincronizada,
    /// intacta, con el contenido completo de una de las dos versiones
    /// (vieja si el corte fue en el espejo, nueva si fue en la principal) —
    /// como la única fuente fiable, y `Geometry::read` cae a ella
    /// automáticamente si la principal no decodifica.
    ///
    /// **Corte después de que la cabecera (principal o su espejo) esté
    /// duradera**: la posición nueva de la meta B ya tiene, de forma
    /// duradera, una copia válida del último estado confirmado — montar por
    /// ahí (si el desempate de `Meta::load` la elige) no pierde nada
    /// tampoco. Ver `the_database_survives_a_crash_during_relocation` y
    /// `a_crash_after_the_header_write_does_not_roll_back_a_commit`, en
    /// `relocation_tests`.
    ///
    /// **No hace falta reservar la página destino aquí** — a diferencia de
    /// lo que un primer intento de esta función podría sugerir: ninguna
    /// extensión de fichero (ni `alloc` ni el cierre de `commit` que
    /// serializa la lista de libres) entrega jamás esa página concreta como
    /// dato, así que para cuando esta función se ejecuta ya está
    /// garantizado que no hay nada ahí que proteger — ver
    /// `skip_meta_b_target`. El `debug_assert` de abajo comprueba esa
    /// invariante en vez de repetir el trabajo que ya hace el salto.
    fn relocate_meta_b(&mut self) -> Result<()> {
        let geometry = self.db.pager.geometry();
        let target = Self::final_meta_b_page(geometry.page_size);
        if geometry.meta_b_page == target {
            return Ok(());
        }
        debug_assert!(
            self.meta.n_pages > target,
            "relocate_meta_b se llamó con el fichero todavía por debajo de la página destino: \
             skip_meta_b_target no puede haber protegido esa página todavía"
        );

        let mut new_geometry = geometry;
        new_geometry.meta_b_page = target;

        let current = *self.db.committed.read().unwrap();
        // Con `new_geometry`, NO con `geometry`: `MetaSlot::B.page(&geometry)`
        // resuelve con la posición VIEJA, no con `target` — escribir así deja
        // la posición nueva sin ningún contenido legible justo cuando la
        // cabecera, dos líneas más abajo, empieza a apuntar ahí. Con
        // `new_geometry`, `MetaSlot::B.page(&new_geometry)` ya es `target`.
        // Las tres sincronizaciones pasan por `sync_upto` (ver su
        // comentario): lo que se está escribiendo es el
        // estado CONFIRMADO (`current.0`), así que cada una de ellas
        // demuestra en disco esa meta y el punto durable puede avanzar
        // hasta ella sin pagar ningún `fsync` que no se fuera a pagar de
        // todos modos.
        let durable_txn = current.0.txn_id;
        // Sellada como ranura B, igual que en su posición vieja: el tag ata
        // la LETRA de la ranura, no su número de página, precisamente para
        // que una reubicación no invalide lo que ya estaba escrito — ver
        // `MetaSlot::index`. De `new_geometry` el sellado solo usa `db_id`,
        // que es el mismo en las dos; `meta_b_page` no entra en el tag.
        let seal = self.seal_meta(&new_geometry, current.0, MetaSlot::B)?;
        current.0.store_via(&self.db.pager, &new_geometry, MetaSlot::B, seal.as_ref())?;
        self.db.sync_upto(durable_txn)?;

        new_geometry.write_mirror(self.db.pager.storage())?;
        self.db.sync_upto(durable_txn)?;

        new_geometry.write(self.db.pager.storage())?;
        self.db.sync_upto(durable_txn)?;
        self.db.pager.set_geometry(new_geometry);

        // **`set_geometry` corre DESPUÉS de un `sync` que puede fallar
        // (INFO de revisión posterior a la entrega, decisión documentada en
        // vez de cambiada).** Si ese `sync()?` devuelve `Err` — un error de
        // E/S real, no un desgarro (que siempre devuelve `Ok`, ver
        // `Storage::write_at`) — el `?` corta la función aquí: la geometría
        // en memoria se queda VIEJA aunque la escritura en sí pueda haber
        // llegado al medio. No se ajusta a propósito: cualquier fallo de
        // `sync()` en este motor (también en `Db::maybe_sync`, unas líneas
        // más abajo en `commit`) ya se trata igual — se propaga como `Err`
        // sin intentar distinguir "la escritura llegó pero el `fsync` no"
        // de "no llegó nada" — y aquí AUTOCURA sin necesitar ese distingo:
        // como `geometry.meta_b_page` (en memoria) sigue siendo la vieja,
        // el PRÓXIMO commit vuelve a entrar en esta función (el guard de
        // `commit` sigue viendo el umbral superado) y repite las tres
        // escrituras desde cero — inofensivo tanto si la vez anterior no
        // llegó a nada como si llegó pero el `sync` mintió, porque las tres
        // escrituras son idempotentes (la misma `new_geometry`/copia de
        // meta, recalculada igual). Verificado de punta a punta con
        // `relocation_survives_a_torn_write_at_every_cut_point_under_every_sync_policy`
        // (`crypto.rs`): ninguna combinación de política de `Sync`, ranura
        // activa o punto de corte pierde datos ni reutiliza un contador.
        //
        // La posición VIEJA queda libre de verdad: nada vuelve a apuntarla
        // desde aquí en adelante (la cabecera, ya duradera, señala
        // `target`), así que puede reciclarse como cualquier otra página
        // libre en vez de perderse para siempre. Autorrevisión de esta
        // ronda: sin esto, cada base que llega a reubicar pierde una página
        // (512 B a 32 KB, según `page_size`) para siempre — nada la libera
        // ni la reutiliza jamás. Detectado y regresionado con
        // `free_subtree_accepts_a_child_at_the_old_meta_b_page_once_it_has_been_recycled`
        // y `relocation_reclaims_the_old_meta_b_page_without_leaking_it`, en
        // `tree.rs`. **Corrección de atribución (ronda de revisión
        // posterior a la entrega):** una versión anterior de este comentario
        // citaba `overflow_inside_a_bulk_freed_subtree_leaves_no_orphan_pages`
        // y `churn_then_range_delete_on_a_low_fanout_tree_leaves_no_orphan_pages`
        // como detectores — las dos operan enteras dentro de una única
        // transacción SIN CONFIRMAR (nunca llaman a `commit()`), así que
        // `relocate_meta_b` no llega a ejecutarse ni una vez en ninguna de
        // las dos: lo que de verdad detectaban era el hueco de
        // `skip_meta_b_target` en `WriteTxn::pages_in_use` (ver su
        // comentario), un hallazgo relacionado pero distinto — revertir
        // este `free` las deja en verde.
        //
        // Segura de liberar ANTES de que termine esta transacción, no solo
        // tras confirmar: a diferencia de una página de árbol, una página de
        // meta nunca es visible a través de `Meta.root`/`freelist_head` de
        // ningún snapshot — ningún lector, viejo o nuevo, la referencia
        // jamás — así que no hace falta la misma protección de lector que
        // `free` da a una página de árbol reciclada (ver su comentario).
        //
        // No a prueba de cortes hasta el final: si el proceso muere DESPUÉS
        // de que la cabecera ya apunta a `target` (duradero, los dos `sync`
        // de arriba ya pasaron) pero ANTES de que ESTA transacción llegue a
        // confirmar de verdad, este `free` — mutación solo en memoria, igual
        // que cualquier otra de esta transacción — no sobrevive, y la
        // reubicación no se reintenta en la siguiente sesión (ya completó:
        // `geometry.meta_b_page == target` la próxima vez que se llame), así
        // que la página queda perdida en ese cruce concreto. Peor que
        // "nunca perderla", mejor que "perderla siempre": el caso común —
        // una reubicación cuya transacción sí llega a confirmar — la
        // recicla.
        self.free(geometry.meta_b_page);
        Ok(())
    }

    /// Última página del prefijo que NINGÚN recorte puede tocar jamás, más
    /// uno: el suelo absoluto de `Db::reclaim_tail`.
    ///
    /// Se deriva de la geometría vigente, no de constantes:
    ///
    /// - **Página `0`**: la cabecera (bytes `0..64`) y su espejo
    ///   (`HEADER_MIRROR_OFFSET..+64`, es decir `64..128`) viven las dos
    ///   dentro de ella, porque `MIN_PAGE_SIZE` (512) es mayor que 128 —
    ///   comprobado abajo con un `debug_assert` en vez de asumido, que es
    ///   justo la clase de suposición que este proyecto ya ha pagado cara.
    /// - **`meta_a_page` y `meta_b_page`**, leídas de la geometría: la B se
    ///   MUEVE (tarea 18), así que una constante aquí valdría solo hasta la
    ///   primera reubicación.
    /// - **La página destino de la reubicación** (`final_meta_b_page`)
    ///   mientras `n_pages` esté por encima de ella: en ese tramo está
    ///   reservada aunque la reubicación todavía no haya ocurrido — ver
    ///   `skip_meta_b_target` — así que no es libre ni puede recortarse
    ///   "por debajo" sin cambiar el significado de ese hueco.
    ///
    /// **En la práctica nunca ata**, y esa es la comprobación de verdad:
    /// ninguna de esas páginas entra jamás en la lista de libres mientras
    /// cumple su papel (la `0` y la `1` nunca; la meta B actual tampoco; el
    /// destino de la reubicación tampoco, porque `skip_meta_b_target` lo
    /// retira del espacio de numeración), así que el sufijo libre que
    /// calcula `Freelist::free_suffix_start` se detiene por encima de todas
    /// ellas por sí solo. Este suelo es el cinturón: si alguna vez una de
    /// esas páginas apareciera como libre por un defecto en otro sitio, el
    /// recorte se negaría a llevársela en vez de dejar el fichero sin
    /// cabecera.
    fn reserved_floor(&self) -> PageNo {
        let g = self.db.pager.geometry();
        debug_assert!(
            crate::header::HEADER_MIRROR_OFFSET + crate::header::HEADER_SIZE as u64
                <= u64::from(g.page_size),
            "el espejo de la cabecera ya no cabe en la página 0: el suelo del recorte \
             tendría que dejar de ser una sola página"
        );
        let mut floor = 1;
        floor = core::cmp::max(floor, g.meta_a_page + 1);
        floor = core::cmp::max(floor, g.meta_b_page + 1);
        let target = Self::final_meta_b_page(g.page_size);
        if self.meta.n_pages > target {
            floor = core::cmp::max(floor, target + 1);
        }
        floor
    }

    /// Decide hasta dónde puede recortarse el fichero, o `None` si no hay
    /// ninguna cola libre que devolver. No escribe nada ni muta nada que
    /// `WriteTxn::Drop` no sepa deshacer: si devuelve `None`, la
    /// transacción se abandona sin commit y el fichero queda exactamente
    /// como estaba.
    ///
    /// **Sincroniza primero, a propósito y sin condición de política.** El
    /// suelo de reutilización cuenta la meta DURABLE como lector implícito
    /// (ver `Db::durable` y `Db::reuse_floor`), así que bajo
    /// `Sync::Interval`/`Never` un punto durable retrasado dejaría fuera del
    /// recorte todo lo liberado desde entonces — hasta el fichero entero,
    /// bajo `Sync::Never`, donde el punto durable podría no haberse movido
    /// nunca. Pagar UN `fsync` aquí pone el punto durable al día y hace que
    /// el recorte dependa solo de lo que de verdad está vivo, no de la
    /// política de sincronización. Es el mismo trato que ya se da a la
    /// recuperación de espacio en `WriteTxn::recycle` y en `commit`
    /// (`reclaim_needs_a_sync`), solo que aquí es incondicional: quien llama
    /// a `reclaim_tail` ha pedido explícitamente una operación de
    /// mantenimiento, no un `put` en el camino caliente.
    ///
    /// Nótese lo que NO hace: bajar el suelo. Sincronizar SUBE el punto
    /// durable pagando por él; los lectores vivos siguen contando igual.
    fn plan_shrink(&mut self) -> Result<Option<PageNo>> {
        let committed = self.db.committed.read().unwrap().0.txn_id;
        self.db.sync_upto(committed)?;
        let floor = self.db.reuse_floor();
        let n_pages = self.meta.n_pages;
        let reserved = self.reserved_floor();
        let txn_id = self.meta.txn_id;
        let pager = &self.db.pager;
        let state = self.guard.as_mut().expect("estado presente");
        // La lista COMPLETA, no la foto perezosa: ver `Freelist::absorb`.
        // Los contenedores que devuelve cuentan como cola recortable aunque
        // `pop` todavía no los sirva — ver `Freelist::free_suffix_start`,
        // que explica por qué recortar y reutilizar no son la misma
        // pregunta y ocurren en momentos distintos del commit.
        let containers = state.freelist.absorb(pager, txn_id)?;
        let cut = core::cmp::max(
            state.freelist.free_suffix_start(n_pages, Some(floor), &containers),
            reserved,
        );
        Ok(if cut < n_pages { Some(cut) } else { None })
    }

    /// Escribe la lista de libres, sincroniza, escribe la meta inactiva y
    /// vuelve a sincronizar. Ese orden es lo que hace el commit atómico: la
    /// meta solo apunta a páginas que ya están en disco.
    pub fn commit(self) -> Result<()> {
        self.commit_maybe_shrinking(false).map(|_| ())
    }

    /// `commit`, con la opción de devolverle al sistema de ficheros la cola
    /// libre del fichero. Devuelve la extensión (en páginas) que el fichero
    /// tiene al terminar — `Db::reclaim_tail` la usa para saber si esta
    /// pasada ha progresado.
    ///
    /// # El orden, que es donde esto se rompe si se rompe
    ///
    /// 1. `plan_shrink` decide el corte (y no escribe nada).
    /// 2. La lista de libres se purga de todo lo que va a dejar de existir
    ///    y se serializa YA purgada.
    /// 3. La meta con el `n_pages` reducido se escribe **y se sincroniza**.
    /// 4. La OTRA ranura recibe esa misma meta **y se sincroniza**.
    /// 5. Solo entonces se recorta el fichero.
    ///
    /// **3 y 5 no son intercambiables.** Recortar antes de que la meta
    /// reducida sea duradera deja, si la corriente se va en medio, una meta
    /// superviviente que declara `n_pages` páginas sobre un fichero que ya
    /// no las tiene: su raíz, sus nodos internos y su cadena de lista de
    /// libres pueden apuntar más allá del final, y ahí no hay recuperación
    /// posible — es la misma forma del hallazgo 7 de
    /// `review-final-corrupcion.md`, donde un `n_pages` manipulado en un
    /// byte mandaba el primer `alloc` a escribir terabytes más allá. En el
    /// orden correcto, un corte entre 4 y 5 deja lo contrario: `n_pages`
    /// pequeño sobre un fichero todavía grande, que es exactamente el
    /// estado que `Db::open` ya sabe reconciliar desde siempre (barre
    /// `[meta.n_pages, file_pages)` y mete esas páginas en la lista de
    /// libres) — no se pierde nada y la cola se puede volver a recortar
    /// después.
    ///
    /// **Por qué las DOS ranuras.** El diseño de dos metas promete que si
    /// una no decodifica se monta por la otra. Tras un recorte, esa otra —la
    /// meta anterior, con el `n_pages` grande— describiría un fichero que ya
    /// no existe: `Db::open` la elegiría por ser la única legible y fallaría
    /// al leer su cadena de libres más allá del final (`UnexpectedEof` es
    /// fatal, no se degrada con gracia como un `Corrupt`), dejando la base
    /// inaccesible. Escribir la misma meta en las dos ranuras antes de
    /// recortar cierra esa ventana por completo, y deja una invariante
    /// simple de comprobar: **ninguna meta legible del fichero referencia
    /// jamás una página más allá del final**. Cuesta una página de escritura
    /// y un `fsync` de más en una operación de mantenimiento explícita. Las
    /// dos ranuras quedan idénticas, que es el único caso de empate en
    /// `txn_id` que `Meta::load` ya trataba de forma determinista (ver su
    /// comentario) — el siguiente commit vuelve a alternar con normalidad.
    fn commit_maybe_shrinking(mut self, shrink: bool) -> Result<PageNo> {
        let cut = if shrink {
            match self.plan_shrink()? {
                Some(cut) => Some(cut),
                // Nada que devolver: se abandona la transacción sin
                // escribir ni una página. `Drop` restaura la lista de
                // libres que `absorb` trajo a memoria.
                None => return Ok(self.meta.n_pages),
            }
        } else {
            None
        };
        // Reubicación de la meta B (tarea 18), antes de tocar nada más: se
        // comprueba en TODO commit una vez el fichero pasa de 4 KB, pero
        // `relocate_meta_b` es barata de llamar de más — un campo comparado
        // — y no hace nada si ya está en su sitio, así que no hace falta
        // acotarlo a "la primera vez". `u64` en la multiplicación: con
        // `n_pages`/`page_size` en `u32`, el producto desborda de sobra
        // antes de que ninguno de los dos se acerque a su máximo real.
        if (self.meta.n_pages as u64) * (self.page_size() as u64) > 4096 {
            // El fichero tiene que estar MATERIALIZADO hasta `n_pages` antes
            // de reubicar la meta B: la reubicación escribe en su página
            // destino contando con que el fichero ya llega hasta ahí, y con
            // el buffer de páginas sucias esas páginas pueden seguir en RAM.
            // Sin esto, un corte justo en la reubicación deja una meta que
            // apunta más allá del final del fichero y la base no vuelve a
            // abrirse: `Io(UnexpectedEof)`, que es lo que cazó
            // `relocation_survives_a_torn_write_at_every_cut_point_under_every_sync_policy`.
            self.flush_dirty()?;
            self.relocate_meta_b()?;
        }
        let mut n_pages = self.meta.n_pages;
        let txn_id = self.meta.txn_id;
        {
            // Lo que quede en el conjunto propio al llegar aquí son páginas
            // que esta transacción asignó y liberó, pero que nadie volvió a
            // pedir antes de confirmar. `own_free` es puramente de esta
            // transacción — nunca se sirve a otra ni sobrevive a un aborto
            // — así que si no se vuelca aquí a la lista de libres
            // persistente antes de serializarla, estas páginas no quedan
            // referenciadas por NADA tras el commit: ni por el árbol nuevo
            // (ya no las usa) ni por la lista de libres (nunca se enteró de
            // ellas) ni por la meta vieja (las liberó esta misma
            // transacción). Fuga silenciosa, no corrupción — pero fuga al
            // fin. Se etiquetan con `txn_id`, igual que cualquier otra
            // página que libera esta transacción: la próxima que las pida
            // pasa por la misma comprobación de la meta confirmada que el
            // resto de la lista de libres.
            let state = self.guard.as_mut().expect("estado presente");
            for page in self.own_free.drain(..) {
                state.freelist.push(page, txn_id);
            }
        }
        // Pone al día el punto durable ANTES de serializar la lista de
        // libres, si se ha quedado demasiado atrás (ver
        // `Db::reclaim_needs_a_sync`).
        //
        // **Aquí, y no solo en `WriteTxn::recycle`.** `Freelist::flush`
        // reserva un contenedor por cada grupo que tenga que escribir, y
        // los pide con un `alloc` PROPIO —el cierre de aquí abajo— que
        // extiende el fichero sin pasar por `WriteTxn::alloc` ni por
        // ninguna comprobación de presupuesto. Con el punto durable
        // retrasado, `flush` no puede reciclar nada como contenedor y
        // extiende tantas páginas como grupos tenga; cada commit deja un
        // grupo más, así que el coste por commit crece con el retraso y
        // las páginas que extiende engordan la propia lista: medido, un
        // banco de 2 000 commits sobre 200 claves pasaba de 24 a 2 088
        // páginas y de 8 000 a 65 000 escrituras físicas cuando el
        // presupuesto solo se comprobaba en `alloc`. Sincronizando aquí,
        // `flush` recicla contenedores como siempre y las tres cosas
        // —espacio, escrituras y `fsync`— quedan acotadas a la vez.
        if self.db.reclaim_needs_a_sync() {
            let previous = self.db.committed.read().unwrap().0.txn_id;
            self.db.sync_upto(previous)?;
        }
        {
            let pager = &self.db.pager;
            let page_size = self.page_size();
            // La lista de libres solo extiende el fichero cuando no hay
            // nada ya libre y suficientemente viejo que reutilizar como
            // contenedor — ver el comentario de `Freelist::flush` para el
            // porqué (tarea 19, hallazgo de crecimiento cuadrático) y por
            // qué esa decisión vive DENTRO de `flush`, no aquí: solo
            // `flush` sabe, mientras escribe, cuántos contenedores hacen
            // falta de verdad tras `fill_from_disk` y el reciclado de
            // `written_head` — decidirlo desde fuera, antes de llamar,
            // trabaja sobre una fotografía que ya está desactualizada para
            // cuando `flush` la necesita.
            //
            // Mismo guardián de lector más antiguo que usa `WriteTxn::alloc`
            // (ver su comentario y el del campo `Db::durable`): páginas
            // liberadas por ESTA misma transacción (el volcado de
            // `own_free` justo arriba, ya etiquetado con `txn_id`) quedan
            // descartadas sin más — no son "de antes de esta transacción" —
            // porque el suelo no puede pasar de la meta confirmada, que
            // sigue siendo la del commit ANTERIOR mientras este todavía no
            // ha confirmado.
            //
            // Que el suelo sea el DURABLE importa aquí tanto como en
            // `alloc`, y cierra además un agujero que estaba documentado
            // como conocido: `Freelist::flush` recicla como contenedor
            // tanto páginas libres cualesquiera como la cadena física que
            // el `flush` anterior escribió, y con la meta ESCRITA como
            // suelo podía reasignar la cadena que la meta DURABLE todavía
            // declaraba como suya — dejando a `Db::open` releyendo una
            // cadena de lista de libres ya reasignada (ver el comentario
            // de `Freelist::flush` en `freelist.rs` y el de la degradación
            // con gracia en `Db::open`, más arriba).
            let oldest = Some(self.db.reuse_floor());
            // Purga y compacta ANTES de serializar (ver `Freelist::truncate_at`):
            // la cadena que esta meta va a apuntar no puede mencionar ni una
            // página que el recorte se lleva por delante, y los contenedores
            // que `flush` saque de `pop` a continuación tienen que salir de
            // abajo para no clavar la cola ellos mismos. `n_pages` baja aquí
            // porque es la base desde la que extiende el cierre `alloc` de
            // más abajo: si `flush` necesita más contenedores de los que
            // puede reciclar, extiende desde el corte y `n_pages` vuelve a
            // subir — el recorte final usa el valor de después, no el de
            // ahora, así que ese caso encoge un poco menos pero nunca deja
            // una página escrita fuera del fichero.
            //
            // El suelo con el que se purga es el de AQUÍ, que puede ser más
            // alto que el que usó `plan_shrink` (un lector que muere entre
            // medias lo sube; el `fsync` de `reclaim_needs_a_sync`, también).
            // No importa: `[cut, n_pages)` ya era servible con el suelo más
            // bajo, y un suelo más alto solo puede añadir páginas servibles
            // POR DEBAJO del corte, que es donde no cambian nada.
            if let Some(cut) = cut {
                self.guard
                    .as_mut()
                    .expect("estado presente")
                    .freelist
                    .truncate_at(cut, oldest);
                n_pages = cut;
            }
            // Salta la página destino final de la meta B igual que `alloc`
            // (tarea 18, ver el comentario de `skip_meta_b_target`): una
            // página de lista de libres es tan "dato en vivo" como cualquier
            // nodo del árbol, y esta es una extensión de fichero completamente
            // aparte de `WriteTxn::alloc` — nada comparte el salto entre las
            // dos si no se repite aquí. Solo se llega a extender si `flush`
            // no encuentra nada reutilizable primero (ver su comentario).
            let mut alloc = || -> Result<PageNo> {
                let p = Self::skip_meta_b_target(n_pages, page_size)?;
                n_pages = p.checked_add(1).ok_or(Error::Full)?;
                Ok(p)
            };
            // El MISMO flujo de nonces que usa `write_page` para el resto
            // de la transacción (tarea 17): las páginas de lista de libres
            // necesitan nonces tan únicos como las del árbol, y un flujo
            // propio con el mismo prefijo repartiría exactamente los mismos
            // — ver el comentario de `Freelist::flush` en `freelist.rs`.
            //
            // `state.freelist` y `state.nonce_stream` son campos DISTINTOS
            // del mismo `WriterState`, así que el préstamo mutable de cada
            // uno es disjunto y pueden viajar juntos a `flush` sin la
            // gimnasia de referencias sueltas que hacía falta cuando el
            // contador tenía dos campos y un cierre de por medio.
            let state = self.guard.as_mut().expect("estado presente");
            let (head, tail) = state.freelist.flush(
                pager,
                &mut alloc,
                txn_id,
                oldest,
                state.nonce_stream.as_mut(),
            )?;
            self.meta.freelist_head = head;
            self.meta.freelist_tail = tail;
        }
        self.meta.n_pages = n_pages;
        // Aquí iba la escritura del techo de contador de nonce en la meta
        // de este commit (`Meta::write_counter`). **Eliminada con el cambio
        // a nonces aleatorios**: no hay ningún contador que persistir,
        // porque la apertura siguiente estrenará su propio prefijo y
        // arrancará de cero — ver `WriterState::nonce_stream`. Un commit de
        // una base cifrada escribe hoy exactamente los mismos bytes de meta
        // que uno de una base sin cifrar, salvo la clave envuelta.

        // La meta de ESTA transacción todavía no está escrita, así que si
        // esta sincronización ocurre, lo que se demuestra duradero es el
        // commit ANTERIOR (con las páginas de este ya en el medio, que es
        // justo el orden que hace atómico el commit). Ver `Db::sync_upto`.
        // TODO lo que la meta va a referenciar tiene que estar en el fichero
        // ANTES que la meta: es lo que hace que un corte a mitad de commit
        // deje la transacción entera fuera y no a medias. Con el buffer de
        // páginas sucias eso deja de ser automático —hasta aquí solo estaban
        // en RAM— así que el volcado va antes del `fsync` que hace duradero
        // el commit anterior y, sobre todo, antes de escribir esta meta.
        self.flush_dirty()?;

        let previous = self.db.committed.read().unwrap().0.txn_id;
        self.db.maybe_sync(previous)?;

        let target = self.slot.other();
        let geometry = self.db.pager.geometry();
        // Un sellado por ranura ESCRITA, no por commit: el camino del
        // recorte (`Some(cut)`, más abajo) escribe las dos, y cada una
        // necesita el suyo — mismo contenido, otra letra, otro nonce.
        let seal = self.seal_meta(&geometry, self.meta, target)?;
        self.meta.store_via(&self.db.pager, &geometry, target, seal.as_ref())?;
        match cut {
            None => {
                // Y aquí sí: la meta de esta transacción ya está escrita, así
                // que una sincronización que ocurra ahora la hace duradera y
                // el punto durable puede avanzar hasta ella.
                self.db.maybe_sync(self.meta.txn_id)?;
            }
            Some(_) => {
                // `sync_upto`, no `maybe_sync`: bajo `Sync::Never` o un
                // `Sync::Interval` largo, `maybe_sync` no sincroniza nada, y
                // recortar detrás de una meta que solo está escrita —no
                // demostrada en el medio— es precisamente el orden que
                // convierte un corte de corriente en una base irrecuperable.
                // Ver la cabecera de esta función.
                self.db.sync_upto(self.meta.txn_id)?;
                let seal = self.seal_meta(&geometry, self.meta, self.slot)?;
                self.meta.store_via(&self.db.pager, &geometry, self.slot, seal.as_ref())?;
                self.db.sync_upto(self.meta.txn_id)?;
                self.db.pager.truncate(n_pages)?;
                // El suelo de la PRÓXIMA transacción es la extensión real
                // del fichero, que acaba de encoger. Sin esto, el
                // `max(meta.n_pages, n_pages_floor)` de `begin_write`
                // devolvería `n_pages` al valor de antes del recorte en la
                // siguiente escritura: el fichero se quedaría pequeño
                // mientras el motor cree tener páginas asignadas que ya no
                // existen — ni siquiera en la lista de libres, porque
                // acaban de purgarse de ella — es decir, un agujero de
                // páginas sin dueño que `audit_pages` denunciaría de
                // inmediato. Ver `WriterState::n_pages_floor`.
                self.state().n_pages_floor = n_pages;
            }
        }

        *self.db.committed.write().unwrap() = (self.meta, target);
        self.committed = true;
        Ok(n_pages)
    }
}

impl Db {
    /// Sincroniza según la política configurada. `upto` es el `txn_id`
    /// cuya meta YA está escrita en el medio en el momento de la llamada
    /// —no la que se escribirá después— y `extent` la extensión del
    /// fichero ahora mismo: si la sincronización llega a ocurrir, ese par
    /// pasa a ser el punto durable. Ver `sync_upto`.
    fn maybe_sync(&self, upto: TxnId) -> Result<()> {
        match self.sync {
            Sync::Commit => self.sync_upto(upto),
            Sync::Never => Ok(()),
            Sync::Interval(d) => {
                let mut last = self.last_sync.lock().unwrap();
                if last.elapsed() >= d {
                    self.sync_upto(upto)?;
                    *last = Instant::now();
                }
                Ok(())
            }
        }
    }

    /// Sincroniza y, solo si el `sync()` devolvió `Ok`, avanza el punto
    /// durable hasta `upto`.
    ///
    /// **Es el único sitio del motor que mueve `Db::durable`**, y el orden
    /// —primero el medio, después el campo— es toda la garantía: un
    /// `sync()` correcto significa que todo lo escrito ANTES de él está en
    /// el medio, incluida la meta de `upto`, así que a partir de aquí
    /// reutilizar páginas que `upto` ya no referencia no puede dañar a
    /// ningún estado que un corte de corriente pueda hacer montar. Si
    /// `sync()` falla, el punto durable se queda donde estaba y el motor
    /// sigue protegiendo el estado anterior: exactamente la misma
    /// disciplina que tenía el techo de contador de nonce mientras existió:
    /// no avanzar con una escritura que quizá no se hizo durable.
    fn sync_upto(&self, upto: TxnId) -> Result<()> {
        self.pager.sync()?;
        self.durable.fetch_max(upto, Ordering::SeqCst);
        Ok(())
    }

    /// Suelo de reutilización: la transacción más antigua que todavía
    /// puede necesitar ver una página liberada, contando la meta DURABLE
    /// como lector implícito (ver el campo `durable`) además de los
    /// lectores reales.
    ///
    /// `min` con `committed`: el punto durable nunca debería superar a la
    /// meta confirmada, pero durante el commit hay un instante en que la
    /// meta nueva ya se sincronizó y `Db::committed` todavía no se ha
    /// publicado; tomar el mínimo hace que ese instante no pueda adelantar
    /// el suelo por delante de lo que cualquier otro hilo ve como
    /// confirmado, sin costar nada.
    ///
    /// Cada candado se toma y se suelta por separado, dentro de su propia
    /// sentencia: así no hay ningún orden de adquisición que mantener
    /// entre `committed`, `durable` y `readers`.
    fn reuse_floor(&self) -> TxnId {
        let committed = self.committed.read().unwrap().0.txn_id;
        let durable = self.durable.load(Ordering::SeqCst);
        let implicit = core::cmp::min(committed, durable);
        match self.oldest_reader() {
            Some(r) => core::cmp::min(r, implicit),
            None => implicit,
        }
    }

    /// El `txn_id` más antiguo que el motor todavía tiene que respetar: por
    /// debajo de él, una página liberada ya se puede reutilizar.
    ///
    /// Es la métrica que la sección 5 del documento de diseño exige, y existe
    /// para diagnosticar el único modo de fallo operativo del diseño
    /// copy-on-write: **un lector que no suelta su snapshot impide reciclar
    /// todo lo liberado desde entonces, y el fichero crece sin que nada esté
    /// roto**. Es la misma limitación conocida de LMDB. Sin este número el
    /// síntoma es indistinguible de una fuga del motor, porque `audit_pages`
    /// dice `true` con razón —las páginas son coherentes, solo que ninguna se
    /// puede tocar— y el tamaño del fichero no dice de quién es la culpa.
    ///
    /// Se lee comparándolo con el `txn_id` actual (`db.begin_read().txn_id()`):
    /// la diferencia es el retraso, y un retraso que no baja es un lector
    /// olvidado. Cero es el valor de una base recién abierta sin commits.
    ///
    /// Cuenta como lector, además de los reales, **la meta durable**: hasta
    /// que un `fsync` la pone al día, un corte de corriente todavía puede
    /// hacer montar ese estado anterior, así que sus páginas siguen vivas. Por
    /// eso con `Sync::Never` este número se queda atrás aunque no haya ningún
    /// lector abierto, y es la explicación de por qué esa política deja el
    /// fichero más grande (§12.4 del diseño).
    ///
    /// Es un valor instantáneo, no una reserva: puede subir en cuanto un
    /// lector se suelta o un `fsync` avanza el punto durable.
    pub fn oldest_retained_txn(&self) -> TxnId {
        self.reuse_floor()
    }

    /// ¿Toca pagar un `fsync` para poder reciclar?
    ///
    /// Solo tiene sentido preguntarlo cuando la lista de libres no ha
    /// podido servir nada: si el punto durable va por detrás de la meta
    /// confirmada, sincronizar AHORA lo pone al día y con ello desbloquea
    /// todas las páginas liberadas hasta esa meta. La alternativa es
    /// extender el fichero.
    ///
    /// **Por qué hay un presupuesto y no se sincroniza a la primera.** Una
    /// carga en régimen permanente libera en cada transacción más o menos
    /// tantas páginas como asigna, y todas quedan etiquetadas con esa
    /// misma transacción: sincronizar en cuanto la lista de libres no
    /// sirve significaría un `fsync` por transacción, que es tanto como no
    /// tener sincronización relajada. Dejando crecer el fichero un poco
    /// primero, cada `fsync` desbloquea de golpe toda la basura acumulada
    /// desde el anterior, y el coste queda amortizado: como mucho un
    /// `fsync` por cada `n_pages/16` páginas de crecimiento (con un suelo
    /// de 16 páginas para bases diminutas), y el fichero nunca se pasa de
    /// ese mismo margen sobre lo que ocuparía sincronizando siempre. Ver
    /// las medidas en el informe de esta tarea.
    ///
    /// Bajo `Sync::Commit` esto devuelve `false` SIEMPRE —el punto durable
    /// va al día por construcción— así que ni se llega a evaluar el
    /// presupuesto ni se emite ningún `fsync` de más.
    fn reclaim_needs_a_sync(&self) -> bool {
        let committed = self.committed.read().unwrap().0.txn_id;
        let durable = self.durable.load(Ordering::SeqCst);
        committed.saturating_sub(durable) >= MAX_DURABLE_LAG
    }

    /// Devuelve al sistema de ficheros la cola libre del fichero y responde
    /// cuántos BYTES ha devuelto (`0` si no había nada que devolver).
    ///
    /// # Por qué existe
    ///
    /// La lista de libres recicla el espacio DENTRO del fichero, así que un
    /// borrado masivo deja de hacerlo crecer — pero no lo encoge: la
    /// longitud del fichero es una marca de agua del pico histórico. Para
    /// una flota de miles de bases pequeñas, una por inquilino, eso
    /// significa que el día que un inquilino baja de un plan de retención de
    /// 5 días a uno de 2 su fichero se queda para siempre en el tamaño del
    /// plan que ya no paga. Esta llamada es lo que ese trabajo de cambio de
    /// plan ejecuta después de podar.
    ///
    /// # Explícita, nunca automática
    ///
    /// No la llama `commit`, y es deliberado: una base que borra por la
    /// mañana y vuelve a escribir por la tarde recortaría y volvería a
    /// extender el fichero todos los días, pagando `fsync` y fragmentación
    /// a cambio de nada. Quien sabe que el pico no va a volver es el
    /// llamante, no el motor.
    ///
    /// # Qué recorta, y qué no
    ///
    /// Solo la COLA: el sufijo de páginas libres que hay al final del
    /// fichero. No mueve páginas vivas hacia abajo — eso sería una
    /// compactación, con reescritura del árbol y un coste completamente
    /// distinto — así que una sola página viva alta puede limitar lo que se
    /// recupera. En la práctica no lo hace, porque la operación reordena la
    /// lista de libres de menor a mayor antes de reescribir la cadena (ver
    /// `Freelist::truncate_at`), y la cadena de libres es lo único que suele
    /// quedar arriba cuando el árbol se ha vaciado.
    ///
    /// # Repite hasta que deja de ganar
    ///
    /// Cada pasada libera páginas que la siguiente ya puede llevarse: los
    /// contenedores de la cadena de libres ANTERIOR solo dejan de estar
    /// vivos cuando la meta que los sustituye es duradera, cosa que ocurre
    /// dentro de esta misma llamada. El bucle termina siempre: una pasada
    /// que no reduce la extensión corta el bucle, y la extensión es un `u32`
    /// que solo baja. La pasada final que no gana nada no escribe nada
    /// (`plan_shrink` abandona la transacción antes de tocar el fichero).
    ///
    /// # Coste
    ///
    /// Un `fsync` para poner al día el punto durable, más dos por pasada que
    /// recorte de verdad. Trabajo proporcional al número de páginas LIBRES
    /// (hay que traer la lista entera a memoria), no al tamaño del árbol: no
    /// recorre ningún dato.
    ///
    /// # Errores
    ///
    /// `Error::WriterBusy` si hay otra transacción de escritura viva — toma
    /// el mismo candado de escritor único que `begin_write`. Los lectores
    /// abiertos NO la bloquean, pero sí limitan lo que puede recortar: una
    /// página que un snapshot vivo todavía podría necesitar no se toca (el
    /// mismo suelo que gobierna el reciclado de páginas, ver
    /// `Db::reuse_floor`).
    pub fn reclaim_tail(&self) -> Result<u64> {
        let page_size = u64::from(self.pager.geometry().page_size);
        let before = self.pager.file_pages()?;
        let mut extent = before;
        loop {
            let tx = self.begin_write()?;
            let after = tx.commit_maybe_shrinking(true)?;
            if after >= extent {
                break;
            }
            extent = after;
        }
        Ok(u64::from(before - extent) * page_size)
    }
}

impl Db {
    /// Registra un índice (tarea 16). Si el catálogo ya tiene ese `id` con
    /// una definición distinta, falla: el llamante decide si reconstruirlo o
    /// corregir la llamada.
    ///
    /// **Compara el registro COMPLETO del catálogo** (versión, unicidad,
    /// `ns`, nombre — todo lo que `IndexDef::encode` guarda), no solo la
    /// versión (ronda 2 de revisión, hallazgo 5). Redefinir el mismo `id`
    /// como único cuando antes no lo era, o sobre otro `ns`, bajo la MISMA
    /// versión, dejaría el índice mintiendo en silencio exactamente igual
    /// que un extractor cambiado sin subir la versión: `scan_index`
    /// buscaría en el árbol equivocado, o `put`/`delete` dejarían de
    /// comprobar una unicidad que el catálogo en disco todavía promete.
    /// Todo ese resto SÍ vive en el catálogo, así que compararlo no cuesta
    /// nada extra. Lo único que de verdad no se puede comprobar así —
    /// **y no hay forma de comprobarlo, en ninguna ronda de correcciones**
    /// — es `extract` en sí: es código del llamante, un puntero a función
    /// sin ninguna propiedad observable que distinga "la misma lógica" de
    /// "otra lógica que hoy calcula lo mismo por casualidad" (ni siquiera
    /// comparar la dirección del puntero es fiable entre unidades de
    /// compilación, ver el comentario de `IndexDef` sobre `PartialEq`).
    /// `version` sigue siendo, y seguirá siendo, la única defensa posible
    /// contra ESE cambio concreto.
    ///
    /// Registrar el mismo `id` dos veces en el mismo proceso (misma
    /// definición) es idempotente: sustituye la entrada en memoria en vez de
    /// duplicarla. Sin esto, una segunda llamada dejaría dos copias del
    /// mismo `IndexDef` en `indexes`, y `indexes_for` se lo entregaría dos
    /// veces a `WriteTxn::put`/`delete` — no corrompe nada (borrar y volver
    /// a poner la misma entrada es idempotente), pero duplica trabajo en
    /// cada escritura para siempre, en silencio.
    ///
    /// **No hace `backfill`** (ronda 2 de revisión, hallazgo 10, sin arreglo
    /// — documentado): filas escritas en `ns` ANTES de esta llamada se
    /// quedan sin indexar para siempre. Como la comparación de arriba es
    /// contra el registro tal cual quedó grabado la primera vez, reabrir
    /// más tarde con la MISMA definición nunca lo detecta ni lo avisa — el
    /// índice está simplemente incompleto desde el principio, en silencio.
    /// Levantar un índice sobre datos preexistentes exige hoy que quien
    /// llama reescriba esas filas él mismo (p. ej. un `put` de cada fila
    /// sobre su propio valor) después de `define_index`, antes de confiar
    /// en `scan_index`.
    ///
    /// **Es la única forma de habilitar la escritura sobre un `ns` que el
    /// catálogo declara indexado**: sin esta llamada, `put` y `delete`
    /// fallan ahí con `Error::IndexNotDeclared` en vez de dejar el índice
    /// divergiendo (ver `Db::catalog_indexes` y `WriteTxn::refuse_undeclared`).
    /// Las dos caras leen el MISMO catálogo, bajo `CATALOG_NS`, con el mismo
    /// decodificador de `index.rs` (`stored_version` aquí para comparar el
    /// registro entero, `stored_ns` allí para saber a qué espacio de claves
    /// pertenece): la de aquí pregunta por un id concreto, la de allí
    /// recorre el rango entero una vez por apertura.
    pub fn define_index(&self, def: IndexDef) -> Result<()> {
        if def.id >= 0x80 {
            return Err(Error::BadFormat);
        }
        // (Ronda 2 de revisión, hallazgo 6): `ns` debe caer fuera de los dos
        // rangos que el propio motor se reserva — el catálogo (`ns == 0`) y
        // el espacio de cualquier índice (`ns >= INDEX_NS_BASE`, donde vive
        // CADA índice, incluido este mismo). Sin este chequeo, un `IndexDef`
        // con `ns = CATALOG_NS` indexaría el catálogo consigo mismo, y uno
        // con `ns >= INDEX_NS_BASE` indexaría las entradas crudas de OTRO
        // índice — en ambos casos, `WriteTxn::put`/`delete` empezarían a
        // mutar esos espacios reservados como si fueran datos de usuario
        // cada vez que alguien escribe ahí (incluida la propia maquinaria
        // de índices), con resultados que ninguna otra comprobación de este
        // módulo anticipa.
        if def.ns == CATALOG_NS || def.ns >= INDEX_NS_BASE {
            return Err(Error::BadFormat);
        }
        let mut tx = self.begin_write()?;
        match tx.get(CATALOG_NS, &[def.id])? {
            Some(record) => {
                let stored = IndexDef::stored_version(&record).ok_or(Error::BadFormat)?;
                if record != def.encode() {
                    return Err(Error::IndexVersionMismatch {
                        id: def.id,
                        stored,
                        provided: def.version,
                    });
                }
            }
            None => {
                tx.put_raw(CATALOG_NS, &[def.id], &def.encode())?;
                tx.commit()?;
            }
        }
        let mut indexes = self.indexes.lock().unwrap();
        match indexes.iter_mut().find(|d| d.id == def.id) {
            Some(slot) => *slot = def,
            None => indexes.push(def),
        }
        Ok(())
    }

    /// Índices registrados sobre el espacio de claves `ns`, en el orden en
    /// que se definieron.
    fn indexes_for(&self, ns: u8) -> Vec<IndexDef> {
        self.indexes.lock().unwrap().iter().copied().filter(|d| d.ns == ns).collect()
    }
}

#[cfg(feature = "audit")]
impl Db {
    /// Comprueba que cada página de `[0, n_pages)` tiene EXACTAMENTE un
    /// dueño (tarea 19): el prefijo fijo reservado (cabecera, meta A, meta
    /// B en su posición actual — más el hueco que la reubicación de la
    /// tarea 18 todavía no ha llenado, si toca), el árbol de datos completo
    /// (recorrido desde la raíz — hojas, internos y cada cadena de overflow
    /// que cuelgue de una hoja; TODOS los espacios de claves a la vez,
    /// porque el catálogo y los índices secundarios viven en el mismo árbol
    /// bajo otro prefijo de `ns`, tarea 16) o la lista de libres (los
    /// propios nodos de la cadena Y las páginas que enumeran).
    ///
    /// Devuelve `Ok(false)` — no `Err` — si alguna página aparece en más de
    /// una de esas categorías, o si alguna por debajo de `n_pages` no
    /// aparece en ninguna: las dos son el mismo defecto de fondo ("el
    /// asignador y el árbol o la lista de libres ya no están de acuerdo
    /// sobre quién es dueño de esta página"), solo que en direcciones
    /// opuestas — doble asignación y fuga. `Err` queda para corrupción de
    /// verdad: una página que no decodifica, un tipo inesperado donde el
    /// árbol o la lista de libres esperaban otro. Esta distinción es
    /// deliberada: `prop_assert!(db.audit_pages().unwrap(), ...)` en
    /// `tests/props.rs` (tarea 19) trata el `false` como el fallo que la
    /// propiedad existe para atrapar, y deja que un `Err` — que no debería
    /// poder ocurrir jamás sobre un árbol que este mismo motor construyó —
    /// haga panicar el `.unwrap()`, que `proptest` captura y reduce igual.
    ///
    /// Recorre TODO el fichero, O(n_pages): no forma parte de ningún camino
    /// caliente (`put`/`get`/`commit` no la llaman nunca) — es una
    /// comprobación de integridad estilo `fsck`, para pruebas y para quien
    /// integra este motor y quiera verificar offline que un fichero no está
    /// corrompido. Por eso vive tras la feature `audit` en vez de sin más
    /// bajo `std` (ver su comentario en `Cargo.toml`).
    ///
    /// Opera sobre la META CONFIRMADA (`self.committed`), nunca sobre una
    /// transacción de escritura en curso: por eso es segura de llamar desde
    /// fuera de cualquier `WriteTxn`, con el candado de escritor libre —
    /// coherente con la firma que pide el brief, `db.audit_pages()` sobre
    /// `&Db`, no sobre `&mut WriteTxn`.
    ///
    /// # Por qué `Db::open` NO la llama
    ///
    /// Decisión explícita, no un olvido. Una revisión encontró un fichero
    /// que `open` aceptaba en silencio y sobre el que esta función
    /// devolvía `Ok(false)`, y preguntó si abrir debería enterarse. No:
    ///
    /// 1. **`Ok(false)` es fuga o doble dueño, no ilegibilidad.** Una fuga
    ///    —páginas que nadie reclama— no impide leer ni escribir nada; es
    ///    espacio desperdiciado. Negar la apertura por eso convertiría un
    ///    problema de contabilidad en una base inaccesible, justo el
    ///    criterio contrario al que ya siguen la reparación de cabecera y
    ///    la degradación de la lista de libres.
    /// 2. **Costaría lo que el motor promete que abrir no cuesta.** Esto
    ///    recorre el árbol entero y la cadena de libres entera: O(n_pages).
    ///    Abrir cuesta hoy tres lecturas —cabecera y dos metas— sin
    ///    importar el tamaño del fichero, y hay criterio de salida y
    ///    pruebas que lo fijan (`open_costs_the_same_on_a_small_and_a_large_file`
    ///    aquí, `opening_costs_the_same_at_thirty_kilobytes_..` en
    ///    `tests/size.rs`). Un motor pensado para arrancar en un
    ///    dispositivo pequeño no puede pagar un `fsck` en cada apertura.
    /// 3. **El defecto concreto que producía aquel `Ok(false)` está
    ///    cerrado en origen** (ver el campo `durable`), que es donde había
    ///    que cerrarlo: detectarlo al abrir habría sido tratar el síntoma.
    ///
    /// Quien quiera la comprobación la tiene aquí, explícita y bajo su
    /// propia feature, para ejecutarla cuando le convenga.
    pub fn audit_pages(&self) -> Result<bool> {
        let (meta, _slot) = *self.committed.read().unwrap();
        let n_pages = meta.n_pages;
        let geometry = self.pager.geometry();

        // Defensa en profundidad sobre la frontera de `Db::open`
        // (`check_meta_against_file`): esa comprobación ya garantiza que la
        // meta confirmada nunca declara más páginas de las que el fichero
        // tiene, así que este `if` no debería poder dispararse nunca. Se
        // paga igual —una llamada a `Storage::len` frente a un recorrido
        // O(n_pages) que esta función va a hacer a continuación, es decir,
        // nada— porque esta es LA función que uno ejecuta ante la sospecha
        // de corrupción: es la última que puede permitirse creerse un
        // contador de disco para dimensionar una reserva de memoria. Con
        // `n_pages = u32::MAX` eran 4,29 GB de golpe (SIGABRT bajo
        // cualquier límite razonable) para auditar un fichero de 4 KB.
        if n_pages > self.pager.file_pages()? {
            return Err(Error::Corrupt {
                page: self.committed.read().unwrap().1.page(&geometry),
                kind: crate::CorruptKind::MetaMismatch,
            });
        }

        // Una única bolsa para las tres categorías (reservadas, árbol,
        // lista de libres): así una página que dos de ellas reclaman a la
        // vez — el defecto exacto que esta función existe para atrapar —
        // se detecta sin importar en qué orden se recorran.
        let mut seen = alloc::vec![false; n_pages as usize];
        let mut ok = true;
        let mut mark = |p: PageNo| match seen.get_mut(p as usize) {
            Some(slot) if !*slot => {
                *slot = true;
                true
            }
            _ => false,
        };

        // Prefijo fijo: cabecera (0), meta A (1 — `WriteTxn::last_reserved_page`)
        // y meta B en su posición ACTUAL (dinámica, tarea 18).
        ok &= mark(0);
        ok &= mark(1);
        ok &= mark(geometry.meta_b_page);
        // El hueco de la reubicación de la meta B, si el fichero ya lo
        // cruzó pero la reubicación todavía no ha sucedido — mismo cálculo
        // que `WriteTxn::pages_in_use` (ver su comentario, más arriba en
        // este fichero): `alloc`/`commit` nunca reparten esta página
        // (`WriteTxn::skip_meta_b_target`), así que no puede aparecer ni en
        // el árbol ni en la lista de libres hasta que la reubicación de
        // verdad la libere.
        let target = WriteTxn::final_meta_b_page(geometry.page_size);
        if target != geometry.meta_b_page && n_pages > target {
            ok &= mark(target);
        }

        if meta.root != 0 {
            ok &= audit_walk_tree(&self.pager, meta.root, 1, &mut mark)?;
        }

        if meta.freelist_head != 0 {
            let mut freelist_ok = true;
            Freelist::walk_chain(&self.pager, meta.freelist_head, |chain_page, entries| {
                freelist_ok &= mark(chain_page);
                for &p in entries {
                    freelist_ok &= mark(p);
                }
            })?;
            ok &= freelist_ok;
        }

        Ok(ok && seen.iter().all(|&b| b))
    }
}

/// Recorre el árbol de datos desde `page_no`, marcando con `mark` cada
/// página que alcanza — hojas, internos y cada cadena de overflow que
/// cuelgue de una hoja. Función libre, no método de `Db` (tarea 19, mismo
/// patrón que ya usa el resto de este fichero con `tree.rs`): así
/// `Db::audit_pages` puede pasarle el mismo cierre `mark` que ya alimentó
/// con el prefijo reservado, sin pelearse con el comprobador de préstamos
/// por tenerlo capturado dos veces a la vez dentro de un método.
///
/// Corta en cuanto `mark` dice "ya vista" — no sigue explorando desde ahí —
/// así que una página que aparece dos veces en el árbol (un DAG corrupto
/// con hijos compartidos) nunca hace recorrer el mismo subárbol dos veces:
/// el TRABAJO total queda acotado por `n_pages`, sin necesitar un contador
/// de saltos aparte como `tree::RangeBudget`.
///
/// **Pero el trabajo no es la profundidad, y confundirlos costaba el
/// proceso entero.** Esto recurre de verdad (se llama a sí misma en las dos
/// líneas de la rama `Internal`), así que lo que hay que acotar es la
/// PROFUNDIDAD de la pila, y "acotada por `n_pages`" son hasta 2^32 marcos.
/// Una cadena de nodos internos encadenados por `extra` —cada uno con cero
/// separadores, cada uno una página perfectamente válida con su CRC
/// correcto— desbordaba la pila y abortaba el proceso (SIGABRT) con 10 000
/// páginas, un fichero de 5 MB; sobre la pila de 8 MiB del hilo principal,
/// del orden de 40 000, un tamaño de fichero corriente. Y lo hacía
/// precisamente en `audit_pages`, es decir, en lo que uno ejecuta ANTE LA
/// SOSPECHA de corrupción.
///
/// La cota es `MAX_DEPTH`, la misma que llevan las siete funciones de
/// `tree.rs` que descienden el árbol (`descend`, `insert_rec`,
/// `delete_rec`, `free_subtree`, `delete_range_rec`, `Cursor::seek_from`,
/// `Cursor::advance_to_next_leaf`) y por la misma razón: un árbol legítimo
/// nunca es más profundo que eso —ninguna operación de escritura puede
/// construirlo, porque todas ellas se niegan a bajar más— así que superarla
/// prueba un ciclo o un injerto, no un árbol grande. `free_subtree` ya
/// rechazó expresamente este mismo razonamiento de "queda acotado por el
/// número de páginas" en su comentario, con estas palabras: *desbordar la
/// pila es un fallo del propio proceso, no solo un cuelgue*.
#[cfg(feature = "audit")]
fn audit_walk_tree(
    pager: &Pager,
    page_no: PageNo,
    depth: u32,
    mark: &mut impl FnMut(PageNo) -> bool,
) -> Result<bool> {
    if depth > crate::tree::MAX_DEPTH {
        return Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::TreeLoop });
    }
    if !mark(page_no) {
        return Ok(false);
    }
    let valid = pager.read(page_no)?;
    let page = valid.page();
    let mut ok = true;
    match page.page_type() {
        crate::page::PageType::Leaf => {
            for i in 0..page.n_slots() {
                if let crate::page::LeafValue::Overflow { first, .. } = page.leaf_value(i) {
                    ok &= audit_walk_overflow(pager, first, mark)?;
                }
            }
        }
        crate::page::PageType::Internal => {
            for i in 0..page.n_slots() {
                ok &= audit_walk_tree(pager, page.child(i), depth + 1, mark)?;
            }
            ok &= audit_walk_tree(pager, page.extra(), depth + 1, mark)?;
        }
        _ => return Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::PageType }),
    }
    Ok(ok)
}

/// Recorre una cadena de overflow desde `first`, marcando cada página con
/// `mark`. A diferencia de `audit_walk_tree`, iterativa y no recursiva: una
/// cadena de overflow puede tener cientos de páginas para un solo valor
/// grande (tarea 13), y nada limita su longitud a la profundidad de un
/// árbol bien formado.
#[cfg(feature = "audit")]
fn audit_walk_overflow(
    pager: &Pager,
    first: PageNo,
    mark: &mut impl FnMut(PageNo) -> bool,
) -> Result<bool> {
    let mut ok = true;
    let mut current = first;
    while current != 0 {
        if !mark(current) {
            ok = false;
            break;
        }
        let valid = pager.read(current)?;
        let page = valid.page();
        if page.page_type() != crate::page::PageType::Overflow {
            return Err(Error::Corrupt { page: current, kind: crate::CorruptKind::PageType });
        }
        current = page.extra();
    }
    Ok(ok)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::storage::MemStorage;
    use alloc::sync::Arc;

    fn fresh() -> (Arc<MemStorage>, Db) {
        let s = Arc::new(MemStorage::new());
        let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        (s, db)
    }

    /// Permite conservar el medio tras cerrar la base, para reabrirla.
    struct ArcStorage(Arc<MemStorage>);
    impl Storage for ArcStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
        fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
    }


    #[test]
    fn a_fresh_database_is_under_five_kilobytes() {
        let (s, _db) = fresh();
        assert!(s.len().unwrap() <= 4_608, "suelo de la fase 1: 9 páginas de 512 B");
    }

    /// `audit_pages` se mantiene en verde a través de una reubicación real
    /// de la meta B (tarea 19, segunda ronda de revisión): 80 `put` (que
    /// cruzan de sobra los 4 KB que disparan `relocate_meta_b`) seguidos de
    /// 40 `delete` — comprobado tras CADA `commit`, no solo al final, para
    /// que un fallo señale exactamente qué transacción lo introdujo.
    #[test]
    fn audit_pages_stays_clean_across_a_real_relocation() {
        let (_s, db) = fresh();
        for i in 0..80u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), &alloc::vec![7u8; 100]).unwrap();
            tx.commit().unwrap();
            assert!(db.audit_pages().unwrap(), "audit_pages falló tras el commit {i}");
        }
        for i in 0..40u32 {
            let mut tx = db.begin_write().unwrap();
            let ts = 1_760_000_000_000u64 + i as u64 * 520;
            let mut key = alloc::vec::Vec::with_capacity(10);
            key.extend_from_slice(&ts.to_be_bytes());
            key.extend_from_slice(&((i % 8) as u16).to_be_bytes());
            tx.delete(0x01, &key).unwrap();
            tx.commit().unwrap();
            assert!(db.audit_pages().unwrap(), "audit_pages falló tras el delete {i}");
        }
    }

    /// Regresión exacta del hallazgo CRÍTICO de la segunda ronda de
    /// revisión de la tarea 19: una primera versión de la reutilización de
    /// páginas ya libres como contenedor de `Freelist::flush` (ver su
    /// comentario) devolvía las páginas pre-extraídas pero no usadas a la
    /// lista de libres DESPUÉS de que `flush` ya hubiera fijado
    /// `meta.freelist_head`/`tail` para ESTE `commit` — así que esas
    /// páginas quedaban vivas solo en memoria, invisibles para cualquier
    /// lectura desde disco (`Db::open`, `audit_pages`) hasta un `flush`
    /// posterior que quizá no llegara nunca. Cuatro `put` de la misma
    /// clave, seguidos de un `delete` que no encuentra nada que borrar (la
    /// clave vacía nunca se insertó): `audit_pages` encontraba una página
    /// sin dueño. La corrección de verdad no vive aquí, sino en que
    /// `Freelist::flush` resuelve sobrantes/faltantes ANTES de escribir,
    /// nunca después — este test solo fija el caso mínimo que lo probó.
    #[test]
    fn no_page_is_lost_when_a_reused_container_goes_unused() {
        let (_s, db) = fresh();
        for _ in 0..3 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &[0], &[]).unwrap();
            tx.commit().unwrap();
        }
        let mut tx = db.begin_write().unwrap();
        tx.delete(0x01, &[]).unwrap();
        tx.commit().unwrap();

        assert!(db.audit_pages().unwrap(), "pagina perdida o contada dos veces");
    }

    /// **Nada llega al medio antes del commit**, y `pending_writes` cuenta
    /// las páginas que esta transacción ha ensuciado.
    ///
    /// Hasta el buffer de páginas sucias (ver `Pager::pending`) las dos cosas
    /// eran la misma: `write_page` escribía a través, así que "páginas
    /// ensuciadas" y "escrituras físicas emitidas" coincidían y esta prueba
    /// las comparaba. Ya no coinciden, y la diferencia ES la mejora: un
    /// commit de mil filas ensucia 2.009 veces y escribe 13 páginas.
    ///
    /// Lo que se comprueba ahora es lo que de verdad hay que defender: a
    /// mitad de transacción el medio no ha visto NADA. Si alguien vuelve a
    /// escribir a través, esta prueba se pone en rojo — la anterior no lo
    /// habría hecho, porque su invariante se cumplía en los dos mundos.
    ///
    /// `tests/faults.rs` no se ve afectado: no calcula la escritura de la
    /// meta con `pending_writes()`, sino midiendo un commit de referencia
    /// sobre un medio aparte, así que se recalibra solo.
    #[test]
    fn nothing_reaches_the_medium_before_the_commit() {
        let s = Arc::new(crate::storage::FaultStorage::new(MemStorage::new(), None));
        let db = Db::create(Box::new(Arc::clone(&s)), Options::default()).unwrap();
        let before = s.write_count();
        let mut tx = db.begin_write().unwrap();
        for i in 0..50u32 {
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
        }
        assert!(tx.pending_writes() > 0, "cincuenta `put` tienen que ensuciar alguna página");
        assert_eq!(
            s.write_count() - before,
            0,
            "el medio ha recibido escrituras a mitad de transacción: las páginas sucias se están \
             escribiendo a través en vez de acumularse hasta el commit"
        );
        tx.commit().unwrap();
        let physical = s.write_count() - before;
        assert!(physical > 0, "el commit tiene que haber escrito de verdad");
    }

    /// **Las dos pruebas que pide la tarea 19 (segunda ronda de revisión,
    /// hallazgo CRÍTICO)**: sin ellas, nada en la suite habría notado que la
    /// corrección de la fuga de la primera ronda (`Freelist::flush` recicla
    /// el contenedor del `flush` anterior, ver `written_head` en
    /// `freelist.rs`) cambiaba una fuga LINEAL (1-2 páginas por `commit`,
    /// acotada) por un crecimiento CUADRÁTICO (300 páginas físicas tras 30
    /// `commit` de un solo `put`, 374 418 tras 500 — medido con la carga de
    /// clave repetida de más abajo, antes de la corrección de esta ronda,
    /// ver el informe de la tarea 19). La causa: `flush` escribía un
    /// contenedor por GRUPO, y cada `commit` añadía un grupo nuevo sin que
    /// nada consumiera los viejos — así que el reciclado de `written_head`
    /// realimentaba el problema en vez de resolverlo.
    ///
    /// Dos cargas DISTINTAS, no una — la revisión posterior a la primera
    /// versión de este test encontró su comentario prometiendo "una sola
    /// clave" mientras el código escribía 500 claves DISTINTAS, y las dos
    /// formas dan números diferentes que vale la pena afirmar por separado
    /// en vez de mezclar en un único umbral flojo:
    /// - `..._with_a_single_repeated_key`: la misma clave, 500 veces
    ///   (COW puro, sin que el árbol crezca). Mide PLANO en 7 páginas en
    ///   los tres puntos (30/100/500 `commit`) — el número que de verdad
    ///   demuestra que el crecimiento dejó de ser cuadrático, porque aquí
    ///   NUNCA debería hacer falta más que un puñado fijo de páginas
    ///   (cabecera, metas, árbol de una hoja, lista de libres).
    /// - `..._with_many_distinct_keys`: 500 claves distintas (el árbol sí
    ///   crece y se divide). Mide 7/11/20 — crece un poco porque el árbol
    ///   en sí necesita más páginas, pero sigue muy lejos de las 300/3 918/
    ///   374 418 del crecimiento cuadrático.
    #[test]
    fn freelist_growth_stays_bounded_with_a_single_repeated_key() {
        let (s, db) = fresh();
        for i in 0..500u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &[0], b"v").unwrap();
            tx.commit().unwrap();
            let commits = i + 1;
            if matches!(commits, 30 | 100 | 500) {
                let pages = s.len().unwrap() / 512;
                assert!(
                    pages <= 20,
                    "tras {commits} commits de la MISMA clave el fichero tiene \
                     {pages} páginas — debería quedarse en un puñado fijo, no crecer"
                );
            }
        }
    }

    #[test]
    fn freelist_growth_stays_bounded_with_many_distinct_keys() {
        let (s, db) = fresh();
        for i in 0..500u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            tx.commit().unwrap();
            let commits = i + 1;
            if matches!(commits, 30 | 100 | 500) {
                let pages = s.len().unwrap() / 512;
                assert!(
                    pages <= u64::from(commits) * 10,
                    "tras {commits} commits de claves distintas el fichero tiene \
                     {pages} páginas — crecimiento no acotado (cuadrático o peor)"
                );
            }
        }
    }

    #[test]
    fn commit_makes_writes_visible_to_new_readers() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![7u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.root(), p);
        assert_eq!(r.read_page(p).unwrap()[0], 7);
    }

    #[test]
    fn a_reader_keeps_seeing_its_snapshot_after_a_later_commit() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let r = db.begin_read();
        let seen = r.root();

        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        tx.write_page(q, &alloc::vec![2u8; 512]).unwrap();
        tx.set_root(q);
        tx.commit().unwrap();

        assert_eq!(r.root(), seen, "el lector no ve el commit posterior");
        assert_eq!(db.begin_read().root(), q);
    }

    #[test]
    fn a_page_freed_while_a_reader_is_live_is_not_recycled() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let reader = db.begin_read();

        let mut tx = db.begin_write().unwrap();
        tx.free(p);
        let q = tx.alloc().unwrap();
        assert_ne!(q, p, "no se recicla mientras el lector la ve");
        tx.commit().unwrap();
        drop(reader);

        let mut tx = db.begin_write().unwrap();
        assert_eq!(tx.alloc().unwrap(), p, "reciclada cuando el lector se va");
        tx.commit().unwrap();
    }

    #[test]
    fn an_aborted_transaction_leaves_no_trace() {
        let (_s, db) = fresh();
        let before = db.begin_read().txn_id();
        {
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![9u8; 512]).unwrap();
            tx.set_root(p);
            // se descarta sin commit
        }
        assert_eq!(db.begin_read().txn_id(), before);
        assert_eq!(db.begin_read().root(), 0);
    }

    #[test]
    fn reopening_recovers_pages_leaked_by_an_interrupted_transaction() {
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![3u8; 512]).unwrap();
            // Sin commit: la página queda escrita en el fichero pero sin dueño.
        }
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        // 3, no 9 (tarea 18): con el suelo bajado, la primera página
        // asignable tras crear la base es la 3 (cabecera, meta A y meta B en
        // su posición inicial ocupan 0..=2), no la 9 de cuando la meta B
        // nacía ya en su posición final.
        assert_eq!(tx.alloc().unwrap(), 3, "la página huérfana vuelve a la lista de libres");
        tx.commit().unwrap();
    }

    /// Almacén mínimo que simula un corte de corriente sin cifrado: solo
    /// revierte cabecera y las dos ranuras de meta a su último `sync()`,
    /// dejando TODO lo demás (páginas de árbol, de lista de libres) tal
    /// como la última escritura las dejara — modela que esas escrituras SÍ
    /// llegaron al medio aunque el `fsync` que las haría duraderas nunca
    /// llegó. Simplificado de `crypto::tests::PowerLossStorage` (sin
    /// desgarros parciales ni seguimiento de nonces, que esa versión
    /// necesita y esta no) para el camino PLANO del hallazgo HIGH de la
    /// tarea 19, segunda ronda de revisión: la degradación con gracia de
    /// `Db::open` nunca fue específica del cifrado — su única cobertura
    /// era un test de `crypto.rs` que dejaba de fallar — así que esta ruta
    /// en sí (sin `Options.encryption`) no tenía ninguna prueba propia.
    struct PowerLossStorage {
        inner: MemStorage,
        last_synced_meta: Mutex<[[u8; 512]; 3]>,
        last_synced_header: Mutex<[[u8; crate::header::HEADER_SIZE]; 2]>,
    }

    const PL_META_OFFSETS: [u64; 3] = [512, 1024, 4096];
    const PL_HEADER_OFFSETS: [u64; 2] = [0, crate::header::HEADER_MIRROR_OFFSET];

    impl PowerLossStorage {
        fn new() -> Self {
            Self {
                inner: MemStorage::new(),
                last_synced_meta: Mutex::new([[0u8; 512]; 3]),
                last_synced_header: Mutex::new([[0u8; crate::header::HEADER_SIZE]; 2]),
            }
        }

        fn simulate_power_loss(&self) {
            let saved_meta = *self.last_synced_meta.lock().unwrap();
            for (i, &offset) in PL_META_OFFSETS.iter().enumerate() {
                self.inner.write_at(offset, &saved_meta[i]).unwrap();
            }
            let saved_header = *self.last_synced_header.lock().unwrap();
            for (i, &offset) in PL_HEADER_OFFSETS.iter().enumerate() {
                self.inner.write_at(offset, &saved_header[i]).unwrap();
            }
        }
    }

    impl Storage for PowerLossStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.inner.read_at(o, b)
        }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            self.inner.write_at(o, b)
        }
        fn sync(&self) -> Result<()> {
            {
                let mut saved = self.last_synced_meta.lock().unwrap();
                for (i, &offset) in PL_META_OFFSETS.iter().enumerate() {
                    let mut buf = [0u8; 512];
                    let _ = self.inner.read_at(offset, &mut buf);
                    saved[i] = buf;
                }
            }
            {
                let mut saved = self.last_synced_header.lock().unwrap();
                for (i, &offset) in PL_HEADER_OFFSETS.iter().enumerate() {
                    let mut buf = [0u8; crate::header::HEADER_SIZE];
                    let _ = self.inner.read_at(offset, &mut buf);
                    saved[i] = buf;
                }
            }
            self.inner.sync()
        }
        fn len(&self) -> Result<u64> {
            self.inner.len()
        }
        fn truncate(&self, len: u64) -> Result<()> {
            self.inner.truncate(len)
        }
    }

    struct ArcPowerLoss(Arc<PowerLossStorage>);
    impl Storage for ArcPowerLoss {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.0.read_at(o, b)
        }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            self.0.write_at(o, b)
        }
        fn sync(&self) -> Result<()> {
            self.0.sync()
        }
        fn len(&self) -> Result<u64> {
            self.0.len()
        }
        fn truncate(&self, len: u64) -> Result<()> {
            self.0.truncate(len)
        }
    }

    /// Una cadena de lista de libres que no decodifica no puede impedir
    /// abrir un fichero por lo demás legible: `Db::open` la da por perdida
    /// (poniendo a cero `freelist_head`/`tail` también en la meta EN
    /// MEMORIA) y sigue adelante. Ver su comentario.
    ///
    /// **Esta prueba ataca la cadena DIRECTAMENTE, y esa es toda su
    /// razón de ser.** Hasta la corrección del suelo de reutilización
    /// (ver el campo `Db::durable`), la única cobertura de esta rama eran
    /// dos pruebas de corte de corriente —la de aquí abajo y la gemela de
    /// `crypto.rs`— que llegaban a ella de rebote: bajo `Sync::Never`, el
    /// reciclado podía reasignar el contenedor físico que la meta
    /// superviviente seguía declarando como su cadena. Ese escenario ya no
    /// existe —el suelo durable impide reciclar nada que la meta durable
    /// referencie, cadena de libres incluida— así que aquellas dos pruebas
    /// dejaron de ejercitar esta rama (comprobado poniendo un `panic!` en
    /// ella: ninguna prueba del crate lo dispara ya). Sin una prueba
    /// directa, la degradación se quedaría sin cobertura ninguna mientras
    /// dos nombres de prueba seguirían sugiriendo lo contrario — que es
    /// exactamente el patrón que este proyecto lleva media docena de
    /// rondas persiguiendo.
    ///
    /// Sigue siendo código necesario: la cadena puede no decodificar por
    /// motivos que nada tienen que ver con el reciclado — un medio que
    /// devuelve basura, un fichero manipulado, un formato futuro — y
    /// negarle la entrada a la base entera por eso sería el mismo error
    /// que la reparación de cabecera existe para evitar.
    #[test]
    fn an_unreadable_freelist_chain_does_not_keep_the_database_from_opening() {
        let s = Arc::new(MemStorage::new());
        let head = {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            for i in 0..40u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), &alloc::vec![7u8; 60]).unwrap();
                tx.commit().unwrap();
            }
            let head = db.committed.read().unwrap().0.freelist_head;
            assert_ne!(head, 0, "el fixture tiene que dejar una cadena de libres de verdad");
            head
        };
        // Basura en la cabeza de la cadena: ni tipo de página válido ni CRC.
        s.write_at(head as u64 * 512, &alloc::vec![0xEE; 512]).unwrap();

        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default())
            .expect("una cadena de libres ilegible no debe impedir abrir");
        assert!(
            db.audit_pages().is_ok(),
            "audit_pages no debe fallar con Err tras una apertura que ya tuvo éxito"
        );
        let r = db.begin_read();
        for i in 0..40u32 {
            assert_eq!(
                r.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
                Some(alloc::vec![7u8; 60].as_slice()),
                "el árbol sigue entero: lo perdido es la contabilidad de libres, no el dato"
            );
        }
        drop(r);
        let mut tx = db.begin_write().unwrap();
        tx.put(0x01, b"tras-degradar", b"v").unwrap();
        tx.commit().unwrap();
    }

    /// Camino PLANO (sin cifrado) del hallazgo HIGH de la tarea 19, segunda
    /// ronda de revisión: un corte de corriente que deja viva una meta
    /// vieja no debe impedir reabrir.
    ///
    /// **Lo que este escenario ejercitaba ya no ocurre, y la prueba se
    /// queda para fijar que no vuelva a ocurrir.** Cuando se escribió, el
    /// reciclado podía reasignar bajo `Sync::Never` el contenedor físico
    /// que la meta superviviente seguía señalando como su cadena de
    /// libres, y reabrir solo funcionaba gracias a la degradación con
    /// gracia de `Db::open`. Con el suelo de reutilización anclado a la
    /// meta DURABLE (ver el campo `Db::durable`) eso es imposible: nada de
    /// lo que la meta durable referencia se reparte. Así que hoy esta
    /// prueba reabre por el camino normal, sin degradar nada — la
    /// degradación tiene ahora su prueba propia y directa, justo arriba.
    #[test]
    fn a_stale_meta_after_simulated_power_loss_still_opens_without_audit_erroring() {
        let s = Arc::new(PowerLossStorage::new());
        let opts = Options { sync: Sync::Never, ..Options::default() };
        let db = Db::create(Box::new(ArcPowerLoss(Arc::clone(&s))), opts).unwrap();
        // 300, no menos: con la reutilización de contenedores de la tarea
        // 19 (ver `Freelist::flush`) el fichero crece mucho más despacio
        // que antes, así que hacen falta bastantes más `commit` que en un
        // motor que solo extendiera para cruzar los 4 KB que disparan la
        // sincronización incondicional de `relocate_meta_b` — sin cruzarlos,
        // la meta que sobrevive al corte sería la vacía de `Db::create` (
        // `freelist_head = 0`), y este test no reproduciría nada.
        for i in 0..300u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), b"v").unwrap();
            tx.commit().unwrap();
        }
        drop(db);
        s.simulate_power_loss();

        let db2 = Db::open(Box::new(ArcPowerLoss(Arc::clone(&s))), opts)
            .expect("un fichero por lo demás legible no debe rechazar la apertura");

        // Hallazgo HIGH #2 de la misma ronda: sin poner a cero
        // `freelist_head`/`tail` en la meta EN MEMORIA al degradar,
        // `audit_pages` devolvería `Err(Corrupt)` aquí mismo, justo tras un
        // `open` que acaba de tener éxito — reportando "corrupción de
        // verdad" (el significado documentado de `Err` en `audit_pages`,
        // ver su comentario) sobre un fichero que `open` ya aceptó como
        // legible. `Ok(_)`, no `Ok(true)`: la cadena abandonada puede
        // seguir describiendo páginas que ahora nadie reclama — y esa
        // pérdida puede ser grande, no un puñado de páginas (un caso real
        // midió el 48 % del fichero, ver el comentario de `Db::open`) — así
        // que `audit_pages` puede legítimamente devolver `Ok(false)` (fuga
        // detectada, no corrupción: exactamente la distinción que su propio
        // comentario documenta) en vez de `Ok(true)`. Lo que este test
        // prueba es que NO hace panic con `Err`, no que la contabilidad
        // quede perfecta tras abandonar una cadena entera.
        assert!(
            db2.audit_pages().is_ok(),
            "audit_pages no debe fallar con Err tras una apertura que ya tuvo éxito"
        );

        // La base sigue siendo plenamente usable tras degradar: un commit
        // más no debe fallar ni redescubrir la cadena perdida como si
        // fuera dato en vivo.
        let mut tx = db2.begin_write().unwrap();
        tx.put(0x01, b"tras-degradar", b"v").unwrap();
        tx.commit().unwrap();
        assert!(db2.audit_pages().is_ok());
    }

    #[test]
    fn draining_the_recovered_pages_never_hands_out_a_page_twice() {
        // La recuperación mete las páginas huérfanas en la lista de libres. Si
        // `n_pages` no avanza hasta la extensión real del fichero, en cuanto esas
        // páginas se agoten el camino de extensión de `alloc` vuelve a repartir
        // desde el `n_pages` viejo y entrega una página que ya está en uso.
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..5 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
            }
            // Sin commit: las cinco quedan huérfanas en el fichero.
        }

        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let mut seen = alloc::collections::BTreeSet::new();
        for _ in 0..12 {
            let p = tx.alloc().unwrap();
            assert!(seen.insert(p), "la página {p} se repartió dos veces");
        }
        tx.commit().unwrap();
    }

    /// Aquí vivía `extending_the_counter_ceiling_leaves_both_meta_slots_carrying_it`,
    /// la comprobación en caja blanca del protocolo de extensión del techo
    /// de contador de nonce: que una extensión dejara LAS DOS ranuras de
    /// meta llevando el techo nuevo y describiendo el mismo estado
    /// confirmado. Se ha ido con el protocolo — ver
    /// `WriterState::nonce_stream`. Lo que aquella prueba protegía era la
    /// invariante "el registro duradero del techo sobrevive a una escritura
    /// de meta desgarrada"; sin techo que registrar, la invariante no tiene
    /// contenido.
    ///
    /// La consecuencia observable, y comprobada, es que hoy una base
    /// cifrada escribe exactamente las mismas metas que una sin cifrar:
    /// `a_reopened_encrypted_database_pays_no_extra_sync_at_all` (`crypto.rs`).
    #[test]
    fn a_second_writer_is_rejected_while_one_is_open() {
        let (_s, db) = fresh();
        let _tx = db.begin_write().unwrap();
        assert_eq!(db.begin_write().err(), Some(Error::WriterBusy));
    }

    #[test]
    fn open_costs_the_same_on_a_small_and_a_large_file() {
        // Coste constante: tres lecturas, cabecera y dos metas. Se comprueba
        // contando lecturas, no midiendo tiempo.
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..2_000 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![0u8; 512]).unwrap();
            }
            tx.commit().unwrap();
        }
        s.reset_read_count();
        let _db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        assert!(s.read_count() <= 4, "apertura de coste constante");
    }

    /// Extractor de juguete para las dos pruebas de coste de abajo: lo único
    /// que importa de él es que exista un índice en el catálogo.
    fn by_value(_key: &[u8], value: &[u8]) -> Vec<Vec<u8>> {
        alloc::vec![value.to_vec()]
    }

    fn indexed_def() -> IndexDef {
        IndexDef { id: 1, name: "por_valor", version: 1, ns: 0x10, unique: false, extract: by_value }
    }

    /// Fija la decisión de diseño de `Db::catalog_indexes`: el catálogo se
    /// lee en la primera ESCRITURA, nunca al abrir. Leerlo en `Db::open`
    /// sería un descenso hasta la hoja más a la izquierda del árbol —el
    /// catálogo es el `ns` más pequeño— y eso crece con la profundidad, es
    /// decir con el tamaño de la base: rompería tanto esta cota como el
    /// `assert_eq!(small, large)` de
    /// `opening_costs_the_same_at_thirty_kilobytes_and_at_two_hundred_thousand_entries`
    /// (`tests/size.rs`), que es el criterio de salida de la
    /// especificación sobre coste de apertura.
    ///
    /// Mismo límite que `open_costs_the_same_on_a_small_and_a_large_file`,
    /// aquí arriba, pero sobre una base CON índice y con datos de verdad:
    /// esa otra prueba mide un fichero sin catálogo ninguno, así que no
    /// habría notado una regresión que leyera el catálogo solo cuando lo
    /// hay.
    #[test]
    fn opening_a_database_never_reads_the_catalog() {
        let s = Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            db.define_index(indexed_def()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x10, alloc::format!("pk{i:04}").as_bytes(), b"madrid").unwrap();
            }
            tx.commit().unwrap();
        }
        s.reset_read_count();
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
        assert!(
            s.read_count() <= 4,
            "abrir no debe tocar el catálogo: {} lecturas",
            s.read_count()
        );
        // Y un lector tampoco lo paga jamás: el catálogo solo lo consultan
        // `put`/`delete`/`delete_range`.
        let before = s.read_count();
        let r = db.begin_read();
        assert_eq!(r.get(0x10, b"pk0007").unwrap().unwrap(), b"madrid");
        drop(r);
        let cost_of_a_read = s.read_count() - before;
        assert!(cost_of_a_read <= 3, "una lectura no debe pagar catálogo: {cost_of_a_read}");
    }

    /// El catálogo se lee UNA vez por apertura, no una por escritura.
    ///
    /// `cache_pages: 0` a propósito (ver `Pager`): con la caché por medio,
    /// un recorrido repetido del catálogo saldría casi gratis y esta prueba
    /// pasaría igual sin memorización ninguna — no probaría nada. Sin caché,
    /// cada lectura cuesta una lectura física de verdad y la diferencia
    /// entre "lo leo siempre" y "lo leí una vez" es visible.
    ///
    /// Las tres escrituras son sobre la MISMA clave y el mismo valor, así
    /// que su coste de árbol es idéntico entre sí; lo único que puede
    /// distinguir a la primera es el recorrido del catálogo.
    #[test]
    fn the_catalog_is_read_once_per_handle_not_once_per_write() {
        let s = Arc::new(MemStorage::new());
        let opts = Options { cache_pages: 0, ..Options::default() };
        {
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            db.define_index(indexed_def()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for i in 0..50u32 {
                tx.put(0x10, alloc::format!("pk{i:04}").as_bytes(), b"madrid").unwrap();
            }
            tx.commit().unwrap();
        }

        // Reabre SIN declarar el índice y escribe en un `ns` que el catálogo
        // no indexa: el camino que sí consulta el catálogo y sigue adelante.
        let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
        let mut tx = db.begin_write().unwrap();
        let mut cost = [0u64; 3];
        for c in &mut cost {
            s.reset_read_count();
            tx.put(0x20, b"k", b"v").unwrap();
            *c = s.read_count();
        }
        tx.commit().unwrap();

        assert!(
            cost[0] > cost[1],
            "la primera escritura debe pagar el recorrido del catálogo: {cost:?}"
        );
        assert_eq!(cost[1], cost[2], "y ninguna posterior debe volver a pagarlo: {cost:?}");
    }

    #[test]
    fn freeing_a_page_in_an_aborted_transaction_does_not_persist() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        {
            let mut tx = db.begin_write().unwrap();
            tx.free(p);
            // se descarta sin commit
        }

        // El root confirmado sigue señalando a p: si el `free` de la
        // transacción abortada sobreviviera, la siguiente transacción
        // repartiría p como si estuviera libre mientras sigue siendo el
        // root vigente — dos dueños a la vez.
        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        assert_ne!(q, p, "p sigue en uso: el free() de la transacción abortada no debió persistir");
        tx.commit().unwrap();
    }

    #[test]
    fn an_alloc_from_the_freelist_in_an_aborted_transaction_is_not_lost() {
        let (_s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        // Libera p de verdad (con commit), así queda en la lista de libres
        // persistente.
        let mut tx = db.begin_write().unwrap();
        tx.free(p);
        tx.commit().unwrap();

        {
            // Esta transacción hace alloc() -> saca p de la lista de
            // libres, pero se aborta sin commit.
            let mut tx = db.begin_write().unwrap();
            assert_eq!(tx.alloc().unwrap(), p);
            // se descarta sin commit
        }

        // p debería seguir disponible: nadie la posee y la transacción que
        // la recicló nunca llegó a confirmar.
        let mut tx = db.begin_write().unwrap();
        let q = tx.alloc().unwrap();
        assert_eq!(q, p, "p se perdió: el abort no debió dejarla fuera de la lista de libres para siempre");
        tx.commit().unwrap();
    }

    /// Regresión del hallazgo 1 de la revisión de la tarea 12: sin lectores
    /// vivos, `free` seguido de `alloc` dentro de la MISMA transacción sin
    /// confirmar reciclaba una página que todavía pertenece al árbol
    /// confirmado — la meta confirmada actúa como un lector implícito que
    /// `oldest_reader` por sí solo no representa. Comprueba las dos mitades
    /// del contrato: que `alloc` no entrega esa página, y que abortar la
    /// transacción (sin `commit`) no deja ningún byte en disco distinto de
    /// como estaba.
    #[test]
    fn freeing_a_committed_page_is_not_reused_within_the_same_uncommitted_transaction() {
        let (s, db) = fresh();
        let mut tx = db.begin_write().unwrap();
        let p = tx.alloc().unwrap();
        tx.write_page(p, &alloc::vec![7u8; 512]).unwrap();
        tx.set_root(p);
        tx.commit().unwrap();

        let before = s.snapshot();

        {
            let mut tx = db.begin_write().unwrap();
            tx.free(p);
            let q = tx.alloc().unwrap();
            assert_ne!(
                q, p,
                "p sigue vivo en el árbol confirmado: reciclarla ya, sin que esta transacción \
                 haya confirmado, dejaría la meta confirmada apuntando a basura si hay un corte \
                 antes del commit"
            );
            // se descarta sin commit: ni `q` ni el free() de `p` deben tocar disco.
        }

        let after = s.snapshot();
        assert_eq!(
            before, after,
            "abortar sin commit no debe cambiar ni un byte del fichero ya confirmado"
        );
    }

    /// Recuperación de la cola libre del fichero (`Db::reclaim_tail`).
    mod reclaim_tests {
        use super::*;
        use crate::meta::{Meta, MetaSlot};

        /// Un registro con la forma del `request_logs` del edge de quota,
        /// que es la carga real de este motor y la que midió el eje de
        /// espacio de la revisión final: clave de 10 B (marca de tiempo de
        /// 8 B en big-endian, para que el orden de clave sea el orden
        /// temporal, más 2 B de identificador) y valor de 24 B.
        fn log_key(i: u32) -> alloc::vec::Vec<u8> {
            let ts = 1_760_000_000_000u64 + u64::from(i) * 520;
            let mut key = alloc::vec::Vec::with_capacity(10);
            key.extend_from_slice(&ts.to_be_bytes());
            key.extend_from_slice(&((i % 8) as u16).to_be_bytes());
            key
        }

        /// Escribe `[from, to)` en lotes de 100, como el escritor agrupado
        /// del edge.
        fn fill(db: &Db, from: u32, to: u32) {
            for chunk in (from..to).collect::<alloc::vec::Vec<_>>().chunks(100) {
                let mut tx = db.begin_write().unwrap();
                for &i in chunk {
                    tx.put(0x01, &log_key(i), &[7u8; 24]).unwrap();
                }
                tx.commit().unwrap();
            }
        }

        /// Borra `[from, to)` una a una, como la poda por retención.
        fn prune(db: &Db, from: u32, to: u32) {
            for i in from..to {
                let mut tx = db.begin_write().unwrap();
                tx.delete(0x01, &log_key(i)).unwrap();
                tx.commit().unwrap();
            }
        }

        fn file_pages(s: &Arc<MemStorage>) -> u64 {
            s.len().unwrap() / 512
        }

        /// Páginas realmente vivas: las que `audit_pages` reconoce como de
        /// alguien (prefijo reservado, árbol, contenedores de la cadena de
        /// libres), es decir todo lo que NO está en la lista de libres.
        /// Medido desde el fichero, no desde el estado en memoria.
        fn live_pages(db: &Db) -> u32 {
            let (meta, _) = *db.committed.read().unwrap();
            let mut free = 0u32;
            if meta.freelist_head != 0 {
                Freelist::walk_chain(&db.pager, meta.freelist_head, |_, entries| {
                    free += entries.len() as u32;
                })
                .unwrap();
            }
            meta.n_pages - free
        }

        /// **Ninguna meta LEGIBLE del fichero puede referenciar una página
        /// más allá del final.** Es la invariante que hace seguro el
        /// recorte, y se comprueba sobre las DOS ranuras leídas del medio —
        /// no sobre el estado en memoria — porque el peligro es justamente
        /// la ranura que el motor ya no usa: si `Meta::load` tuviera que
        /// caer en ella (la activa ilegible por un sector dañado), una meta
        /// con el `n_pages` de antes del recorte mandaría a `Db::open` a
        /// leer más allá del final del fichero, donde `UnexpectedEof` es
        /// fatal y no se degrada con gracia.
        fn assert_no_meta_points_past_the_end(s: &Arc<MemStorage>) {
            let geometry = Geometry::read(s.as_ref()).unwrap();
            let pages = (s.len().unwrap() / u64::from(geometry.page_size)) as u32;
            let mut legible = 0;
            for slot in [MetaSlot::A, MetaSlot::B] {
                let mut buf = alloc::vec![0u8; geometry.page_size as usize];
                let offset = u64::from(slot.page(&geometry)) * u64::from(geometry.page_size);
                if s.read_at(offset, &mut buf).is_err() {
                    continue;
                }
                let Ok(meta) = Meta::decode(&buf) else { continue };
                legible += 1;
                assert!(
                    meta.n_pages <= pages,
                    "la ranura {slot:?} declara {} páginas sobre un fichero de {pages}",
                    meta.n_pages
                );
                for (name, p) in [
                    ("root", meta.root),
                    ("catalog_root", meta.catalog_root),
                    ("freelist_head", meta.freelist_head),
                    ("freelist_tail", meta.freelist_tail),
                ] {
                    assert!(p < pages, "la ranura {slot:?} apunta con {name} a la página {p} de un fichero de {pages}");
                }
            }
            assert_eq!(legible, 2, "las dos ranuras deben quedar legibles tras un recorte");
        }

        /// **La prueba que motiva toda la operación.** Carga la base con
        /// 2 000 registros con la forma del edge, borra los 2 000, y
        /// comprueba con números que el fichero VUELVE.
        ///
        /// Sin `reclaim_tail`, el eje de espacio de la revisión final midió
        /// aquí un fichero clavado en su pico con el 95 % de espacio muerto
        /// para siempre: la lista de libres recicla dentro del fichero pero
        /// la longitud es una marca de agua que solo sube. Los números
        /// exactos dependen de la forma del registro (aquella medida daba
        /// 267 páginas con 13 en uso; esta carga da las que afirme el
        /// `assert` de abajo), así que lo que se fija aquí no es una cifra
        /// mágica sino la RELACIÓN: tras el recorte el fichero no puede ser
        /// más que un puñado de páginas por encima de lo que de verdad está
        /// vivo.
        #[test]
        fn deleting_everything_and_reclaiming_gives_the_file_back() {
            let (s, db) = fresh();
            fill(&db, 0, 2000);
            let peak = file_pages(&s);
            prune(&db, 0, 2000);
            let before = file_pages(&s);
            let live = live_pages(&db);
            assert_eq!(before, peak, "sin recorte, el fichero se queda en su pico historico");
            assert!(
                u64::from(live) * 8 < before,
                "la premisa de esta prueba es que el fichero quede casi vacio: {live} paginas \
                 vivas de {before}"
            );

            let txn_before = db.begin_read().txn_id();
            let freed = db.reclaim_tail().unwrap();
            let after = file_pages(&s);
            // Cada pasada que recorta es un commit, y cada commit son dos
            // `fsync`. El bucle termina por construcción (la extensión es un
            // `u32` que solo baja), pero "termina" no es lo mismo que
            // "converge rápido": esta cota fija que el número de pasadas es
            // un puñado y no proporcional al tamaño del fichero, que es lo
            // que de verdad haría inaceptable la operación en una base
            // grande. Se cumple porque cada pasada empaqueta la cadena de
            // libres abajo del todo, así que la primera ya deja el fichero
            // en su suelo y la segunda solo lo confirma.
            let passes = db.begin_read().txn_id() - txn_before;
            assert!(
                passes <= 4,
                "el recorte necesito {passes} pasadas (commits) para converger"
            );
            assert!(
                after <= u64::from(live) + 4,
                "tras el recorte el fichero tiene {after} paginas con solo {live} vivas: \
                 la cola no se ha devuelto"
            );
            assert_eq!(freed, (before - after) * 512, "los bytes devueltos deben ser los que faltan");
            assert!(
                freed * 100 / (before * 512) >= 90,
                "solo se devolvio el {} % del fichero",
                freed * 100 / (before * 512)
            );

            assert!(db.audit_pages().unwrap(), "la contabilidad de paginas no cuadra tras recortar");
            assert_no_meta_points_past_the_end(&s);
            assert_eq!(db.reclaim_tail().unwrap(), 0, "una segunda pasada no tiene nada que devolver");

            // Y la base sigue siendo una base: reabre y admite escritura.
            drop(db);
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            assert!(db.audit_pages().unwrap());
            assert_eq!(db.begin_read().get(0x01, &log_key(0)).unwrap(), None);
            fill(&db, 0, 100);
            assert_eq!(
                db.begin_read().get(0x01, &log_key(0)).unwrap().as_deref(),
                Some(&[7u8; 24][..])
            );
            assert!(db.audit_pages().unwrap());
        }

        /// El caso de uso literal del encargo: un inquilino baja de plan, su
        /// ventana de retención se estrecha y la poda borra el excedente. Lo
        /// que queda tiene que seguir ahí, entero, tras devolver la cola.
        #[test]
        fn pruning_to_a_shorter_retention_window_returns_the_surplus() {
            let (s, db) = fresh();
            fill(&db, 0, 1500);
            let before = file_pages(&s);
            // La ventana nueva se queda con los 200 registros más recientes.
            prune(&db, 0, 1300);

            let freed = db.reclaim_tail().unwrap();
            let after = file_pages(&s);
            assert!(freed > 0 && after < before, "{before} -> {after} paginas");

            let r = db.begin_read();
            for i in 1300..1500u32 {
                assert_eq!(
                    r.get(0x01, &log_key(i)).unwrap().as_deref(),
                    Some(&[7u8; 24][..]),
                    "el registro {i} de la ventana viva desaparecio con el recorte"
                );
            }
            for i in [0u32, 1, 700, 1299] {
                assert_eq!(r.get(0x01, &log_key(i)).unwrap(), None);
            }
            drop(r);
            assert!(db.audit_pages().unwrap());
            assert_no_meta_points_past_the_end(&s);

            // Y sobrevive a un cierre: lo que se recortó no era de nadie.
            drop(db);
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            let r = db.begin_read();
            for i in 1300..1500u32 {
                assert_eq!(r.get(0x01, &log_key(i)).unwrap().as_deref(), Some(&[7u8; 24][..]));
            }
            assert!(!s.snapshot().is_empty());
        }

        /// **El guardián de lectores, que es la mitad del contrato.** Un
        /// lector abierto sostiene un snapshot cuyas páginas siguen vivas
        /// para él aunque el árbol confirmado ya no las use: recortarlas no
        /// le devolvería un dato viejo, le devolvería `UnexpectedEof`.
        ///
        /// La prueba lo comprueba en los dos sentidos, que es lo que la hace
        /// decisiva: con el lector vivo el recorte no se lleva NADA, y en
        /// cuanto el lector muere el mismo recorte se lleva casi todo.
        #[test]
        fn a_live_reader_keeps_the_tail_until_it_goes_away() {
            let (s, db) = fresh();
            fill(&db, 0, 800);
            let reader = db.begin_read();
            prune(&db, 0, 800);
            let before = file_pages(&s);

            let freed = db.reclaim_tail().unwrap();
            // El DAÑO primero, la política después: si el recorte se lleva
            // páginas del snapshot del lector, lo que este bucle encuentra
            // no es un dato viejo sino un `UnexpectedEof` — el fichero ya no
            // llega hasta ahí. Comprobarlo antes que el conteo de bytes hace
            // que un motor sin guardián de lectores falle señalando el
            // registro que ha perdido, no un número.
            for i in 0..800u32 {
                assert_eq!(
                    reader.get(0x01, &log_key(i)).unwrap().as_deref(),
                    Some(&[7u8; 24][..]),
                    "el snapshot del lector perdio el registro {i} por culpa del recorte"
                );
            }
            assert_eq!(freed, 0, "el lector abierto todavia puede necesitar esas paginas");
            assert_eq!(file_pages(&s), before);
            drop(reader);

            let freed = db.reclaim_tail().unwrap();
            assert!(freed > 0, "sin lectores, la misma cola si se devuelve");
            assert!(file_pages(&s) * 4 < before, "{} paginas de {before}", file_pages(&s));
            assert!(db.audit_pages().unwrap());
        }

        /// El recorte no puede depender de la política de sincronización.
        /// Bajo `Sync::Never` el punto durable puede llevar decenas de
        /// transacciones sin moverse, y como cuenta como lector implícito
        /// (ver `Db::durable`) un recorte ingenuo no encontraría nada
        /// reutilizable que devolver. `plan_shrink` paga un `fsync` para
        /// ponerlo al día — subir el suelo pagando por él, nunca bajarlo.
        #[test]
        fn it_returns_the_tail_under_every_sync_policy() {
            for sync in [Sync::Commit, Sync::Never, Sync::Interval(Duration::from_secs(3600))] {
                let s = Arc::new(MemStorage::new());
                let opts = Options { sync, ..Options::default() };
                let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
                fill(&db, 0, 600);
                prune(&db, 0, 600);
                let before = file_pages(&s);
                let freed = db.reclaim_tail().unwrap();
                assert!(
                    freed > 0 && file_pages(&s) * 4 < before,
                    "{sync:?}: {before} -> {} paginas",
                    file_pages(&s)
                );
                assert!(db.audit_pages().unwrap(), "{sync:?}");
                assert_no_meta_points_past_the_end(&s);
                drop(db);
                let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
                assert!(db.audit_pages().unwrap(), "{sync:?}: tras reabrir");
            }
        }

        /// El suelo reservado no se toca ni cuando no queda nada más: la
        /// cabecera, su espejo y las dos ranuras de meta siguen ahí, y una
        /// base recién creada —donde no hay ninguna cola que devolver— no
        /// pierde ni un byte.
        #[test]
        fn it_never_truncates_into_the_reserved_prefix() {
            let (s, db) = fresh();
            let fresh_len = s.len().unwrap();
            assert_eq!(db.reclaim_tail().unwrap(), 0, "una base recien creada no tiene cola");
            assert_eq!(s.len().unwrap(), fresh_len);

            fill(&db, 0, 400);
            prune(&db, 0, 400);
            db.reclaim_tail().unwrap();

            let geometry = Geometry::read(s.as_ref()).unwrap();
            let pages = (s.len().unwrap() / u64::from(geometry.page_size)) as u32;
            assert!(pages > geometry.meta_a_page, "la meta A tiene que seguir dentro del fichero");
            assert!(pages > geometry.meta_b_page, "la meta B tiene que seguir dentro del fichero");
            // La cabecera y su espejo viven los dos en la página 0.
            let mut mirror = [0u8; crate::header::HEADER_SIZE];
            s.read_at(crate::header::HEADER_MIRROR_OFFSET, &mut mirror).unwrap();
            assert_eq!(Geometry::read(s.as_ref()).unwrap(), geometry);
            assert_no_meta_points_past_the_end(&s);
        }

        /// Tras recortar, la siguiente escritura tiene que partir de la
        /// extensión NUEVA. Sin bajar `WriterState::n_pages_floor`, el
        /// `max(meta.n_pages, floor)` de `begin_write` devolvería el
        /// `n_pages` de antes del recorte y el motor creería tener asignadas
        /// páginas que ya no existen en el fichero ni en la lista de libres:
        /// un agujero sin dueño que `audit_pages` denuncia de inmediato.
        #[test]
        fn writing_after_a_reclaim_starts_from_the_new_extent() {
            let (s, db) = fresh();
            fill(&db, 0, 700);
            prune(&db, 0, 700);
            db.reclaim_tail().unwrap();
            let after_reclaim = file_pages(&s);

            fill(&db, 5000, 5100);
            assert!(db.audit_pages().unwrap(), "hueco de paginas sin dueno tras escribir");
            let grown = file_pages(&s);
            assert!(
                grown < after_reclaim + 60,
                "el fichero salto de {after_reclaim} a {grown} paginas para 100 registros: \
                 la escritura no esta partiendo de la extension nueva"
            );
            let r = db.begin_read();
            for i in 5000..5100u32 {
                assert_eq!(r.get(0x01, &log_key(i)).unwrap().as_deref(), Some(&[7u8; 24][..]));
            }
        }

        /// Toma el mismo candado de escritor único que `begin_write`, y lo
        /// dice con un error propio en vez de bloquear.
        #[test]
        fn it_refuses_while_another_writer_is_live() {
            let (_s, db) = fresh();
            let tx = db.begin_write().unwrap();
            assert_eq!(db.reclaim_tail(), Err(Error::WriterBusy));
            drop(tx);
            assert!(db.reclaim_tail().is_ok());
        }

        /// Una base CIFRADA se recorta igual: nada del camino de cifrado
        /// depende de la longitud del fichero ni de las páginas que
        /// desaparecen — el nonce es aleatorio por apertura y viaja dentro
        /// de cada página, y la clave envuelta vive en la meta, que las dos
        /// ranuras conservan.
        #[cfg(feature = "encryption")]
        #[test]
        fn an_encrypted_database_returns_its_tail_too() {
            use crate::crypto::{Algorithm, Encryption};
            let s = Arc::new(MemStorage::new());
            let opts = Options {
                encryption: Some(Encryption { key: [3u8; 32], algorithm: Algorithm::XChaCha20Poly1305 }),
                ..Options::default()
            };
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            fill(&db, 0, 500);
            prune(&db, 0, 400);
            let before = file_pages(&s);
            let freed = db.reclaim_tail().unwrap();
            assert!(freed > 0 && file_pages(&s) < before);
            assert!(db.audit_pages().unwrap());

            drop(db);
            let db = Db::open(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            let r = db.begin_read();
            for i in 400..500u32 {
                assert_eq!(
                    r.get(0x01, &log_key(i)).unwrap().as_deref(),
                    Some(&[7u8; 24][..]),
                    "el registro cifrado {i} no sobrevivio al recorte"
                );
            }
            drop(r);
            // Y sigue escribiendo con nonces nuevos sobre las páginas
            // recicladas del tramo recortado.
            fill(&db, 500, 560);
            assert!(db.audit_pages().unwrap());
        }
    }

    /// Tarea 18: reubicación de la meta B y suelo de 1,5 KB.
    mod relocation_tests {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[test]
        fn a_fresh_database_is_under_two_kilobytes() {
            let s = Arc::new(MemStorage::new());
            let _db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            assert!(s.len().unwrap() <= 1_536, "suelo: 3 páginas de 512 B");
        }

        #[test]
        fn the_second_meta_moves_when_the_file_grows_past_four_kilobytes() {
            let s = Arc::new(MemStorage::new());
            let db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), Options::default()).unwrap();
            assert_eq!(Geometry::read(&*s).unwrap().meta_b_page, 2);

            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x01, &i.to_be_bytes(), &[0u8; 40]).unwrap();
            }
            tx.commit().unwrap();

            assert!(s.len().unwrap() > 4096);
            assert_eq!(Geometry::read(&*s).unwrap().meta_b_page, 8, "reubicada al offset 4096");

            // No basta con que la cabecera apunte al sitio nuevo: los datos
            // escritos en la MISMA transacción que disparó la reubicación
            // tienen que seguir siendo legibles. Si `relocate_meta_b`
            // hubiera escrito sobre una página que el árbol seguía usando
            // (ver `allocation_never_hands_out_the_meta_b_relocation_target`
            // y `freelist_serialization_never_hands_out_the_meta_b_relocation_target_either`,
            // más abajo, para el porqué eso ya no puede pasar), esto lo
            // habría dejado ilegible o con el valor equivocado.
            let r = db.begin_read();
            for i in [0u32, 1, 100, 199] {
                assert_eq!(
                    r.get(0x01, &i.to_be_bytes()).unwrap().as_deref(),
                    Some(&[0u8; 40][..]),
                    "clave {i} corrupta o perdida tras la reubicación"
                );
            }
        }

        /// Envuelve `MemStorage` y deja pasar CUALQUIER escritura salvo la
        /// SEGUNDA vez que se escribe la cabecera (offset 0, `HEADER_SIZE`
        /// bytes): la primera (`Db::create`) tiene que suceder para poder
        /// montar nada; la segunda —la única reescritura de cabecera que
        /// existe en este motor, la de `relocate_meta_b`— falla siempre,
        /// modelando un corte de corriente justo ahí, después de que la meta
        /// ya aterrizó, con `sync`, en su posición nueva (ver el orden
        /// documentado en `WriteTxn::relocate_meta_b`).
        struct CrashOnHeaderWrite {
            inner: MemStorage,
            header_writes: std::sync::atomic::AtomicU64,
        }
        impl Storage for CrashOnHeaderWrite {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
                self.inner.read_at(o, b)
            }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
                if o == 0 && b.len() == crate::header::HEADER_SIZE {
                    let n = self.header_writes.fetch_add(1, Ordering::SeqCst) + 1;
                    if n >= 2 {
                        return Err(Error::Io(crate::IoError::WriteZero));
                    }
                }
                self.inner.write_at(o, b)
            }
            fn sync(&self) -> Result<()> {
                self.inner.sync()
            }
            fn len(&self) -> Result<u64> {
                self.inner.len()
            }
            fn truncate(&self, len: u64) -> Result<()> {
                self.inner.truncate(len)
            }
        }

        /// Corte de corriente ENTRE las dos escrituras de `relocate_meta_b`:
        /// la meta ya está, de forma duradera, en su posición nueva, pero la
        /// cabecera nunca llega a cambiar. La base tiene que seguir
        /// montando — por la cabecera VIEJA, que sigue siendo coherente con
        /// la posición VIEJA de la meta, nunca tocada — y el commit
        /// interrumpido no debe haberse perdido ni un byte de lo que ya
        /// estaba confirmado antes de él. Reemplaza la prueba homónima del
        /// brief: tal como estaba escrita ahí (una única clave, sin cruzar
        /// nunca los 4 KB) `relocate_meta_b` no llegaba a invocarse, así que
        /// no ejercitaba ninguna reubicación — pasaba por la razón
        /// equivocada.
        #[test]
        fn the_database_survives_a_crash_during_relocation() {
            let crash = Arc::new(CrashOnHeaderWrite {
                inner: MemStorage::new(),
                header_writes: std::sync::atomic::AtomicU64::new(0),
            });
            let db = Db::create(Box::new(ArcCrash(Arc::clone(&crash))), Options::default()).unwrap();

            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"k", b"v").unwrap();
            tx.commit().unwrap();

            // Cruza los 4 KB: dispara `relocate_meta_b`, que aquí se corta
            // justo al intentar escribir la cabecera.
            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
            }
            assert!(tx.commit().is_err(), "la escritura de cabecera debia fallar en esta prueba");

            // "Reinicio": una base nueva, sin envoltorio de fallos, sobre la
            // misma foto de bytes que dejó el corte.
            let recovered = MemStorage::new();
            recovered.restore(crash.inner.snapshot());
            let recovered = Arc::new(recovered);

            assert_eq!(
                Geometry::read(&*recovered).unwrap().meta_b_page, 2,
                "la cabecera no debio cambiar: la escritura que la actualiza fue la que se corto"
            );

            let db = Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default()).unwrap();
            assert_eq!(
                db.begin_read().get(0x01, b"k").unwrap().as_deref(),
                Some(b"v".as_slice()),
                "el commit anterior al corte no debio perderse"
            );
            assert_eq!(
                db.begin_read().get(0x02, &0u32.to_be_bytes()).unwrap(),
                None,
                "el commit interrumpido no debio verse, ni parcial ni completo"
            );

            // La reubicación se reintenta en el siguiente commit que cruce
            // el umbral, y esta vez completa.
            let mut tx = db.begin_write().unwrap();
            for i in 200..400u32 {
                tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
            }
            tx.commit().unwrap();
            assert_eq!(Geometry::read(&*recovered).unwrap().meta_b_page, 8);
        }

        struct ArcCrash(Arc<CrashOnHeaderWrite>);
        impl Storage for ArcCrash {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
            fn sync(&self) -> Result<()> { self.0.sync() }
            fn len(&self) -> Result<u64> { self.0.len() }
            fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
        }

        /// BLOCKER hallado en revisión: `Db::open`'s orphan-page recovery
        /// loop es un TERCER sitio que reparte números de página (además de
        /// `alloc` y del cierre de `commit` que serializa la lista de
        /// libres) y no aplicaba `skip_meta_b_target`. La propia escritura
        /// de `relocate_meta_b` en la posición nueva EXTIENDE el fichero
        /// hasta esa página (offset 4096, 512 B → 4608 B de fichero) antes
        /// de que la cabecera cambie o esta transacción confirme; si el
        /// proceso muere justo ahí, `meta.n_pages` (de la ÚLTIMA
        /// confirmación real, más baja) a `file_pages` (que ya incluye la
        /// página destino) es exactamente el rango que recorre este bucle
        /// — sin el salto, empuja la página destino a la lista de libres,
        /// `alloc` la reparte con normalidad, el árbol la usa como dato, y
        /// la reubicación siguiente le escribe meta encima.
        #[test]
        fn reopening_after_a_crash_during_relocation_never_recovers_the_relocation_target_into_the_freelist() {
            let crash = Arc::new(CrashOnHeaderWrite {
                inner: MemStorage::new(),
                header_writes: std::sync::atomic::AtomicU64::new(0),
            });
            let db = Db::create(Box::new(ArcCrash(Arc::clone(&crash))), Options::default()).unwrap();

            // Llega a n_pages = 8 sin cruzar el umbral (cinco asignaciones a
            // mano, mismo patrón que otras pruebas de este módulo), y
            // confirma: el guard de `commit` ve 8 * 512 = 4096, no > 4096,
            // así que `relocate_meta_b` no corre todavía.
            let mut tx = db.begin_write().unwrap();
            let mut pages = Vec::new();
            for _ in 0..5 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
                pages.push(p);
            }
            tx.set_root(pages[0]);
            tx.commit().unwrap();

            // Una asignación más cruza el umbral (`skip_meta_b_target`
            // desvía a la 9, n_pages queda en 10): el `commit` dispara
            // `relocate_meta_b`, que escribe la copia de la meta en la
            // página 8 (extendiendo el fichero a 4608 B) y sincroniza —
            // hasta aquí, duradero — y entonces la escritura de cabecera
            // falla, simulando el corte.
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![2u8; 512]).unwrap();
            assert!(tx.commit().is_err(), "la escritura de cabecera debia fallar en esta prueba");

            let recovered = MemStorage::new();
            recovered.restore(crash.inner.snapshot());
            let recovered = Arc::new(recovered);
            assert!(
                recovered.len().unwrap() >= 8 * 512 + 512,
                "la premisa de esta prueba es que la escritura de la meta en la posicion nueva \
                 ya extendio el fichero mas alla de la pagina destino"
            );

            let db = Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default()).unwrap();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..20 {
                let p = tx.alloc().unwrap();
                assert_ne!(
                    p, 8,
                    "la recuperacion de paginas huerfanas de Db::open entrego la pagina destino \
                     de la reubicacion de la meta B"
                );
            }
        }

        #[test]
        fn page_sizes_of_four_kilobytes_or_more_never_relocate() {
            let s = Arc::new(MemStorage::new());
            let opts = Options { page_size: 4096, ..Options::default() };
            let _db = Db::create(Box::new(ArcStorage(Arc::clone(&s))), opts).unwrap();
            assert_eq!(Geometry::read(&*s).unwrap().meta_b_page, 2, "ya están en sectores distintos");
        }

        /// Envuelve `MemStorage` y deja pasar la primera escritura de
        /// cabecera (offset 0, `HEADER_SIZE` bytes) intacta — la de
        /// `Db::create`, que tiene que suceder para poder montar nada — pero
        /// falla CUALQUIER escritura que llegue después de la SEGUNDA
        /// escritura de cabecera (la de `relocate_meta_b`, la única
        /// reescritura de cabecera que existe en este motor). Modela un
        /// corte justo después de que la cabecera ya apunta a la posición
        /// nueva, pero antes de que este commit termine de escribir su
        /// propia meta.
        struct CrashAfterSecondHeaderWrite {
            inner: MemStorage,
            header_writes: std::sync::atomic::AtomicU64,
            dead: AtomicBool,
        }
        impl Storage for CrashAfterSecondHeaderWrite {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
                self.inner.read_at(o, b)
            }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
                if self.dead.load(Ordering::SeqCst) {
                    return Err(Error::Io(crate::IoError::WriteZero));
                }
                if o == 0 && b.len() == crate::header::HEADER_SIZE {
                    let n = self.header_writes.fetch_add(1, Ordering::SeqCst) + 1;
                    self.inner.write_at(o, b)?;
                    if n == 2 {
                        self.dead.store(true, Ordering::SeqCst);
                    }
                    return Ok(());
                }
                self.inner.write_at(o, b)
            }
            fn sync(&self) -> Result<()> {
                self.inner.sync()
            }
            fn len(&self) -> Result<u64> {
                self.inner.len()
            }
            fn truncate(&self, len: u64) -> Result<()> {
                self.inner.truncate(len)
            }
        }
        struct ArcCrash2(Arc<CrashAfterSecondHeaderWrite>);
        impl Storage for ArcCrash2 {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
            fn sync(&self) -> Result<()> { self.0.sync() }
            fn len(&self) -> Result<u64> { self.0.len() }
            fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
        }

        /// Self-review (interacción con la tarea 9): un corte justo DESPUÉS
        /// de que la cabecera cambia, pero antes de que el commit que
        /// disparó la reubicación termine de escribir su propia meta, no
        /// debe hacer retroceder el último commit REALMENTE confirmado antes
        /// de esa transacción — solo puede perderse el trabajo de la propia
        /// transacción interrumpida, como en cualquier aborto.
        ///
        /// Construida para fallar contra una versión anterior de
        /// `relocate_meta_b` que escribía la copia de la meta en la posición
        /// VIEJA (con la geometría de antes de la reubicación) en vez de en
        /// `target`: cuando la ranura activa al empezar la transacción que
        /// dispara la reubicación es la B, esa versión dejaba la página
        /// nueva sin ningún contenido legible, y un corte en esta ventana
        /// hacía que `Meta::load` recuperase la meta A — un commit entero
        /// más vieja — como si fuera la última confirmada. Con la meta
        /// copiada en `target` (la corrección de esta ronda), las dos
        /// ranuras describen el mismo último commit real y el desempate por
        /// `txn_id` siempre elige la correcta.
        #[test]
        fn a_crash_after_the_header_write_does_not_roll_back_a_commit() {
            let crash =
                Arc::new(CrashAfterSecondHeaderWrite {
                    inner: MemStorage::new(),
                    header_writes: std::sync::atomic::AtomicU64::new(0),
                    dead: AtomicBool::new(false),
                });
            let db = Db::create(Box::new(ArcCrash2(Arc::clone(&crash))), Options::default()).unwrap();

            // Un commit vacío basta para pasar la ranura activa de A a B:
            // `commit` siempre escribe en `self.slot.other()`, sin importar
            // si esta transacción tocó algo.
            db.begin_write().unwrap().commit().unwrap();
            assert_eq!(db.begin_read().txn_id(), 2, "la ranura activa ahora es B");

            // Cruza los 4 KB (seis `alloc()` con página de 512 B llegan a
            // n_pages = 10, ver `WriteTxn::skip_meta_b_target`) sin tocar el
            // árbol: esta prueba es sobre la meta, no sobre datos.
            let mut tx = db.begin_write().unwrap();
            for _ in 0..6 {
                tx.alloc().unwrap();
            }
            assert!(tx.commit().is_err(), "la segunda escritura de cabecera debia fallar en esta prueba");

            let recovered = MemStorage::new();
            recovered.restore(crash.inner.snapshot());
            let recovered = Arc::new(recovered);
            assert_eq!(Geometry::read(&*recovered).unwrap().meta_b_page, 8, "la cabecera si cambio");

            let db = Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default()).unwrap();
            assert_eq!(
                db.begin_read().txn_id(), 2,
                "el commit vacio (txn_id 2), ya confirmado antes de la transaccion interrumpida, \
                 no debio retroceder a txn_id 1"
            );
        }

        /// Envuelve `MemStorage` y DESGARRA (no bloquea) la SEGUNDA
        /// escritura de cabecera: solo los primeros `prefix` bytes
        /// aterrizan, el resto conserva lo que ya había — modela un corte
        /// de corriente a MEDIO ESCRIBIR, no "la escritura nunca llegó".
        struct TearSecondHeaderWrite {
            inner: MemStorage,
            header_writes: std::sync::atomic::AtomicU64,
            prefix: usize,
            dead: AtomicBool,
        }
        impl Storage for TearSecondHeaderWrite {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
                self.inner.read_at(o, b)
            }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
                if self.dead.load(Ordering::SeqCst) {
                    return self.inner.write_at(o, b);
                }
                if o == 0 && b.len() == crate::header::HEADER_SIZE {
                    let n = self.header_writes.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 2 {
                        self.dead.store(true, Ordering::SeqCst);
                        return self.inner.write_at(o, &b[..self.prefix]);
                    }
                }
                self.inner.write_at(o, b)
            }
            fn sync(&self) -> Result<()> {
                self.inner.sync()
            }
            fn len(&self) -> Result<u64> {
                self.inner.len()
            }
            fn truncate(&self, len: u64) -> Result<()> {
                self.inner.truncate(len)
            }
        }
        struct ArcTearHeader(Arc<TearSecondHeaderWrite>);
        impl Storage for ArcTearHeader {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
            fn sync(&self) -> Result<()> { self.0.sync() }
            fn len(&self) -> Result<u64> { self.0.len() }
            fn truncate(&self, len: u64) -> Result<()> { self.0.truncate(len) }
        }

        /// HIGH hallado en revisión: la reescritura de cabecera de
        /// `relocate_meta_b` no tenía protección de desgarro, ni espejo, ni
        /// camino de reconstrucción — justo la inmunidad que tenía la
        /// cabecera de solo-escritura-una-vez (tarea 3), y que esta tarea le
        /// quita. La cabecera nueva difiere de la vieja solo en los bytes
        /// 44..48 (`meta_b_page`) y 60..64 (el CRC); un corte que aterrice
        /// entre el 45 y el 63 dejaba `meta_b_page` ya actualizado (entero o
        /// a medias) con el CRC todavía viejo — `Geometry::decode` lo
        /// rechaza con `Corrupt { kind: Checksum }`, y sin ninguna cabecera
        /// legible en absoluto, `Db::open` no puede montar la base NUNCA
        /// MÁS, aunque todo lo demás —las dos metas, el árbol entero— siga
        /// intacto.
        #[test]
        fn a_torn_header_rewrite_does_not_permanently_brick_the_database() {
            for prefix in [45usize, 47, 48, 55, 60, 62, 63] {
                let crash = Arc::new(TearSecondHeaderWrite {
                    inner: MemStorage::new(),
                    header_writes: std::sync::atomic::AtomicU64::new(0),
                    prefix,
                    dead: AtomicBool::new(false),
                });
                let db = Db::create(Box::new(ArcTearHeader(Arc::clone(&crash))), Options::default())
                    .unwrap();
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, b"antes", b"confirmado").unwrap();
                tx.commit().unwrap();

                // Cruza los 4 KB: dispara `relocate_meta_b`, cuya segunda
                // escritura de cabecera este arnés desgarra en `prefix`.
                let mut tx = db.begin_write().unwrap();
                for i in 0..200u32 {
                    tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
                }
                let _ = tx.commit();

                let recovered = MemStorage::new();
                recovered.restore(crash.inner.snapshot());
                let recovered = Arc::new(recovered);

                let db = Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default())
                    .unwrap_or_else(|e| {
                        panic!(
                            "prefix {prefix}: una cabecera desgarrada no debe dejar la base \
                             inservible para siempre: {e:?}"
                        )
                    });
                assert_eq!(
                    db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                    Some(b"confirmado".as_slice()),
                    "prefix {prefix}: el commit anterior al corte no debio perderse"
                );
            }
        }

        /// LOW hallado en la revisión posterior a la corrección del HIGH: el
        /// espejo existe para sobrevivir a UN desgarro, pero si `Db::open`
        /// no repara la principal tras usarlo, esa reapertura ya gastó la
        /// redundancia sin devolverla — la base sigue abriendo, pero desde
        /// ahí corre sobre una sola copia legible para siempre (la cabecera
        /// no vuelve a tocarse tras la única reubicación de la vida del
        /// fichero), a un sector malo de quedar inservible sin ningún
        /// aviso.
        #[test]
        fn reopening_after_a_torn_primary_repairs_it_from_the_mirror() {
            let crash = Arc::new(TearSecondHeaderWrite {
                inner: MemStorage::new(),
                header_writes: std::sync::atomic::AtomicU64::new(0),
                prefix: 45,
                dead: AtomicBool::new(false),
            });
            let db = Db::create(Box::new(ArcTearHeader(Arc::clone(&crash))), Options::default())
                .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"antes", b"confirmado").unwrap();
            tx.commit().unwrap();

            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
            }
            let _ = tx.commit();

            let recovered = MemStorage::new();
            recovered.restore(crash.inner.snapshot());
            let recovered = Arc::new(recovered);

            // Antes de reabrir: la principal, tal cual quedó del corte, NO
            // decodifica sola — la premisa de esta prueba.
            let mut primary_before = [0u8; crate::header::HEADER_SIZE];
            recovered.read_at(0, &mut primary_before).unwrap();
            assert!(
                Geometry::decode(&primary_before).is_err(),
                "la premisa de esta prueba es que la principal, sin reparar, no decodifica"
            );

            Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default()).unwrap();

            // Tras reabrir: la principal debe decodificar POR SÍ SOLA, sin
            // necesitar el espejo — la reparación la reescribió.
            let mut primary_after = [0u8; crate::header::HEADER_SIZE];
            recovered.read_at(0, &mut primary_after).unwrap();
            assert!(
                Geometry::decode(&primary_after).is_ok(),
                "la reapertura debio reparar la cabecera principal a partir del espejo"
            );

            // Una tercera sesión, sin espejo de por medio (el arnés de
            // corte ya no está activo): si la reparación no hubiera
            // ocurrido de verdad, esta apertura seguiría dependiendo del
            // espejo en silencio, sin que esta prueba lo notara — la
            // comprobación de arriba, sobre los bytes crudos, es la que de
            // verdad prueba la reparación.
            let db3 = Db::open(Box::new(ArcStorage(Arc::clone(&recovered))), Options::default())
                .unwrap();
            assert_eq!(
                db3.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                Some(b"confirmado".as_slice())
            );
        }

        /// Envuelve un medio ya construido y hace que TODA escritura falle
        /// — modela un medio de solo lectura (o cualquier fallo de E/S
        /// persistente en la escritura de reparación, sector dañado
        /// incluido). Las lecturas funcionan con normalidad: `Db::open`
        /// tiene que poder terminar sin errores de E/S artificiales fuera
        /// de la escritura de reparación misma, que es lo único que esta
        /// prueba quiere que falle.
        struct ReadOnlyStorage(Arc<MemStorage>);
        impl Storage for ReadOnlyStorage {
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
                self.0.read_at(o, b)
            }
            fn write_at(&self, _o: u64, _b: &[u8]) -> Result<()> {
                Err(Error::Io(crate::IoError::PermissionDenied))
            }
            /// Recortar es modificar: un medio de solo lectura lo rechaza
            /// igual que una escritura, no en silencio.
            fn truncate(&self, _len: u64) -> Result<()> {
                Err(Error::Io(crate::IoError::PermissionDenied))
            }
            fn sync(&self) -> Result<()> {
                self.0.sync()
            }
            fn len(&self) -> Result<u64> {
                self.0.len()
            }
        }

        /// Regresión hallada en revisión sobre la reparación de arriba: la
        /// primera versión propagaba con `?` el error de la escritura o el
        /// `sync` de reparación. Sobre un medio de solo lectura con la
        /// principal dañada, eso convertía una apertura que antes
        /// funcionaba — sin reparación, `Db::open` nunca escribía nada —
        /// en un `Err` que le niega la base entera a quien llama, aunque
        /// el fichero sea perfectamente legible y el espejo ya diera una
        /// geometría válida. La reparación es oportunista, no de carga: un
        /// fallo suyo debe dejar el fichero en el mismo estado degradado
        /// de una sola copia legible en el que ya estaba, y abrir de
        /// todos modos.
        #[test]
        fn a_read_only_medium_with_a_damaged_primary_still_opens() {
            let crash = Arc::new(TearSecondHeaderWrite {
                inner: MemStorage::new(),
                header_writes: std::sync::atomic::AtomicU64::new(0),
                prefix: 45,
                dead: AtomicBool::new(false),
            });
            let db = Db::create(Box::new(ArcTearHeader(Arc::clone(&crash))), Options::default())
                .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, b"antes", b"confirmado").unwrap();
            tx.commit().unwrap();

            let mut tx = db.begin_write().unwrap();
            for i in 0..200u32 {
                tx.put(0x02, &i.to_be_bytes(), &[0u8; 40]).unwrap();
            }
            let _ = tx.commit();

            let recovered = MemStorage::new();
            recovered.restore(crash.inner.snapshot());
            let recovered = Arc::new(recovered);

            // Premisa: la principal, tal cual quedó del corte, no
            // decodifica sola — igual que en
            // `reopening_after_a_torn_primary_repairs_it_from_the_mirror`.
            let mut primary_before = [0u8; crate::header::HEADER_SIZE];
            recovered.read_at(0, &mut primary_before).unwrap();
            assert!(
                Geometry::decode(&primary_before).is_err(),
                "la premisa de esta prueba es que la principal, sin reparar, no decodifica"
            );

            let db = Db::open(Box::new(ReadOnlyStorage(Arc::clone(&recovered))), Options::default())
                .unwrap_or_else(|e| {
                    panic!(
                        "un medio de solo lectura con la principal danada debe abrir igual, \
                         usando el espejo, sin que el fallo de la reparacion se propague: {e:?}"
                    )
                });
            assert_eq!(
                db.begin_read().get(0x01, b"antes").unwrap().as_deref(),
                Some(b"confirmado".as_slice()),
                "la base debe ser utilizable aunque la reparacion no pudiera escribirse"
            );
        }

        /// Invariante que hace segura la reubicación sin necesidad de
        /// "rescatar" nada en el momento de reubicar (ver el comentario de
        /// `WriteTxn::skip_meta_b_target`): la página destino nunca sale de
        /// `alloc`, ni siquiera tras muchas asignaciones seguidas.
        #[test]
        fn allocation_never_hands_out_the_meta_b_relocation_target() {
            let (_s, db) = fresh();
            let mut tx = db.begin_write().unwrap();
            for _ in 0..20 {
                let p = tx.alloc().unwrap();
                assert_ne!(p, 8, "la pagina destino de la reubicacion de la meta B no debe repartirse nunca");
            }
            tx.commit().unwrap();
        }

        /// El otro camino de extensión de fichero — el cierre que `commit`
        /// usa para serializar la lista de libres, aparte de `alloc` — tiene
        /// que saltarse la misma página. Construida para fallar sin ese
        /// segundo salto: cinco páginas asignadas a mano dejan `n_pages`
        /// exactamente en el destino (8), sin cruzar todavía el umbral de
        /// reubicación (8 × 512 = 4096, no > 4096); liberar cuatro de ellas
        /// desde otra transacción (van directas a la lista de libres
        /// persistente, no al cupo propio de la transacción) obliga a
        /// `commit` a serializarlas extendiendo el fichero — y sin el salto
        /// en ese cierre, la única página nueva que hace falta sería
        /// exactamente la 8.
        ///
        /// **La aserción final ya NO exige exactamente `{4,5,6,7}`** (ronda
        /// de revisión posterior de la tarea 19, tras el hallazgo de
        /// crecimiento cuadrático): `Freelist::flush` ahora puede reutilizar
        /// alguna de esas mismas páginas COMO CONTENEDOR de la propia lista
        /// de libres, en vez de entregársela siempre a `alloc` — ver el
        /// comentario de `flush`. Eso es legítimo (nada se pierde ni se
        /// cuenta dos veces — confirmado con `pages_are_never_lost_or_
        /// double_allocated` a 500 casos y con
        /// `audit_pages_stays_clean_across_a_real_relocation`, más arriba,
        /// que audita tras cada `commit` de un cruce real de reubicación) y
        /// determinista, pero cambia CUÁLES páginas
        /// concretas termina viendo `alloc`. Lo que este test protege de
        /// verdad —que la reubicación nunca entrega la página destino (8)
        /// ni pierde ninguna de las liberadas— sigue comprobado, solo que
        /// sin acoplarse a la identidad exacta de un detalle interno del
        /// asignador.
        #[test]
        fn freelist_serialization_never_hands_out_the_meta_b_relocation_target_either() {
            let (s, db) = fresh();

            let mut tx = db.begin_write().unwrap();
            let mut pages = Vec::new();
            for _ in 0..5 {
                let p = tx.alloc().unwrap();
                tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
                pages.push(p);
            }
            tx.set_root(pages[0]);
            tx.commit().unwrap();
            assert_eq!(pages, alloc::vec![3, 4, 5, 6, 7]);

            let mut tx = db.begin_write().unwrap();
            for &p in &pages[1..] {
                tx.free(p);
            }
            tx.commit().unwrap();

            let freelist_head = db.committed.read().unwrap().0.freelist_head;
            assert_ne!(
                freelist_head, 8,
                "la serializacion de la lista de libres entrego la pagina destino de la reubicacion \
                 de la meta B"
            );
            assert_eq!(Geometry::read(&*s).unwrap().meta_b_page, 2, "todavia no crucé el umbral");

            // Un commit más cruza los 4 KB (n_pages ya estaba en 10 tras
            // serializar la lista de libres) y dispara la reubicación real.
            // Su propio `alloc()` puede reciclar de la lista de libres que
            // acaba de crecer (mismo orden de preferencia de siempre: antes
            // que extender), así que se registra junto con el resto.
            let mut recycled = alloc::collections::BTreeSet::new();
            let mut tx = db.begin_write().unwrap();
            let p = tx.alloc().unwrap();
            recycled.insert(p);
            tx.write_page(p, &alloc::vec![2u8; 512]).unwrap();
            tx.commit().unwrap();
            assert_eq!(Geometry::read(&*s).unwrap().meta_b_page, 8);

            // La lista de libres sigue siendo legible y sigue entregando
            // páginas: si `relocate_meta_b` hubiera escrito encima de la
            // página de lista de libres real en vez de solo su destino
            // reservado, esto fallaría con `Corrupt` en vez de reciclar
            // limpio.
            let mut tx = db.begin_write().unwrap();
            while recycled.len() < pages[1..].len() {
                recycled.insert(tx.alloc().unwrap());
            }
            tx.commit().unwrap();

            assert_eq!(
                recycled.len(),
                pages[1..].len(),
                "deben reciclarse tantas páginas nuevas como se liberaron"
            );
            assert!(
                !recycled.contains(&8),
                "la pagina destino de la reubicacion de la meta B no debe repartirse nunca"
            );
        }
    }
}

/// Regresión de la clase entera: **un número leído del disco se usa para
/// dimensionar una reserva de memoria o para direccionar el fichero, sin
/// contrastarlo con lo que el fichero ES.**
///
/// Los siete defectos que cierra esta ronda comparten esa raíz. La frontera
/// está en dos sitios, uno por cada punto de entrada: `Db::open`
/// (`check_meta_against_file`) para los campos de la meta, y
/// `freelist::PageDomain` para las entradas de la lista de libres. Estas
/// pruebas entran por el API público —`Db::open`, `get`, `put`, `delete`,
/// `audit_pages`— porque el defecto es que el API público se porta mal;
/// llamar al validador comprobaría que el validador funciona, que es otra
/// cosa.
///
/// **Alcanzabilidad: manipulación.** El CRC32 por página se comprueba antes
/// que ningún campo, así que la podredumbre de bits y las escrituras
/// desgarradas se detienen en `CorruptKind::Checksum`. Cada fixture de aquí
/// recalcula el CRC —con el mismo `crc32` del crate— exactamente como haría
/// quien manipulase el fichero a propósito. Dos de ellos (`n_pages`)
/// funcionan igual sobre una base CIFRADA, porque las metas se escriben en
/// claro: ver la prueba con `#[cfg(feature = "encryption")]` al final.
#[cfg(all(test, feature = "std"))]
mod tampering_tests {
    use super::*;
    use crate::freelist::FREELIST_HEADER;
    use crate::storage::MemStorage;
    use crate::CorruptKind;
    use alloc::vec;

    const PS: u64 = 512;

    fn medium() -> Arc<MemStorage> {
        Arc::new(MemStorage::new())
    }

    fn open(s: &Arc<MemStorage>) -> Result<Db> {
        Db::open(Box::new(Arc::clone(s)), Options::default())
    }

    /// Base con datos reales y una cadena de lista de libres real en disco:
    /// 40 `put` y 30 `delete` dejan páginas liberadas de sobra. Devuelve la
    /// página de la meta ganadora y la cabeza de la cadena de libres.
    fn seeded(s: &Arc<MemStorage>) -> (PageNo, PageNo) {
        let db = Db::create(Box::new(Arc::clone(s)), Options::default()).unwrap();
        for i in 0..40u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), &[7u8; 60]).unwrap();
            tx.commit().unwrap();
        }
        for i in 0..30u32 {
            let mut tx = db.begin_write().unwrap();
            tx.delete(0x01, &i.to_be_bytes()).unwrap();
            tx.commit().unwrap();
        }
        let (meta, slot) = *db.committed.read().unwrap();
        let geometry = db.pager.geometry();
        assert_ne!(meta.freelist_head, 0, "el fixture debe dejar una cadena de libres real");
        (slot.page(&geometry), meta.freelist_head)
    }

    fn read_page(s: &Arc<MemStorage>, page: PageNo) -> Vec<u8> {
        let mut b = vec![0u8; PS as usize];
        s.read_at(page as u64 * PS, &mut b).unwrap();
        b
    }

    /// Recalcula el CRC de una página exactamente como lo hace el motor: sin
    /// esto, la manipulación se detendría en `CorruptKind::Checksum` y la
    /// prueba no llegaría a tocar el código que de verdad examina.
    fn rewrite_page(s: &Arc<MemStorage>, page: PageNo, mut b: Vec<u8>) {
        let mut h = crate::crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());
        s.write_at(page as u64 * PS, &b).unwrap();
    }

    /// Reescribe un campo de la meta ganadora con el propio codificador del
    /// crate (CRC de meta incluido), igual que la sonda de la revisión.
    ///
    /// **Conserva el sellado ORIGINAL de la ranura** (nonce y tag, bytes
    /// 108..148) en vez de ponerlo a cero: es el atacante más fuerte que se
    /// puede modelar sin la clave — cambia lo que quiere, recalcula el CRC
    /// y deja intacto todo lo que no sabe fabricar. Sobre una base SIN
    /// cifrar esos 40 bytes son cero de todos modos y esto no cambia nada;
    /// sobre una cifrada es la diferencia entre probar la autenticación de
    /// verdad y probar que un tag a cero no vale.
    fn tamper_meta(s: &Arc<MemStorage>, meta_page: PageNo, f: impl FnOnce(&mut Meta)) {
        let b = read_page(s, meta_page);
        let mut meta = Meta::decode(&b).unwrap();
        let seal = Meta::seal_of(&b);
        f(&mut meta);
        s.write_at(meta_page as u64 * PS, &meta.encode(PS as u32, Some(&seal))).unwrap();
    }

    /// Cuántas entradas dice tener la página de lista de libres `page`.
    fn freelist_count(s: &Arc<MemStorage>, page: PageNo) -> u16 {
        u16::from_le_bytes(read_page(s, page)[28..30].try_into().unwrap())
    }

    // ---- Hallazgo 7 (+6): `meta.n_pages` contra la longitud real -------

    /// **Hallazgo 7.** Un solo byte del campo `n_pages` bastaba para que el
    /// primer `alloc` repartiera un número de página disparatado y
    /// `Pager::write` escribiera a `n_pages * page_size`: 7,5 GB en la
    /// sonda de la revisión, 343 GB con el byte de al lado. Sobre un
    /// fichero real no falla —crea un fichero disperso, el `commit`
    /// devuelve `Ok`— y la base queda con una extensión gigantesca que ya
    /// no se puede reabrir.
    ///
    /// Sin la corrección, `Db::open` devuelve `Ok` aquí: acepta la meta tal
    /// cual y la adopta (`max(meta.n_pages, file_pages)`), que es
    /// exactamente lo contrario de rechazarla. Esta prueba sigue con un
    /// `put` acotado a propósito —`n_pages` manipulada a 100 000, no a
    /// `u32::MAX`— para que el fallo sobre código sin corregir sea un
    /// fichero de 51 MB que la aserción de longitud denuncia, y no una
    /// reserva de gigabytes que se lleve por delante la corrida entera.
    #[test]
    fn a_meta_that_declares_more_pages_than_the_file_has_is_rejected_at_open() {
        let s = medium();
        let (meta_page, _) = seeded(&s);
        let real_len = s.len().unwrap();
        tamper_meta(&s, meta_page, |m| m.n_pages = 100_000);

        let result = open(&s);
        assert!(
            matches!(result.as_ref(), Err(Error::Corrupt { kind: CorruptKind::MetaMismatch, .. })),
            "una meta que declara 100 000 páginas sobre un fichero de {} debe \
             dar Err(Corrupt{{MetaMismatch}}); se obtuvo {:?}",
            real_len / PS,
            result.map(|_| "Ok(Db)")
        );
        assert_eq!(
            s.len().unwrap(),
            real_len,
            "abrir no debe haber tocado el fichero"
        );
    }

    /// **Hallazgo 6.** `audit_pages` reservaba `vec![false; n_pages]` con
    /// `n_pages` leída de la meta: 4,29 GB de golpe (SIGABRT bajo cualquier
    /// límite de memoria) para auditar un fichero de 4 KB. La corrección no
    /// está en `audit_pages` sino en la puerta: una meta así ya no llega a
    /// montar. Sin ella, `Db::open` devuelve `Ok` y es la LLAMADA A
    /// `audit_pages` —lo que uno ejecuta justo ante la sospecha de
    /// corrupción— la que mata el proceso.
    #[test]
    fn a_page_count_of_u32_max_never_reaches_the_vec_that_audit_pages_sizes_from_it() {
        let s = medium();
        let (meta_page, _) = seeded(&s);
        tamper_meta(&s, meta_page, |m| m.n_pages = u32::MAX);

        let result = open(&s);
        assert!(
            matches!(result.as_ref(), Err(Error::Corrupt { kind: CorruptKind::MetaMismatch, .. })),
            "se esperaba Err(Corrupt{{MetaMismatch}}); se obtuvo {:?} — y con \
             `Ok`, el `audit_pages` siguiente reserva 4,29 GB",
            result.map(|_| "Ok(Db)")
        );
    }

    /// La misma manipulación sobre una base CIFRADA, y **ahora se detiene
    /// una capa antes**.
    ///
    /// Cuando se escribió esta prueba, la meta viajaba en claro con solo un
    /// CRC32, así que los hallazgos 6 y 7 eran alcanzables sin conocer la
    /// clave — a diferencia del resto de la clase, que el cifrado por
    /// página cerraba por accidente — y lo único que los paraba era la
    /// frontera de `Db::open` contra la longitud real del fichero
    /// (`check_meta_against_file`, `CorruptKind::MetaMismatch`). Esa
    /// frontera sigue ahí y sigue siendo la única defensa de una base SIN
    /// cifrar, pero en una cifrada ya no llega a ejecutarse para este caso:
    /// la ranura no autentica (`CorruptKind::MetaAuth`) y la apertura se
    /// para en `Meta::load_verified`.
    ///
    /// La diferencia no es cosmética. `MetaMismatch` solo atrapa valores
    /// IMPOSIBLES —una `n_pages` mayor que el fichero, una raíz que no
    /// direcciona nada—, así que un atacante que se quede dentro de lo
    /// plausible (repuntar `root` a una página que SÍ existe) lo esquivaba
    /// entero. `MetaAuth` no depende de que el valor falsificado sea
    /// absurdo: ver `a_meta_forged_at_every_field_is_rejected_on_open`.
    #[cfg(feature = "encryption")]
    #[test]
    fn a_tampered_page_count_is_rejected_on_an_encrypted_database_too() {
        let key = crate::crypto::Encryption {
            key: [3u8; 32],
            algorithm: crate::crypto::Algorithm::XChaCha20Poly1305,
        };
        let opts = || Options { encryption: Some(key), ..Options::default() };
        let s = medium();
        let meta_page = {
            let db = Db::create(Box::new(Arc::clone(&s)), opts()).unwrap();
            for i in 0..20u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), &[7u8; 60]).unwrap();
                tx.commit().unwrap();
            }
            let (_, slot) = *db.committed.read().unwrap();
            slot.page(&db.pager.geometry())
        };
        tamper_meta(&s, meta_page, |m| m.n_pages = u32::MAX);

        let result = Db::open(Box::new(Arc::clone(&s)), opts());
        assert!(
            matches!(result.as_ref(), Err(Error::Corrupt { kind: CorruptKind::MetaAuth, .. })),
            "una base cifrada tiene que rechazar su meta manipulada por el TAG, antes de \
             llegar a la frontera contra la longitud del fichero; se obtuvo {:?}",
            result.map(|_| "Ok(Db)")
        );
    }

    // ---- Hallazgos 3, 3 bis y 5: entradas de la lista de libres --------

    /// **Hallazgo 3.** Sustituir UNA entrada de la página de lista de libres
    /// por `0` y recalcular su CRC hacía que `alloc()` repartiera la página
    /// 0 —la cabecera del fichero— y que el siguiente `put` la
    /// sobrescribiera con una hoja. El `commit` devolvía `Ok(())`; el daño
    /// solo se veía al reabrir, con `Err(BadFormat)` y sin espejo de
    /// cabecera al que caer, porque vive en esa misma página.
    ///
    /// Sobre el código sin corregir, esta prueba falla en el segundo
    /// `open`, con `Err(BadFormat)`: la base entera se ha perdido.
    #[test]
    fn a_freelist_entry_of_zero_never_becomes_a_page_that_put_overwrites() {
        let s = medium();
        let (_, head) = seeded(&s);
        assert!(freelist_count(&s, head) >= 1, "el fixture necesita al menos una entrada");
        let mut b = read_page(&s, head);
        b[FREELIST_HEADER..FREELIST_HEADER + 4].copy_from_slice(&0u32.to_le_bytes());
        rewrite_page(&s, head, b);

        {
            let db = open(&s).expect("una lista de libres manipulada no debe impedir abrir");
            for i in 100..140u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), &[9u8; 60]).unwrap();
                tx.commit().unwrap();
            }
        }

        let db = open(&s).expect(
            "la base tiene que poder reabrirse: si `alloc` repartió la página 0, \
             el `put` de arriba escribió una hoja encima de la cabecera",
        );
        let r = db.begin_read();
        for i in 100..140u32 {
            assert_eq!(
                r.get(0x01, &i.to_be_bytes()).unwrap(),
                Some(vec![9u8; 60]),
                "clave {i} escrita tras la manipulación"
            );
        }
        assert_eq!(r.get(0x01, &35u32.to_be_bytes()).unwrap(), Some(vec![7u8; 60]));
    }

    /// **Hallazgo 3 bis.** La misma entrada sin validar, pero GRANDE: el
    /// motor escribe a `page_no * page_size`. La revisión lo alcanzó
    /// cambiando UN byte (el más alto de la segunda entrada), que llevó la
    /// entrada a 2,67×10^9 y la escritura a 1,37 TB; sobre un fichero real
    /// eso crea un fichero disperso, el `commit` tiene éxito, y la base ya
    /// no se puede reabrir jamás.
    ///
    /// Aquí la entrada se pone en 200 000 —no en 2,67×10^9— a propósito:
    /// sobre código sin corregir el daño es un fichero de 102 MB que la
    /// aserción de longitud denuncia, en vez de una reserva de terabytes
    /// que mataría la corrida. Es el mismo camino, con el mismo `alloc`,
    /// escalado para que el fallo se pueda REPORTAR.
    #[test]
    fn a_freelist_entry_past_the_end_of_the_file_never_becomes_a_write_at_that_offset() {
        let s = medium();
        let (_, head) = seeded(&s);
        let mut b = read_page(&s, head);
        b[FREELIST_HEADER..FREELIST_HEADER + 4].copy_from_slice(&200_000u32.to_le_bytes());
        rewrite_page(&s, head, b);

        let db = open(&s).expect("una lista de libres manipulada no debe impedir abrir");
        for i in 100..120u32 {
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, &i.to_be_bytes(), &[9u8; 60]).unwrap();
            tx.commit().unwrap();
        }
        let len = s.len().unwrap();
        assert!(
            len < 200 * 1024,
            "el fichero mide {len} bytes: `alloc` sirvió la entrada manipulada y \
             algo escribió a {} bytes del principio",
            200_000u64 * PS
        );
    }

    /// **Hallazgo 5.** `pages_in_use` restaba sin proteger `n_pages - free`,
    /// con `free` contado desde lo que la lista de libres trajo del disco.
    /// Subiendo el `count` de la página de cabeza a su máximo físico (120
    /// entradas con páginas de 512 B, que `decode_freelist_page` aceptaba
    /// porque su única comprobación era justo ese máximo), `free` supera a
    /// `n_pages`: pánico en depuración («attempt to subtract with
    /// overflow») y `Ok(4294967183)` en release — páginas en uso en un
    /// fichero de siete. Ninguna de las dos cosas es `Err`.
    ///
    /// Hoy las 117 entradas de relleno son ceros, que la frontera rechaza
    /// (`PageDomain`), así que la cadena entera se descarta al abrir y
    /// `pages_in_use` no llega a ver un número inflado. El
    /// `saturating_sub` cubre lo que la frontera no puede ver sin memoria
    /// proporcional a la lista entera: entradas válidas REPETIDAS.
    #[test]
    fn a_freelist_count_larger_than_the_file_does_not_underflow_pages_in_use() {
        let s = medium();
        let (_, head) = seeded(&s);
        let mut b = read_page(&s, head);
        b[28..30].copy_from_slice(&120u16.to_le_bytes());
        rewrite_page(&s, head, b);

        let db = open(&s).expect("una lista de libres manipulada no debe impedir abrir");
        let mut tx = db.begin_write().unwrap();
        let (in_use, total) = (tx.pages_in_use(), tx.n_pages());
        assert!(
            in_use <= total,
            "{in_use} páginas en uso de {total}: la cuenta sale de un contador de disco"
        );
    }

    // ---- Hallazgo 3 bis, cara de la reapertura ------------------------

    /// Medio que informa una longitud MAYOR que la real sin escribir un
    /// solo byte: es lo que un sistema de ficheros devuelve tras un
    /// `pwrite` disperso a un offset enorme (hallazgo 3 bis) y la única
    /// forma de reproducir ese estado sin reservar los terabytes de verdad.
    struct LongTail {
        inner: Arc<MemStorage>,
        reported: u64,
    }

    impl Storage for LongTail {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
            self.inner.read_at(o, b)
        }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
            self.inner.write_at(o, b)
        }
        fn sync(&self) -> Result<()> {
            self.inner.sync()
        }
        fn len(&self) -> Result<u64> {
            Ok(core::cmp::max(self.inner.len()?, self.reported))
        }
        fn truncate(&self, len: u64) -> Result<()> {
            self.inner.truncate(len)
        }
    }

    /// El bucle de reconciliación de `Db::open` empuja una entrada de lista
    /// de libres por cada página entre `meta.n_pages` y el final del
    /// fichero: trabajo Y memoria proporcionales a la longitud del medio.
    /// Con el fichero disperso que dejaba el hallazgo 3 bis (2,7×10^9
    /// páginas) eso pedía del orden de 10 GB y el proceso moría DENTRO de
    /// `Db::open`, así que la base quedaba inservible para siempre: ninguna
    /// herramienta del motor llegaba a arrancar, porque `open` es la puerta.
    ///
    /// Dos casos, en este orden a propósito. El primero (una cola justo por
    /// encima de `MAX_RECOVERABLE_TAIL`) sobre código sin corregir devuelve
    /// `Ok` tras reconciliar un millón de páginas: falla como aserción, sin
    /// matar nada. El segundo (un medio de 3 TB, que desborda el espacio de
    /// numeración de 32 bits) sí mataría la corrida sin la corrección, y no
    /// se llega a ejecutar porque el primero ya ha fallado.
    #[test]
    fn a_file_far_longer_than_its_meta_declares_is_rejected_instead_of_reconciled_page_by_page() {
        let s = medium();
        seeded(&s);
        let real = s.len().unwrap();

        let just_over = real + (u64::from(MAX_RECOVERABLE_TAIL) + 1) * PS;
        let result = Db::open(
            Box::new(LongTail { inner: Arc::clone(&s), reported: just_over }),
            Options::default(),
        );
        assert!(
            matches!(result.as_ref(), Err(Error::Corrupt { kind: CorruptKind::MetaMismatch, .. })),
            "un fichero con {} páginas más de las que la meta declara no es una \
             transacción interrumpida; se obtuvo {:?}",
            MAX_RECOVERABLE_TAIL + 1,
            result.map(|_| "Ok(Db)")
        );

        // 3 TB: `len / page_size` son 6×10^9 páginas, que NO caben en el
        // `u32` con el que el motor direcciona. Truncar (`as u32`) las
        // convertía en 1,7×10^9 — un número pequeño, y por tanto una
        // frontera que deja pasar justo lo que tenía que parar. Ver
        // `Pager::file_pages`.
        let three_terabytes = 3 * 1024 * 1024 * 1024 * 1024u64;
        let result = Db::open(
            Box::new(LongTail { inner: Arc::clone(&s), reported: three_terabytes }),
            Options::default(),
        );
        assert!(
            matches!(result.as_ref(), Err(Error::Corrupt { kind: CorruptKind::MetaMismatch, .. })),
            "un medio que informa 3 TB debe rechazarse, no dar la vuelta al \
             contador de páginas; se obtuvo {:?}",
            result.map(|_| "Ok(Db)")
        );
    }

    // ---- Hallazgo 4: profundidad de `audit_walk_tree` -----------------

    /// **Hallazgo 4.** `audit_walk_tree` recurre de verdad y no llevaba
    /// cota de profundidad: su comentario razonaba que «queda acotada por
    /// `n_pages`», que son hasta 2^32 marcos de pila. Una cadena de nodos
    /// internos válidos encadenados por `extra` desbordaba la pila y
    /// abortaba el proceso (SIGABRT) con 10 000 páginas —un fichero de 5
    /// MB— y `audit_pages` es, justamente, lo que uno ejecuta ante la
    /// sospecha de corrupción.
    ///
    /// La cadena de esta prueba tiene 130 eslabones: dos por encima de
    /// `MAX_DEPTH` y muy por debajo de lo que desborda ninguna pila. Es
    /// deliberado — lo que hay que probar es la COTA, y probarla con 10 000
    /// eslabones mataría la corrida entera en vez de reportar un fallo.
    /// Sobre código sin corregir esta prueba no aborta: devuelve
    /// `Ok(false)`, una respuesta silenciosamente equivocada («este fichero
    /// tiene páginas descolgadas») en lugar de `Err(Corrupt)` («este
    /// fichero no es un árbol»). La muerte del proceso con la cadena larga
    /// se comprobó aparte, en un binario de pruebas lanzado a propósito.
    #[cfg(feature = "audit")]
    #[test]
    fn audit_pages_rejects_a_chain_of_internal_nodes_deeper_than_a_tree_can_be() {
        use crate::page::{PageBuilder, PageType};

        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let page_size = tx.logical_page_size();
        let chain: Vec<PageNo> =
            (0..crate::tree::MAX_DEPTH + 2).map(|_| tx.alloc().unwrap()).collect();
        for (i, &page) in chain.iter().enumerate() {
            let mut b = PageBuilder::new(page_size, PageType::Internal);
            // Cero separadores y `extra` al siguiente eslabón: páginas que
            // `PageBuilder` construye, con su CRC correcto, que
            // `PageRef::parse` acepta sin una queja.
            b.set_extra(chain.get(i + 1).copied().unwrap_or(0));
            let bytes = b.build(&[]).unwrap();
            tx.write_page(page, &bytes).unwrap();
        }
        tx.set_root(chain[0]);
        tx.commit().unwrap();

        let result = db.audit_pages();
        assert!(
            matches!(result, Err(Error::Corrupt { kind: CorruptKind::TreeLoop, .. })),
            "una cadena de {} nodos internos debe cortar con Err(Corrupt{{TreeLoop}}) \
             a la profundidad máxima; se obtuvo {result:?}",
            chain.len()
        );
    }

    // ---- La meta autenticada (formato 3) -------------------------------
    //
    // El octavo hallazgo de la ronda de manipulación, el único que quedó
    // abierto entonces por ser un cambio de formato: **una base cifrada no
    // detectaba una meta falsificada**. Los hallazgos 6 y 7 se cerraron
    // contrastando la meta contra la longitud real del fichero, que atrapa
    // valores IMPOSIBLES; lo que sigue ataca con valores PLAUSIBLES, que
    // aquella frontera no puede ver.
    //
    // Todo se conduce desde `Db::open` con el API público, nunca llamando a
    // un validador interno: la pregunta es si la PUERTA rechaza el fichero,
    // no si existe una función que sepa decir que no.

    #[cfg(feature = "encryption")]
    mod authenticated_meta {
        use super::*;
        use crate::crypto::{Algorithm, Encryption};
        use crate::meta::META_AUTH_END;

        const MASTER: [u8; 32] = [0xa7; 32];

        fn algorithms() -> Vec<Algorithm> {
            #[allow(unused_mut)]
            let mut v = vec![Algorithm::XChaCha20Poly1305];
            #[cfg(feature = "aes")]
            v.push(Algorithm::Aes256GcmSiv);
            v
        }

        fn opts_for(key: [u8; 32], algorithm: Algorithm) -> Options {
            Options {
                encryption: Some(Encryption { key, algorithm }),
                ..Options::default()
            }
        }

        /// Base cifrada con datos reales y varios commits detrás, de modo
        /// que las dos ranuras lleven metas DISTINTAS (`txn_id` consecutivos
        /// y raíces distintas) — sin eso, un fallo de "cae a la otra ranura"
        /// pasaría inadvertido porque las dos dirían lo mismo.
        ///
        /// Devuelve `(página de la ranura viva, página de la otra)`.
        fn seeded_encrypted(s: &Arc<MemStorage>, opts: Options) -> (PageNo, PageNo) {
            let db = Db::create(Box::new(Arc::clone(s)), opts).unwrap();
            for i in 0..20u32 {
                let mut tx = db.begin_write().unwrap();
                tx.put(0x01, &i.to_be_bytes(), &[7u8; 60]).unwrap();
                tx.commit().unwrap();
            }
            let (live_meta, slot) = *db.committed.read().unwrap();
            let geometry = db.pager.geometry();
            let live = slot.page(&geometry);
            let stale = slot.other().page(&geometry);
            assert_ne!(live, stale);
            // Premisa: las dos ranuras difieren de verdad.
            let mut other = vec![0u8; PS as usize];
            s.read_at(stale as u64 * PS, &mut other).unwrap();
            let other = Meta::decode(&other).expect("la ranura vieja tambien decodifica");
            assert_ne!(
                other.txn_id, live_meta.txn_id,
                "el fixture necesita dos ranuras con contenido distinto"
            );
            (live, stale)
        }

        /// Reescribe la ranura de `page` conservando su sellado original
        /// (nonce y tag) y recalculando el CRC32 — el atacante más fuerte
        /// que se puede modelar sin la clave.
        fn forge(s: &Arc<MemStorage>, page: PageNo, f: impl FnOnce(&mut Meta)) {
            let b = read_page(s, page);
            let seal = Meta::seal_of(&b);
            let mut meta = Meta::decode(&b).unwrap();
            f(&mut meta);
            s.write_at(page as u64 * PS, &meta.encode(PS as u32, Some(&seal))).unwrap();
        }

        /// Igual, pero tocando bytes CRUDOS: sirve para las regiones que
        /// `Meta` no modela (los dos huecos reservados a cero).
        fn forge_raw(s: &Arc<MemStorage>, page: PageNo, at: usize, value: u8) {
            let mut b = read_page(s, page);
            b[at] = value;
            let crc = crate::crc32::checksum(&b[..crate::meta::META_SIZE - 4]);
            b[crate::meta::META_SIZE - 4..crate::meta::META_SIZE]
                .copy_from_slice(&crc.to_le_bytes());
            s.write_at(page as u64 * PS, &b).unwrap();
        }

        /// **La prueba central.** Un campo cada vez, con el CRC recalculado
        /// y el sellado original intacto: `Db::open` tiene que negarse.
        ///
        /// **Comportamiento sin este cambio, MEDIDO** (autenticación
        /// desactivada, formato y sellado intactos): ocho de las nueve
        /// falsificaciones de campo y las CUATRO de byte reservado abrían la
        /// base con `Ok(Db)` y sin una sola queja.
        ///
        /// - `root = 3`: `Db::open` devuelve `Ok`, y de las veinte claves
        ///   confirmadas **catorce desaparecen** (`get` → `Ok(None)`,
        ///   ni un `Err` en ninguna) mientras seis siguen contestando. Es
        ///   el caso que da nombre a todo esto: acepta una meta falsificada
        ///   y devuelve datos equivocados, en silencio.
        /// - `txn_id += 1000`: `Ok(Db)` montando por la ranura falsificada,
        ///   que a partir de ahí gana la selección para siempre — la
        ///   genuina no vuelve a montar por muchos commits que se hagan.
        /// - `n_pages -= 1`, `flags`, `format_major`, `catalog_root`,
        ///   `freelist_head`/`tail` y los cuatro bytes reservados: `Ok(Db)`.
        ///
        /// La única que ya fallaba era `wrapped_key`, y no por
        /// autenticación de la meta sino porque esos 60 bytes son un AEAD
        /// bajo la clave MAESTRA desde la tarea 17: `Err(Decrypt)`. Se
        /// mantiene en la lista precisamente para dejar constancia de qué
        /// parte del hueco ya estaba tapada y cuál no.
        ///
        /// Y el límite de la única defensa que había: `n_pages = u32::MAX`
        /// sí fallaba con `MetaMismatch` (hallazgo 7,
        /// `check_meta_against_file` contra la longitud real), pero
        /// `n_pages -= 1` —igual de falso, y plausible— pasaba. Por eso la
        /// lista de arriba usa el valor plausible y no el absurdo.
        #[test]
        fn a_meta_forged_at_every_field_is_rejected_on_open() {
            type Forgery = (&'static str, fn(&mut Meta));
            // `root` y `catalog_root` apuntan a una página que EXISTE (el
            // fixture tiene decenas): un valor plausible, invisible para
            // `check_meta_against_file`, que es lo que hace que esta prueba
            // diga algo nuevo.
            const FORGERIES: &[Forgery] = &[
                ("txn_id", |m| m.txn_id += 1_000),
                ("root", |m| m.root = 3),
                ("catalog_root", |m| m.catalog_root = 3),
                ("freelist_head", |m| m.freelist_head = 3),
                ("freelist_tail", |m| m.freelist_tail = 3),
                ("n_pages", |m| m.n_pages -= 1),
                ("flags", |m| m.flags ^= crate::header::FLAG_PREFIX_COMPRESSION),
                ("format_major", |m| m.format_major = 99),
                ("wrapped_key", |m| {
                    let mut w = m.wrapped_key.expect("base cifrada");
                    w[0] ^= 0xff;
                    m.wrapped_key = Some(w);
                }),
            ];

            for algorithm in algorithms() {
                let opts = opts_for(MASTER, algorithm);
                for (name, forgery) in FORGERIES {
                    let s = medium();
                    let (live, _) = seeded_encrypted(&s, opts);
                    forge(&s, live, *forgery);

                    let result = Db::open(Box::new(Arc::clone(&s)), opts);
                    assert!(
                        result.is_err(),
                        "{algorithm:?}/{name}: una meta falsificada con el CRC recalculado \
                         abrio la base; sin autenticacion esto devuelve Ok(Db) y el motor \
                         sirve el estado que eligio el atacante"
                    );
                }

                // Los dos huecos reservados a cero, byte a byte crudo: no
                // los modela `Meta`, así que `decode`/`encode` los
                // normalizaría y una autenticación calculada sobre los
                // campos RECODIFICADOS (en vez de sobre los bytes del
                // plato) los dejaría fuera de cobertura sin que se note.
                for at in [32usize, 39, 100, 107] {
                    let s = medium();
                    let (live, _) = seeded_encrypted(&s, opts);
                    forge_raw(&s, live, at, 0xff);

                    let result = Db::open(Box::new(Arc::clone(&s)), opts);
                    assert!(
                        matches!(
                            result.as_ref(),
                            Err(Error::Corrupt { kind: CorruptKind::MetaAuth, .. })
                        ),
                        "{algorithm:?}: el byte reservado {at} no esta autenticado; se obtuvo {:?}",
                        result.map(|_| "Ok(Db)")
                    );
                }
            }
        }

        /// `page_size_log2` se queda fuera de la lista de arriba porque su
        /// desenlace es OTRO, no porque no esté autenticado: la ranura se
        /// descarta antes de llegar a la autenticación, en la comprobación
        /// de geometría contra la cabecera que `Meta::load_verified` hereda
        /// del formato 1. Con la ranura viva descartada, la base monta por
        /// la vieja — que es lo correcto para el caso que esa comprobación
        /// modela (leer con el tamaño de página equivocado), y sigue sin
        /// darle al atacante lo que buscaba: lo único que consigue es una
        /// vuelta atrás, que es el límite conocido de este diseño.
        ///
        /// Falsificando las DOS ranuras no queda candidata ninguna y la
        /// apertura falla.
        #[test]
        fn a_forged_page_size_is_discarded_by_the_geometry_check_not_by_the_tag() {
            for algorithm in algorithms() {
                let opts = opts_for(MASTER, algorithm);
                let s = medium();
                let (live, stale) = seeded_encrypted(&s, opts);
                let live_txn = Meta::decode(&read_page(&s, live)).unwrap().txn_id;
                forge(&s, live, |m| m.page_size_log2 = 12);

                let db = Db::open(Box::new(Arc::clone(&s)), opts)
                    .expect("con una ranura sana la base sigue abriendo");
                assert!(
                    db.committed.read().unwrap().0.txn_id < live_txn,
                    "{algorithm:?}: deberia haber montado por la ranura vieja"
                );
                drop(db);

                forge(&s, stale, |m| m.page_size_log2 = 12);
                assert!(
                    Db::open(Box::new(Arc::clone(&s)), opts).is_err(),
                    "{algorithm:?}: sin ninguna ranura de geometria coherente no hay base"
                );
            }
        }

        /// Falsificar SOLO la ranura viva no debe caer a la vieja en
        /// silencio: eso convertiría un ataque detectado en una vuelta atrás
        /// sin señal. Ver `Meta::load_verified`.
        ///
        /// **Sin este cambio, medido:** `Ok(Db)`, y catorce de las veinte
        /// claves confirmadas devuelven `Ok(None)` — desaparecidas, sin un
        /// solo error por ninguna parte. Ver
        /// `a_meta_forged_at_every_field_is_rejected_on_open`.
        #[test]
        fn forging_only_the_live_slot_does_not_silently_fall_back_to_the_older_one() {
            for algorithm in algorithms() {
                let opts = opts_for(MASTER, algorithm);
                let s = medium();
                let (live, _) = seeded_encrypted(&s, opts);
                forge(&s, live, |m| m.root = 3);

                let result = Db::open(Box::new(Arc::clone(&s)), opts);
                assert!(
                    matches!(
                        result.as_ref(),
                        Err(Error::Corrupt { kind: CorruptKind::MetaAuth, .. })
                    ),
                    "{algorithm:?}: se esperaba Err(Corrupt{{MetaAuth}}) y NO una vuelta atrás \
                     silenciosa a la otra ranura; se obtuvo {:?}",
                    result.map(|_| "Ok(Db)")
                );
            }
        }

        /// Intercambiar el contenido de las dos ranuras. Las dos son metas
        /// genuinas de esta misma base, con su CRC y su tag de verdad: lo
        /// único que cambia es dónde vive cada una.
        ///
        /// **Sin la identidad de la ranura en los datos asociados esto
        /// pasaría desapercibido** aunque el tag existiera, y no sería un
        /// ataque menor: quien controla qué ranura ocupa cada `txn_id`
        /// controla cuál gana la selección de `Meta::load_verified`, es
        /// decir con qué versión del árbol monta la base.
        ///
        /// **Sin este cambio, medido:** `Ok(Db)`, montando tan campante por
        /// la ranura que el atacante colocó donde quiso.
        #[test]
        fn swapping_the_two_meta_slots_is_rejected() {
            for algorithm in algorithms() {
                let opts = opts_for(MASTER, algorithm);
                let s = medium();
                let (live, stale) = seeded_encrypted(&s, opts);

                let (a, b) = (read_page(&s, live), read_page(&s, stale));
                s.write_at(live as u64 * PS, &b).unwrap();
                s.write_at(stale as u64 * PS, &a).unwrap();

                let result = Db::open(Box::new(Arc::clone(&s)), opts);
                assert!(
                    matches!(
                        result.as_ref(),
                        Err(Error::Corrupt { kind: CorruptKind::MetaAuth, .. })
                    ),
                    "{algorithm:?}: intercambiar las ranuras debe fallar la autenticacion; \
                     se obtuvo {:?}",
                    result.map(|_| "Ok(Db)")
                );
            }
        }

        /// Una meta de OTRA base, en sus dos variantes, que se paran en dos
        /// capas distintas del orden de apertura:
        ///
        /// - **Otra clave maestra**: el envoltorio de los bytes 40..100 no
        ///   abre con la maestra de esta base, así que ni siquiera se llega
        ///   a tener una clave de datos con la que comprobar el tag.
        ///   `Err(Decrypt)`.
        /// - **La MISMA clave maestra, otro fichero**: el envoltorio SÍ
        ///   abre, y da la clave de datos de la otra base — con la que su
        ///   tag es perfectamente válido. Lo que no cuadra es el `db_id`,
        ///   que viaja en los datos asociados y sale de la CABECERA de este
        ///   fichero. `Err(Corrupt{MetaAuth})`.
        ///
        /// El segundo caso es el que justifica meter `db_id` en los datos
        /// asociados: sin él, un atacante que gestione dos bases con la
        /// misma clave maestra —el caso normal de un servidor con miles de
        /// bases por inquilino, que es justo el escenario de este motor—
        /// puede trasplantar metas entre ellas sin conocer ninguna clave de
        /// datos.
        ///
        /// **Sin este cambio, medido:** el primer caso ya fallaba
        /// (`Err(Decrypt)`, el AEAD del envoltorio bajo la maestra, que
        /// existe desde la tarea 17). El segundo NO se rechazaba por nada
        /// que se pareciese a una comprobación de identidad: daba
        /// `Err(Decrypt { page: 10 })` — la meta ajena se aceptaba entera y
        /// el fallo aparecía después, al intentar descifrar una página del
        /// árbol con la clave de datos de otra base, con un diagnóstico que
        /// dice "tus datos están corruptos" en vez de "esta meta no es de
        /// este fichero".
        ///
        /// Y ese rechazo era ACCIDENTAL, no una garantía: depende de que
        /// las páginas que la meta ajena referencia no se dejen descifrar
        /// aquí. Variando la forma de la base donante, el mismo trasplante
        /// daba `Err(Corrupt{MetaMismatch})` (por `n_pages` contra la
        /// longitud del fichero) o directamente `Ok(Db)` — tres desenlaces
        /// distintos por tres razones que no tienen nada que ver entre sí ni
        /// con la autenticidad de la meta. Con el `db_id` en los datos
        /// asociados hay una sola razón y siempre la misma.
        #[test]
        fn a_meta_from_another_database_is_rejected() {
            for algorithm in algorithms() {
                for (label, other_master, expected_auth) in [
                    ("otra clave maestra", [0x11u8; 32], false),
                    ("misma clave, otro fichero", MASTER, true),
                ] {
                    let victim = medium();
                    let (live, _) = seeded_encrypted(&victim, opts_for(MASTER, algorithm));

                    let donor = medium();
                    let (donor_live, _) =
                        seeded_encrypted(&donor, opts_for(other_master, algorithm));

                    // La ranura donante se copia a la MISMA letra de ranura
                    // que ocupaba en su base, para que el intercambio de
                    // ranuras no sea lo que la delate: lo único distinto es
                    // el fichero.
                    assert_eq!(
                        live % PS as u32,
                        donor_live % PS as u32,
                        "las dos bases deberian tener la misma geometria"
                    );
                    let bytes = read_page(&donor, donor_live);
                    victim.write_at(live as u64 * PS, &bytes).unwrap();

                    let result = Db::open(Box::new(Arc::clone(&victim)), opts_for(MASTER, algorithm));
                    if expected_auth {
                        assert!(
                            matches!(
                                result.as_ref(),
                                Err(Error::Corrupt { kind: CorruptKind::MetaAuth, .. })
                            ),
                            "{algorithm:?}/{label}: se esperaba fallo de autenticacion por db_id; \
                             se obtuvo {:?}",
                            result.map(|_| "Ok(Db)")
                        );
                    } else {
                        assert!(
                            matches!(result.as_ref(), Err(Error::Decrypt { .. })),
                            "{algorithm:?}/{label}: se esperaba Err(Decrypt) al desenvolver; \
                             se obtuvo {:?}",
                            result.map(|_| "Ok(Db)")
                        );
                    }
                }
            }
        }

        /// El límite que este diseño NO cierra, escrito como prueba para
        /// que quede documentado y no como una frase optimista en un
        /// comentario: **una meta ANTIGUA y genuina de esta misma base se
        /// acepta**. Está firmada con la clave correcta, con el `db_id`
        /// correcto y en la ranura correcta; nada dentro del fichero puede
        /// distinguirla de la actual salvo su `txn_id`, y el `txn_id` lo
        /// eligió quien escribió la copia.
        ///
        /// Defenderse de esto exige un ancla de confianza FUERA del
        /// fichero — un contador monótono en hardware, o el `txn_id`
        /// esperado guardado en otro sitio — que este motor no tiene y que
        /// esta tarea no promete. Ver el informe.
        #[test]
        fn an_older_genuine_meta_of_the_same_database_still_replays() {
            for algorithm in algorithms() {
                let opts = opts_for(MASTER, algorithm);
                let s = medium();
                let (live, stale) = seeded_encrypted(&s, opts);

                // La copia de seguridad que un atacante haría: los bytes de
                // la ranura vieja, guardados y vueltos a poner encima de la
                // nueva. Sigue siendo la ranura de la letra equivocada, así
                // que se pone en SU sitio (la vieja) y se destruye la nueva
                // — que es todo lo que hace falta para retroceder.
                let old = read_page(&s, stale);
                s.write_at(stale as u64 * PS, &old).unwrap();
                s.write_at(live as u64 * PS, &[0u8; PS as usize]).unwrap();

                let db = Db::open(Box::new(Arc::clone(&s)), opts)
                    .expect("una meta genuina y vieja autentica perfectamente");
                let rolled_back = db.committed.read().unwrap().0.txn_id;
                let current = Meta::decode(&old).unwrap().txn_id;
                assert_eq!(
                    rolled_back, current,
                    "{algorithm:?}: la meta vieja monta, y eso es un limite conocido del \
                     diseño, no un defecto abierto"
                );
            }
        }

        /// La región autenticada cubre exactamente `0..META_AUTH_END` y ni
        /// un byte más: cambiar el nonce o el tag hace la ranura ilegible
        /// (fallan el CRC, que va después), no "aceptable de otra forma".
        /// Fija que el CRC sigue cubriendo el sellado.
        #[test]
        fn the_checksum_covers_the_seal_too() {
            let opts = opts_for(MASTER, Algorithm::XChaCha20Poly1305);
            for at in [META_AUTH_END, crate::meta::META_TAG_OFF] {
                let s = medium();
                let (live, _) = seeded_encrypted(&s, opts);
                let mut b = read_page(&s, live);
                b[at] ^= 0xff;
                // SIN recalcular el CRC: el sellado está dentro de lo que
                // cubre, así que tocarlo ya rompe el CRC.
                s.write_at(live as u64 * PS, &b).unwrap();

                let mut probe = vec![0u8; PS as usize];
                s.read_at(live as u64 * PS, &mut probe).unwrap();
                assert!(
                    matches!(
                        Meta::decode(&probe),
                        Err(Error::Corrupt { kind: CorruptKind::Checksum, .. })
                    ),
                    "el byte {at} del sellado deberia entrar en el CRC32 de la ranura"
                );
            }
        }

        /// Una base SIN cifrar deja el sellado a cero y `Db::open` no
        /// comprueba nada más que el CRC. **No es un descuido: es lo que el
        /// formato sin cifrado garantiza**, y decirlo con una prueba impide
        /// que alguien lea el resto de este módulo y suponga que la
        /// autenticación protege también ahí.
        #[test]
        fn without_encryption_there_is_no_key_and_therefore_no_authentication() {
            let s = medium();
            let (live, _) = seeded(&s);
            let bytes = read_page(&s, live);
            assert_eq!(
                &bytes[META_AUTH_END..crate::meta::META_SIZE - 4],
                &[0u8; crate::crypto::STORED_NONCE_LEN + crate::crypto::TAG_LEN][..],
                "sin cifrado el sellado se escribe a cero"
            );

            // Y la misma falsificación que una base cifrada rechaza, aquí
            // se acepta: `root` a una página existente, CRC recalculado.
            forge(&s, live, |m| m.root = 3);
            assert!(
                Db::open(Box::new(Arc::clone(&s)), Options::default()).is_ok(),
                "sin clave no hay nada con lo que rechazarla, y el formato no promete otra cosa"
            );
        }
    }
}
