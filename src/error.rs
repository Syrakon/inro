use crate::PageNo;

/// Todos los errores del motor. `Copy` a propósito: nada de `String` ni de
/// `Box<dyn Error>`, que en IoT cuestan memoria y tamaño de binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io(IoError),
    /// Una página no valida su suma de comprobación o su estructura interna.
    /// Identifica la página concreta para que el llamante pueda decidir entre
    /// reintentar, degradar o recrear la base.
    Corrupt { page: PageNo, kind: CorruptKind },
    /// El fichero no es una base inro.
    BadFormat,
    /// El fichero usa una versión de formato que este binario no entiende.
    VersionTooNew { found: u16, supported: u16 },
    /// El fichero usa una versión de formato ANTERIOR a la mínima que este
    /// binario sabe leer. Existe desde el cambio de diseño a nonces
    /// aleatorios, que rompe el formato: la disposición de una página
    /// cifrada pasó de `contador (8) || tag (16) || texto cifrado` a
    /// `nonce (24) || tag (16) || texto cifrado`, y la meta dejó de llevar
    /// el techo de contador en los bytes 100..108.
    ///
    /// **Por qué un error y no una lectura "compatible".** Un fichero del
    /// formato 1 SIN cifrar es, byte a byte, estructuralmente legible por
    /// este binario (la diferencia vive toda en las páginas cifradas y en
    /// un campo de la meta que ya no se lee). Aceptarlo dejaría el motor
    /// con dos reglas — "acepto el formato 1 si además no está cifrado" —
    /// y con un fichero cifrado del formato 1 que se abriría sin quejarse
    /// para fallar más tarde y peor: los primeros 8 bytes de cada página
    /// eran un contador y ahora se leen como el principio de un nonce, así
    /// que el descifrado falla como si la clave fuera incorrecta o la
    /// página estuviera manipulada. Rechazar por versión, una sola regla
    /// para todos, dice exactamente lo que pasa.
    ///
    /// **El formato 3 (meta autenticada) añade un motivo que el 2 no
    /// tenía, y es de seguridad, no de comodidad.** Una ranura de meta pasó
    /// de 112 a 152 bytes, con el CRC32 mudándose de 108..112 a 148..152:
    /// leída con la disposición vieja, una ranura nueva falla el CRC, así
    /// que un fichero del formato 3 nunca se malinterpretaría por un
    /// binario del 2. Al revés sí importaría: si este binario aceptara
    /// ficheros del formato 2, existiría una vía de apertura SIN
    /// autenticar, y bastaría bajar el `format_major` de la cabecera —que
    /// no está autenticada, ni puede estarlo: hay que leerla para saber
    /// dónde vive la meta que lleva la clave— para volver a colar metas
    /// falsificadas con solo un CRC32 recalculado. Un rechazo limpio por
    /// versión cierra esa puerta sin tener que autenticar la cabecera.
    VersionTooOld { found: u16, supported: u16 },
    /// Este proceso ya tiene abierto ese mismo fichero (`FileStorage::open`,
    /// comparando rutas CANONICALIZADAS: `./base` y `/abs/base` son la
    /// misma). Dos asas independientes sobre un fichero significan dos
    /// `Db::write_lock` distintos: el escritor único deja de serlo, y el
    /// copy-on-write de dos escritores concurrentes es corrupción — con
    /// cifrado o sin él.
    ///
    /// **Ya no es además un fallo de confidencialidad** (cambio de diseño a
    /// nonces aleatorios). Antes lo era, y era lo peor de los dos daños:
    /// las dos asas arrancaban su contador de nonce desde el mismo
    /// `write_counter` de la meta, así que repartían LOS MISMOS nonces bajo
    /// la misma clave de datos. Ahora cada apertura sortea su propio
    /// prefijo de 16 bytes (`crypto::NonceStream`), así que dos asas no
    /// pueden colisionar aunque este rechazo no existiera. Lo que queda —
    /// la corrupción del árbol por dos escritores copy-on-write — sigue
    /// siendo motivo de sobra para rechazar la segunda asa.
    ///
    /// No cubre un SEGUNDO PROCESO: ver la sección 3.4 de la
    /// especificación. Quien reparta un mismo fichero entre varios procesos
    /// tiene que excluirlos por su cuenta.
    AlreadyOpen,
    /// Ya hay una transacción de escritura en curso en este proceso.
    WriterBusy,
    /// La transacción de escritura anterior entró en pánico mientras tenía
    /// el candado de escritor tomado (p. ej. dentro de un extractor de
    /// índice que no debía entrar en pánico nunca — ver `IndexDef::extract`)
    /// y lo dejó envenenado. A diferencia de `WriterBusy`, este candado
    /// nunca se libera solo: confundir los dos casos bajo el mismo error
    /// dejaría cualquier `begin_write` posterior fallando para siempre con
    /// un mensaje que sugiere "espera y reintenta" cuando la base en
    /// realidad necesita intervención.
    WriterPoisoned,
    /// El extractor registrado no coincide con el que construyó el índice.
    IndexVersionMismatch { id: u8, stored: u32, provided: u32 },
    /// Un índice único ya contiene ese valor indexado.
    DuplicateKey { id: u8 },
    /// El catálogo EN DISCO declara el índice `id` sobre el espacio de
    /// claves `ns`, pero este `Db` no lo tiene registrado: nadie ha llamado
    /// a `define_index` con él desde que se abrió la base. Una escritura
    /// sobre `ns` en ese estado no puede mantener el índice — el extractor
    /// es un puntero a función, código del llamante, y no viaja en el
    /// fichero (ver `IndexDef::encode`, que guarda versión, unicidad, `ns`
    /// y nombre, pero no puede guardar `extract`) — así que el motor sabe
    /// lo bastante para NEGARSE aunque no sepa lo bastante para MANTENER.
    ///
    /// Sin este error, esa escritura seguía adelante por el camino sin
    /// índices: la fila se guardaba sin entrada de índice, o se borraba
    /// dejando la suya huérfana, y la divergencia solo se manifestaba en
    /// otra apertura, la que sí declara sus índices, como una respuesta
    /// EQUIVOCADA de `scan_index` — claves primarias de filas ya borradas y
    /// ausencia de filas recién insertadas. Es un error distinto de
    /// `DeleteRangeIndexed` a propósito: aquí la acción correctora existe y
    /// es concreta — declara tus índices con `define_index` y repite la
    /// operación — mientras que `DeleteRangeIndexed` significa que la
    /// operación no está disponible sobre ese `ns` por mucho que se declare.
    IndexNotDeclared { id: u8, ns: u8 },
    /// `delete_range` sobre un `ns` con índices definidos: el borrado por
    /// rango libera subárboles enteros sin visitar cada entrada (ver el
    /// comentario de `WriteTxn::delete_range`), así que no hay forma barata
    /// de saber qué entradas de índice retirar. Enrutarlo por `delete` clave
    /// a clave sería correcto pero destruiría la garantía de coste que
    /// justifica `delete_range` — justo para el caso de uso, poda diaria por
    /// retención, que más se beneficia de tener también un índice. Fallar
    /// alto y claro es preferible a divergir en silencio.
    ///
    /// **"Con índices definidos" se decide contra el CATÁLOGO en disco**, no
    /// solo contra los `IndexDef` registrados en este `Db` — si no, este
    /// error no llegaba a dispararse nunca en el único proceso donde de
    /// verdad importa: un podador de retención no tiene ningún motivo para
    /// llamar a `define_index` (ni forma de hacerlo: no tiene el extractor),
    /// así que su lista de índices registrados está vacía y `delete_range`
    /// se colaba por el camino sin índices, huerfanando de golpe todas las
    /// entradas del rango. A diferencia de `IndexNotDeclared`, declarar el
    /// índice no cambia el resultado: la operación sigue rechazada.
    DeleteRangeIndexed { ns: u8 },
    KeyTooLarge { len: u32, max: u32 },
    /// No queda espacio direccionable: el fichero alcanzó 2^32 páginas.
    Full,
    /// El descifrado falló: clave incorrecta o página manipulada.
    Decrypt { page: PageNo },
    /// Comprobación interna, no un fallo del llamante: `WriteTxn::write_page`
    /// detectó que iba a sellar `page` con un número de escritura
    /// (`NonceStream::issued`) que ya se había usado dentro de esta misma
    /// transacción. Con el diseño actual (contador monótono por apertura,
    /// que no rebobina nunca) esto es matemáticamente inalcanzable si el
    /// resto del motor es correcto: convierte la invariante de unicidad del
    /// nonce, de la que depende toda la confidencialidad del cifrado por
    /// página, de una suposición no comprobada a algo que el propio motor
    /// verifica en cada escritura.
    NonceReuse { page: PageNo },
    /// El flujo de nonces de esta apertura se agotó y no hay forma de
    /// renovarlo. Solo alcanzable bajo `no_std` con AES-256-GCM-SIV: su
    /// nonce de 12 bytes deja un campo de contador de 32 bits, así que a
    /// las 2^32 escrituras de página de una misma apertura hace falta un
    /// prefijo aleatorio nuevo — bajo `std` se sortea de `/dev/urandom` y
    /// esto no llega a ocurrir, pero sin sistema operativo no hay de dónde
    /// sortearlo y el llamante solo aportó un prefijo. Fallar aquí es lo
    /// correcto: la alternativa sería repetir un nonce en silencio. Ver
    /// `crypto::NonceStream::next`.
    NonceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    NotFound,
    PermissionDenied,
    UnexpectedEof,
    WriteZero,
    Other(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptKind {
    Checksum,
    PageType,
    SlotOffset,
    CellBounds,
    FreelistLoop,
    /// El descenso del árbol superó la profundidad máxima legítima sin
    /// alcanzar una hoja: un ciclo de punteros a hijos, no un árbol válido.
    TreeLoop,
    /// El recorrido de una cadena de páginas de overflow (tarea 13) superó
    /// el número de páginas que le corresponden sin terminar: un ciclo en
    /// los punteros `next`, no una cadena válida. Ni `FreelistLoop` ni
    /// `TreeLoop` encajan: no es la lista de libres ni el descenso del
    /// árbol, es un tercer tipo de cadena de punteros con su propio
    /// recorrido acotado.
    OverflowLoop,
    MetaMismatch,
    /// Una meta-ranura COMPLETA (su CRC32 cuadra con sus propios bytes) que
    /// no lleva el tag de autenticación que le corresponde bajo la clave de
    /// datos de esta base. Solo alcanzable en una base CIFRADA: sin clave no
    /// hay nada con lo que autenticar (ver `meta::MetaSeal`).
    ///
    /// **Distinto de `Checksum`, y el distingo es toda la señal.** Una
    /// ranura desgarrada por un corte de corriente falla el CRC —los bytes
    /// que hay en el plato son mitad de una meta y mitad de otra, y ningún
    /// CRC certifica esa mezcla— y el motor la descarta en silencio para
    /// montar por la otra ranura: es exactamente el fallo que el diseño de
    /// dos ranuras existe para absorber. Una ranura que SÍ cuadra su CRC es,
    /// por construcción, una ranura entera: nadie la desgarró. Que además no
    /// autentique significa que alguien calculó ese CRC sobre un contenido
    /// que la clave no avala — manipulación, no un fallo del medio — y por
    /// eso `Db::open` se detiene aquí en vez de caer a la otra ranura. Ver
    /// `Meta::load_verified`.
    MetaAuth,
}

pub type Result<T> = core::result::Result<T, Error>;
