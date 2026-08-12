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
    /// Este proceso ya tiene abierto ese mismo fichero (`FileStorage::open`,
    /// comparando rutas CANONICALIZADAS: `./base` y `/abs/base` son la
    /// misma). Dos asas independientes sobre un fichero significan dos
    /// `Db::write_lock` distintos —el escritor único deja de serlo, y el
    /// copy-on-write de dos escritores concurrentes es corrupción— y, con
    /// cifrado, dos `live_counter` independientes, es decir los MISMOS
    /// nonces bajo la misma clave de datos: dos textos cifrados con el
    /// mismo nonce se anulan al XOR y revelan el texto plano.
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
    /// `delete_range` sobre un `ns` con índices definidos: el borrado por
    /// rango libera subárboles enteros sin visitar cada entrada (ver el
    /// comentario de `WriteTxn::delete_range`), así que no hay forma barata
    /// de saber qué entradas de índice retirar. Enrutarlo por `delete` clave
    /// a clave sería correcto pero destruiría la garantía de coste que
    /// justifica `delete_range` — justo para el caso de uso, poda diaria por
    /// retención, que más se beneficia de tener también un índice. Fallar
    /// alto y claro es preferible a divergir en silencio.
    DeleteRangeIndexed { ns: u8 },
    KeyTooLarge { len: u32, max: u32 },
    /// No queda espacio direccionable: el fichero alcanzó 2^32 páginas.
    Full,
    /// El descifrado falló: clave incorrecta o página manipulada.
    Decrypt { page: PageNo },
    /// Comprobación interna, no un fallo del llamante: `WriteTxn::write_page`
    /// detectó que iba a sellar `page` con un contador de nonce que ya se
    /// había usado dentro de esta misma transacción. Con el diseño actual
    /// (contador monótono por transacción, reservado por adelantado —
    /// tarea 17, ronda de revisión posterior) esto es matemáticamente
    /// inalcanzable si el resto del motor es correcto: convierte la
    /// invariante de unicidad del nonce, de la que depende toda la
    /// confidencialidad del cifrado por página, de una suposición no
    /// comprobada a algo que el propio motor verifica en cada escritura.
    NonceReuse { page: PageNo },
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
}

pub type Result<T> = core::result::Result<T, Error>;
