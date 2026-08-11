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
    /// Ya hay una transacción de escritura en curso en este proceso.
    WriterBusy,
    /// El extractor registrado no coincide con el que construyó el índice.
    IndexVersionMismatch { id: u8, stored: u32, provided: u32 },
    /// Un índice único ya contiene ese valor indexado.
    DuplicateKey { id: u8 },
    KeyTooLarge { len: u32, max: u32 },
    /// No queda espacio direccionable: el fichero alcanzó 2^32 páginas.
    Full,
    /// El descifrado falló: clave incorrecta o página manipulada.
    Decrypt { page: PageNo },
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
