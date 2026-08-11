//! Catálogo de índices secundarios.
//!
//! Un índice secundario es una segunda B+tree derivada de los datos: el
//! motor invoca `IndexDef::extract` en cada `put`/`delete` de su espacio de
//! claves origen y mantiene las entradas de índice **dentro de la misma
//! transacción** que los datos (ver `tx::WriteTxn::put`/`delete`). Eso
//! compra atomicidad: el índice y el dato no pueden divergir, ni siquiera
//! ante un corte de corriente a mitad de escritura, porque ambos viven o
//! mueren con el mismo commit.
//!
//! Este módulo solo contiene el tipo de valor `IndexDef` y la codificación
//! de sus claves — puras funciones sin estado. El cableado con `Db`,
//! `WriteTxn` y `ReadTxn` vive en `tx.rs`, donde viven esos tipos: así sus
//! campos internos siguen siendo privados a ese módulo, el mismo patrón que
//! ya usa `tree.rs` (funciones libres que `tx.rs` invoca, no `impl` sobre
//! los tipos de otro fichero).

use alloc::vec::Vec;
use crate::{Error, Result};

/// Espacio de claves del catálogo.
pub const CATALOG_NS: u8 = 0x00;
/// Primer espacio de claves reservado a índices. El índice `id` vive en
/// `INDEX_NS_BASE | id`.
pub const INDEX_NS_BASE: u8 = 0x80;

/// Definición de un índice secundario. `Copy` a propósito: sin asignación y
/// sin estado capturado.
///
/// `PartialEq`/`Eq` se derivan por conveniencia de pruebas (comparar dos
/// `IndexDef` completos en una aserción); el motor nunca compara dos
/// `IndexDef` entre sí — solo sus campos `id`/`ns`, que son `u8` normales —
/// así que la comparación de `extract` por dirección de función, que el
/// compilador avisa que no es fiable entre unidades de compilación, nunca es
/// el criterio real de nada.
#[allow(unpredictable_function_pointer_comparisons)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexDef {
    /// Identificador, de 0 a 127. Determina el espacio de claves del índice.
    pub id: u8,
    pub name: &'static str,
    /// Subir esta versión al cambiar `extract`. Es lo único que impide que un
    /// extractor distinto deje el índice mintiendo en silencio.
    pub version: u32,
    /// Espacio de claves cuyos datos indexa.
    pub ns: u8,
    pub unique: bool,
    pub extract: fn(key: &[u8], value: &[u8]) -> Vec<Vec<u8>>,
}

impl IndexDef {
    pub fn index_ns(&self) -> u8 {
        INDEX_NS_BASE | self.id
    }

    /// Registro del catálogo: versión, unicidad, espacio y nombre.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(6 + self.name.len());
        v.extend_from_slice(&self.version.to_le_bytes());
        v.push(self.unique as u8);
        v.push(self.ns);
        v.extend_from_slice(self.name.as_bytes());
        v
    }

    pub(crate) fn stored_version(record: &[u8]) -> Option<u32> {
        record.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
}

/// Clave de índice.
///
/// En un índice único es el valor indexado a secas: la unicidad la impone la
/// colisión de clave en el árbol, sin comprobación adicional, y la clave
/// primaria viaja como valor.
///
/// En uno no único incorpora la clave primaria para que dos filas con el mismo
/// valor indexado no colisionen, más su longitud en dos bytes **al final**. Al
/// final y no al principio porque anteponerla rompería el orden lexicográfico
/// por valor indexado, que es justo lo que hace útil el índice.
pub(crate) fn index_key(def: &IndexDef, indexed: &[u8], primary: &[u8]) -> Vec<u8> {
    if def.unique {
        indexed.to_vec()
    } else {
        let mut k = Vec::with_capacity(indexed.len() + primary.len() + 2);
        k.extend_from_slice(indexed);
        k.extend_from_slice(primary);
        k.extend_from_slice(&(primary.len() as u16).to_le_bytes());
        k
    }
}

/// Recupera la clave primaria de una entrada de índice no único.
pub(crate) fn primary_of(entry: &[u8]) -> Result<&[u8]> {
    if entry.len() < 2 {
        return Err(Error::BadFormat);
    }
    let pk_len = u16::from_le_bytes(entry[entry.len() - 2..].try_into().unwrap()) as usize;
    entry
        .get(entry.len() - 2 - pk_len..entry.len() - 2)
        .ok_or(Error::BadFormat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    /// Indexa el valor entero como clave secundaria.
    fn by_value(_key: &[u8], value: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        alloc::vec![value.to_vec()]
    }

    fn def() -> IndexDef {
        IndexDef { id: 1, name: "por_valor", version: 1, ns: 0x10, unique: false, extract: by_value }
    }

    fn db() -> Db {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(def()).unwrap();
        db
    }

    /// Permite conservar el medio tras cerrar la base, para reabrirla. Cada
    /// módulo de pruebas define su propia copia local (ver `tx.rs` y
    /// `tree.rs`): es un tipo diminuto y sin estado propio del test, no algo
    /// que merezca una utilidad compartida entre módulos.
    struct ArcStorage(alloc::sync::Arc<MemStorage>);
    impl crate::Storage for ArcStorage {
        fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> { self.0.read_at(o, b) }
        fn write_at(&self, o: u64, b: &[u8]) -> Result<()> { self.0.write_at(o, b) }
        fn sync(&self) -> Result<()> { self.0.sync() }
        fn len(&self) -> Result<u64> { self.0.len() }
    }

    #[test]
    fn an_insert_populates_the_index() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.put(0x10, b"pk2", b"madrid").unwrap();
        tx.put(0x10, b"pk3", b"lisboa").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.scan_index(1, b"madrid", b"madrid\xff").unwrap(), alloc::vec![b"pk1".to_vec(), b"pk2".to_vec()]);
        assert_eq!(r.scan_index(1, b"lisboa", b"lisboa\xff").unwrap(), alloc::vec![b"pk3".to_vec()]);
    }

    #[test]
    fn updating_a_row_moves_its_index_entry() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.put(0x10, b"pk1", b"lisboa").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert!(r.scan_index(1, b"madrid", b"madrid\xff").unwrap().is_empty());
        assert_eq!(r.scan_index(1, b"lisboa", b"lisboa\xff").unwrap(), alloc::vec![b"pk1".to_vec()]);
    }

    #[test]
    fn deleting_a_row_removes_its_index_entry() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.delete(0x10, b"pk1").unwrap();
        tx.commit().unwrap();
        assert!(db.begin_read().scan_index(1, b"", b"\xff").unwrap().is_empty());
    }

    #[test]
    fn a_unique_index_rejects_a_duplicate() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(IndexDef { unique: true, ..def() }).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        assert!(tx.put(0x10, b"pk2", b"madrid").is_err());
    }

    #[test]
    fn reopening_with_a_stale_extractor_version_is_rejected() {
        let s = alloc::sync::Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
            db.define_index(def()).unwrap();
        }
        let db = Db::open(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
        let err = db.define_index(IndexDef { version: 2, ..def() }).unwrap_err();
        assert_eq!(err, Error::IndexVersionMismatch { id: 1, stored: 1, provided: 2 });
    }

    // --- Autorrevisión de la tarea 16: contrato falsificable -----------
    //
    // "Tras cualquier secuencia de puts y deletes sobre un espacio de claves
    // indexado, `scan_index` devuelve exactamente las claves primarias cuya
    // fila vigente cae en el rango consultado — sin entradas obsoletas ni
    // ausentes — y una operación fallida no deja ni el dato ni el índice
    // cambiados." Este bloque construye los casos adversariales del punto 5
    // del encargo y, tras cada uno, recorre el ESPACIO DE CLAVES CRUDO del
    // índice (no `scan_index`, que ya oculta el problema si lo tuviera) y
    // verifica que cada entrada apunta a una fila viva cuyo valor actual de
    // verdad se reindexa a esa clave.

    /// Recorre `def.index_ns()` entero y comprueba, para cada entrada, que
    /// la clave primaria que codifica sigue existiendo en `ns` con un valor
    /// vigente cuya extracción produce exactamente esa clave indexada. Un
    /// fallo aquí es una entrada huérfana o obsoleta.
    fn assert_no_orphans(r: &crate::tx::ReadTxn, def: &IndexDef) {
        let mut cursor = r.scan(def.index_ns(), b"", b"\xff").unwrap();
        let mut n = 0usize;
        while let Some((k, v)) = cursor.next().unwrap() {
            n += 1;
            let (indexed, primary): (Vec<u8>, Vec<u8>) = if def.unique {
                (k.clone(), v.clone())
            } else {
                let pk = primary_of(&k).unwrap().to_vec();
                let indexed = k[..k.len() - 2 - pk.len()].to_vec();
                (indexed, pk)
            };
            let current = r.get(def.ns, &primary).unwrap_or_else(|e| {
                panic!("entrada de índice huérfana: pk {primary:?} no existe ({e:?})")
            });
            let current = current.unwrap_or_else(|| {
                panic!("entrada de índice huérfana: pk {primary:?} ya no existe en ns {}", def.ns)
            });
            let reextracted = (def.extract)(&primary, &current);
            assert!(
                reextracted.contains(&indexed),
                "entrada de índice obsoleta: pk {primary:?} tiene valor actual {current:?} \
                 que ya no se extrae a {indexed:?} (extrae {reextracted:?})"
            );
        }
        let _ = n; // solo para depurar a mano si hace falta
    }

    /// Dirección contraria a `assert_no_orphans`: recorre `def.ns` entero
    /// (los datos, no el índice) y comprueba que CADA clave que el
    /// extractor produce para la fila vigente tiene de verdad su entrada de
    /// índice. Ninguna de las dos direcciones basta por separado — "sin
    /// huérfanas" (índice→dato) no detectaría un `put` que se saltara la
    /// indexación de una fila nueva, porque esa fila nunca aparecería en el
    /// recorrido del índice. Solo con las dos juntas queda cubierto el
    /// contrato completo: "exactamente las claves primarias cuyo valor
    /// vigente cae en el rango — ni entradas obsoletas ni ausentes".
    fn assert_no_missing_entries(r: &crate::tx::ReadTxn, def: &IndexDef) {
        let mut cursor = r.scan(def.ns, b"", b"\xff").unwrap();
        while let Some((pk, value)) = cursor.next().unwrap() {
            for ik in (def.extract)(&pk, &value) {
                let found = if def.unique {
                    r.get(def.index_ns(), &ik).unwrap().as_deref() == Some(pk.as_slice())
                } else {
                    let entry = index_key(def, &ik, &pk);
                    r.get(def.index_ns(), &entry).unwrap().is_some()
                };
                assert!(
                    found,
                    "falta entrada de índice: pk {pk:?}, valor {value:?} debería indexar \
                     bajo {ik:?} y no la tiene"
                );
            }
        }
    }

    /// Invariante bidireccional completo del contrato de la tarea (punto 5
    /// del encargo): sin entradas obsoletas Y sin entradas ausentes.
    fn assert_index_consistent(r: &crate::tx::ReadTxn, def: &IndexDef) {
        assert_no_orphans(r, def);
        assert_no_missing_entries(r, def);
    }

    #[test]
    fn insert_then_reinsert_after_delete_leaves_no_orphan() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.delete(0x10, b"pk1").unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.scan_index(1, b"madrid", b"madrid\xff").unwrap(), alloc::vec![b"pk1".to_vec()]);
        assert_index_consistent(&r, &def());
    }

    /// Actualizar una parte del valor que el extractor NO usa no debe dejar
    /// el índice en un estado raro: la clave de índice vieja y la nueva son
    /// la misma cadena de bytes, así que este caso ejercita el camino
    /// borrar-y-reinsertar con `indexed` sin cambios. Además, con un índice
    /// único, es el caso exacto que puede confundirse con "duplicado
    /// consigo mismo" si la comprobación de unicidad compara solo
    /// existencia en vez de comparar la clave primaria almacenada.
    #[test]
    fn updating_a_non_indexed_part_of_the_value_is_not_a_self_duplicate() {
        // Extrae solo los primeros 4 bytes (la "ciudad"); el resto del valor
        // es información no indexada (aquí, un contador).
        fn city_only(_key: &[u8], value: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
            alloc::vec![value[..4].to_vec()]
        }
        let d = IndexDef { id: 2, name: "ciudad", version: 1, ns: 0x11, unique: true, extract: city_only };
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(d).unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.put(0x11, b"pk1", b"mad:001").unwrap();
        // Cambia solo la parte no indexada (el contador), la ciudad ("mad:")
        // permanece igual: esto NO debe fallar con DuplicateKey contra su
        // propia entrada anterior.
        tx.put(0x11, b"pk1", b"mad:002").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.get(0x11, b"pk1").unwrap().unwrap(), b"mad:002");
        assert_eq!(r.scan_index(2, b"mad:", b"mad;").unwrap(), alloc::vec![b"pk1".to_vec()]);
        assert_index_consistent(&r, &d);
    }

    #[test]
    fn two_rows_sharing_an_indexed_value_leave_no_orphan() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.put(0x10, b"pk2", b"madrid").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.scan_index(1, b"madrid", b"madrid\xff").unwrap(), alloc::vec![b"pk1".to_vec(), b"pk2".to_vec()]);
        assert_index_consistent(&r, &def());
    }

    #[test]
    fn a_rejected_duplicate_leaves_neither_data_nor_index_changed() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(IndexDef { unique: true, ..def() }).unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"pk1", b"madrid").unwrap();
        tx.commit().unwrap();

        // Intenta un duplicado en una transacción nueva y la abandona sin
        // commit tras el error, tal y como exige el contrato del motor para
        // cualquier `Err` de `put` (ver el comentario de `WriteTxn::put`).
        {
            let mut tx = db.begin_write().unwrap();
            assert!(tx.put(0x10, b"pk2", b"madrid").is_err());
            // se descarta sin commit
        }

        let r = db.begin_read();
        assert_eq!(r.get(0x10, b"pk2").unwrap(), None, "el dato rechazado no debe existir");
        assert_eq!(r.scan_index(1, b"madrid", b"madrid\xff").unwrap(), alloc::vec![b"pk1".to_vec()]);
        assert_index_consistent(&r, &IndexDef { unique: true, ..def() });
    }

    /// Un extractor que produce varias claves por fila (p. ej. etiquetas
    /// separadas por coma): cada clave extraída debe tener su propia entrada
    /// de índice, y una actualización que cambia el conjunto de etiquetas
    /// debe mover exactamente las que cambiaron, sin dejar huérfanas las que
    /// ya no aplican ni duplicar las que se conservan.
    #[test]
    fn an_extractor_returning_several_keys_per_row_leaves_no_orphan() {
        fn tags(_key: &[u8], value: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
            value.split(|&b| b == b',').map(|t| t.to_vec()).collect()
        }
        let d = IndexDef { id: 3, name: "etiquetas", version: 1, ns: 0x12, unique: false, extract: tags };
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(d).unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.put(0x12, b"pk1", b"rojo,azul").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.scan_index(3, b"rojo", b"rojo\xff").unwrap(), alloc::vec![b"pk1".to_vec()]);
        assert_eq!(r.scan_index(3, b"azul", b"azul\xff").unwrap(), alloc::vec![b"pk1".to_vec()]);
        assert_index_consistent(&r, &d);
        drop(r);

        // Cambia el conjunto: pierde "rojo", conserva "azul", gana "verde".
        let mut tx = db.begin_write().unwrap();
        tx.put(0x12, b"pk1", b"azul,verde").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert!(r.scan_index(3, b"rojo", b"rojo\xff").unwrap().is_empty(), "rojo debe desaparecer");
        assert_eq!(r.scan_index(3, b"azul", b"azul\xff").unwrap(), alloc::vec![b"pk1".to_vec()], "azul se conserva");
        assert_eq!(r.scan_index(3, b"verde", b"verde\xff").unwrap(), alloc::vec![b"pk1".to_vec()], "verde es nueva");
        assert_index_consistent(&r, &d);
    }

    /// Regresión de la interacción con el límite de `page_size / 4` (tarea
    /// 11): una clave de índice no único es `indexado + primaria + 2`, y
    /// ambas mitades pueden ser individualmente legales y aun así superar el
    /// límite juntas. Debe rechazarse LIMPIO — `KeyTooLarge`, no un pánico,
    /// no una escritura de datos que se cuela mientras el índice falla — y
    /// sin tocar ni el dato ni el índice.
    #[test]
    fn an_oversized_concatenated_index_key_is_rejected_cleanly() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        // page_size 512 -> límite 128 bytes. 90 (indexado) + 90 (pk) + 2 >
        // 128, pero cada mitad por separado cabe de sobra.
        db.define_index(def()).unwrap();

        let mut tx = db.begin_write().unwrap();
        let big_pk = alloc::vec![b'k'; 90];
        let big_value = alloc::vec![b'v'; 90];
        let err = tx.put(0x10, &big_pk, &big_value).unwrap_err();
        assert!(
            matches!(err, Error::KeyTooLarge { .. }),
            "se esperaba KeyTooLarge, se obtuvo {err:?}"
        );
        // se descarta sin commit

        let r = db.begin_read();
        assert_eq!(r.get(0x10, &big_pk).unwrap(), None, "el dato no debe haberse escrito");
        assert!(r.scan_index(1, b"", b"\xff").unwrap().is_empty(), "el índice no debe tener entradas");
    }
}
