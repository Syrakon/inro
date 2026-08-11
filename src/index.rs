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
    /// Se invoca dentro de `WriteTxn::put`/`delete`, con el candado de
    /// escritor de `Db` tomado durante toda la llamada. **No debe entrar en
    /// pánico.** Un pánico aquí envenena ese candado (`std::sync::Mutex` de
    /// la biblioteca estándar) de forma permanente — no se libera con
    /// reintentar, como si estuviera ocupado, sino que cada `begin_write`
    /// posterior falla para siempre (`Error::WriterPoisoned`) hasta que el
    /// proceso se reinicie. El motor no puede protegerse de esto por sí
    /// solo: `extract` es código del llamante, sin forma de ejecutarlo en un
    /// entorno aislado sin coste, en un motor cuyo presupuesto es justo cero
    /// dependencias y mínima huella.
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
///
/// `entry` puede ser basura: una página de índice corrupta, o (tarea 16,
/// ronda 2 de revisión, hallazgo 4) cualquiera puede escribir bytes
/// arbitrarios directamente en el espacio de claves de un índice con
/// `tx.put(0x80 | id, ...)`, sin pasar por `WriteTxn::put`, que es el único
/// sitio que garantiza el formato. `pk_len` viene de esos dos últimos bytes
/// sin validar, así que puede ser mayor que `entry.len()`; restar sin
/// comprobar (`entry.len() - 2 - pk_len`) desbordaría por abajo — pánico en
/// depuración, envoltura silenciosa en release — y este motor solo devuelve
/// `Err` ante una entrada corrupta, nunca entra en pánico ni la interpreta
/// mal (la misma regla que ya sigue `read_overflow`, ver su comentario en
/// `tree.rs`). `checked_sub` hace la resta y la comprobación de rango en un
/// solo paso, sin ese hueco.
pub(crate) fn primary_of(entry: &[u8]) -> Result<&[u8]> {
    if entry.len() < 2 {
        return Err(Error::BadFormat);
    }
    let pk_len = u16::from_le_bytes(entry[entry.len() - 2..].try_into().unwrap()) as usize;
    let start = entry.len().checked_sub(2 + pk_len).ok_or(Error::BadFormat)?;
    Ok(&entry[start..entry.len() - 2])
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

    /// Límite superior que cubre CUALQUIER clave real del motor: ninguna
    /// clave (primaria o de índice) puede superar `page_size / 4` bytes de
    /// contenido (128 con `page_size` 512, ver la tarea 11), así que 300
    /// bytes a `0xff` exceden por mucho hasta la más larga. Un solo byte
    /// `0xff` (como usa el modismo de `scan_index` documentado en su propio
    /// comentario) NO basta como "cubre todo": es un prefijo estricto de
    /// cualquier clave que también empiece por `0xff`, así que compara MENOR
    /// que ella y la deja fuera de un rango que debía cubrirlo todo — ronda
    /// 2 de revisión, hallazgo 9 y "arregla tu propia cobertura de
    /// pruebas": con el límite de un byte, cualquier entrada cuyo primer
    /// byte fuera `0xff` quedaba invisible para estos dos comprobadores,
    /// así que una fila huérfana o ausente en esa esquina nunca se habría
    /// detectado.
    const SCAN_EVERYTHING: [u8; 300] = [0xff; 300];

    /// Recorre `def.index_ns()` entero y comprueba, para cada entrada, que
    /// la clave primaria que codifica sigue existiendo en `ns` con un valor
    /// vigente cuya extracción produce exactamente esa clave indexada. Un
    /// fallo aquí es una entrada huérfana o obsoleta.
    fn assert_no_orphans(r: &crate::tx::ReadTxn, def: &IndexDef) {
        let mut cursor = r.scan(def.index_ns(), b"", &SCAN_EVERYTHING).unwrap();
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
        let mut cursor = r.scan(def.ns, b"", &SCAN_EVERYTHING).unwrap();
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
        // 90 + 90 + 2 = 182 bytes de contenido, + 1 del prefijo de `ns` que
        // `scoped()` antepone antes de que la clave llegue a `tree::put`
        // (ronda 2 de revisión, hallazgo 2) = 183.
        assert_eq!(err, Error::KeyTooLarge { len: 183, max: 128 });
        // se descarta sin commit

        let r = db.begin_read();
        assert_eq!(r.get(0x10, &big_pk).unwrap(), None, "el dato no debe haberse escrito");
        assert!(r.scan_index(1, b"", &SCAN_EVERYTHING).unwrap().is_empty(), "el índice no debe tener entradas");
    }

    // --- Ronda 2 de revisión: correcciones ------------------------------

    /// Hallazgo 1: `delete_range` sobre un `ns` con índices definidos se
    /// rechaza en vez de dejar el índice divergiendo en silencio (ver el
    /// análisis completo en el comentario de `WriteTxn::delete_range`). Ni
    /// el dato ni el índice deben cambiar tras el rechazo.
    #[test]
    fn delete_range_is_refused_on_an_indexed_namespace() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        for i in 0..20u32 {
            tx.put(0x10, alloc::format!("{i:03}").as_bytes(), b"madrid").unwrap();
        }
        tx.commit().unwrap();

        {
            let mut tx = db.begin_write().unwrap();
            let err = tx.delete_range(0x10, b"000", b"010").unwrap_err();
            assert_eq!(err, Error::DeleteRangeIndexed { ns: 0x10 });
            // se descarta sin commit
        }

        let r = db.begin_read();
        for i in 0..20u32 {
            assert!(
                r.get(0x10, alloc::format!("{i:03}").as_bytes()).unwrap().is_some(),
                "un delete_range rechazado no debió borrar ninguna fila"
            );
        }
        assert_eq!(
            r.scan_index(1, b"madrid", &SCAN_EVERYTHING).unwrap().len(),
            20,
            "tampoco debió cambiar el índice"
        );
    }

    /// `delete_range` sigue funcionando con normalidad sobre un `ns` SIN
    /// índices, aunque la misma base tenga índices definidos sobre otros
    /// espacios de claves — el rechazo del hallazgo 1 es por `ns`, no
    /// global.
    #[test]
    fn delete_range_still_works_on_a_namespace_without_indexes() {
        let db = db(); // índice definido sobre ns=0x10, no sobre 0x20
        let mut tx = db.begin_write().unwrap();
        for i in 0..5u32 {
            tx.put(0x20, alloc::format!("{i:03}").as_bytes(), b"x").unwrap();
        }
        tx.delete_range(0x20, b"000", b"003").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert!(r.get(0x20, b"000").unwrap().is_none());
        assert!(r.get(0x20, b"002").unwrap().is_none());
        assert!(r.get(0x20, b"003").unwrap().is_some());
        assert!(r.get(0x20, b"004").unwrap().is_some());
    }

    /// Hallazgo 2: el chequeo de tamaño de una entrada de índice tenía que
    /// contar el byte de `ns` que `scoped()` antepone antes de que la clave
    /// llegue a `tree::put` — sin el `+ 1`, una entrada de EXACTAMENTE
    /// `page_size / 4` pasaba la planificación y fallaba en la aplicación,
    /// con la entrada vieja ya borrada. Estas dos pruebas fijan el límite
    /// justo en la frontera: la entrada de índice (contenido, sin el byte
    /// de `ns`) mide 127 bytes en la primera (127+1=128=límite, se acepta) y
    /// 128 en la segunda (128+1=129>límite, se rechaza).
    #[test]
    fn an_index_entry_exactly_at_the_cap_is_accepted() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let indexed = alloc::vec![b'v'; 64];
        let pk = alloc::vec![b'k'; 61]; // 64 + 61 + 2 = 127 -> escapado 128
        tx.put(0x10, &pk, &indexed).unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.get(0x10, &pk).unwrap().unwrap(), indexed);
        assert_index_consistent(&r, &def());
    }

    #[test]
    fn an_index_entry_one_byte_over_the_cap_is_rejected_cleanly() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let indexed = alloc::vec![b'v'; 64];
        let pk = alloc::vec![b'k'; 62]; // 64 + 62 + 2 = 128 -> escapado 129
        let err = tx.put(0x10, &pk, &indexed).unwrap_err();
        assert_eq!(err, Error::KeyTooLarge { len: 129, max: 128 });
        // se descarta sin commit

        let r = db.begin_read();
        assert!(r.get(0x10, &pk).unwrap().is_none());
        assert_index_consistent(&r, &def());
    }

    /// Regresión precisa del hallazgo 2 tal y como lo demostró la revisión:
    /// no una fila nueva, sino una ACTUALIZACIÓN, que es donde la
    /// planificación en dos fases seguía siendo insuficiente sin el `+ 1` —
    /// la fase de aplicación borra las entradas viejas ANTES de insertar las
    /// nuevas (ver `WriteTxn::put`), así que si el chequeo de tamaño de la
    /// planificación no atrapaba el caso límite exacto, la entrada vieja se
    /// llegaba a borrar de verdad, y solo entonces fallaba la inserción de
    /// la nueva — dejando la fila con su valor viejo pero sin ninguna
    /// entrada de índice.
    ///
    /// Comprueba el estado DENTRO de la propia transacción, antes de
    /// descartarla — no solo tras el `drop` — porque abandonar la
    /// transacción limpia cualquier huella de todas formas: comprobar solo
    /// después no distinguiría "la planificación nunca tocó la entrada
    /// vieja" de "la tocó, y el abandono deshizo el estropicio". Con el
    /// error `len`/`max` es indistinguible entre ambos casos, porque
    /// `tree::put` acaba viendo la misma clave sobredimensionada de todas
    /// formas y reporta el mismo valor — la única prueba que de verdad
    /// distingue "se validó todo antes de mutar" de "se mutó y se deshizo"
    /// es mirar dentro de la transacción viva.
    #[test]
    fn updating_to_an_oversized_index_entry_leaves_the_old_entry_intact() {
        let db = db();
        let d = def();
        let mut tx = db.begin_write().unwrap();
        let small_indexed = alloc::vec![b'v'; 4];
        let pk = alloc::vec![b'k'; 62];
        tx.put(0x10, &pk, &small_indexed).unwrap();
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();
        let big_indexed = alloc::vec![b'w'; 64]; // 64 + 62 + 2 = 128 -> escapado 129
        let err = tx.put(0x10, &pk, &big_indexed).unwrap_err();
        assert_eq!(err, Error::KeyTooLarge { len: 129, max: 128 });

        let old_entry = index_key(&d, &small_indexed, &pk);
        assert!(
            tx.get(d.index_ns(), &old_entry).unwrap().is_some(),
            "la entrada de índice vieja no debió borrarse antes de validar la nueva"
        );
        assert_eq!(tx.get(0x10, &pk).unwrap().unwrap(), small_indexed, "el dato tampoco debió tocarse");
        // se descarta sin commit

        let r = db.begin_read();
        assert_eq!(r.get(0x10, &pk).unwrap().unwrap(), small_indexed, "la fila no debió cambiar");
        assert_index_consistent(&r, &d);
    }

    /// Hallazgo 3: una clave primaria demasiado grande para un índice ÚNICO
    /// no aparece nunca en la entrada de índice (que en un único es solo el
    /// valor indexado), así que el chequeo de tamaño de la entrada no la ve.
    /// Sin un chequeo aparte, la entrada de índice se llegaba a escribir de
    /// verdad en la fase de aplicación y solo el `put_raw` del dato
    /// primario fallaba al final — dejando esa entrada huérfana en memoria
    /// si quien llama no abandonaba la transacción.
    #[test]
    fn an_oversized_primary_key_is_rejected_before_any_index_mutation() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(IndexDef { unique: true, ..def() }).unwrap();

        let mut tx = db.begin_write().unwrap();
        let big_pk = alloc::vec![b'k'; 200]; // muy por encima de los 128 del límite
        let err = tx.put(0x10, &big_pk, b"madrid").unwrap_err();
        assert_eq!(err, Error::KeyTooLarge { len: 201, max: 128 });
        // se descarta sin commit

        let r = db.begin_read();
        assert!(r.get(0x10, &big_pk).unwrap().is_none());
        assert!(
            r.scan_index(1, b"madrid", &SCAN_EVERYTHING).unwrap().is_empty(),
            "no debe quedar ninguna entrada de índice huérfana"
        );
    }

    /// Hallazgo 4: `primary_of` debe devolver `Err`, nunca entrar en
    /// pánico, ante una entrada de índice corrupta. Alcanzable desde la API
    /// pública sin ni siquiera pasar por un índice de verdad: escribir bytes
    /// arbitrarios directamente en el espacio de claves reservado a un
    /// índice (aquí, `0x81` = `INDEX_NS_BASE | 1`) es indistinguible, para
    /// `WriteTxn::put`, de escribir en cualquier otro `ns` sin índices — no
    /// hay ningún índice CON `ns = 0x81`, así que la escritura se acepta sin
    /// pasar por la maquinaria de índices, y la corrupción solo se
    /// manifiesta después, al leerla como si fuera una entrada real.
    #[test]
    fn scan_index_reports_bad_format_instead_of_panicking_on_a_garbage_entry() {
        let db = db(); // índice id=1, no único -> index_ns = 0x81
        let mut tx = db.begin_write().unwrap();
        // Los últimos dos bytes de una entrada no única codifican la
        // longitud de la clave primaria; aquí dicen 65535 sobre una entrada
        // de solo 2 bytes en total.
        tx.put(0x81, b"\xff\xff", b"").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        let err = r.scan_index(1, b"", &SCAN_EVERYTHING).unwrap_err();
        assert_eq!(err, Error::BadFormat, "una entrada corrupta debe dar Err, nunca pánico");
    }

    /// Hallazgo 5: redefinir el mismo `id` bajo la MISMA versión pero con
    /// otra unicidad (o, en la segunda prueba, otro `ns`) debe rechazarse
    /// igual que un cambio de versión — comparando solo `version` esto se
    /// aceptaba en silencio, y `scan_index`/la comprobación de unicidad
    /// quedaban actuando sobre una definición que ya no coincide con lo que
    /// hay en el catálogo.
    #[test]
    fn redefining_with_the_same_version_but_different_uniqueness_is_rejected() {
        let s = alloc::sync::Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
            db.define_index(def()).unwrap(); // unique: false, version: 1
        }
        let db = Db::open(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
        let err = db.define_index(IndexDef { unique: true, ..def() }).unwrap_err();
        assert_eq!(err, Error::IndexVersionMismatch { id: 1, stored: 1, provided: 1 });
    }

    #[test]
    fn redefining_with_the_same_version_but_a_different_ns_is_rejected() {
        let s = alloc::sync::Arc::new(MemStorage::new());
        {
            let db = Db::create(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
            db.define_index(def()).unwrap(); // ns: 0x10, version: 1
        }
        let db = Db::open(Box::new(ArcStorage(alloc::sync::Arc::clone(&s))), Options::default()).unwrap();
        let err = db.define_index(IndexDef { ns: 0x11, ..def() }).unwrap_err();
        assert_eq!(err, Error::IndexVersionMismatch { id: 1, stored: 1, provided: 1 });
    }

    /// Redefinir con EXACTAMENTE el mismo registro (misma versión, unicidad,
    /// `ns` y nombre) sigue siendo idempotente — la comparación de registro
    /// completo no debe convertirse en una comparación más estricta de lo
    /// necesario.
    #[test]
    fn redefining_with_an_identical_record_still_succeeds() {
        let db = db();
        db.define_index(def()).unwrap();
        db.define_index(def()).unwrap();
    }

    /// Hallazgo 6: `def.ns` no puede caer en ninguno de los dos rangos que
    /// el propio motor se reserva.
    #[test]
    fn define_index_rejects_the_catalog_namespace() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let err = db.define_index(IndexDef { ns: CATALOG_NS, ..def() }).unwrap_err();
        assert_eq!(err, Error::BadFormat);
    }

    #[test]
    fn define_index_rejects_an_index_namespace() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let err = db.define_index(IndexDef { ns: INDEX_NS_BASE | 5, ..def() }).unwrap_err();
        assert_eq!(err, Error::BadFormat);
    }

    /// Hallazgo 7: un extractor que entra en pánico deja el candado de
    /// escritor envenenado (mecanismo del propio `std::sync::Mutex`, no
    /// algo que este motor construya) — `begin_write` debe reportarlo con un
    /// error DISTINTO de `WriterBusy`, porque a diferencia de "ocupado" este
    /// no se resuelve solo con reintentar: se queda envenenado para
    /// siempre.
    #[test]
    fn a_panicking_extractor_poisons_the_writer_lock_with_a_distinct_error() {
        fn panics(_key: &[u8], _value: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
            panic!("extractor caprichoso");
        }
        let d = IndexDef { id: 4, name: "malo", version: 1, ns: 0x13, unique: false, extract: panics };
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(d).unwrap();

        // Silencia el volcado por defecto del pánico (ruido esperado, no un
        // fallo del test) mientras se provoca y se atrapa.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(alloc::boxed::Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tx = db.begin_write().unwrap();
            let _ = tx.put(0x13, b"pk1", b"x");
        }));
        std::panic::set_hook(prev_hook);
        assert!(result.is_err(), "se esperaba que el extractor entrara en pánico");

        assert_eq!(
            db.begin_write().err(),
            Some(Error::WriterPoisoned),
            "un candado envenenado no debe confundirse con WriterBusy"
        );
    }

    /// Hallazgo 9 (documentado, sin arreglo — ver el comentario de
    /// `scan_index`): el modismo `v ++ [0xff]` como límite superior para
    /// "todo lo que vale `v`" excluye, en un índice no único, cualquier fila
    /// cuya clave primaria empiece por el byte `0xff` — comparado byte a
    /// byte, `v ++ 0xff` es un prefijo estricto de `v ++ 0xff ++ más_bytes`,
    /// y un prefijo estricto compara menor, así que esa fila cae fuera de
    /// `[from, to)`. Esta prueba fija el comportamiento documentado: el
    /// modismo estrecho pierde la fila, un límite con margen de sobra no.
    #[test]
    fn the_v_plus_0xff_scan_idiom_drops_a_primary_key_starting_with_0xff() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        tx.put(0x10, b"aaa", b"madrid").unwrap();
        tx.put(0x10, b"\xff\xff\xff", b"madrid").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        let narrow = r.scan_index(1, b"madrid", b"madrid\xff").unwrap();
        assert_eq!(
            narrow,
            alloc::vec![b"aaa".to_vec()],
            "el modismo v++0xff debe perder la fila cuya pk empieza por 0xff"
        );

        let mut wide_to = b"madrid".to_vec();
        wide_to.extend_from_slice(&SCAN_EVERYTHING);
        let wide = r.scan_index(1, b"madrid", &wide_to).unwrap();
        assert_eq!(wide, alloc::vec![b"aaa".to_vec(), b"\xff\xff\xff".to_vec()], "un límite con margen sí las ve a las dos");
    }

    /// Regresión de la tarea 19 (pruebas basadas en propiedades contra un
    /// oráculo `BTreeMap`): una hoja que mezcla entradas de TRES espacios
    /// de claves distintos — catálogo, datos y un índice secundario —
    /// puede perder TODA la compresión de prefijo compartida entre ellas
    /// (cada espacio empieza por un byte de `ns` distinto), y entonces el
    /// punto de corte por CUENTA de entradas que usaba `tree::emit` al
    /// dividir una hoja podía quedarse literalmente un byte corto — aunque
    /// el contenido combinado cupiera de sobra en dos páginas — y fallar
    /// con `Error::KeyTooLarge` en un `put` perfectamente legítimo.
    ///
    /// Extraído de `proptest` (`tests/props.rs`,
    /// `the_secondary_index_matches_a_recomputed_index_after_every_op`).
    /// **No "de forma fiable" al número de casos por defecto** (corrección
    /// de la ronda de revisión de la tarea 19 que encontró esta frase
    /// demasiado optimista): medido con `PROPTEST_CASES=20` explícito
    /// (el valor por defecto de este fichero, ver `tests/props.rs`), diez
    /// ejecuciones independientes solo fallan en 3 — de ahí el fichero
    /// `tests/props.proptest-regressions`, comiteado con esta misma
    /// corrección: registra la semilla exacta que sí lo encuentra, para que
    /// `cargo test` la repita SIEMPRE, sin depender de acertar con el nº de
    /// casos aleatorios de turno. Reproducido aquí a mano con
    /// `PROPTEST_CASES=1000 PROPTEST_MAX_SHRINK_ITERS=500000 cargo test
    /// --test props
    /// the_secondary_index_matches_a_recomputed_index_after_every_op` y
    /// reducido desde ahí hasta estos nueve `put`. **El nombre del
    /// índice importa tanto como las claves y valores**: forma parte del
    /// registro de catálogo (`ns` 0x00) que comparte hoja con los demás, así
    /// que cambiar su longitud en un solo byte desplaza el presupuesto justo
    /// lo suficiente para dejar de reproducir el fallo — confirmado de
    /// primera mano: una versión anterior de esta prueba usaba `"cubo"` (4
    /// bytes) en vez de `"bucket"` (6, el mismo nombre que usa la propiedad)
    /// y pasaba sin ejercitar nada, con o sin la corrección de `emit`.
    #[test]
    fn a_leaf_split_that_loses_all_prefix_compression_still_succeeds() {
        fn bucket_of(_key: &[u8], value: &[u8]) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
            alloc::vec![alloc::vec![value.first().copied().unwrap_or(0)]]
        }
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        db.define_index(IndexDef {
            id: 1,
            name: "bucket",
            version: 1,
            ns: 0x01,
            unique: false,
            extract: bucket_of,
        })
        .unwrap();

        // `vfirst` es el único byte no nulo de cada valor: como `bucket_of`
        // solo mira el primer byte, sigue eligiendo a qué cubo del índice
        // cae cada fila sin necesitar un valor de verdad — el resto de
        // bytes son de relleno, para llegar al tamaño exacto que hace falta
        // para que la hoja combinada (catálogo + datos + índice) se quede
        // corta con el punto de corte por CUENTA de entradas.
        let ops: &[(&[u8], usize, u8)] = &[
            (&[0], 77, 0),
            (&[0, 0, 0, 0], 78, 74),
            (&[], 21, 74),
            (&[0, 0, 0, 1], 92, 0),
            (&[2], 122, 64),
            (&[3], 8, 64),
            (&[2, 0, 0], 111, 64),
            (&[5], 89, 0),
            (&[2, 0], 110, 0),
        ];
        for (k, vlen, vfirst) in ops {
            let mut v = alloc::vec![0u8; *vlen];
            if !v.is_empty() {
                v[0] = *vfirst;
            }
            let mut tx = db.begin_write().unwrap();
            tx.put(0x01, k, &v).unwrap();
            tx.commit().unwrap();
        }

        let r = db.begin_read();
        for (k, vlen, _) in ops {
            assert_eq!(
                r.get(0x01, k).unwrap().map(|v| v.len()),
                Some(*vlen),
                "clave {k:?} no sobrevivió a la división"
            );
        }
    }
}
