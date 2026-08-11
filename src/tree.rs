use alloc::vec::Vec;

use crate::page::{CellPayload, PageBuilder, PageRef, PageType};
use crate::tx::{PageSource, WriteTxn};
use crate::{Error, PageNo, Result};

/// Posición de `key` entre las claves de la página, teniendo en cuenta el
/// prefijo común.
///
/// Es más sutil de lo que parece: la clave buscada puede no empezar por el
/// prefijo de la página, y en ese caso está fuera del rango de la página
/// entera, no en una posición intermedia.
pub fn search_key(page: &PageRef<'_>, key: &[u8]) -> core::result::Result<usize, usize> {
    let prefix = page.prefix();
    let n = core::cmp::min(prefix.len(), key.len());
    match key[..n].cmp(&prefix[..n]) {
        // La clave diverge del prefijo por debajo: menor que todas las de la página.
        core::cmp::Ordering::Less => Err(0),
        // Diverge por arriba: mayor que todas.
        core::cmp::Ordering::Greater => Err(page.n_slots()),
        core::cmp::Ordering::Equal => {
            if key.len() < prefix.len() {
                // La clave es prefijo estricto del prefijo común, luego menor
                // que cualquier clave completa de la página.
                Err(0)
            } else {
                page.search(&key[prefix.len()..])
            }
        }
    }
}

/// Índice del hijo por el que continúa la búsqueda de `key` en un nodo
/// interno. Devuelve `n_slots` para indicar el hijo del campo `extra`.
fn child_index(page: &PageRef<'_>, key: &[u8]) -> usize {
    match search_key(page, key) {
        // key == s_i, luego key >= s_i: el hijo c_i solo tiene claves < s_i.
        Ok(i) => i + 1,
        // s_{i-1} <= key < s_i: el hijo c_i es el correcto.
        Err(i) => i,
    }
}

fn child_at(page: &PageRef<'_>, i: usize) -> PageNo {
    if i < page.n_slots() { page.child(i) } else { page.extra() }
}

/// Cota de profundidad para el descenso: defensa contra un ciclo de punteros
/// a hijos, ya sea por un fichero corrupto o por un futuro bug de división,
/// borrado o reequilibrado que enlazara un nodo consigo mismo indirectamente.
///
/// El argumento "cada nodo interno rama en al menos dos, luego con páginas de
/// 32 bits la profundidad no puede pasar de 32" — que sostuvo este número
/// cuando solo existía inserción — YA NO VALE por sí solo. Ese argumento
/// asume un árbol balanceado en altura, y `delete_rec` rompe esa suposición a
/// propósito: cuando un nodo interno queda con un solo hijo, lo descarta y
/// empalma ese hijo un nivel más arriba (ver el comentario junto a
/// `entries.is_empty()` en `delete_rec`), pero **no** funde páginas
/// infrautilizadas con sus hermanas — alcance deliberado de la tarea 12,
/// documentado también en el brief. El resultado es que ramas distintas del
/// mismo árbol pueden tener profundidades distintas: unas se quedan cortas
/// donde colapsó una hoja, otras siguen creciendo donde se sigue insertando,
/// y nada las vuelve a igualar.
///
/// Medido, no derivado: construir un árbol y luego someterlo a churn
/// sostenido (borrar y reinsertar sin nunca fundir páginas — exactamente el
/// patrón de una carga de retención con desorden) da una profundidad que
/// crece aproximadamente como `1,65·log₂(n) − 4,5`, bastante por encima del
/// `log₂(n)` de un árbol balanceado. `churn_grows_depth_but_stays_within_the_measured_ceiling`
/// en `delete_invariant_tests` ejercita el mismo fenómeno a menor escala (800
/// claves, 15 000 ciclos) y confirma que la profundidad SÍ crece con el
/// churn, no solo que se queda acotada. Extrapolando esa fórmula al mayor
/// número de páginas direccionable (`n = 2^32`) da profundidad ≈ 50 — todavía
/// por debajo de 64, pero con un margen de solo ~1,3×, no el ~2× que
/// sugería el argumento del árbol balanceado, y sin cota superior demostrada:
/// es una extrapolación de una fórmula empírica, no una prueba. Lo que
/// restauraría la derivación limpia es fundir páginas infrautilizadas con
/// sus hermanas en vez de solo colapsar el caso de un único hijo — trabajo de
/// fase 2, no de esta tarea.
///
/// 128 duplica el margen real medido sin coste apreciable: el único precio es
/// que detectar un ciclo genuino tarda 128 lecturas de página en vez de 64,
/// seguimos hablando de microsegundos, no de una degradación perceptible.
///
/// Esta cuenta también depende de que `put` rechace claves mayores que
/// `page_size / 4` antes de tocar ninguna página (ver el chequeo al
/// principio de `put`): sin ese límite, dividir un nodo interno con pocas
/// entradas puede dejar una mitad sin separador propio, un nodo de un solo
/// hijo que no ramifica y que degenera aún más rápido de lo que ya degenera
/// el colapso sin fusión. Si algún día se toca ese límite, o se añade fusión,
/// hay que revisar este comentario entero, no solo el número.
const MAX_DEPTH: u32 = 128;

/// Localiza la hoja donde vive o viviría `key`, y el camino de nodos internos
/// recorrido desde la raíz. `None` si el árbol está vacío.
pub fn descend(
    src: &impl PageSource,
    root: PageNo,
    key: &[u8],
) -> Result<Option<(PageNo, Vec<PageNo>)>> {
    if root == 0 {
        return Ok(None);
    }
    let mut path = Vec::new();
    let mut current = root;
    let mut depth = 0u32;
    loop {
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(crate::Error::Corrupt {
                page: current,
                kind: crate::CorruptKind::TreeLoop,
            });
        }
        let bytes = src.read_page(current)?;
        let page = PageRef::parse(&bytes, current)?;
        match page.page_type() {
            PageType::Leaf => return Ok(Some((current, path))),
            PageType::Internal => {
                path.push(current);
                current = child_at(&page, child_index(&page, key));
            }
            _ => {
                return Err(crate::Error::Corrupt {
                    page: current,
                    kind: crate::CorruptKind::PageType,
                })
            }
        }
    }
}

/// Valor asociado a `key`, o `None` si no existe.
pub fn get(src: &impl PageSource, root: PageNo, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some((leaf, _)) = descend(src, root, key)? else {
        return Ok(None);
    };
    let bytes = src.read_page(leaf)?;
    let page = PageRef::parse(&bytes, leaf)?;
    match search_key(&page, key) {
        Ok(i) => Ok(Some(page.value(i).to_vec())),
        Err(_) => Ok(None),
    }
}

/// Vista prestada de `entries` que le pasa `emit` a `PageBuilder::build`.
type BorrowedEntries<'a> = [(&'a [u8], CellPayload<'a>)];

/// Resultado de insertar en un subárbol.
enum Insertion {
    /// El subárbol sigue cabiendo en una página; esta es la nueva.
    Updated(PageNo),
    /// El subárbol se dividió. `sep` es la primera clave de `right`.
    Split { left: PageNo, sep: Vec<u8>, right: PageNo },
}

/// Escribe `entries` en una página nueva, o en dos si no caben, liberando la
/// página `old`. Es el único punto del árbol que asigna páginas de nodo, de
/// modo que la política de división vive en un solo sitio.
fn emit(
    tx: &mut WriteTxn,
    old: Option<PageNo>,
    page_type: PageType,
    extra: u32,
    entries: &[(Vec<u8>, CellPayload)],
) -> Result<Insertion> {
    let page_size = tx.page_size();
    let borrowed: Vec<(&[u8], CellPayload)> =
        entries.iter().map(|(k, p)| (k.as_slice(), *p)).collect();

    let mut builder = PageBuilder::new(page_size, page_type);
    builder.set_extra(extra);
    if let Some(bytes) = builder.build(&borrowed) {
        let page_no = tx.alloc()?;
        tx.write_page(page_no, &bytes)?;
        if let Some(old) = old {
            tx.free(old);
        }
        return Ok(Insertion::Updated(page_no));
    }

    // No cabe: partir por la mitad. Con inserción ordenada esto deja la mitad
    // izquierda llena y la derecha con sitio para lo que viene, que es el caso
    // dominante en cargas de log.
    let mid = entries.len() / 2;
    // `mid == 0` solo puede pasar con una única entrada, y solo se llega aquí
    // porque `build` ya falló para ella: no hay nada que partir, la entrada
    // sola no cabe en una página. `put` ya rechaza claves mayores que
    // `page_size / 4` antes de llegar aquí, así que en la práctica esto solo
    // es alcanzable hoy por una hoja de una sola entrada cuyo VALOR es
    // demasiado grande (clave pequeña, valor grande) — las páginas de
    // overflow (tarea 13) lo resolverán moviendo el valor fuera de la celda.
    // El informe debe reflejar qué es lo que no cabe: para una hoja es la
    // celda completa (clave + valor), no solo la clave; para un nodo interno
    // (celda separador + hijo de 4 bytes) sigue siendo la clave, ya cubierta
    // por el límite de `put`, así que esta rama es inalcanzable para
    // internos, pero se deja completa por si ese límite cambiara algún día.
    if mid == 0 {
        let len = match entries[0].1 {
            CellPayload::Value(v) => entries[0].0.len() + v.len(),
            CellPayload::Child(_) => entries[0].0.len(),
        };
        return Err(Error::KeyTooLarge { len: len as u32, max: page_size });
    }

    let (l, r) = borrowed.split_at(mid);
    let sep = entries[mid].0.clone();

    // `entries[j] = (s_j, c_j)` empareja cada separador con su hijo
    // izquierdo, y la cadena completa de hijos es `c_0, c_1, …, c_{n-1},
    // c_n(=extra)`, con `s_i` situado entre `c_i` y `c_{i+1}`. Al promover
    // `sep = s_mid`, la mitad izquierda conserva `l` entera (los pares hasta
    // `c_{mid-1}`) y GANA `c_mid` — el hijo que iba emparejado con el
    // separador que acaba de irse — como su propio `extra`, porque `c_mid`
    // deja de tener separador propio dentro de la izquierda. La mitad
    // derecha empieza en `c_{mid+1}`, no en `c_mid`: la pareja `(sep,
    // c_mid)` no debe quedarse también ahí, o `c_mid` sería inalcanzable (la
    // izquierda nunca lo vuelve a nombrar y el padre solo enruta a la
    // derecha las claves >= `sep`, nunca las que pertenecen a `c_mid`).
    let (left_entries, left_extra, right_entries): (&BorrowedEntries, u32, &BorrowedEntries) =
        match page_type {
            PageType::Internal => {
                let promoted_child = match r[0].1 {
                    CellPayload::Child(c) => c,
                    CellPayload::Value(_) => unreachable!("nodo interno con valor"),
                };
                let right = &r[1..];
                // `right` se queda sin separador propio (un nodo de un solo
                // hijo, que añade profundidad sin ramificar) exactamente
                // cuando la página se divide con solo dos entradas. Con el
                // límite de tamaño de clave que impone `put`
                // (`page_size / 4`), ninguna combinación de separador +
                // hijo llega a ocupar suficiente página como para que dos
                // entradas por sí solas fuercen una división — hacen falta
                // al menos tres para que ambas mitades conserven un
                // separador. Si esto salta, el límite de `put` tiene un
                // agujero: no ensanchar esta comprobación, hay que cerrar
                // ese agujero.
                debug_assert!(
                    !right.is_empty(),
                    "división de nodo interno con la mitad derecha sin separador propio"
                );
                (l, promoted_child, right)
            }
            _ => (l, 0, r),
        };

    let mut lb = PageBuilder::new(page_size, page_type);
    lb.set_extra(left_extra);
    let left_bytes = lb.build(left_entries).ok_or(Error::KeyTooLarge {
        len: entries[0].0.len() as u32,
        max: page_size,
    })?;

    let mut rb = PageBuilder::new(page_size, page_type);
    rb.set_extra(extra);
    let right_bytes = rb.build(right_entries).ok_or(Error::KeyTooLarge {
        len: entries[mid].0.len() as u32,
        max: page_size,
    })?;

    let left = tx.alloc()?;
    tx.write_page(left, &left_bytes)?;
    let right = tx.alloc()?;
    tx.write_page(right, &right_bytes)?;
    if let Some(old) = old {
        tx.free(old);
    }
    Ok(Insertion::Split { left, sep, right })
}

/// Como `descend`, sigue punteros a hijos leídos del disco, así que necesita
/// la misma cota de profundidad: sin ella, un ciclo de páginas corruptas
/// haría que la recursión desbordara la pila en vez de devolver `TreeLoop`.
/// `depth` cuenta la página actual, igual que en `descend` (la raíz entra con
/// `depth == 1`).
fn insert_rec(
    tx: &mut WriteTxn,
    page_no: PageNo,
    key: &[u8],
    value: &[u8],
    depth: u32,
) -> Result<Insertion> {
    if depth > MAX_DEPTH {
        return Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::TreeLoop });
    }
    let bytes = tx.read_page(page_no)?;
    let page = PageRef::parse(&bytes, page_no)?;

    match page.page_type() {
        PageType::Leaf => {
            let mut keys: Vec<Vec<u8>> = Vec::with_capacity(page.n_slots() + 1);
            let mut values: Vec<Vec<u8>> = Vec::with_capacity(page.n_slots() + 1);
            match search_key(&page, key) {
                Ok(i) => {
                    for j in 0..page.n_slots() {
                        keys.push(page.key(j));
                        values.push(if j == i { value.to_vec() } else { page.value(j).to_vec() });
                    }
                }
                Err(i) => {
                    for j in 0..i {
                        keys.push(page.key(j));
                        values.push(page.value(j).to_vec());
                    }
                    keys.push(key.to_vec());
                    values.push(value.to_vec());
                    for j in i..page.n_slots() {
                        keys.push(page.key(j));
                        values.push(page.value(j).to_vec());
                    }
                }
            }
            let entries: Vec<(Vec<u8>, CellPayload)> = keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), CellPayload::Value(v.as_slice())))
                .collect();
            emit(tx, Some(page_no), PageType::Leaf, 0, &entries)
        }

        PageType::Internal => {
            let idx = child_index(&page, key);
            let child = child_at(&page, idx);
            let result = insert_rec(tx, child, key, value, depth + 1)?;

            let mut entries: Vec<(Vec<u8>, CellPayload)> = Vec::with_capacity(page.n_slots() + 2);
            let mut extra = page.extra();

            for j in 0..page.n_slots() {
                entries.push((page.key(j), CellPayload::Child(page.child(j))));
            }

            match result {
                Insertion::Updated(new_child) => {
                    if idx < page.n_slots() {
                        entries[idx].1 = CellPayload::Child(new_child);
                    } else {
                        extra = new_child;
                    }
                }
                Insertion::Split { left, sep, right } => {
                    if idx < page.n_slots() {
                        // c_i se parte: (sep, left) hereda las claves bajas y
                        // (s_i, right) el resto del rango original.
                        entries[idx].1 = CellPayload::Child(right);
                        entries.insert(idx, (sep, CellPayload::Child(left)));
                    } else {
                        // El hijo `extra` se parte: la izquierda pasa a ser
                        // una celda con separador propio y la derecha el nuevo
                        // `extra`.
                        entries.push((sep, CellPayload::Child(left)));
                        extra = right;
                    }
                }
            }

            emit(tx, Some(page_no), PageType::Internal, extra, &entries)
        }

        _ => Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::PageType }),
    }
}

/// Inserta o reemplaza `key`. Devuelve la raíz nueva.
///
/// Si devuelve `Err`, el llamante debe abandonar la transacción (dejar caer
/// el `WriteTxn` sin llamar a `commit`) en vez de reintentar sobre el mismo
/// `tx`. Un fallo a mitad de `insert_rec` puede ocurrir después de que algún
/// nivel más profundo ya haya liberado su página vieja (`emit` libera antes
/// de que el nivel de arriba termine de reconstruirse); hoy eso es seguro
/// solo porque `WriteTxn::drop` restaura la lista de libres al estado previo
/// a la transacción entera cuando esta nunca hizo `commit`. Si esa restauración
/// se optimizara para no deshacer siempre, un `put` fallido dejaría páginas
/// liberadas de más sin que la raíz llegara a apuntar a la reconstrucción
/// parcial — dos dueños o una fuga, según el caso.
pub fn put(tx: &mut WriteTxn, root: PageNo, key: &[u8], value: &[u8]) -> Result<PageNo> {
    let page_size = tx.page_size();
    // Una división de nodo interno promueve un separador y reparte el resto
    // entre dos mitades; para que ambas conserven al menos un separador
    // propio hacen falta al menos tres entradas en total (ver el
    // `debug_assert` en `emit`). Limitar aquí, antes de tocar ninguna
    // página, a `page_size / 4` garantiza ese mínimo: ni siquiera el peor
    // caso (separador + hijo de 4 bytes, sin prefijo compartido) llena una
    // página con menos de cuatro entradas de ese tamaño. Sin este límite,
    // claves grandes degeneran casi toda división interna en un nodo de un
    // solo hijo — profundidad sin ramificar, hasta reventar `MAX_DEPTH` en
    // un árbol perfectamente válido y dejar sus claves ilegibles.
    let max_key = page_size / 4;
    if key.len() as u32 > max_key {
        return Err(Error::KeyTooLarge { len: key.len() as u32, max: max_key });
    }

    if root == 0 {
        let entries = alloc::vec![(key.to_vec(), CellPayload::Value(value))];
        return match emit(tx, None, PageType::Leaf, 0, &entries)? {
            Insertion::Updated(p) => Ok(p),
            Insertion::Split { .. } => unreachable!(
                "emit con una sola entrada nunca divide: cabe (Updated) o falla dentro de \
                 emit (Err), nunca Split"
            ),
        };
    }

    match insert_rec(tx, root, key, value, 1)? {
        Insertion::Updated(p) => Ok(p),
        Insertion::Split { left, sep, right } => {
            // El árbol crece por arriba: raíz nueva con un solo separador.
            let entries = alloc::vec![(sep, CellPayload::Child(left))];
            match emit(tx, None, PageType::Internal, right, &entries)? {
                Insertion::Updated(p) => Ok(p),
                Insertion::Split { .. } => unreachable!("una raíz de una entrada siempre cabe"),
            }
        }
    }
}

/// Resultado de borrar en un subárbol.
enum Removal {
    /// Sin cambios: la clave no estaba. La página original sigue siendo válida.
    Unchanged,
    /// El subárbol sigue existiendo en esta página nueva.
    Updated(PageNo),
    /// El subárbol quedó vacío y su página ya está liberada.
    Gone,
}

/// Como `descend` e `insert_rec`, sigue punteros a hijos leídos del disco, así
/// que necesita la misma cota de profundidad: sin ella, un ciclo de páginas
/// corruptas haría que la recursión desbordara la pila en vez de devolver
/// `TreeLoop`. `depth` cuenta la página actual, igual que en las otras dos (la
/// raíz entra con `depth == 1`).
fn delete_rec(tx: &mut WriteTxn, page_no: PageNo, key: &[u8], depth: u32) -> Result<Removal> {
    if depth > MAX_DEPTH {
        return Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::TreeLoop });
    }
    let bytes = tx.read_page(page_no)?;
    let page = PageRef::parse(&bytes, page_no)?;

    match page.page_type() {
        PageType::Leaf => {
            let Ok(hit) = search_key(&page, key) else {
                return Ok(Removal::Unchanged);
            };
            if page.n_slots() == 1 {
                tx.free(page_no);
                return Ok(Removal::Gone);
            }
            let mut keys = Vec::with_capacity(page.n_slots() - 1);
            let mut values = Vec::with_capacity(page.n_slots() - 1);
            for j in 0..page.n_slots() {
                if j != hit {
                    keys.push(page.key(j));
                    values.push(page.value(j).to_vec());
                }
            }
            let entries: Vec<(Vec<u8>, CellPayload)> = keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), CellPayload::Value(v.as_slice())))
                .collect();
            match emit(tx, Some(page_no), PageType::Leaf, 0, &entries)? {
                Insertion::Updated(p) => Ok(Removal::Updated(p)),
                // Quitar una entrada nunca puede hacer que las restantes dejen
                // de caber donde ya cabían.
                Insertion::Split { .. } => unreachable!("borrar no divide"),
            }
        }

        PageType::Internal => {
            let idx = child_index(&page, key);
            let child = child_at(&page, idx);
            let result = delete_rec(tx, child, key, depth + 1)?;
            if matches!(result, Removal::Unchanged) {
                return Ok(Removal::Unchanged);
            }

            let mut entries: Vec<(Vec<u8>, CellPayload)> = Vec::with_capacity(page.n_slots());
            for j in 0..page.n_slots() {
                entries.push((page.key(j), CellPayload::Child(page.child(j))));
            }
            let mut extra = page.extra();

            match result {
                Removal::Updated(new_child) => {
                    if idx < page.n_slots() {
                        entries[idx].1 = CellPayload::Child(new_child);
                    } else {
                        extra = new_child;
                    }
                }
                Removal::Gone => {
                    if idx < page.n_slots() {
                        entries.remove(idx);
                    } else {
                        // Desaparece el hijo `extra`: el de la última celda
                        // pasa a ocupar su lugar y pierde su separador.
                        //
                        // Solo `None` puede llegar aquí en la práctica —
                        // `entries` se construye dos líneas más arriba
                        // enteramente con `CellPayload::Child`, nunca con
                        // `Value` — pero se hace explícito en vez de agrupar
                        // ambos bajo un `_`: un `_` sugiere que un valor
                        // fuera posible en un nodo interno, cuando en
                        // realidad sería corrupción, no un caso normal más.
                        match entries.pop() {
                            Some((_, CellPayload::Child(c))) => extra = c,
                            Some((_, CellPayload::Value(_))) => {
                                unreachable!("nodo interno con valor: `entries` solo contiene `CellPayload::Child`")
                            }
                            None => {
                                tx.free(page_no);
                                return Ok(Removal::Gone);
                            }
                        }
                    }
                }
                Removal::Unchanged => unreachable!("ya se descartó arriba"),
            }

            // Un nodo interno sin separadores tiene un único hijo: sobra como
            // nivel. Se descarta y el padre apunta directamente al nieto. Así
            // el árbol encoge por arriba sin código específico de raíz.
            if entries.is_empty() {
                tx.free(page_no);
                return Ok(if extra == 0 { Removal::Gone } else { Removal::Updated(extra) });
            }

            match emit(tx, Some(page_no), PageType::Internal, extra, &entries)? {
                Insertion::Updated(p) => Ok(Removal::Updated(p)),
                Insertion::Split { .. } => unreachable!("borrar no divide"),
            }
        }

        _ => Err(Error::Corrupt { page: page_no, kind: crate::CorruptKind::PageType }),
    }
}

/// Borra `key`. Devuelve la raíz nueva y si la clave existía.
pub fn delete(tx: &mut WriteTxn, root: PageNo, key: &[u8]) -> Result<(PageNo, bool)> {
    if root == 0 {
        return Ok((0, false));
    }
    match delete_rec(tx, root, key, 1)? {
        Removal::Unchanged => Ok((root, false)),
        Removal::Updated(p) => Ok((p, true)),
        Removal::Gone => Ok((0, true)),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::page::{CellPayload, PageBuilder, PageType};
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    /// Construye a mano un árbol de dos niveles para probar el descenso sin
    /// depender todavía de `put`.
    fn tree_with_two_leaves(db: &Db) -> PageNo {
        let mut tx = db.begin_write().unwrap();
        let left = tx.alloc().unwrap();
        let right = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let l = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"aa".as_slice(), CellPayload::Value(b"1")),
                (b"bb".as_slice(), CellPayload::Value(b"2")),
            ])
            .unwrap();
        let r = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"mm".as_slice(), CellPayload::Value(b"3")),
                (b"zz".as_slice(), CellPayload::Value(b"4")),
            ])
            .unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(right);
        let rt = rb.build(&[(b"mm".as_slice(), CellPayload::Child(left))]).unwrap();

        tx.write_page(left, &l).unwrap();
        tx.write_page(right, &r).unwrap();
        tx.write_page(root, &rt).unwrap();
        tx.set_root(root);
        tx.commit().unwrap();
        root
    }

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    #[test]
    fn search_key_handles_keys_outside_the_page_prefix() {
        let raw = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"logs/10".as_slice(), CellPayload::Value(b"a")),
                (b"logs/20".as_slice(), CellPayload::Value(b"b")),
            ])
            .unwrap();
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.prefix(), b"logs/");
        assert_eq!(search_key(&p, b"logs/10"), Ok(0));
        assert_eq!(search_key(&p, b"logs/15"), Err(1));
        assert_eq!(search_key(&p, b"aaa"), Err(0), "menor que todo el prefijo");
        assert_eq!(search_key(&p, b"zzz"), Err(2), "mayor que todo el prefijo");
        assert_eq!(search_key(&p, b"log"), Err(0), "prefijo estricto del prefijo");
    }

    #[test]
    fn get_finds_keys_in_both_leaves() {
        let db = db();
        tree_with_two_leaves(&db);
        let r = db.begin_read();
        assert_eq!(get(&r, r.root(), b"aa").unwrap().as_deref(), Some(b"1".as_slice()));
        assert_eq!(get(&r, r.root(), b"bb").unwrap().as_deref(), Some(b"2".as_slice()));
        assert_eq!(get(&r, r.root(), b"mm").unwrap().as_deref(), Some(b"3".as_slice()));
        assert_eq!(get(&r, r.root(), b"zz").unwrap().as_deref(), Some(b"4".as_slice()));
    }

    #[test]
    fn get_returns_none_for_absent_keys() {
        let db = db();
        tree_with_two_leaves(&db);
        let r = db.begin_read();
        for k in [b"a".as_slice(), b"cc", b"nn", b"zzzz"] {
            assert_eq!(get(&r, r.root(), k).unwrap(), None, "clave {k:?}");
        }
    }

    #[test]
    fn get_on_an_empty_tree_returns_none() {
        let db = db();
        let r = db.begin_read();
        assert_eq!(r.root(), 0);
        assert_eq!(get(&r, 0, b"lo que sea").unwrap(), None);
    }

    #[test]
    fn descend_reports_the_path_from_root_to_leaf() {
        let db = db();
        let root = tree_with_two_leaves(&db);
        let r = db.begin_read();
        let (leaf, path) = descend(&r, root, b"zz").unwrap().unwrap();
        assert_eq!(path, alloc::vec![root]);
        assert_ne!(leaf, root);
    }

    /// Dos nodos internos cuyo campo `extra` se apunta el uno al otro: no hay
    /// ninguna hoja alcanzable. Sin una cota de profundidad, `descend`
    /// rebotaría entre ambos para siempre en vez de devolver un error.
    #[test]
    fn descend_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let a = tx.alloc().unwrap();
        let b = tx.alloc().unwrap();

        let mut ab = PageBuilder::new(512, PageType::Internal);
        ab.set_extra(b);
        let pa = ab.build(&[]).unwrap();

        let mut bb = PageBuilder::new(512, PageType::Internal);
        bb.set_extra(a);
        let pb = bb.build(&[]).unwrap();

        tx.write_page(a, &pa).unwrap();
        tx.write_page(b, &pb).unwrap();
        tx.set_root(a);
        tx.commit().unwrap();

        let r = db.begin_read();
        let err = descend(&r, r.root(), b"cualquiera").unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    /// Confirma que la cota de profundidad no molesta a un árbol legítimo de
    /// tres niveles: raíz -> dos nodos internos -> cuatro hojas.
    #[test]
    fn descend_still_reaches_leaves_in_a_three_level_tree() {
        let db = db();
        let mut tx = db.begin_write().unwrap();

        let leaf_a = tx.alloc().unwrap();
        let leaf_b = tx.alloc().unwrap();
        let leaf_c = tx.alloc().unwrap();
        let leaf_d = tx.alloc().unwrap();
        let mid_left = tx.alloc().unwrap();
        let mid_right = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let la = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"aa".as_slice(), CellPayload::Value(b"1")),
                (b"bb".as_slice(), CellPayload::Value(b"2")),
            ])
            .unwrap();
        let lb = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"cc".as_slice(), CellPayload::Value(b"3")),
                (b"dd".as_slice(), CellPayload::Value(b"4")),
            ])
            .unwrap();
        let lc = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"mm".as_slice(), CellPayload::Value(b"5")),
                (b"nn".as_slice(), CellPayload::Value(b"6")),
            ])
            .unwrap();
        let ld = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"tt".as_slice(), CellPayload::Value(b"7")),
                (b"zz".as_slice(), CellPayload::Value(b"8")),
            ])
            .unwrap();

        let mut mlb = PageBuilder::new(512, PageType::Internal);
        mlb.set_extra(leaf_b);
        let ml = mlb.build(&[(b"cc".as_slice(), CellPayload::Child(leaf_a))]).unwrap();

        let mut mrb = PageBuilder::new(512, PageType::Internal);
        mrb.set_extra(leaf_d);
        let mr = mrb.build(&[(b"tt".as_slice(), CellPayload::Child(leaf_c))]).unwrap();

        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(mid_right);
        let rt = rb.build(&[(b"mm".as_slice(), CellPayload::Child(mid_left))]).unwrap();

        tx.write_page(leaf_a, &la).unwrap();
        tx.write_page(leaf_b, &lb).unwrap();
        tx.write_page(leaf_c, &lc).unwrap();
        tx.write_page(leaf_d, &ld).unwrap();
        tx.write_page(mid_left, &ml).unwrap();
        tx.write_page(mid_right, &mr).unwrap();
        tx.write_page(root, &rt).unwrap();
        tx.set_root(root);
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(get(&r, r.root(), b"aa").unwrap().as_deref(), Some(b"1".as_slice()));
        assert_eq!(get(&r, r.root(), b"dd").unwrap().as_deref(), Some(b"4".as_slice()));
        assert_eq!(get(&r, r.root(), b"mm").unwrap().as_deref(), Some(b"5".as_slice()));
        assert_eq!(get(&r, r.root(), b"zz").unwrap().as_deref(), Some(b"8".as_slice()));

        let (leaf, path) = descend(&r, r.root(), b"zz").unwrap().unwrap();
        assert_eq!(leaf, leaf_d);
        assert_eq!(path, alloc::vec![root, mid_right]);
    }
}

#[cfg(all(test, feature = "std"))]
mod put_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    #[test]
    fn insert_into_an_empty_tree_creates_a_leaf_root() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"k", b"v").unwrap();
        assert_ne!(root, 0);
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(b"v".as_slice()));
    }

    #[test]
    fn inserting_the_same_key_twice_replaces_the_value() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"k", b"uno").unwrap();
        let root = put(&mut tx, root, b"k", b"dos").unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(b"dos".as_slice()));
    }

    #[test]
    fn many_inserts_split_the_root_and_stay_readable() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in 0..500u32 {
            let key = alloc::format!("clave/{i:06}");
            root = put(&mut tx, root, key.as_bytes(), &i.to_le_bytes()).unwrap();
        }
        for i in 0..500u32 {
            let key = alloc::format!("clave/{i:06}");
            assert_eq!(
                get(&tx, root, key.as_bytes()).unwrap().as_deref(),
                Some(&i.to_le_bytes()[..]),
                "clave {key}"
            );
        }
    }

    #[test]
    fn descending_insert_order_also_works() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in (0..500u32).rev() {
            let key = alloc::format!("clave/{i:06}");
            root = put(&mut tx, root, key.as_bytes(), b"x").unwrap();
        }
        for i in 0..500u32 {
            let key = alloc::format!("clave/{i:06}");
            assert!(get(&tx, root, key.as_bytes()).unwrap().is_some(), "clave {key}");
        }
    }

    #[test]
    fn a_value_survives_a_commit_and_reopen_of_the_reader() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"persistente", b"si").unwrap();
        tx.set_root(root);
        tx.commit().unwrap();
        let r = db.begin_read();
        assert_eq!(get(&r, r.root(), b"persistente").unwrap().as_deref(), Some(b"si".as_slice()));
    }

    #[test]
    fn the_old_root_is_freed_after_an_update() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let first = put(&mut tx, 0, b"a", b"1").unwrap();
        let second = put(&mut tx, first, b"b", b"2").unwrap();
        assert_ne!(first, second, "copy-on-write: la raíz nueva es otra página");
        tx.set_root(second);
        tx.commit().unwrap();
        // Sin lectores vivos, la página vieja vuelve a estar disponible.
        let mut tx = db.begin_write().unwrap();
        assert_eq!(tx.alloc().unwrap(), first);
        tx.commit().unwrap();
    }

    /// Defecto original descrito en la tarea 11: con `root == 0` una única
    /// clave tan grande que ni siquiera cabe sola en una página nueva hacía
    /// que `emit` calculara `mid = entries.len() / 2 == 0`, y el `assert!`
    /// original entraba en pánico ahí. Tras la revisión de la tarea 11 (punto
    /// "claves grandes degeneran la ramificación"), `put` rechaza esta clave
    /// mucho antes, en su propio chequeo de entrada (`key.len() >
    /// page_size / 4`) — así que esta prueba ya no ejercita el `mid == 0` de
    /// `emit` en concreto, pero sigue siendo la prueba de que una clave
    /// enorme nunca produce pánico, solo `Error`.
    #[test]
    fn a_key_alone_too_big_for_a_page_returns_an_error_instead_of_panicking() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let huge_key = alloc::vec![b'x'; 1000];
        let err = put(&mut tx, 0, &huge_key, b"v").unwrap_err();
        assert!(
            matches!(err, crate::Error::KeyTooLarge { .. }),
            "se esperaba KeyTooLarge, se obtuvo {err:?}"
        );
    }

    /// Mismo espíritu que la prueba anterior, pero por el otro camino que
    /// podía producir `entries.len() == 1` en `emit`: el ascenso de un
    /// separador huérfano al hacer crecer la raíz (`put`, rama
    /// `Insertion::Split` tras `insert_rec`). Con el límite de `page_size / 4`
    /// ya en vigor, cada clave de este bucle (490 bytes con `page_size` 512)
    /// se rechaza en el chequeo de entrada de `put` desde la primera
    /// iteración — la ruta original ya no es alcanzable, y así debe ser. Se
    /// deja la prueba porque sigue demostrando la propiedad que le da nombre:
    /// ninguna combinación de claves grandes debe entrar en pánico.
    #[test]
    fn growing_the_root_with_a_lone_oversized_separator_does_not_panic() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        let prefix = alloc::vec![b'k'; 470];
        for i in 0..30u32 {
            let mut key = prefix.clone();
            key.extend_from_slice(alloc::format!("{i:020}").as_bytes());
            match put(&mut tx, root, &key, b"v") {
                Ok(new_root) => root = new_root,
                Err(crate::Error::KeyTooLarge { .. }) => {} // aceptable: no cabe, pero no entra en pánico
                Err(e) => panic!("error inesperado: {e:?}"),
            }
        }
    }

    /// Regresión de la revisión de la tarea 11: `put` debe rechazar de
    /// entrada, sin tocar ninguna página, cualquier clave mayor que
    /// `page_size / 4` — a 512 bytes de página, 128. Los valores exactos del
    /// error son parte del contrato (`Error` es `PartialEq`), no solo su
    /// variante.
    #[test]
    fn put_rejects_a_key_larger_than_a_quarter_page() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let key = alloc::vec![b'k'; 129];
        let err = put(&mut tx, 0, &key, b"v").unwrap_err();
        assert_eq!(err, crate::Error::KeyTooLarge { len: 129, max: 128 });
    }

    /// El límite es `> page_size / 4`, no `>=`: una clave que ocupa
    /// exactamente el límite se acepta.
    #[test]
    fn put_accepts_a_key_exactly_at_a_quarter_page() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let key = alloc::vec![b'k'; 128];
        let root = put(&mut tx, 0, &key, b"v").unwrap();
        assert_eq!(get(&tx, root, &key).unwrap().as_deref(), Some(b"v".as_slice()));
    }

    /// Regresión del hallazgo 3 de la revisión: cuando `emit` no puede
    /// construir una hoja de una sola entrada porque el VALOR es demasiado
    /// grande (no la clave, que aquí es diminuta y pasa de sobra el chequeo
    /// de `put`), el error debe reportar la longitud de la celda completa
    /// (clave + valor), no solo la de la clave — si no, quien reciba el error
    /// no puede saber qué recortar.
    #[test]
    fn key_too_large_from_an_oversized_value_reports_the_combined_length() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let huge_value = alloc::vec![0u8; 2000];
        let err = put(&mut tx, 0, b"k", &huge_value).unwrap_err();
        match err {
            crate::Error::KeyTooLarge { len, max } => {
                assert_eq!(len, 1 + 2000, "debe reportar clave + valor, no solo la clave");
                assert_eq!(max, 512);
            }
            other => panic!("se esperaba KeyTooLarge, se obtuvo {other:?}"),
        }
    }

    /// Regresión del hallazgo 1 de la revisión: con claves cerca del límite
    /// de `page_size / 4` (128 bytes a 512 de página) y sin prefijo
    /// compartido entre ellas — el peor caso para la ramificación, porque no
    /// hay compresión de prefijo que ayude — el árbol debe seguir siendo
    /// poco profundo. Antes del arreglo, este mismo escenario (con claves de
    /// 250 bytes) daba profundidad 34 a 3.000 claves y profundidad 65 — por
    /// encima de `MAX_DEPTH` — a 95.512, dejando el árbol entero ilegible.
    /// Aquí se afirma una cota real de profundidad, no solo que las
    /// inserciones no fallen.
    #[test]
    fn keys_near_the_limit_keep_the_tree_shallow() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        let n = 3000u32;
        // 127 bytes: justo por debajo del límite de 128, y sin prefijo común
        // entre claves (el sufijo numérico va al principio, no al final), así
        // que la compresión de prefijo de la página no puede disimular un mal
        // factor de ramificación.
        for i in 0..n {
            let mut key = alloc::format!("{i:07}").into_bytes();
            key.resize(127, b'k');
            root = put(&mut tx, root, &key, b"v").unwrap();
        }
        let mut max_depth = 0usize;
        for i in (0..n).step_by(37) {
            let mut key = alloc::format!("{i:07}").into_bytes();
            key.resize(127, b'k');
            let (_, path) = descend(&tx, root, &key).unwrap().unwrap();
            max_depth = max_depth.max(path.len() + 1); // +1: la propia hoja
        }
        assert!(
            max_depth <= 12,
            "profundidad {max_depth} con {n} claves de 127 bytes: la ramificación \
             sigue degenerando"
        );
    }

    /// Cota de profundidad: como `descend`, `insert_rec` sigue punteros a
    /// hijos leídos del disco, así que un ciclo de páginas corruptas debe
    /// devolver `TreeLoop` en vez de desbordar la pila.
    #[test]
    fn insert_rec_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let a = tx.alloc().unwrap();
        let b = tx.alloc().unwrap();

        let mut ab = crate::page::PageBuilder::new(512, PageType::Internal);
        ab.set_extra(b);
        let pa = ab.build(&[]).unwrap();

        let mut bb = crate::page::PageBuilder::new(512, PageType::Internal);
        bb.set_extra(a);
        let pb = bb.build(&[]).unwrap();

        tx.write_page(a, &pa).unwrap();
        tx.write_page(b, &pb).unwrap();

        let err = put(&mut tx, a, b"cualquiera", b"v").unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }
}

/// Pruebas de propiedades más allá de los casos concretos de `put_tests`:
/// orden aleatorio, claves duplicadas fuera de orden, y que las páginas
/// liberadas de verdad se reciclan. `check_invariants` recorre el árbol
/// entero y comprueba que cada separador particiona correctamente a sus
/// hijos y que ninguna página se referencia dos veces — el contrato exacto
/// que debe sostener cualquier secuencia de inserciones.
#[cfg(all(test, feature = "std"))]
mod invariant_tests {
    use super::*;
    use crate::page::PageType;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};
    use alloc::collections::BTreeSet;

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    /// xorshift32, sin dependencias: solo hace falta un orden pseudoaleatorio
    /// reproducible, no calidad criptográfica.
    ///
    /// `pub(crate)`: la reutiliza también `delete_invariant_tests` para sus
    /// propios casos adversariales de borrado.
    pub(crate) struct Rng(pub(crate) u32);
    impl Rng {
        pub(crate) fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
    }

    /// Recorre el árbol entero y comprueba, recursivamente, que cada
    /// separador de cada nodo interno particiona correctamente a sus hijos:
    /// c_i solo tiene claves < s_i, c_n (extra) solo tiene claves >= s_{n-1}.
    /// También acumula las páginas visitadas para detectar aliasing (una
    /// misma página referenciada dos veces en el árbol).
    ///
    /// `pub(crate)`: la reutiliza también `delete_invariant_tests` (tarea
    /// 12), que ejerce el mismo contrato tras secuencias de borrados.
    pub(crate) fn check_invariants(
        tx: &impl PageSource,
        page_no: PageNo,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        visited: &mut BTreeSet<PageNo>,
    ) {
        assert!(visited.insert(page_no), "página {page_no} referenciada dos veces en el árbol");
        let bytes = tx.read_page(page_no).unwrap();
        let page = PageRef::parse(&bytes, page_no).unwrap();
        match page.page_type() {
            PageType::Leaf => {
                let mut prev: Option<Vec<u8>> = None;
                for i in 0..page.n_slots() {
                    let k = page.key(i);
                    if let Some(lo) = lo {
                        assert!(k.as_slice() >= lo, "clave {k:?} por debajo de su cota inferior {lo:?}");
                    }
                    if let Some(hi) = hi {
                        assert!(k.as_slice() < hi, "clave {k:?} por encima de su cota superior {hi:?}");
                    }
                    if let Some(p) = &prev {
                        assert!(p.as_slice() < k.as_slice(), "claves desordenadas en la hoja {page_no}");
                    }
                    prev = Some(k);
                }
            }
            PageType::Internal => {
                let mut prev_sep: Option<Vec<u8>> = None;
                for i in 0..page.n_slots() {
                    let sep = page.key(i);
                    if let Some(p) = &prev_sep {
                        assert!(p.as_slice() < sep.as_slice(), "separadores desordenados en {page_no}");
                    }
                    // Cota inferior real de c_i: el separador anterior
                    // (s_{i-1}), no la cota de toda la página. Sin esto el
                    // chequeo no distinguiría un hijo con claves por debajo
                    // de donde debería (justo el tipo de fallo que produjo
                    // el defecto de `emit` al dividir nodos internos).
                    let child_lo = prev_sep.as_deref().or(lo);
                    let child_hi = Some(sep.as_slice());
                    check_invariants(tx, page.child(i), child_lo, child_hi, visited);
                    prev_sep = Some(sep);
                }
                let extra_lo = prev_sep.as_deref().or(lo);
                check_invariants(tx, page.extra(), extra_lo, hi, visited);
            }
            _ => panic!("tipo de página inesperado en el árbol: {:?}", page.page_type()),
        }
    }

    #[test]
    fn random_order_insertion_is_fully_readable_and_well_formed() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut rng = Rng(0xC0FFEE);
        let n = 2000u32;
        let mut order: Vec<u32> = (0..n).collect();
        // Fisher-Yates con el xorshift local.
        for i in (1..order.len()).rev() {
            let j = (rng.next() as usize) % (i + 1);
            order.swap(i, j);
        }
        let mut root = 0;
        for &i in &order {
            let key = alloc::format!("clave/{i:06}");
            root = put(&mut tx, root, key.as_bytes(), &i.to_le_bytes()).unwrap();
        }
        for i in 0..n {
            let key = alloc::format!("clave/{i:06}");
            assert_eq!(
                get(&tx, root, key.as_bytes()).unwrap().as_deref(),
                Some(&i.to_le_bytes()[..]),
                "clave {key}"
            );
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Igual que la prueba anterior, pero con claves justo por debajo del
    /// límite nuevo de `page_size / 4` (127 de 128, a 512 de página) en vez
    /// de las claves cortas de log. Es el caso que motivó la revisión: con
    /// claves grandes, el árbol tenía un factor de ramificación degenerado
    /// (~1,3) por una división de nodo interno que dejaba una mitad sin
    /// separador propio. `check_invariants` verifica de nuevo la partición
    /// completa (no solo que las 2500 claves se lean), así que cualquier
    /// nodo de un solo hijo que sobreviviera al límite de `put` lo
    /// delataría igual que delató el defecto original.
    #[test]
    fn random_order_insertion_with_near_limit_keys_stays_well_formed() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut rng = Rng(0xA5A5_5A5A);
        let n = 2500u32;
        let mut order: Vec<u32> = (0..n).collect();
        for i in (1..order.len()).rev() {
            let j = (rng.next() as usize) % (i + 1);
            order.swap(i, j);
        }
        let key_for = |i: u32| -> Vec<u8> {
            let mut k = alloc::format!("{i:07}").into_bytes();
            k.resize(127, b'k');
            k
        };
        let mut root = 0;
        for &i in &order {
            let key = key_for(i);
            root = put(&mut tx, root, &key, &i.to_le_bytes()).unwrap();
        }
        for i in 0..n {
            let key = key_for(i);
            assert_eq!(
                get(&tx, root, &key).unwrap().as_deref(),
                Some(&i.to_le_bytes()[..]),
                "clave {i}"
            );
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    #[test]
    fn duplicate_keys_inserted_out_of_order_keep_only_the_latest_value() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut rng = Rng(0x1234_5678);
        let n = 300u32;
        let mut root = 0;
        let mut expected = alloc::collections::BTreeMap::new();
        // Cada clave se inserta varias veces con valores distintos; la
        // última en el orden de inserción (no en el de la clave) debe ganar.
        for _round in 0..5 {
            let mut order: Vec<u32> = (0..n).collect();
            for i in (1..order.len()).rev() {
                let j = (rng.next() as usize) % (i + 1);
                order.swap(i, j);
            }
            for &i in &order {
                let key = alloc::format!("clave/{i:06}");
                let value = alloc::format!("v{}-{}", i, rng.next());
                root = put(&mut tx, root, key.as_bytes(), value.as_bytes()).unwrap();
                expected.insert(i, value);
            }
        }
        for (i, v) in &expected {
            let key = alloc::format!("clave/{i:06}");
            assert_eq!(
                get(&tx, root, key.as_bytes()).unwrap().as_deref(),
                Some(v.as_bytes()),
                "clave {key}"
            );
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Permite conservar un asa al medio tras entregar la `Box<dyn Storage>`
    /// a `Db::create`, para poder medir el tamaño del fichero después.
    /// Calcado del mismo patrón que usa `tx.rs` en sus propias pruebas.
    struct ArcStorage(alloc::sync::Arc<MemStorage>);
    impl crate::Storage for ArcStorage {
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
    }

    /// Repetir puts sobre la MISMA clave, sin lectores vivos, no debe hacer
    /// crecer el fichero sin límite: cada `put` libera la página vieja
    /// (`emit`'s `old`) y `alloc` la recicla de inmediato, porque no hay
    /// ningún lector pinchado en un snapshot más viejo.
    #[test]
    fn repeated_updates_to_one_key_do_not_leak_pages() {
        let storage = alloc::sync::Arc::new(MemStorage::new());
        let db =
            Db::create(alloc::boxed::Box::new(ArcStorage(storage.clone())), Options::default())
                .unwrap();

        let mut tx = db.begin_write().unwrap();
        let mut root = put(&mut tx, 0, b"k", b"0").unwrap();
        tx.set_root(root);
        tx.commit().unwrap();
        let size_after_first_commit = storage.snapshot().len();

        let mut tx = db.begin_write().unwrap();
        for i in 0..2000u32 {
            root = put(&mut tx, root, b"k", &i.to_le_bytes()).unwrap();
        }
        tx.set_root(root);
        tx.commit().unwrap();
        let size_after_2000_updates = storage.snapshot().len();

        let r = db.begin_read();
        assert_eq!(get(&r, r.root(), b"k").unwrap().as_deref(), Some(&1999u32.to_le_bytes()[..]));
        // Una hoja de una sola clave no debería requerir más páginas que al
        // principio, salvo el puñado que ocupa la lista de libres al
        // serializarse: nada que crezca proporcionalmente a 2000 puts.
        assert!(
            size_after_2000_updates <= size_after_first_commit + 4096,
            "el fichero creció de {size_after_first_commit} a {size_after_2000_updates} bytes \
             tras 2000 actualizaciones de la misma clave: páginas filtradas en vez de recicladas"
        );
    }
}

#[cfg(all(test, feature = "std"))]
mod delete_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    #[test]
    fn deleting_a_present_key_removes_it() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"a", b"1").unwrap();
        let root = put(&mut tx, root, b"b", b"2").unwrap();
        let (root, existed) = delete(&mut tx, root, b"a").unwrap();
        assert!(existed);
        assert_eq!(get(&tx, root, b"a").unwrap(), None);
        assert_eq!(get(&tx, root, b"b").unwrap().as_deref(), Some(b"2".as_slice()));
    }

    #[test]
    fn deleting_an_absent_key_reports_false_and_does_not_rewrite() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"a", b"1").unwrap();
        let (new_root, existed) = delete(&mut tx, root, b"z").unwrap();
        assert!(!existed);
        assert_eq!(new_root, root, "sin cambios no hay copy-on-write");
    }

    #[test]
    fn emptying_the_tree_returns_a_null_root() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"solo", b"1").unwrap();
        let (root, existed) = delete(&mut tx, root, b"solo").unwrap();
        assert!(existed);
        assert_eq!(root, 0);
    }

    #[test]
    fn deleting_everything_from_a_deep_tree_collapses_it() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in 0..800u32 {
            root = put(&mut tx, root, alloc::format!("k/{i:06}").as_bytes(), b"v").unwrap();
        }
        for i in 0..800u32 {
            let (r, existed) = delete(&mut tx, root, alloc::format!("k/{i:06}").as_bytes()).unwrap();
            assert!(existed, "clave {i}");
            root = r;
        }
        assert_eq!(root, 0, "el árbol vacío no deja raíz");
    }

    #[test]
    fn the_remaining_keys_survive_interleaved_deletes() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in 0..600u32 {
            root = put(&mut tx, root, alloc::format!("k/{i:06}").as_bytes(), b"v").unwrap();
        }
        for i in (0..600u32).step_by(2) {
            let (r, _) = delete(&mut tx, root, alloc::format!("k/{i:06}").as_bytes()).unwrap();
            root = r;
        }
        for i in 0..600u32 {
            let present = get(&tx, root, alloc::format!("k/{i:06}").as_bytes()).unwrap().is_some();
            assert_eq!(present, i % 2 == 1, "clave {i}");
        }
    }
}

/// Casos adversariales de autorrevisión de la tarea 12, más allá de los del
/// propio informe: el primero y el último elemento de una hoja, una clave
/// igual a un separador interno, el colapso de un nodo interno de dos hijos,
/// el vaciado específico del hijo `extra` sin colapso completo, e
/// intercalado aleatorio a una escala que fuerza varios niveles. Reutiliza
/// `check_invariants` de `invariant_tests`, el mismo contrato que delató los
/// dos defectos reales de la tarea 11.
#[cfg(all(test, feature = "std"))]
mod delete_invariant_tests {
    use super::invariant_tests::{check_invariants, Rng};
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};
    use alloc::collections::BTreeSet;

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    /// Cota de profundidad: como `descend` e `insert_rec`, `delete_rec` sigue
    /// punteros a hijos leídos del disco, así que un ciclo de páginas
    /// corruptas debe devolver `TreeLoop` en vez de desbordar la pila. Mismo
    /// árbol de dos nodos internos con `extra` cruzado que usa la prueba
    /// análoga de `put_tests` para `insert_rec`.
    #[test]
    fn delete_rec_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let a = tx.alloc().unwrap();
        let b = tx.alloc().unwrap();

        let mut ab = PageBuilder::new(512, PageType::Internal);
        ab.set_extra(b);
        let pa = ab.build(&[]).unwrap();

        let mut bb = PageBuilder::new(512, PageType::Internal);
        bb.set_extra(a);
        let pb = bb.build(&[]).unwrap();

        tx.write_page(a, &pa).unwrap();
        tx.write_page(b, &pb).unwrap();

        let err = delete(&mut tx, a, b"cualquiera").unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    #[test]
    fn deleting_the_first_key_of_a_leaf_keeps_the_rest_readable() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for k in [b"aa".as_slice(), b"bb", b"cc", b"dd", b"ee"] {
            root = put(&mut tx, root, k, b"v").unwrap();
        }
        let (root, existed) = delete(&mut tx, root, b"aa").unwrap();
        assert!(existed);
        assert_eq!(get(&tx, root, b"aa").unwrap(), None);
        for k in [b"bb".as_slice(), b"cc", b"dd", b"ee"] {
            assert!(get(&tx, root, k).unwrap().is_some(), "clave {k:?}");
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    #[test]
    fn deleting_the_last_key_of_a_leaf_keeps_the_rest_readable() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for k in [b"aa".as_slice(), b"bb", b"cc", b"dd", b"ee"] {
            root = put(&mut tx, root, k, b"v").unwrap();
        }
        let (root, existed) = delete(&mut tx, root, b"ee").unwrap();
        assert!(existed);
        assert_eq!(get(&tx, root, b"ee").unwrap(), None);
        for k in [b"aa".as_slice(), b"bb", b"cc", b"dd"] {
            assert!(get(&tx, root, k).unwrap().is_some(), "clave {k:?}");
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Encuentra un separador real de un nodo interno: `root.key(0)`. Por
    /// cómo `emit` promueve separadores (siempre una clave que ya existía en
    /// una hoja, nunca un valor sintético), esta clave sigue siendo
    /// recuperable con `get` mientras nadie la haya borrado — condición que
    /// esta prueba comprueba antes de borrarla, para no dar por hecho el
    /// propio mecanismo que quiere ejercitar.
    fn first_root_separator(tx: &WriteTxn, root: PageNo) -> Vec<u8> {
        let bytes = tx.read_page(root).unwrap();
        let page = PageRef::parse(&bytes, root).unwrap();
        assert_eq!(page.page_type(), PageType::Internal, "se esperaba una raíz interna");
        page.key(0)
    }

    #[test]
    fn deleting_a_key_equal_to_an_internal_separator_keeps_routing_correct() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut rng = Rng(0x5EED_5EED);
        let n = 2000u32;
        let mut order: Vec<u32> = (0..n).collect();
        for i in (1..order.len()).rev() {
            let j = (rng.next() as usize) % (i + 1);
            order.swap(i, j);
        }
        let mut root = 0;
        for &i in &order {
            root = put(&mut tx, root, alloc::format!("clave/{i:06}").as_bytes(), b"v").unwrap();
        }

        let sep = first_root_separator(&tx, root);
        assert!(
            get(&tx, root, &sep).unwrap().is_some(),
            "el separador debe ser una clave viva antes de borrarla"
        );

        let (root, existed) = delete(&mut tx, root, &sep).unwrap();
        assert!(existed, "el separador debía existir como clave");
        assert_eq!(get(&tx, root, &sep).unwrap(), None);

        for i in 0..n {
            let key = alloc::format!("clave/{i:06}");
            let expected_present = key.as_bytes() != sep.as_slice();
            let present = get(&tx, root, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, expected_present, "clave {key}");
        }
        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Construye a mano un nodo interno con exactamente dos hijos hoja:
    /// `left` en la celda 0 (separador `mm`) y `right` en `extra`. Da control
    /// total sobre la forma del árbol, en vez de depender de que `put`
    /// produzca por casualidad justo dos hijos.
    fn two_leaf_tree(tx: &mut WriteTxn) -> (PageNo, PageNo, PageNo) {
        let left = tx.alloc().unwrap();
        let right = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let l = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"aa".as_slice(), CellPayload::Value(b"1")),
                (b"bb".as_slice(), CellPayload::Value(b"2")),
            ])
            .unwrap();
        let r = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"mm".as_slice(), CellPayload::Value(b"3")),
                (b"zz".as_slice(), CellPayload::Value(b"4")),
            ])
            .unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(right);
        let rt = rb.build(&[(b"mm".as_slice(), CellPayload::Child(left))]).unwrap();

        tx.write_page(left, &l).unwrap();
        tx.write_page(right, &r).unwrap();
        tx.write_page(root, &rt).unwrap();
        (root, left, right)
    }

    /// Vaciar la hoja izquierda de un nodo interno de dos hijos debe hacer
    /// que la raíz colapse: `entries` queda vacío tras el `remove(idx)` de la
    /// única celda, así que el nodo interno se libera y la raíz pasa a ser
    /// exactamente la hoja superviviente (`right`), sin nivel intermedio.
    #[test]
    fn emptying_a_leaf_collapses_its_two_child_parent() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let (root, _left, right) = two_leaf_tree(&mut tx);

        let (root, existed) = delete(&mut tx, root, b"aa").unwrap();
        assert!(existed);
        assert_ne!(root, 0, "queda una clave, el árbol no debe vaciarse todavía");

        let (root, existed) = delete(&mut tx, root, b"bb").unwrap();
        assert!(existed);
        assert_eq!(
            root, right,
            "la raíz colapsada debe ser exactamente la hoja superviviente, sin nivel intermedio"
        );

        let bytes = tx.read_page(root).unwrap();
        let page = PageRef::parse(&bytes, root).unwrap();
        assert_eq!(page.page_type(), PageType::Leaf, "el nodo interno de un solo hijo debe desaparecer");

        assert_eq!(get(&tx, root, b"aa").unwrap(), None);
        assert_eq!(get(&tx, root, b"bb").unwrap(), None);
        assert_eq!(get(&tx, root, b"mm").unwrap().as_deref(), Some(b"3".as_slice()));
        assert_eq!(get(&tx, root, b"zz").unwrap().as_deref(), Some(b"4".as_slice()));

        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Construye a mano un nodo interno con tres hijos hoja: `left` (celda 0,
    /// separador `gg`), `middle` (celda 1, separador `mm`) y `right` en
    /// `extra`. Con dos separadores de partida, vaciar `right` no puede
    /// colapsar el nodo entero (le queda un separador de sobra): ejercita el
    /// camino de `Removal::Gone` sobre `extra` (`entries.pop()`, pierde su
    /// separador) de forma aislada del colapso completo.
    fn three_leaf_tree(tx: &mut WriteTxn) -> (PageNo, PageNo, PageNo, PageNo) {
        let left = tx.alloc().unwrap();
        let middle = tx.alloc().unwrap();
        let right = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let l = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"aa".as_slice(), CellPayload::Value(b"1")),
                (b"bb".as_slice(), CellPayload::Value(b"2")),
            ])
            .unwrap();
        let m = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"gg".as_slice(), CellPayload::Value(b"3")),
                (b"hh".as_slice(), CellPayload::Value(b"4")),
            ])
            .unwrap();
        let r = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"mm".as_slice(), CellPayload::Value(b"5")),
                (b"zz".as_slice(), CellPayload::Value(b"6")),
            ])
            .unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(right);
        let rt = rb
            .build(&[
                (b"gg".as_slice(), CellPayload::Child(left)),
                (b"mm".as_slice(), CellPayload::Child(middle)),
            ])
            .unwrap();

        tx.write_page(left, &l).unwrap();
        tx.write_page(middle, &m).unwrap();
        tx.write_page(right, &r).unwrap();
        tx.write_page(root, &rt).unwrap();
        (root, left, middle, right)
    }

    #[test]
    fn emptying_the_extra_child_drops_its_separator_without_collapsing() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let (root, left, middle, _right) = three_leaf_tree(&mut tx);

        let (root, existed) = delete(&mut tx, root, b"mm").unwrap();
        assert!(existed);
        let (root, existed) = delete(&mut tx, root, b"zz").unwrap();
        assert!(existed, "la segunda clave de la hoja `extra` también existía");

        let bytes = tx.read_page(root).unwrap();
        let page = PageRef::parse(&bytes, root).unwrap();
        assert_eq!(page.page_type(), PageType::Internal, "queda un separador: no debe colapsar");
        assert_eq!(page.n_slots(), 1, "el separador `mm` de la celda de `middle` debe perderse");
        assert_eq!(page.key(0), b"gg");
        assert_eq!(page.child(0), left, "la hoja `left` no se toca");
        assert_eq!(
            page.extra(),
            middle,
            "`middle` pasa a ocupar el hueco de `extra` y pierde su separador propio"
        );

        assert_eq!(get(&tx, root, b"mm").unwrap(), None);
        assert_eq!(get(&tx, root, b"zz").unwrap(), None);
        assert_eq!(get(&tx, root, b"aa").unwrap().as_deref(), Some(b"1".as_slice()));
        assert_eq!(get(&tx, root, b"bb").unwrap().as_deref(), Some(b"2".as_slice()));
        assert_eq!(get(&tx, root, b"gg").unwrap().as_deref(), Some(b"3".as_slice()));
        assert_eq!(get(&tx, root, b"hh").unwrap().as_deref(), Some(b"4".as_slice()));

        let mut visited = BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }

    /// Intercalado aleatorio de inserciones y borrados sobre un universo fijo
    /// de claves, a una escala (6000 operaciones, 500 claves posibles) que
    /// fuerza divisiones y colapsos repetidos en varios niveles. El modelo de
    /// referencia es un `BTreeSet`; tras cada operación de borrado se
    /// comprueba también que `existed` coincide con la pertenencia al
    /// conjunto esperado, no solo el estado final.
    #[test]
    fn random_interleaved_puts_and_deletes_match_the_expected_set() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut rng = Rng(0x1EAF_5EED);
        let universe = 500u32;
        let mut expected: BTreeSet<u32> = BTreeSet::new();
        let mut root = 0;

        for _ in 0..6000 {
            let i = rng.next() % universe;
            let key = alloc::format!("k/{i:05}");
            if rng.next().is_multiple_of(2) {
                root = put(&mut tx, root, key.as_bytes(), b"v").unwrap();
                expected.insert(i);
            } else {
                let (r, existed) = delete(&mut tx, root, key.as_bytes()).unwrap();
                assert_eq!(existed, expected.contains(&i), "borrado de la clave {i}");
                root = r;
                expected.remove(&i);
            }
        }

        for i in 0..universe {
            let key = alloc::format!("k/{i:05}");
            let present = get(&tx, root, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, expected.contains(&i), "clave {i}");
        }

        if expected.is_empty() {
            assert_eq!(root, 0, "sin claves no debe quedar raíz");
        } else {
            assert_ne!(root, 0);
            let mut visited = BTreeSet::new();
            check_invariants(&tx, root, None, None, &mut visited);
        }
    }

    /// Asa a `MemStorage` que sobrevive a la `Box<dyn Storage>` entregada a
    /// `Db::create`, para poder medir el tamaño del fichero después. Calcado
    /// del mismo patrón que usa `invariant_tests`.
    struct ArcStorage(alloc::sync::Arc<MemStorage>);
    impl crate::Storage for ArcStorage {
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
    }

    /// Borrar TODAS las claves de un árbol y reinsertarlas, varias veces
    /// seguidas, no debe hacer crecer el fichero sin límite: cada página que
    /// `delete_rec` libera (hojas vacías y nodos internos colapsados) debe
    /// quedar disponible para que `put` la recicle en el ciclo siguiente.
    #[test]
    fn deleting_everything_then_reinserting_does_not_leak_pages() {
        let storage = alloc::sync::Arc::new(MemStorage::new());
        let db =
            Db::create(alloc::boxed::Box::new(ArcStorage(storage.clone())), Options::default())
                .unwrap();

        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        let n = 400u32;
        for i in 0..n {
            root = put(&mut tx, root, alloc::format!("k/{i:05}").as_bytes(), b"v").unwrap();
        }
        tx.set_root(root);
        tx.commit().unwrap();
        let size_after_build = storage.snapshot().len();

        for _cycle in 0..3 {
            let mut tx = db.begin_write().unwrap();
            let mut root = tx.root();
            for i in 0..n {
                let (r, existed) =
                    delete(&mut tx, root, alloc::format!("k/{i:05}").as_bytes()).unwrap();
                assert!(existed, "clave {i}");
                root = r;
            }
            assert_eq!(root, 0, "el árbol vacío no deja raíz");
            for i in 0..n {
                root = put(&mut tx, root, alloc::format!("k/{i:05}").as_bytes(), b"v").unwrap();
            }
            tx.set_root(root);
            tx.commit().unwrap();
        }
        let size_after_cycles = storage.snapshot().len();

        assert!(
            size_after_cycles <= size_after_build + 4096,
            "el fichero creció de {size_after_build} a {size_after_cycles} bytes tras ciclos \
             completos de borrado + reinserción: páginas filtradas en vez de recicladas"
        );
    }
}
