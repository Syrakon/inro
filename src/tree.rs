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
/// a hijos, ya sea por un fichero corrupto o por un futuro bug de división o
/// reequilibrado que enlazara un nodo consigo mismo indirectamente.
///
/// Cada nodo interno tiene al menos un separador más el hijo del campo
/// `extra`, luego al menos dos hijos: el árbol es como mínimo binario, y con
/// números de página de 32 bits un árbol legítimo no puede tener más de
/// `2^32` hojas, así que no puede pasar de profundidad 32. 64 duplica ese
/// margen sin dejar de cortar un ciclo en tiempo acotado.
const MAX_DEPTH: u32 = 64;

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
    // sola no cabe en una página. Con una sola entrada su clave se convierte
    // en el prefijo entero de la página (ver `PageBuilder::build`), así que
    // el límite lo marca la clave. Esto es alcanzable hoy con una clave lo
    // bastante grande; las páginas de overflow (tarea 13) lo evitarán para
    // valores grandes con clave pequeña, pero mientras tanto una entrada así
    // debe devolver `Error`, nunca entrar en pánico.
    if mid == 0 {
        return Err(Error::KeyTooLarge { len: entries[0].0.len() as u32, max: page_size });
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
                (l, promoted_child, &r[1..])
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
pub fn put(tx: &mut WriteTxn, root: PageNo, key: &[u8], value: &[u8]) -> Result<PageNo> {
    if root == 0 {
        let entries = alloc::vec![(key.to_vec(), CellPayload::Value(value))];
        return match emit(tx, None, PageType::Leaf, 0, &entries)? {
            Insertion::Updated(p) => Ok(p),
            Insertion::Split { .. } => Err(Error::KeyTooLarge {
                len: (key.len() + value.len()) as u32,
                max: tx.page_size(),
            }),
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

    /// Defecto descrito en la tarea 11: con `root == 0` una única clave
    /// (root == 0) tan grande que ni siquiera cabe sola en una página nueva
    /// hace que `emit` calcule `mid = entries.len() / 2 == 0`. El `assert!`
    /// original entraba en pánico ahí; el motor nunca debe entrar en pánico
    /// con datos de entrada, por grandes que sean — debe devolver `Error`.
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

    /// Mismo defecto, buscado también por el otro camino que puede producir
    /// `entries.len() == 1` en `emit`: el ascenso de un separador huérfano al
    /// hacer crecer la raíz (`put`, rama `Insertion::Split` tras
    /// `insert_rec`). Una hoja con claves que comparten un prefijo larguísimo
    /// se llena, se divide, y el separador promovido puede terminar siendo
    /// una clave tan larga que, sola y sin nada con quien compartir prefijo,
    /// no cabe como raíz interna de una sola entrada. Ninguna combinación
    /// aquí debe entrar en pánico; si no cabe, el único error aceptable es
    /// `KeyTooLarge`.
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
    struct Rng(u32);
    impl Rng {
        fn next(&mut self) -> u32 {
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
    fn check_invariants(
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
