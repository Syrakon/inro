use alloc::vec::Vec;

use crate::page::{PageRef, PageType};
use crate::tx::PageSource;
use crate::{PageNo, Result};

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
    loop {
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
}
