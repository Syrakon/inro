use alloc::collections::VecDeque;
use alloc::vec;

use crate::page::{PageRef, PageType, PAGE_HEADER_SIZE};
use crate::pager::Pager;
use crate::{crc32, PageNo, Result, TxnId};

pub const FREELIST_HEADER: usize = 32;

/// Un grupo de páginas liberadas, con la transacción más reciente que las
/// liberó. Se reutiliza el grupo entero o ninguna de sus páginas.
struct Group {
    max_txn: TxnId,
    pages: VecDeque<PageNo>,
}

/// Cola de páginas libres. En memoria solo viven los grupos de los extremos;
/// los intermedios se leen bajo demanda al vaciarse la cabeza.
pub struct Freelist {
    groups: VecDeque<Group>,
    /// Primera página en disco que aún no se ha traído a `groups`.
    next_on_disk: PageNo,
    /// Páginas de lista de libres ya leídas y consumidas por `fill_from_disk`:
    /// quedan libres ellas mismas, pero no se ofrecen a `pop` hasta el
    /// próximo `flush`. Intercalarlas directamente en el grupo que acaban de
    /// producir (liberado en la misma transacción que las suyas) rompería el
    /// orden FIFO cuando un grupo original ocupa varias páginas físicas: el
    /// número de la página contenedora aparecería antes de que el siguiente
    /// trozo del mismo grupo lógico se hubiera servido.
    reclaimed: VecDeque<(TxnId, PageNo)>,
    dirty: bool,
}

impl Freelist {
    pub fn empty() -> Self {
        Self { groups: VecDeque::new(), next_on_disk: 0, reclaimed: VecDeque::new(), dirty: false }
    }

    /// Carga la cola entera en memoria, siguiendo la cadena desde `head`
    /// hasta agotarla. Es la forma más simple de reconstruir el estado
    /// completo (usada aquí y por el arranque); el acceso incremental
    /// durante una transacción, que no necesita traer más que la cabeza,
    /// pasa por `pop_refill`.
    pub fn load(pager: &Pager, head: PageNo, _tail: PageNo) -> Result<Self> {
        let mut f = Self::empty();
        f.next_on_disk = head;
        while f.fill_from_disk(pager)? {}
        Ok(f)
    }

    /// Trae el siguiente grupo de disco, si queda alguno.
    fn fill_from_disk(&mut self, pager: &Pager) -> Result<bool> {
        if self.next_on_disk == 0 {
            return Ok(false);
        }
        let page_no = self.next_on_disk;
        let bytes = pager.read(page_no)?;
        let p = PageRef::parse(&bytes, page_no)?;
        if p.page_type() != PageType::Freelist {
            return Err(crate::Error::Corrupt {
                page: page_no,
                kind: crate::CorruptKind::PageType,
            });
        }
        let max_txn = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        let count = u16::from_le_bytes(bytes[28..30].try_into().unwrap()) as usize;
        let mut pages = VecDeque::with_capacity(count);
        for i in 0..count {
            let at = FREELIST_HEADER + 4 * i;
            pages.push_back(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()));
        }

        let next = p.extra();
        if next == self.next_on_disk {
            return Err(crate::Error::Corrupt {
                page: page_no,
                kind: crate::CorruptKind::FreelistLoop,
            });
        }
        self.next_on_disk = next;
        self.groups.push_back(Group { max_txn, pages });
        // La página que acaba de leerse queda libre ella misma en cuanto se
        // consume su contenido; ver el campo `reclaimed`.
        self.reclaimed.push_back((max_txn, page_no));
        self.dirty = true;
        Ok(true)
    }

    /// Registra `page` como liberada por la transacción `txn`.
    pub fn push(&mut self, page: PageNo, txn: TxnId) {
        self.dirty = true;
        match self.groups.back_mut() {
            Some(g) if g.max_txn == txn => g.pages.push_back(page),
            _ => {
                let mut pages = VecDeque::new();
                pages.push_back(page);
                self.groups.push_back(Group { max_txn: txn, pages });
            }
        }
    }

    /// Toma la página libre más antigua reutilizable. `oldest_reader` es el
    /// snapshot del lector vivo más antiguo, o `None` si no hay ninguno.
    pub fn pop(&mut self, oldest_reader: Option<TxnId>) -> Option<PageNo> {
        loop {
            let g = self.groups.front()?;
            if let Some(m) = oldest_reader
                && m < g.max_txn
            {
                return None;
            }
            let g = self.groups.front_mut()?;
            if let Some(p) = g.pages.pop_front() {
                self.dirty = true;
                return Some(p);
            }
            self.groups.pop_front();
        }
    }

    /// Igual que `pop`, pero trae grupos de disco si los de memoria se agotan.
    pub fn pop_refill(
        &mut self,
        pager: &Pager,
        oldest_reader: Option<TxnId>,
    ) -> Result<Option<PageNo>> {
        loop {
            if let Some(p) = self.pop(oldest_reader) {
                return Ok(Some(p));
            }
            if !self.fill_from_disk(pager)? {
                return Ok(None);
            }
        }
    }

    /// Escribe la cola a disco y devuelve `(head, tail)` para la meta-página.
    /// `alloc` asigna páginas nuevas; se le pide una por cada página física
    /// que hace falta para serializar los grupos actuales.
    pub fn flush(
        &mut self,
        pager: &Pager,
        alloc: &mut dyn FnMut() -> Result<PageNo>,
    ) -> Result<(PageNo, PageNo)> {
        // Las páginas de lista de libres consumidas desde el último `load`
        // se incorporan aquí, antes de serializar: es la única vía por la
        // que vuelven a quedar disponibles para `pop`, y hacerlo antes de
        // fijar `capacity`/escribir asegura que este `flush` ya las cuenta.
        while let Some((txn, page)) = self.reclaimed.pop_front() {
            self.push(page, txn);
        }

        let page_size = pager.geometry().page_size as usize;
        let capacity = (page_size - FREELIST_HEADER) / 4;

        // Se escribe de la cola hacia la cabeza para poder enlazar cada página
        // con la siguiente, que ya tiene número asignado. Dentro de un mismo
        // grupo, los trozos también se escriben en ese orden (el último
        // trozo empujado, o sea el más reciente, primero) para que el trozo
        // más antiguo termine ocupando el extremo `head`: si no, al releer
        // desde `head` se serviría primero el contenido más nuevo del grupo,
        // invirtiendo el orden FIFO con el que se empujó.
        let mut next: PageNo = self.next_on_disk;
        let mut tail: PageNo = 0;
        let mut head: PageNo = 0;

        for group in self.groups.iter().rev() {
            let flat: alloc::vec::Vec<PageNo> = group.pages.iter().copied().collect();
            for chunk in flat.chunks(capacity).rev() {
                let page_no = alloc()?;
                let mut b = vec![0u8; page_size];
                b[0] = PageType::Freelist as u8;
                b[12..16].copy_from_slice(&next.to_le_bytes());
                b[20..28].copy_from_slice(&group.max_txn.to_le_bytes());
                b[28..30].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
                b[4..6].copy_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
                b[6..8].copy_from_slice(&(page_size as u16).to_le_bytes());
                for (i, &p) in chunk.iter().enumerate() {
                    let at = FREELIST_HEADER + 4 * i;
                    b[at..at + 4].copy_from_slice(&p.to_le_bytes());
                }
                let mut h = crc32::Hasher::new();
                h.update(&b[..8]);
                h.update(&b[12..]);
                b[8..12].copy_from_slice(&h.finish().to_le_bytes());
                pager.write(page_no, &b)?;

                if tail == 0 {
                    tail = page_no;
                }
                head = page_no;
                next = page_no;
            }
        }

        self.dirty = false;
        Ok((head, tail))
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::header::{Geometry, FORMAT_MAJOR};
    use crate::pager::Pager;
    use crate::storage::MemStorage;

    fn pager() -> Pager {
        let g = Geometry {
            page_size: 512, format_major: FORMAT_MAJOR, format_minor: 0, flags: 0,
            db_id: [0; 16], created_unix: 0, meta_a_page: 1, meta_b_page: 8,
        };
        Pager::new(Box::new(MemStorage::new()), g, 8)
    }

    #[test]
    fn a_page_freed_by_txn_n_is_not_reusable_while_an_older_reader_lives() {
        let mut f = Freelist::empty();
        f.push(50, 7);
        assert_eq!(f.pop(Some(6)), None, "hay un lector en el snapshot 6");
        assert_eq!(f.pop(Some(7)), Some(50), "el lector más antiguo ya no la ve");
    }

    #[test]
    fn without_readers_everything_is_reusable() {
        let mut f = Freelist::empty();
        f.push(50, 7);
        f.push(51, 9);
        assert_eq!(f.pop(None), Some(50));
        assert_eq!(f.pop(None), Some(51));
        assert_eq!(f.pop(None), None);
    }

    #[test]
    fn pops_oldest_first() {
        let mut f = Freelist::empty();
        f.push(10, 1);
        f.push(11, 2);
        f.push(12, 3);
        assert_eq!(f.pop(None), Some(10));
        assert_eq!(f.pop(None), Some(11));
    }

    #[test]
    fn survives_a_flush_and_load_roundtrip() {
        let p = pager();
        let mut f = Freelist::empty();
        for n in 100..400u32 {
            f.push(n, 5);
        }
        let mut next = 1000u32;
        let (head, tail) = f
            .flush(&p, &mut || {
                next += 1;
                Ok(next)
            })
            .unwrap();

        let mut g = Freelist::load(&p, head, tail).unwrap();
        for n in 100..400u32 {
            assert_eq!(g.pop(None), Some(n), "orden preservado tras el viaje a disco");
        }
        assert_eq!(g.pop(None), None);
    }

    #[test]
    fn flush_of_an_empty_list_writes_nothing() {
        let p = pager();
        let mut f = Freelist::empty();
        let (head, tail) = f.flush(&p, &mut || panic!("no debe asignar")).unwrap();
        assert_eq!((head, tail), (0, 0));
    }
}
