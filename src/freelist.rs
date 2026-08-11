use alloc::collections::VecDeque;
use alloc::vec;

use crate::page::{PageRef, PageType, PAGE_HEADER_SIZE};
use crate::pager::Pager;
use crate::{crc32, CorruptKind, Error, PageNo, Result, TxnId};

pub const FREELIST_HEADER: usize = 32;

/// Un grupo de páginas liberadas, con la transacción más reciente que las
/// liberó. Se reutiliza el grupo entero o ninguna de sus páginas.
#[derive(Clone)]
struct Group {
    max_txn: TxnId,
    pages: VecDeque<PageNo>,
    /// Marca el grupo que `load` trajo directamente desde `tail`, sin pasar
    /// por la cadena de `next`. Ver el guard en `pop`.
    is_preloaded_tail: bool,
}

/// Decodifica una página de lista de libres ya leída: valida el tipo y
/// limita `count` al máximo que cabe físicamente en la página. Común a
/// `fill_from_disk` y a la carga directa de `tail` en `load`, para no
/// duplicar (y arriesgar desincronizar) la comprobación de límites.
fn decode_freelist_page(bytes: &[u8], page_no: PageNo) -> Result<(TxnId, VecDeque<PageNo>, PageNo)> {
    let p = PageRef::parse(bytes, page_no)?;
    if p.page_type() != PageType::Freelist {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::PageType });
    }
    let max_txn = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    let count = u16::from_le_bytes(bytes[28..30].try_into().unwrap()) as usize;
    // `count` viene de disco y puede ser hostil o estar corrupto. Sin este
    // límite, el bucle de abajo indexaría más allá de la página (con
    // `count` de hasta 65535, hasta 262140 bytes) y entraría en pánico en
    // vez de devolver un error: la tarea 5 fijó que la entrada corrupta
    // produce `Err(Corrupt)`, nunca un pánico, y `PageRef::parse` no puede
    // protegerlo por sí solo porque `count` no forma parte de su modelo de
    // página — vive en el hueco específico del formato de lista de libres.
    let max_count = bytes.len().saturating_sub(FREELIST_HEADER) / 4;
    if count > max_count {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::CellBounds });
    }
    let mut pages = VecDeque::with_capacity(count);
    for i in 0..count {
        let at = FREELIST_HEADER + 4 * i;
        pages.push_back(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()));
    }
    Ok((max_txn, pages, p.extra()))
}

/// Cola de páginas libres. En memoria solo viven los grupos de los extremos
/// (cabeza y cola); los intermedios se leen bajo demanda al vaciarse la
/// cabeza (`pop_refill`) o, en bloque, al hacer `flush`.
///
/// `Clone` es barato: solo copia los grupos materializados en memoria (a lo
/// sumo cabeza y cola), nunca la cadena entera en disco. Lo usa la capa de
/// transacciones para poder deshacer una transacción de escritura abortada:
/// ver `WriteTxn` en `tx.rs`.
#[derive(Clone)]
pub struct Freelist {
    groups: VecDeque<Group>,
    /// Primera página en disco que aún no se ha traído a `groups`, o 0 si
    /// no queda ninguna: el punto exacto de la cadena hasta el que ya se ha
    /// avanzado. `0` también antes de la primera carga.
    next_on_disk: PageNo,
    /// Página `tail` ya cargada aparte por `load`; sirve para que
    /// `fill_from_disk` sepa cuándo su recorrido hacia la cola ha
    /// alcanzado terreno ya conocido y debe detenerse sin releerla. `0` si
    /// `load` nunca cargó una cola aparte (lista vacía, de una sola
    /// página, o `Freelist` construido con `empty()`).
    tail_page: PageNo,
    /// Páginas de lista de libres ya leídas y consumidas: quedan libres
    /// ellas mismas, pero no se ofrecen a `pop` hasta el próximo `flush`,
    /// que las etiqueta con la transacción que hace ese `flush` (ver
    /// `flush`) — nunca con el `max_txn` histórico del grupo que sostenían,
    /// porque esa página solo se volvió basura ahora, al leerla esta
    /// transacción. Intercalarlas directamente en el grupo que acaban de
    /// producir rompería además el orden FIFO cuando un grupo original
    /// ocupa varias páginas físicas.
    reclaimed: VecDeque<PageNo>,
    /// Saltos dados por `fill_from_disk` en la vida de este `Freelist`:
    /// cota defensiva contra ciclos que no sean el caso trivial de una
    /// página que se referencia a sí misma (ver su comprobación).
    hops: u32,
    dirty: bool,
}

impl Freelist {
    pub fn empty() -> Self {
        Self {
            groups: VecDeque::new(),
            next_on_disk: 0,
            tail_page: 0,
            reclaimed: VecDeque::new(),
            hops: 0,
            dirty: false,
        }
    }

    /// Carga perezosa: solo trae a memoria la página `head` (de donde salen
    /// los `pop`) y, si es distinta, la página `tail` (donde aterrizan los
    /// `push`) — como mucho dos páginas físicas, sin que el consumo de RAM
    /// dependa de cuántas páginas libres haya en total. El tramo
    /// intermedio, si lo hay, se trae bajo demanda a través de
    /// `pop_refill`, o en bloque al hacer `flush` (que necesita absorberlo
    /// entero para no perderlo).
    pub fn load(pager: &Pager, head: PageNo, tail: PageNo) -> Result<Self> {
        let mut f = Self::empty();
        if head == 0 {
            return Ok(f);
        }
        if head != tail {
            f.tail_page = tail;
        }
        f.next_on_disk = head;
        f.fill_from_disk(pager)?;
        if head != tail {
            let bytes = pager.read(tail)?;
            let (max_txn, pages, _next) = decode_freelist_page(&bytes, tail)?;
            f.groups.push_back(Group { max_txn, pages, is_preloaded_tail: true });
            f.reclaimed.push_back(tail);
            f.dirty = true;
        }
        Ok(f)
    }

    /// Trae el siguiente tramo de disco, si queda alguno.
    fn fill_from_disk(&mut self, pager: &Pager) -> Result<bool> {
        if self.next_on_disk == 0 {
            return Ok(false);
        }
        if self.next_on_disk == self.tail_page {
            // La cola ya se cargó aparte en `load`: no hay nada más que
            // traer entre lo último resuelto y ella.
            self.next_on_disk = 0;
            return Ok(false);
        }
        let page_no = self.next_on_disk;

        // Cota defensiva contra ciclos: una cadena bien formada visita cada
        // página física a lo sumo una vez, así que no puede necesitar más
        // saltos que páginas tiene el fichero. Superarla prueba un ciclo
        // aunque no sea el caso trivial de una página que apunta a sí
        // misma (comprobado más abajo aparte, porque ese es más barato de
        // detectar en cuanto se da, sin esperar a agotar la cota).
        self.hops += 1;
        if u64::from(self.hops) > u64::from(pager.file_pages()?) {
            return Err(Error::Corrupt { page: page_no, kind: CorruptKind::FreelistLoop });
        }

        let bytes = pager.read(page_no)?;
        let (max_txn, pages, next) = decode_freelist_page(&bytes, page_no)?;
        if next == page_no {
            return Err(Error::Corrupt { page: page_no, kind: CorruptKind::FreelistLoop });
        }
        self.next_on_disk = next;

        let group = Group { max_txn, pages, is_preloaded_tail: false };
        // Si la cola ya está precargada en algún punto de `groups`, este
        // tramo intermedio debe insertarse justo delante de ella para
        // conservar el orden cronológico: al final podría haber pushes de
        // esta misma transacción, más recientes que la cola.
        match self.groups.iter().position(|g| g.is_preloaded_tail) {
            Some(i) => self.groups.insert(i, group),
            None => self.groups.push_back(group),
        }
        // La página que acaba de leerse queda libre ella misma en cuanto se
        // consume su contenido; ver el campo `reclaimed`.
        self.reclaimed.push_back(page_no);
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
                self.groups.push_back(Group { max_txn: txn, pages, is_preloaded_tail: false });
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
            // Si el grupo al frente es la cola precargada por `load` y
            // todavía queda tramo intermedio sin resolver en disco
            // (`next_on_disk != 0`), no se sirve: sería adelantar
            // contenido más reciente por delante de páginas más antiguas
            // que aún no se han traído. `pop` no tiene `pager` para
            // resolverlo — se lo deja a `pop_refill`.
            if g.is_preloaded_tail && self.next_on_disk != 0 {
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

    /// Igual que `pop`, pero trae tramos de disco si los de memoria se
    /// agotan o si el único grupo servible es la cola precargada con tramo
    /// intermedio aún pendiente (ver el guard de `pop`). Un
    /// `fill_from_disk` que no trae nada nuevo no siempre significa "no
    /// queda nada": puede significar solo que acaba de resolverse ese
    /// tramo pendiente, así que hace falta un último intento de `pop`
    /// antes de rendirse.
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
                return Ok(self.pop(oldest_reader));
            }
        }
    }

    /// Escribe la cola a disco y devuelve `(head, tail)` para la
    /// meta-página. `alloc` asigna páginas nuevas; se le pide una por cada
    /// página física que hace falta para serializar los grupos actuales.
    /// `txn` es la transacción que hace este `flush`: es la que se anota a
    /// las páginas de lista de libres que se reciclan a sí mismas (ver
    /// `reclaimed`), nunca la `max_txn` histórica del grupo que sostenían
    /// — esa página solo se volvió basura ahora, al leerla esta
    /// transacción, no cuando se liberaron las páginas que describía.
    pub fn flush(
        &mut self,
        pager: &Pager,
        alloc: &mut dyn FnMut() -> Result<PageNo>,
        txn: TxnId,
    ) -> Result<(PageNo, PageNo)> {
        // Antes de serializar hay que absorber TODO lo que `load` dejó sin
        // traer (el tramo intermedio entre `head` y `tail`): si no, esas
        // páginas quedarían huérfanas, porque el `tail` que las cierra va
        // a reescribirse con una página nueva y nada más las referenciaría.
        // Es trabajo proporcional al tamaño de la lista, pero ocurre solo
        // una vez por commit, no durante toda la transacción — la garantía
        // de RAM acotada es sobre esto último, no sobre este cierre puntual.
        while self.fill_from_disk(pager)? {}

        // Las páginas de lista de libres consumidas (por `load` o por el
        // drenaje de arriba) se incorporan aquí, antes de serializar: es la
        // única vía por la que vuelven a quedar disponibles para `pop`, y
        // hacerlo antes de fijar `capacity`/escribir asegura que este
        // `flush` ya las cuenta.
        while let Some(page) = self.reclaimed.pop_front() {
            self.push(page, txn);
        }

        // `logical_page_size`, no `geometry().page_size` (tarea 17): las
        // páginas de lista de libres pasan por `write_encrypted` más abajo,
        // igual que las del árbol, así que tienen que construirse con el
        // mismo tamaño lógico que espera esa función — si no, el sellado
        // produciría una página física de tamaño incorrecto (o, sin
        // cifrado, esto coincide exactamente con `geometry().page_size`,
        // sin ningún cambio de comportamiento).
        let page_size = pager.logical_page_size() as usize;
        let capacity = (page_size - FREELIST_HEADER) / 4;

        // Se escribe de la cola hacia la cabeza para poder enlazar cada página
        // con la siguiente, que ya tiene número asignado. Dentro de un mismo
        // grupo, los trozos también se escriben en ese orden (el trozo más
        // reciente primero) para que el trozo más antiguo termine ocupando
        // el extremo `head`: si no, al releer desde `head` se serviría
        // primero el contenido más nuevo del grupo, invirtiendo el orden
        // FIFO con el que se empujó.
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
                // `write_encrypted`, no `write` (tarea 17): sin este cambio,
                // una página de lista de libres se quedaría en claro en un
                // fichero cifrado, y además `Pager::read` (que descifra
                // incondicionalmente si hay clave activa) fallaría al
                // releerla más tarde — ver el comentario de `Db::open` en
                // `tx.rs` sobre por qué el `Pager` provisional también
                // necesita la clave antes de leer la lista de libres.
                pager.write_encrypted(page_no, txn, &b)?;

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

    /// Sin llamador todavía (era parte del API público que pedía el brief
    /// de la tarea 8; queda invisible al análisis de código muerto desde
    /// que `freelist` pasó a `pub(crate)` en la ronda 3 de revisión de la
    /// tarea 16). Se conserva para cuando `commit` quiera saltarse la
    /// escritura de la lista de libres si esta transacción no la tocó.
    #[allow(dead_code)]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Páginas libres materializadas en memoria ahora mismo (no cuenta lo
    /// que sigue sin cargar en disco, referenciado por `next_on_disk`).
    /// Solo tiene llamador en pruebas (`WriteTxn::pages_in_use`, también
    /// `#[cfg(test)]`), así que se gatea igual para no quedar en el binario
    /// de producción.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.groups.iter().map(|g| g.pages.len()).sum()
    }

    /// Sin llamador, ni siquiera en pruebas — a diferencia de `len`, que sí
    /// usa `WriteTxn::pages_in_use`. Se conserva por la pareja natural
    /// `len`/`is_empty` (era parte del API público que pedía el brief de la
    /// tarea 8) y porque clippy la pediría en cuanto alguien llamara a
    /// `len() == 0` en vez de a esta.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    /// Escribe a mano una página de lista de libres cruda, para construir
    /// escenarios (ciclos, `count` fuera de rango) que `flush` nunca
    /// produciría por sí solo.
    fn write_raw_freelist_page(
        p: &Pager,
        page_no: PageNo,
        max_txn: TxnId,
        entries: &[PageNo],
        next: PageNo,
    ) {
        let page_size = p.geometry().page_size as usize;
        let mut b = vec![0u8; page_size];
        b[0] = PageType::Freelist as u8;
        b[4..6].copy_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        b[6..8].copy_from_slice(&(page_size as u16).to_le_bytes());
        b[12..16].copy_from_slice(&next.to_le_bytes());
        b[20..28].copy_from_slice(&max_txn.to_le_bytes());
        b[28..30].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        for (i, &e) in entries.iter().enumerate() {
            let at = FREELIST_HEADER + 4 * i;
            b[at..at + 4].copy_from_slice(&e.to_le_bytes());
        }
        let mut h = crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());
        p.write(page_no, &b).unwrap();
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
            .flush(
                &p,
                &mut || {
                    next += 1;
                    Ok(next)
                },
                5,
            )
            .unwrap();

        let mut g = Freelist::load(&p, head, tail).unwrap();
        for n in 100..400u32 {
            assert_eq!(
                g.pop_refill(&p, None).unwrap(),
                Some(n),
                "orden preservado tras el viaje a disco"
            );
        }
        assert_eq!(g.pop_refill(&p, None).unwrap(), None);
    }

    #[test]
    fn flush_of_an_empty_list_writes_nothing() {
        let p = pager();
        let mut f = Freelist::empty();
        let (head, tail) = f.flush(&p, &mut || panic!("no debe asignar"), 5).unwrap();
        assert_eq!((head, tail), (0, 0));
    }

    #[test]
    fn load_does_not_materialise_the_whole_chain() {
        let p = pager();
        let mut f = Freelist::empty();
        for n in 100..400u32 {
            f.push(n, 5);
        }
        let mut next = 1000u32;
        let (head, tail) = f
            .flush(
                &p,
                &mut || {
                    next += 1;
                    Ok(next)
                },
                5,
            )
            .unwrap();

        let g = Freelist::load(&p, head, tail).unwrap();
        assert!(
            g.len() < 300,
            "load materializó {} páginas: la cadena entera cabe en RAM y no debería",
            g.len()
        );
    }

    #[test]
    fn detects_a_multi_page_cycle_not_just_a_direct_self_loop() {
        let p = pager();
        // Cabeza real (1) con contenido, que apunta a un ciclo entre 2 y 3
        // que nunca llega a ninguna cola: 1 -> 2 -> 3 -> 2 -> 3 -> ...
        write_raw_freelist_page(&p, 1, 5, &[100], 2);
        write_raw_freelist_page(&p, 2, 5, &[200], 3);
        write_raw_freelist_page(&p, 3, 5, &[300], 2);

        let mut f = Freelist::empty();
        f.next_on_disk = 1;
        let mut result = Ok(true);
        for _ in 0..20 {
            result = f.fill_from_disk(&p);
            if result.is_err() {
                break;
            }
        }
        assert!(
            matches!(result, Err(Error::Corrupt { kind: CorruptKind::FreelistLoop, .. })),
            "un ciclo de varias páginas debe cortar con FreelistLoop, no crecer sin límite: {:?}",
            result
        );
    }

    #[test]
    fn rejects_an_oversized_count_instead_of_panicking() {
        let p = pager();
        // Página armada a mano, sin pasar por `write_raw_freelist_page`,
        // con un `count` que desbordaría la página (page_size 512,
        // capacidad real 120 entradas).
        let mut b = vec![0u8; 512];
        b[0] = PageType::Freelist as u8;
        b[4..6].copy_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        b[6..8].copy_from_slice(&512u16.to_le_bytes());
        b[20..28].copy_from_slice(&5u64.to_le_bytes());
        b[28..30].copy_from_slice(&60000u16.to_le_bytes());
        let mut h = crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());
        p.write(1, &b).unwrap();

        let mut f = Freelist::empty();
        f.next_on_disk = 1;
        assert_eq!(
            f.fill_from_disk(&p),
            Err(Error::Corrupt { page: 1, kind: CorruptKind::CellBounds })
        );
    }
}
