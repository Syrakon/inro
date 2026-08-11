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
    /// Cabeza de la cadena física que el `flush` MÁS RECIENTE de este mismo
    /// `Freelist` escribió a disco, o `0` si no hay ninguna pendiente de
    /// reciclar. **Corrección de una fuga descubierta por la tarea 19**
    /// (propiedades contra un oráculo `BTreeMap`, `pages_are_never_lost_or_
    /// double_allocated`): sin este campo, cada `flush` extendía el fichero
    /// con páginas NUEVAS para serializar `groups` — nunca reutilizaba,
    /// para no ser recursivo, ver el comentario de `flush` — pero NADA
    /// volvía a marcar la cadena física que el `flush` ANTERIOR había
    /// escrito como libre: `next_on_disk`/`tail_page` solo se rearman en
    /// `load` (una vez por apertura de proceso), así que dentro de una
    /// misma sesión — sin reabrir la base — cada `flush` sucesivo perdía
    /// para siempre las páginas físicas del `flush` justo anterior. Medido:
    /// +1-2 páginas por cada `commit` que liberase algo, sin cota, para
    /// siempre — con `page_size` de 512 B, treinta `commit` de un solo
    /// `put` hacían crecer el fichero de 4 a 59 páginas.
    ///
    /// El contenido lógico de esas páginas (qué números de página listaban
    /// como libres) NUNCA se duplica: sigue viviendo, sin interrupción, en
    /// `groups`, que `flush` nunca vacía. Solo el CONTENEDOR físico —la
    /// página que hizo falta para volcar `groups` a disco la vez
    /// anterior— es lo que este campo recuerda para poder reciclarlo la
    /// PRÓXIMA vez que haga falta escribir una cadena nueva, exactamente
    /// como `load` ya recicla la cola de una cadena heredada de una sesión
    /// previa (`reclaimed`, más abajo). Ver el comienzo de `flush` para el
    /// recorrido que lo consume.
    ///
    /// Por qué no hace falta guardar también la COLA de esta cadena: el
    /// primer paso de `flush` (`while self.fill_from_disk(pager)? {}`) dejó
    /// `next_on_disk` en `0` antes de que esta cadena se escribiera (es su
    /// postcondición, ver `fill_from_disk`), así que la cadena que `flush`
    /// construye siempre encadena su primera página con `next = 0` —
    /// recorrerla desde la cabeza hasta encontrar `next == 0` basta, sin
    /// necesitar saber de antemano dónde termina.
    ///
    /// **Reciclarla es seguro incluso si una meta más vieja y todavía
    /// "actual" (bajo `Sync::Never`/`Interval`, la última sincronizada
    /// puede ir varios `commit` por detrás) sigue señalando esta cadena
    /// como su `freelist_head`/`freelist_tail`: `Db::open` degrada con
    /// gracia si esa cadena ya no decodifica como lista de libres (ver su
    /// comentario en `tx.rs`), así que este campo puede reciclar tan rápido
    /// como el resto del motor recicla cualquier otra página liberada —
    /// no necesita ninguna gestión de sincronía propia.**
    written_head: PageNo,
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
            written_head: 0,
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
    ///
    /// `next_nonce` (tarea 17) da el contador de nonce para CADA página que
    /// este `flush` escribe — deliberadamente NO `txn`: el mismo defecto
    /// que motivó separar el contador del `txn_id` en
    /// `WriteTxn::write_page` (`tx.rs`) aplica aquí igual, así que `flush`
    /// recibe la misma fuente de contadores que usa el resto de la
    /// transacción (`WriterState::live_counter`, `tx.rs`), en vez de
    /// reinventar la suya.
    ///
    /// **Recicla dentro de la misma sesión la cadena física que el `flush`
    /// ANTERIOR escribió** (tarea 19, hallazgo de las pruebas basadas en
    /// propiedades: sin reciclarla, cada `flush` que libera algo dentro de
    /// la misma apertura del proceso deja huérfano el contenedor físico
    /// del `flush` previo — una fuga real, medida en +1-2 páginas por
    /// commit, sin cota mientras el proceso siga abierto). Ver
    /// `written_head`.
    ///
    /// **Esto puede reciclar más rápido de lo que una meta vieja aún
    /// "vigente" tolera.** Bajo `Sync::Never` o un `Sync::Interval` largo,
    /// la meta que sobrevive a un corte de corriente puede quedarse varias
    /// transacciones atrás de la última escrita, y esa meta antigua
    /// todavía puede señalar como `freelist_head`/`freelist_tail` una
    /// página cuyo contenedor físico este reciclado ya reasignó como
    /// página de datos en una transacción posterior no sincronizada. Sin
    /// más, eso rompía `Db::open` con `Error::Corrupt { kind: PageType }`
    /// al releer esa cadena — confirmado de punta a punta, la primera
    /// versión de este reciclado hacía fallar
    /// `crypto::tests::sync_never_or_long_interval_survives_simulated_power_loss_without_reusing_a_counter`
    /// de forma determinista (`--features encryption` o `--features
    /// aes`). La corrección no vive aquí: `Db::open` (`tx.rs`) degrada con
    /// gracia si `Freelist::load` no puede decodificar la cadena heredada
    /// — trata esa cadena concreta como irrecuperable (una fuga acotada,
    /// solo en ese corte exacto) en vez de negarse a abrir un fichero por
    /// lo demás legible, el mismo criterio que ya aplica la reparación de
    /// cabecera. Ver el comentario de `Db::open` junto a esa llamada.
    pub fn flush(
        &mut self,
        pager: &Pager,
        alloc: &mut dyn FnMut() -> Result<PageNo>,
        txn: TxnId,
        oldest_reader: Option<TxnId>,
        next_nonce: &mut dyn FnMut() -> Result<u64>,
    ) -> Result<(PageNo, PageNo)> {
        // Antes de serializar hay que absorber TODO lo que `load` dejó sin
        // traer (el tramo intermedio entre `head` y `tail`): si no, esas
        // páginas quedarían huérfanas, porque el `tail` que las cierra va
        // a reescribirse con una página nueva y nada más las referenciaría.
        // Es trabajo proporcional al tamaño de la lista, pero ocurre solo
        // una vez por commit, no durante toda la transacción — la garantía
        // de RAM acotada es sobre esto último, no sobre este cierre puntual.
        while self.fill_from_disk(pager)? {}

        // Recicla la cadena física que el `flush` ANTERIOR de este mismo
        // `Freelist` escribió (`written_head`, ver su comentario): sin
        // esto, esas páginas se pierden para siempre en cuanto ESTA llamada
        // escribe una cadena nueva que las reemplaza — es la fuga que
        // encontró la tarea 19. Solo recorre sus NÚMEROS de página vía
        // `next` (`decode_freelist_page` también devuelve las entradas que
        // listaba, aquí descartadas con `_`): ese contenido nunca dejó de
        // vivir en `groups`, así que reincorporarlo aquí lo duplicaría —
        // dos copias de la misma página ofreciéndose a `alloc`, un doble
        // reparto silencioso. Solo el CONTENEDOR físico es basura nueva.
        //
        // Mismo guardián de ciclos que `fill_from_disk`: esta cadena la
        // escribió este mismo `Freelist` en un `flush` anterior, así que un
        // ciclo aquí sería un defecto de esta misma función, no corrupción
        // externa — pero la comprobación es tan barata como la de
        // `fill_from_disk` y sigue el mismo patrón del resto del fichero.
        if self.written_head != 0 {
            let mut p = self.written_head;
            let mut hops: u32 = 0;
            loop {
                self.reclaimed.push_back(p);
                hops += 1;
                if u64::from(hops) > u64::from(pager.file_pages()?) {
                    return Err(Error::Corrupt { page: p, kind: CorruptKind::FreelistLoop });
                }
                let bytes = pager.read(p)?;
                let (_max_txn, _pages, next) = decode_freelist_page(&bytes, p)?;
                if next == p {
                    return Err(Error::Corrupt { page: p, kind: CorruptKind::FreelistLoop });
                }
                if next == 0 {
                    break;
                }
                p = next;
            }
            self.written_head = 0;
        }

        // Las páginas de lista de libres consumidas (por `load`, por el
        // drenaje de arriba, o por el reciclado de la cadena propia justo
        // encima) se incorporan aquí, antes de serializar: es la única vía
        // por la que vuelven a quedar disponibles para `pop`, y hacerlo
        // antes de fijar `capacity`/escribir asegura que este `flush` ya
        // las cuenta.
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

        // Fuente los contenedores que va a hacer falta escribir a partir de
        // páginas YA libres (de transacciones ANTERIORES a esta) en vez de
        // extender el fichero por cada una — tarea 19, segunda ronda de
        // revisión tras el hallazgo de crecimiento cuadrático: sin esto,
        // cada contenedor que un `commit` necesita es una página física
        // NUEVA para siempre, y el reciclado de `written_head` (arriba)
        // convierte el contenedor de HOY en una entrada libre más para el
        // `commit` de MAÑANA, que a su vez necesita otro contenedor para
        // describirla — 300 páginas físicas tras 30 `commit` de un solo
        // `put`, 374 418 tras 500, medido sin este bloque (ver el informe
        // de la tarea 19 y el test `freelist_growth_stays_bounded_over_
        // many_commits` en `tx.rs`).
        //
        // Tiene que vivir AQUÍ, dentro de `flush`, y no en la persona que
        // llama (`WriteTxn::commit`, `tx.rs`): solo aquí, tras
        // `fill_from_disk` y el reciclado de `written_head` justo arriba,
        // se conoce el contenido FINAL de `self.groups` que hace falta
        // serializar — calcularlo fuera trabajaría sobre una fotografía
        // que este mismo `flush` todavía va a cambiar.
        //
        // `self.pop(oldest_reader)` — la misma función que sirve
        // `WriteTxn::alloc`, con la misma cota de lector — es sobre `self`,
        // así que sacar una página de `self.groups` para usarla de
        // contenedor no es la recursión con la que se descartaba
        // reutilizar (comentario antiguo, ya no vigente): no hay ningún
        // cierre externo reentrando en `self.groups` mientras algo más lo
        // recorre, es una secuencia de pasos sobre el mismo `&mut self`,
        // uno detrás de otro.
        //
        // `needed` (páginas que hacen falta) es MONÓTONA NO CRECIENTE
        // mientras se saca de aquí mismo: cada página que se saca quita
        // exactamente una entrada de un grupo, así que `needed` baja como
        // mucho en 1 por cada una (nunca sube) — de ahí que el bucle
        // termine: la diferencia `needed - reused.len()` no puede crecer.
        // Puede haber UN sobrante como mucho (si sacar la última página que
        // parecía hacer falta baja `needed` justo en ese paso) — el
        // segundo bucle, más abajo, lo devuelve antes de escribir nada, así
        // que nunca queda una página fuera de la foto que este mismo
        // `flush` va a dejar en disco (a diferencia de devolverla DESPUÉS
        // de llamar, que es como una versión anterior de este cambio
        // perdía páginas de verdad — confirmado con
        // `pages_are_never_lost_or_double_allocated`, tarea 19).
        let needed = |groups: &VecDeque<Group>| -> usize {
            groups
                .iter()
                .filter(|g| !g.pages.is_empty())
                .map(|g| g.pages.len().div_ceil(capacity))
                .sum()
        };
        let mut reused: alloc::vec::Vec<PageNo> = alloc::vec::Vec::new();
        while reused.len() < needed(&self.groups) {
            match self.pop(oldest_reader) {
                Some(p) => reused.push(p),
                None => break,
            }
        }
        while reused.len() > needed(&self.groups) {
            // Sobrante de la convergencia de arriba (ver su comentario):
            // se devuelve etiquetado con ESTA transacción — tan seguro
            // como cualquier otra página que libera por cualquier otro
            // motivo — y, al pasar por `push`, vuelve a contar para
            // `needed` en la siguiente vuelta del bucle de escritura, más
            // abajo, sin ningún hueco temporal sin cubrir.
            if let Some(p) = reused.pop() {
                self.push(p, txn);
            }
        }
        let mut reused = reused.into_iter();

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
                let page_no = match reused.next() {
                    Some(p) => p,
                    None => alloc()?,
                };
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
                // necesita la clave antes de leer la lista de libres. El
                // contador de nonce sale de `next_nonce`, no de `txn`: ver
                // el comentario de este método.
                let counter = next_nonce()?;
                pager.write_encrypted(page_no, counter, &b)?;

                if tail == 0 {
                    tail = page_no;
                }
                head = page_no;
                next = page_no;
            }
        }

        self.dirty = false;
        // Recuerda la cadena que se acaba de escribir para que el PRÓXIMO
        // `flush` de este mismo `Freelist` pueda reciclarla (ver
        // `written_head`) — `0` si esta llamada no escribió nada (`groups`
        // estaba vacío de punta a punta), que es exactamente el valor que
        // ya deja sin efecto el bloque de reciclado de arriba la próxima
        // vez.
        self.written_head = head;
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

    /// Recorre TODA la cadena de libres en disco desde `head`, sin
    /// materializar un `Freelist` ni mutar nada — a diferencia de `load`,
    /// que solo trae a memoria cabeza y cola (ver su comentario). `visit`
    /// recibe, por cada página física de la cadena, su propio número Y las
    /// páginas libres que enumera.
    ///
    /// Único llamador: `Db::audit_pages` (tarea 19, tras la feature
    /// `audit`), que necesita ver cada página exactamente una vez — tanto
    /// los nodos de la propia cadena (que están "en uso" desde el punto de
    /// vista de la contabilidad de páginas, aunque no formen parte del
    /// árbol) como las páginas que listan (esas sí libres de verdad) — para
    /// poder afirmar que ninguna página del fichero se pierde ni se cuenta
    /// dos veces. Ninguna otra ruta necesita recorrer la cadena entera de
    /// una sentada: `pop_refill` trae solo lo que hace falta, y `flush` ya
    /// absorbe el tramo intermedio con `fill_from_disk` en bucle.
    ///
    /// Puramente de lectura — a diferencia de la reutilización de `flush`
    /// (ver su comentario), esto no cambia qué páginas se ofrecen a
    /// `alloc`, así que no hereda ninguno de sus problemas de durabilidad
    /// (el mismo guardián de lector más antiguo que usa `flush` internamente
    /// ya los cierra, en cualquier caso): es sólo para el diagnóstico de
    /// `audit_pages`.
    ///
    /// Mismo guardián de ciclos que `fill_from_disk` (comentario ahí):
    /// una cadena bien formada visita cada página física del fichero como
    /// mucho una vez, así que más saltos que páginas tiene el fichero solo
    /// puede significar un ciclo en los punteros `next`, no una lista
    /// libre válida por grande que sea.
    #[cfg(feature = "audit")]
    pub(crate) fn walk_chain(
        pager: &Pager,
        head: PageNo,
        mut visit: impl FnMut(PageNo, &VecDeque<PageNo>),
    ) -> Result<()> {
        let mut current = head;
        let mut hops: u64 = 0;
        let limit = u64::from(pager.file_pages()?);
        while current != 0 {
            hops += 1;
            if hops > limit {
                return Err(Error::Corrupt { page: current, kind: CorruptKind::FreelistLoop });
            }
            let bytes = pager.read(current)?;
            let (_max_txn, pages, next) = decode_freelist_page(&bytes, current)?;
            visit(current, &pages);
            if next == current {
                return Err(Error::Corrupt { page: current, kind: CorruptKind::FreelistLoop });
            }
            current = next;
        }
        Ok(())
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
        let mut counter = 0u64;
        let (head, tail) = f
            .flush(
                &p,
                &mut || {
                    next += 1;
                    Ok(next)
                },
                5,
                // `Some(0)`, no `None`: TODO lo que hay aquí lleva `max_txn
                // = 5` (el mismo `txn` de este `flush`), así que con
                // `None` (sin ningún lector, cualquier página es "segura")
                // la reutilización nueva de `flush` (ver su comentario)
                // consumiría del propio contenido bajo prueba como si
                // fueran contenedores — exactamente lo que este test NO
                // quiere: que el orden 100..400 sobreviva intacto al viaje
                // a disco. `0` deja fuera a todo (`0 < 5`), como
                // `WriteTxn::commit` deja fuera siempre las páginas que
                // libera esta misma transacción.
                Some(0),
                &mut || {
                    counter += 1;
                    Ok(counter)
                },
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
        let (head, tail) = f
            .flush(&p, &mut || panic!("no debe asignar"), 5, None, &mut || panic!("no debe pedir contador"))
            .unwrap();
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
        let mut counter = 0u64;
        let (head, tail) = f
            .flush(
                &p,
                &mut || {
                    next += 1;
                    Ok(next)
                },
                5,
                Some(0), // ver el comentario en `survives_a_flush_and_load_roundtrip`
                &mut || {
                    counter += 1;
                    Ok(counter)
                },
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
