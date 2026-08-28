use crate::{crc32, varint, CorruptKind, Error, PageNo, Result};

pub const PAGE_HEADER_SIZE: usize = 20;

/// Longitud de valor imposible en línea: marca una referencia de overflow.
/// Una celda de hoja normal guarda `[len_valor varint][bytes]`; una de
/// overflow guarda `[OVERFLOW_MARKER varint][len_real u64][primera página
/// u32]`. Un valor de longitud cero real se distingue sin ambigüedad porque
/// `0 != OVERFLOW_MARKER`: la celda termina justo tras el varint, como
/// cualquier otro valor en línea.
///
/// Es una marca, no una deducción a partir del tamaño de la celda: deducirlo
/// crearía una dependencia circular, porque `cell_end` necesitaría saber si
/// la celda es de overflow para calcular su tamaño, y saberlo requeriría ya
/// conocer `cell_end`. Cabe en diez bytes de varint, pero solo aparece en
/// celdas de overflow, que son minoría, así que el coste es irrelevante.
const OVERFLOW_MARKER: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    Leaf = 0,
    Internal = 1,
    Overflow = 2,
    Freelist = 3,
}

impl PageType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => PageType::Leaf,
            1 => PageType::Internal,
            2 => PageType::Overflow,
            3 => PageType::Freelist,
            _ => return None,
        })
    }
}

/// Todo lo que `PageRef::parse` DERIVA de la cabecera de una página después
/// de comprobarla: los campos que los accesores usan sin volver a validar.
/// Separado de los bytes a propósito, y es lo único que hace posible
/// recordar "estos bytes ya pasaron por `parse`" sin quedarse con un
/// préstamo de ellos — ver `ValidPage`, más abajo.
///
/// `Copy` y unas pocas decenas de bytes: copiarlo cuesta menos que releer
/// la cabecera, y muchísimo menos que revalidarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    page_type: PageType,
    flags: u8,
    n_slots: usize,
    prefix_len: usize,
    slots_at: usize,
}

/// Vista de solo lectura sobre los bytes de una página ya validada.
/// `parse` comprueba el CRC y toda la estructura una vez; a partir de ahí los
/// accesores no vuelven a validar y no pueden salirse de la página.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRef<'a> {
    bytes: &'a [u8],
    layout: Layout,
}

/// Bit de `flags` (byte 1 de la cabecera) que, solo en páginas internas,
/// marca "todos mis hijos DIRECTOS son hojas sin ninguna entrada de
/// overflow, así que pueden liberarse sin abrirlos". Tarea 15, ronda de
/// revisión 1: ver `children_plain` más abajo y el comentario de
/// `free_subtree` en `tree.rs` para la corrección que este bit cierra.
///
/// **El coste real de perderlo, medido — tarea 15, ronda de revisión 2,
/// hallazgo 3.** Este bit es MONÓTONO por nodo: una vez que se pone a
/// `false` (un hijo deja de ser plano — se vuelve interno, o gana una
/// entrada de overflow), solo una RECONSTRUCCIÓN de ese nodo puede
/// volver a ponerlo a `true`, y ninguna operación de hoy reconstruye un
/// nodo SOLO para reevaluar el bit — únicamente lo toca de pasada
/// `insert_rec`/`delete_rec`/`delete_range_rec` cuando de todos modos
/// tenían que tocar ese nodo por otra razón (ver el comentario de
/// `Insertion` en `tree.rs`). Borrar la entrada que causó el overflow NO
/// restaura el bit: el nodo se reconstruye igual, pero el nuevo valor de
/// `children_plain` sigue calculándose a partir del viejo (`viejo &&
/// plano_el_hijo_tocado`), y "viejo" ya era `false`.
///
/// Medido de punta a punta sobre 20.000 entradas
/// (`an_overflow_value_ever_written_costs_its_node_the_fast_path_permanently`,
/// `tree.rs`, guarda estos números como regresión permanente, con margen):
///
/// | Árbol | Páginas leídas — tercio medio | Páginas leídas — poda completa |
/// |---|---|---|
/// | recién sembrado | 50 | 80 |
/// | 4000 ciclos de borrar-y-reinsertar (sin overflow) | 50 | — |
/// | UNA hoja que alguna vez tuvo un valor de overflow (ya borrado) | 71 | — |
/// | TODAS las hojas tuvieron alguna vez un valor de overflow (ya borrados) | 230 | 651 |
///
/// El churn puro (borrar y reinsertar valores normales) no envenena el
/// árbol — la fila de 4000 ciclos es la buena noticia, y por eso merece
/// quedar registrada, no solo el caso malo. Pero un valor grande escrito
/// UNA VEZ bajo un nodo de nivel 2, aunque se borre después, le cuesta a
/// ESE nodo su camino rápido para siempre: 4,6× más lecturas en el peor
/// caso medido sobre un tercio del árbol, más de 8× sobre la poda
/// completa. Una base que alguna vez ha guardado valores grandes deja de
/// tener la garantía de coste de la poda diaria — el motivo de ser de
/// esta tarea — para los nodos que llegaron a tocar esos valores,
/// permanentemente.
///
/// Lo único que restaura el bit es reconstruir el nodo desde cero
/// verificando de verdad sus hijos — fusión de páginas infrautilizadas
/// (ya pendiente desde la tarea 12 por la deriva de profundidad que
/// documenta `MAX_DEPTH` en `tree.rs`) sería el mecanismo natural para
/// hacerlo de paso. Nada de lo que existe hoy lo hace: trabajo de fase 2,
/// no de esta tarea.
const CHILDREN_PLAIN_FLAG: u8 = 0x01;

/// `prev < next` en orden lexicográfico, byte a byte.
///
/// Es exactamente lo que hace `<[u8] as Ord>`, escrito a mano por una razón
/// medida: la comparación de la biblioteca baja a una llamada a `memcmp`, y
/// los sufijos de una página comprimida por prefijo son de unos pocos bytes
/// —dos o tres en la carga real del motor—, así que la llamada cuesta más
/// que la comparación. Sobre una hoja de 4096 B con 142 slots, sustituirla
/// bajó el bucle de validación de 1,399 a 1,270 µs, un 9 %.
///
/// La equivalencia con el operador no se argumenta, se prueba:
/// `manual_suffix_order_matches_the_slice_operator` compara las dos formas
/// sobre todos los pares de un conjunto que incluye el vacío, prefijos,
/// iguales y longitudes distintas.
#[inline]
/// Anexa una celda al final del array de slots de una página YA construida,
/// mutándola en el sitio: sin copiar sus entradas a `Vec`s, sin volver a
/// codificar las que ya estaban y sin pedir una página nueva. Devuelve
/// `false`, **sin haber tocado un solo byte**, si el caso no es anexable, y
/// entonces el llamante reconstruye por el camino de siempre.
///
/// # Por qué solo anexar, y no insertar en cualquier posición
///
/// `parse` exige que los offsets de celda BAJEN según sube la clave (ver el
/// bloque de "dirección del solape" ahí): la celda de la entrada `i` va
/// pegada justo antes de la de `i - 1`. Una inserción por el medio tendría
/// que desplazar todas las celdas posteriores para mantener ese invariante,
/// que es reconstruir la página con otro nombre. Anexar al final es el único
/// caso en el que la celda nueva cabe donde toca —en el hueco libre, que es
/// exactamente el sitio de menor offset— sin mover ninguna otra.
///
/// El slot nuevo tampoco desplaza nada: va en `free_start`, que es el primer
/// byte tras el último slot y ya es hueco libre.
///
/// # Condiciones
///
/// Todas se comprueban aquí, y todas devuelven `false` en vez de entrar en
/// pánico o corromper:
///
/// 1. La página tiene cabecera y al menos una entrada. Con cero entradas el
///    prefijo común sería la clave entera y `build` produciría una página
///    distinta de la que saldría de aquí; no vale la pena el caso.
/// 2. `free_start` cuadra con `n_slots` y `prefix_len` — la misma
///    comprobación redundante que hace `parse`, aquí como red antes de
///    escribir.
/// 3. La clave nueva empieza por el prefijo común actual. Si no, el prefijo
///    se acortaría y habría que recolocar `slots_at` y todas las celdas: eso
///    es reconstruir.
/// 4. El sufijo nuevo es estrictamente mayor que el último — el mismo orden
///    que `parse` verifica. El llamante ya lo sabe por su búsqueda, pero
///    escribir en el sitio sin comprobarlo dejaría una página corrupta si
///    algún día esa búsqueda cambiara.
/// 5. La celda y su slot caben en el hueco libre.
///
/// El CRC se recalcula al final, sobre la página entera: es el único trabajo
/// que sigue siendo proporcional al tamaño de página.
pub fn append_in_place(bytes: &mut [u8], key: &[u8], payload: CellPayload) -> bool {
    if bytes.len() < PAGE_HEADER_SIZE {
        return false;
    }
    let n_slots = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
    let free_start = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
    let cell_start = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
    let prefix_len = u16::from_le_bytes(bytes[16..18].try_into().unwrap()) as usize;
    let slots_at = PAGE_HEADER_SIZE + prefix_len;

    // Condiciones 1 y 2.
    if n_slots == 0
        || slots_at + 2 * n_slots != free_start
        || cell_start > bytes.len()
        || cell_start < free_start
    {
        return false;
    }

    // Condición 3.
    if key.len() < prefix_len || key[..prefix_len] != bytes[PAGE_HEADER_SIZE..slots_at] {
        return false;
    }
    let suffix = &key[prefix_len..];

    // Condición 4: decodificar el sufijo del último slot y compararlo.
    let last_off =
        u16::from_le_bytes(bytes[free_start - 2..free_start].try_into().unwrap()) as usize;
    let Some((last_suffix_len, n_last)) = varint::read(&bytes[last_off..]) else {
        return false;
    };
    let last_from = last_off + n_last;
    let Some(last_suffix) = bytes.get(last_from..last_from + last_suffix_len as usize) else {
        return false;
    };
    if !ascending(last_suffix, suffix) {
        return false;
    }

    // Condición 5. Mismas longitudes que calcula `PageBuilder::build`.
    let mut tmp = [0u8; 10];
    let n1 = varint::write(&mut tmp, suffix.len() as u64);
    let body_len = match payload {
        CellPayload::Value(v) => varint::len(v.len() as u64) + v.len(),
        CellPayload::Overflow { .. } => varint::len(OVERFLOW_MARKER) + 12,
        CellPayload::Child(_) => 4,
    };
    let cell_len = n1 + suffix.len() + body_len;
    let Some(new_off) = cell_start.checked_sub(cell_len) else {
        return false;
    };
    // `+ 2` por el slot nuevo, que se escribe en `free_start`.
    if new_off < free_start + 2 {
        return false;
    }

    // A partir de aquí ya no puede fallar nada: se escribe.
    let mut at = new_off;
    bytes[at..at + n1].copy_from_slice(&tmp[..n1]);
    at += n1;
    bytes[at..at + suffix.len()].copy_from_slice(suffix);
    at += suffix.len();
    match payload {
        CellPayload::Value(v) => {
            let n2 = varint::write(&mut tmp, v.len() as u64);
            bytes[at..at + n2].copy_from_slice(&tmp[..n2]);
            at += n2;
            bytes[at..at + v.len()].copy_from_slice(v);
        }
        CellPayload::Overflow { len, first } => {
            let n2 = varint::write(&mut tmp, OVERFLOW_MARKER);
            bytes[at..at + n2].copy_from_slice(&tmp[..n2]);
            at += n2;
            bytes[at..at + 8].copy_from_slice(&len.to_le_bytes());
            at += 8;
            bytes[at..at + 4].copy_from_slice(&first.to_le_bytes());
        }
        CellPayload::Child(c) => {
            bytes[at..at + 4].copy_from_slice(&c.to_le_bytes());
        }
    }
    bytes[free_start..free_start + 2].copy_from_slice(&(new_off as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&((n_slots + 1) as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&((free_start + 2) as u16).to_le_bytes());
    bytes[6..8].copy_from_slice(&(new_off as u16).to_le_bytes());

    let mut h = crc32::Hasher::new();
    h.update(&bytes[..8]);
    h.update(&bytes[12..]);
    bytes[8..12].copy_from_slice(&h.finish().to_le_bytes());
    true
}

fn ascending(prev: &[u8], next: &[u8]) -> bool {
    for (a, b) in prev.iter().zip(next.iter()) {
        if a != b {
            return a < b;
        }
    }
    prev.len() < next.len()
}

impl<'a> PageRef<'a> {
    pub fn parse(bytes: &'a [u8], page_no: PageNo) -> Result<Self> {
        let corrupt = |kind| Error::Corrupt { page: page_no, kind };

        if bytes.len() < PAGE_HEADER_SIZE {
            return Err(corrupt(CorruptKind::CellBounds));
        }

        // El CRC va primero: sin él, cualquier campo leído a continuación
        // podría ser basura interpretada como estructura válida.
        let stored = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mut h = crc32::Hasher::new();
        h.update(&bytes[..8]);
        h.update(&bytes[12..]);
        if stored != h.finish() {
            return Err(corrupt(CorruptKind::Checksum));
        }

        let page_type = PageType::from_u8(bytes[0]).ok_or_else(|| corrupt(CorruptKind::PageType))?;
        let flags = bytes[1];
        let n_slots = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let free_start = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
        let cell_start = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
        let prefix_len = u16::from_le_bytes(bytes[16..18].try_into().unwrap()) as usize;

        let slots_at = PAGE_HEADER_SIZE + prefix_len;
        let expected_free_start = slots_at + 2 * n_slots;
        // `free_start` es redundante: se deriva de `n_slots` y `prefix_len`.
        // Se almacena precisamente para poder contrastarlo y detectar
        // corrupción que el CRC no vería si afectase a varios campos a la vez.
        if free_start != expected_free_start
            || expected_free_start > bytes.len()
            || cell_start > bytes.len()
            || cell_start < expected_free_start
        {
            return Err(corrupt(CorruptKind::CellBounds));
        }

        let page =
            Self { bytes, layout: Layout { page_type, flags, n_slots, prefix_len, slots_at } };

        // Cada slot debe apuntar dentro del área de celdas, cada celda debe
        // decodificarse entera dentro de la página, los sufijos deben quedar
        // en orden ASCENDENTE ESTRICTO de clave (claves iguales en una misma
        // página también son inválidas) y las celdas no deben solaparse.
        //
        // Dirección del solape: `PageBuilder::build` (más abajo) hace crecer
        // las celdas desde el FINAL de la página hacia el hueco libre —
        // `cursor` arranca en `page_size` y decrece con cada entrada. La
        // entrada 0 (la clave más pequeña, porque `build` exige entradas ya
        // ordenadas) es la PRIMERA en reservar hueco, así que se queda pegada
        // al final de la página; cada entrada siguiente, con clave mayor,
        // ocupa el hueco justo ANTES de la anterior, a un offset MENOR. En
        // una página válida, entonces, `slot(i)` es estrictamente MENOR que
        // `slot(i-1)`: los offsets bajan según sube la clave. Dos celdas
        // vecinas no se solapan si la celda `i` (offset menor, crece hacia
        // arriba) termina antes de donde empieza la celda `i-1` (offset
        // mayor): `cell_end(slot(i)) <= slot(i-1)`. Comprobado contra
        // `parses_a_well_formed_page` y `built_leaf_page_reads_back_identical`
        // más abajo, donde la igualdad se da exactamente (celdas contiguas,
        // sin hueco) — de ahí el `<=`, no `<`.
        // **Ni una comprobación menos que antes, la mitad del trabajo.** El
        // bucle recorre el array de slots como bytes (`chunks_exact(2)`)
        // en vez de indexarlo por posición: `free_start` ya está
        // contrastado contra `slots_at + 2 * n_slots` cuatro líneas más
        // arriba, así que ese rango es exactamente el array de slots, y
        // recorrerlo así le ahorra al compilador una comprobación de
        // límites por slot que no podía eliminar sola.
        //
        // Y pide el sufijo y el final de la celda de UNA vez
        // (`cell_suffix_and_end`) en lugar de llamar a `cell_end` y a
        // `suffix` por separado: las dos empiezan decodificando el MISMO
        // varint de longitud de sufijo y `suffix` volvía además a leer el
        // slot del array. Medido, ese trabajo duplicado era la mayor parte
        // de lo que costaba el bucle.
        let mut prev: Option<(usize, &[u8])> = None;
        for slot in bytes[slots_at..free_start].chunks_exact(2) {
            let off = u16::from_le_bytes(slot.try_into().unwrap()) as usize;
            if off < cell_start || off >= bytes.len() {
                return Err(corrupt(CorruptKind::SlotOffset));
            }
            let (suffix, end) = page
                .cell_suffix_and_end(off)
                .ok_or_else(|| corrupt(CorruptKind::CellBounds))?;
            if let Some((prev_off, prev_suffix)) = prev {
                if !ascending(prev_suffix, suffix) {
                    return Err(corrupt(CorruptKind::SlotOffset));
                }
                if end > prev_off {
                    return Err(corrupt(CorruptKind::CellBounds));
                }
            }
            prev = Some((off, suffix));
        }

        Ok(page)
    }

    fn slot(&self, i: usize) -> usize {
        let at = self.layout.slots_at + 2 * i;
        u16::from_le_bytes(self.bytes[at..at + 2].try_into().unwrap()) as usize
    }

    /// Fin de la celda que empieza en `off`, o `None` si no cabe en la página.
    /// Las celdas de hoja e internas comparten prefijo de formato:
    /// `[len_sufijo varint][sufijo]` seguido de la carga propia del tipo.
    fn cell_end(&self, off: usize) -> Option<usize> {
        let b = self.bytes.get(off..)?;
        let (suffix_len, n1) = varint::read(b)?;
        let after_suffix = off.checked_add(n1)?.checked_add(suffix_len as usize)?;
        self.cell_end_after_suffix(after_suffix)
    }

    /// Sufijo Y final de la celda que empieza en `off`, decodificando una
    /// sola vez el varint de longitud de sufijo del que dependen los dos.
    /// Exactamente las mismas comprobaciones que `cell_end` —es la misma
    /// función con el sufijo devuelto de paso—, más el rango del propio
    /// sufijo, que `cell_end_after_suffix` ya implica pero que aquí se pide
    /// explícitamente para que la ausencia de pánico se vea sin depender de
    /// ese razonamiento.
    fn cell_suffix_and_end(&self, off: usize) -> Option<(&'a [u8], usize)> {
        let b = self.bytes.get(off..)?;
        let (suffix_len, n1) = varint::read(b)?;
        let at = off.checked_add(n1)?;
        let after_suffix = at.checked_add(suffix_len as usize)?;
        let end = self.cell_end_after_suffix(after_suffix)?;
        Some((self.bytes.get(at..after_suffix)?, end))
    }

    /// La mitad de `cell_end` que depende del tipo de página, a partir del
    /// offset donde termina el sufijo. Compartida por `cell_end` y
    /// `cell_suffix_and_end` para que no haya dos copias de estas
    /// comprobaciones que puedan divergir.
    fn cell_end_after_suffix(&self, after_suffix: usize) -> Option<usize> {
        match self.layout.page_type {
            PageType::Leaf => {
                let b = self.bytes.get(after_suffix..)?;
                let (value_len, n2) = varint::read(b)?;
                let body = after_suffix.checked_add(n2)?;
                let end = if value_len == OVERFLOW_MARKER {
                    // `[len_real u64][primera página u32]`, no el valor
                    // inline: ver `OVERFLOW_MARKER`.
                    body.checked_add(12)?
                } else {
                    body.checked_add(value_len as usize)?
                };
                (end <= self.bytes.len()).then_some(end)
            }
            PageType::Internal => {
                let end = after_suffix.checked_add(4)?;
                (end <= self.bytes.len()).then_some(end)
            }
            _ => (after_suffix <= self.bytes.len()).then_some(after_suffix),
        }
    }

    pub fn page_type(&self) -> PageType {
        self.layout.page_type
    }

    /// Solo tiene sentido en páginas internas (`PageType::Internal`): `true`
    /// significa que TODOS los hijos DIRECTOS de esta página son hojas sin
    /// ninguna entrada de overflow, así que `free_subtree` (`tree.rs`) puede
    /// liberarlos volcando sus números de página a la lista de libres sin
    /// abrirlos. `false` no afirma lo contrario con certeza — es la lectura
    /// conservadora por defecto de cualquier página construida antes de
    /// que se supiera con seguridad que sus hijos eran así (ver
    /// `PageBuilder::set_children_plain` y su comentario) — solo dice "no
    /// hay garantía, compruébalo". En páginas hoja el bit está siempre a
    /// cero (`PageBuilder` nunca lo pone en una hoja) y no significa nada.
    pub fn children_plain(&self) -> bool {
        self.layout.flags & CHILDREN_PLAIN_FLAG != 0
    }

    pub fn n_slots(&self) -> usize {
        self.layout.n_slots
    }

    pub fn prefix(&self) -> &'a [u8] {
        &self.bytes[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + self.layout.prefix_len]
    }

    /// En nodos internos, el hijo más a la derecha. En páginas de overflow,
    /// la siguiente página de la cadena (cero si es la última). Cero en el
    /// resto de tipos.
    pub fn extra(&self) -> u32 {
        u32::from_le_bytes(self.bytes[12..16].try_into().unwrap())
    }

    /// Bytes completos de la celda `i`, tal como se almacenaron.
    pub fn cell(&self, i: usize) -> &'a [u8] {
        let off = self.slot(i);
        let end = self.cell_end(off).expect("validado en parse");
        &self.bytes[off..end]
    }

    /// Sufijo de clave de la celda `i`, sin el prefijo común de la página.
    pub fn suffix(&self, i: usize) -> &'a [u8] {
        let off = self.slot(i);
        let (len, n) = varint::read(&self.bytes[off..]).expect("validado en parse");
        &self.bytes[off + n..off + n + len as usize]
    }

    /// Busca `suffix` entre los sufijos de la página. `Ok(i)` si está en la
    /// posición `i`; `Err(i)` con el punto de inserción si no está.
    ///
    /// El llamante debe haber quitado antes el prefijo de la página a la clave
    /// buscada. Comparar sufijos equivale a comparar claves completas porque
    /// todas comparten exactamente el mismo prefijo.
    pub fn search(&self, suffix: &[u8]) -> core::result::Result<usize, usize> {
        let (mut lo, mut hi) = (0usize, self.layout.n_slots);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.suffix(mid).cmp(suffix) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Ok(mid),
            }
        }
        Err(lo)
    }

    /// Valor de la celda `i`, asumiendo que está en línea. Solo válido en
    /// páginas hoja, y solo en celdas que no son de overflow: sobre una
    /// celda de overflow, `value_len` es `OVERFLOW_MARKER` y este método
    /// tomaría un slice de ese tamaño (`usize::MAX` en una máquina de 32
    /// bits o menos, `u64::MAX as usize` en una de 64), saliéndose de la
    /// página y entrando en pánico. Privado a propósito, no solo documentado:
    /// una nota en el comentario no impide que código futuro dentro del
    /// crate lo llame sobre una hoja que mezcle celdas en línea y de
    /// overflow (posible desde la tarea 13) y provoque justo ese pánico.
    /// `#[cfg(test)]` porque, cerrado ese hueco, su único uso que queda es
    /// el de las pruebas de este módulo — todo el código del árbol usa
    /// `leaf_value`, que sí distingue los dos casos; mantenerlo fuera de
    /// pruebas sería superficie muerta en el binario de producción.
    #[cfg(test)]
    fn value(&self, i: usize) -> &'a [u8] {
        let off = self.slot(i);
        let (suffix_len, n1) = varint::read(&self.bytes[off..]).expect("validado en parse");
        let after = off + n1 + suffix_len as usize;
        let (value_len, n2) = varint::read(&self.bytes[after..]).expect("validado en parse");
        &self.bytes[after + n2..after + n2 + value_len as usize]
    }

    /// Valor de la celda `i`, distinguiendo si está en línea o es una
    /// referencia a una cadena de páginas de overflow. Es la variante segura
    /// de `value` para hojas que puedan contener celdas de overflow.
    pub fn leaf_value(&self, i: usize) -> LeafValue<'a> {
        let off = self.slot(i);
        let (suffix_len, n1) = varint::read(&self.bytes[off..]).expect("validado en parse");
        let after = off + n1 + suffix_len as usize;
        let (value_len, n2) = varint::read(&self.bytes[after..]).expect("validado en parse");
        let body = after + n2;
        if value_len == OVERFLOW_MARKER {
            let len = u64::from_le_bytes(self.bytes[body..body + 8].try_into().unwrap());
            let first = u32::from_le_bytes(self.bytes[body + 8..body + 12].try_into().unwrap());
            LeafValue::Overflow { len, first }
        } else {
            LeafValue::Inline(&self.bytes[body..body + value_len as usize])
        }
    }

    /// Hijo izquierdo del separador `i`. Solo válido en nodos internos.
    pub fn child(&self, i: usize) -> PageNo {
        let off = self.slot(i);
        let (suffix_len, n1) = varint::read(&self.bytes[off..]).expect("validado en parse");
        let at = off + n1 + suffix_len as usize;
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }

    /// Clave completa de la celda `i`, reconstruida como prefijo más sufijo.
    /// Asigna: usar solo donde haga falta la clave entera, no en el descenso.
    pub fn key(&self, i: usize) -> alloc::vec::Vec<u8> {
        let mut k = alloc::vec::Vec::with_capacity(self.prefix().len() + self.suffix(i).len());
        k.extend_from_slice(self.prefix());
        k.extend_from_slice(self.suffix(i));
        k
    }

    /// Reconstruye la vista sobre bytes que YA pasaron por `parse`, sin
    /// volver a validar nada.
    ///
    /// **Privada al módulo, no `pub(crate)`, y esa privacidad es la mitad
    /// del argumento de corrección.** La precondición —`layout` tiene que
    /// haber salido de un `parse` sobre exactamente ESTOS bytes— no la puede
    /// comprobar la función; quien la rompa produce un `PageRef` cuyos
    /// accesores creen estar dentro de la página y no lo están, y los
    /// `.expect("validado en parse")` de arriba pasan de ser triviales a ser
    /// pánicos en producción. Al no ser alcanzable fuera de este fichero, el
    /// único llamante posible es `ValidPage::page` (más abajo), que mantiene
    /// las dos mitades JUNTAS en una estructura y por tanto no puede
    /// desparejarlas.
    #[cfg(feature = "std")]
    fn from_validated(bytes: &'a [u8], layout: Layout) -> Self {
        Self { bytes, layout }
    }
}

/// Una página validada que se lleva sus bytes consigo: el resultado de
/// `parse` en una forma que se puede GUARDAR, devolver de una función o
/// meter en una caché, cosa que `PageRef` —que solo presta— no puede.
///
/// **Por qué esto no debilita la validación.** `PageRef::parse` sigue siendo
/// el único sitio donde se comprueba un CRC o un slot: `ValidPage::parse` lo
/// llama y se queda con el `Layout` que produjo. Lo que hace que el par
/// (bytes, layout) no pueda desparejarse nunca es que los bytes viven detrás
/// de un `Arc<[u8]>`, que es **inmutable por construcción**: el crate no usa
/// `Arc::get_mut` ni `Arc::make_mut` en ninguna parte, así que un búfer que
/// entra en un `Arc` no vuelve a cambiar mientras alguien lo sostenga. Un
/// `ValidPage` vivo es, entonces, la afirmación "estos bytes concretos
/// pasaron `parse`", y esa afirmación no caduca: no hay forma de que los
/// bytes muten por debajo de quien lo sostiene.
///
/// Lo que SÍ puede pasar —y ya pasaba antes de este tipo, palabra por
/// palabra— es que el fichero cambie bajo ese número de página mientras
/// alguien sostiene la versión vieja. Sostener `Arc<[u8]>` tenía exactamente
/// la misma propiedad. Que nadie lea una página que el escritor va a
/// reescribir no lo garantiza esta capa, sino la de transacciones (lista de
/// libres más tabla de lectores); ver la documentación de `Pager::write`.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct ValidPage {
    bytes: alloc::sync::Arc<[u8]>,
    layout: Layout,
}

#[cfg(feature = "std")]
impl ValidPage {
    /// Valida `bytes` como la página número `page_no` y se queda con el
    /// resultado. Mismos errores, mismas comprobaciones y mismo coste que
    /// `PageRef::parse`: es una llamada a `PageRef::parse`.
    pub fn parse(bytes: alloc::sync::Arc<[u8]>, page_no: PageNo) -> Result<Self> {
        let layout = PageRef::parse(&bytes, page_no)?.layout;
        Ok(Self { bytes, layout })
    }

    /// Vista prestada de la página, sin revalidar. Barata: dos punteros y
    /// una copia del `Layout`.
    pub fn page(&self) -> PageRef<'_> {
        PageRef::from_validated(&self.bytes, self.layout)
    }

    /// Bytes crudos de la página ya validada, para los pocos sitios que leen
    /// campos que no forman parte del modelo de `PageRef` — el hueco propio
    /// del formato de la lista de libres (`freelist::decode_freelist_page`)
    /// es el único hoy.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Valor de una celda de hoja: en línea, o referencia a una cadena de
/// páginas de overflow (tarea 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafValue<'a> {
    Inline(&'a [u8]),
    Overflow { len: u64, first: PageNo },
}

/// Carga útil de una celda, según el tipo de página.
#[derive(Debug, Clone, Copy)]
pub enum CellPayload<'a> {
    Value(&'a [u8]),
    /// Valor de hoja que ya vive en una cadena de overflow: la celda solo
    /// guarda la referencia (`len`, `first`), no los bytes.
    Overflow { len: u64, first: PageNo },
    Child(PageNo),
}

/// Prefijo común más largo de un conjunto de claves ya ordenado.
/// Con las claves ordenadas basta comparar la primera y la última.
pub fn common_prefix(keys: &[&[u8]]) -> usize {
    let (Some(first), Some(last)) = (keys.first(), keys.last()) else {
        return 0;
    };
    first
        .iter()
        .zip(last.iter())
        .take_while(|(a, b)| a == b)
        .count()
}

pub struct PageBuilder {
    page_size: usize,
    page_type: PageType,
    extra: u32,
    flags: u8,
}

impl PageBuilder {
    pub fn new(page_size: u32, page_type: PageType) -> Self {
        Self { page_size: page_size as usize, page_type, extra: 0, flags: 0 }
    }

    pub fn set_extra(&mut self, extra: u32) -> &mut Self {
        self.extra = extra;
        self
    }

    /// Marca, en una página INTERNA, si todos sus hijos directos son hojas
    /// planas (sin overflow) — ver `PageRef::children_plain`. Sin efecto en
    /// hojas: `build` solo copia `self.flags` tal cual al byte 1 de la
    /// cabecera, así que llamar a esto sobre un `PageBuilder` de tipo `Leaf`
    /// no rompe nada, pero tampoco significa nada — el llamante (`emit`,
    /// `tree.rs`) solo lo invoca para construcciones internas.
    pub fn set_children_plain(&mut self, plain: bool) -> &mut Self {
        if plain {
            self.flags |= CHILDREN_PLAIN_FLAG;
        } else {
            self.flags &= !CHILDREN_PLAIN_FLAG;
        }
        self
    }

    /// Construye la página a partir de entradas **ya ordenadas por clave**.
    /// Devuelve `None` si no caben: es la señal de dividir, no un error.
    ///
    /// Precondición no verificada en release: `entries` debe venir ordenado
    /// por clave y sin duplicados. Si no lo está, `&key[prefix_len..]` puede
    /// entrar en pánico más abajo con un slice fuera de rango, porque
    /// `prefix_len` se deriva solo de la primera y la última clave (ver
    /// `common_prefix`) y una clave intermedia puede ser más corta que ese
    /// prefijo.
    pub fn build(&self, entries: &[(&[u8], CellPayload)]) -> Option<alloc::vec::Vec<u8>> {
        debug_assert!(
            entries.windows(2).all(|w| w[0].0 < w[1].0),
            "las entradas de PageBuilder::build deben venir ordenadas por clave y sin \
             duplicados: la entrada en el índice {} no es mayor que la anterior",
            entries.windows(2).position(|w| w[0].0 >= w[1].0).map_or(0, |i| i + 1)
        );

        let keys: alloc::vec::Vec<&[u8]> = entries.iter().map(|(k, _)| *k).collect();
        let prefix_len = common_prefix(&keys);

        let mut b = alloc::vec![0u8; self.page_size];
        let slots_at = PAGE_HEADER_SIZE + prefix_len;
        let free_start = slots_at + 2 * entries.len();
        // `free_start`, `cell_start` y cada offset de slot se serializan en un
        // campo de 2 bytes (u16): el mayor valor representable es 65535.
        // `PageBuilder` no conoce `header::MAX_PAGE_SIZE` (32 KB desde que se
        // eligió justo para evitar esto) — esta comprobación es defensa en
        // profundidad: sin ella, una página vacía a `page_size == 65536`
        // dejaría `cursor` en exactamente 65536 y `cursor as u16` truncaría
        // en silencio a 0, produciendo una página que `parse` rechazaría.
        if free_start > self.page_size || free_start > u16::MAX as usize {
            return None;
        }
        if let Some(first) = keys.first() {
            b[PAGE_HEADER_SIZE..slots_at].copy_from_slice(&first[..prefix_len]);
        }

        // Las celdas crecen desde el final de la página hacia el hueco libre.
        let mut cursor = self.page_size;
        let mut tmp = [0u8; 10];
        for (i, (key, payload)) in entries.iter().enumerate() {
            let suffix = &key[prefix_len..];
            let n1 = varint::write(&mut tmp, suffix.len() as u64);
            let body_len = match payload {
                CellPayload::Value(v) => varint::len(v.len() as u64) + v.len(),
                // `varint::len(OVERFLOW_MARKER)` es siempre 10 (u64::MAX
                // necesita los 10 bytes completos de un varint LEB128), más
                // los 12 bytes de `[len_real u64][primera página u32]`.
                CellPayload::Overflow { .. } => varint::len(OVERFLOW_MARKER) + 12,
                CellPayload::Child(_) => 4,
            };
            let cell_len = n1 + suffix.len() + body_len;
            if cursor.checked_sub(cell_len)? < free_start {
                return None;
            }
            cursor -= cell_len;

            let mut at = cursor;
            b[at..at + n1].copy_from_slice(&tmp[..n1]);
            at += n1;
            b[at..at + suffix.len()].copy_from_slice(suffix);
            at += suffix.len();
            match payload {
                CellPayload::Value(v) => {
                    let n2 = varint::write(&mut tmp, v.len() as u64);
                    b[at..at + n2].copy_from_slice(&tmp[..n2]);
                    at += n2;
                    b[at..at + v.len()].copy_from_slice(v);
                }
                CellPayload::Overflow { len, first } => {
                    let n2 = varint::write(&mut tmp, OVERFLOW_MARKER);
                    b[at..at + n2].copy_from_slice(&tmp[..n2]);
                    at += n2;
                    b[at..at + 8].copy_from_slice(&len.to_le_bytes());
                    at += 8;
                    b[at..at + 4].copy_from_slice(&first.to_le_bytes());
                }
                CellPayload::Child(c) => {
                    b[at..at + 4].copy_from_slice(&c.to_le_bytes());
                }
            }
            let slot = slots_at + 2 * i;
            b[slot..slot + 2].copy_from_slice(&(cursor as u16).to_le_bytes());
        }

        // Mismo límite de representación que `free_start`, aplicado a
        // `cursor` una vez terminado el bucle: es el valor que se guardará
        // como `cell_start`.
        if cursor > u16::MAX as usize {
            return None;
        }

        b[0] = self.page_type as u8;
        b[1] = self.flags;
        b[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        b[4..6].copy_from_slice(&(free_start as u16).to_le_bytes());
        b[6..8].copy_from_slice(&(cursor as u16).to_le_bytes());
        b[12..16].copy_from_slice(&self.extra.to_le_bytes());
        b[16..18].copy_from_slice(&(prefix_len as u16).to_le_bytes());

        let mut h = crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());

        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye una página cruda a mano para probar el lector sin depender
    /// todavía de `PageBuilder`.
    fn raw_leaf(prefix: &[u8], cells: &[&[u8]]) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0u8; 512];
        b[0] = PageType::Leaf as u8;
        b[2..4].copy_from_slice(&(cells.len() as u16).to_le_bytes());
        b[16..18].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
        b[20..20 + prefix.len()].copy_from_slice(prefix);
        let slots_at = 20 + prefix.len();
        let free_start = slots_at + 2 * cells.len();
        b[4..6].copy_from_slice(&(free_start as u16).to_le_bytes());
        let mut cursor = 512;
        for (i, cell) in cells.iter().enumerate() {
            cursor -= cell.len();
            b[cursor..cursor + cell.len()].copy_from_slice(cell);
            b[slots_at + 2 * i..slots_at + 2 * i + 2]
                .copy_from_slice(&(cursor as u16).to_le_bytes());
        }
        b[6..8].copy_from_slice(&(cursor as u16).to_le_bytes());
        let crc = {
            let mut h = crate::crc32::Hasher::new();
            h.update(&b[..8]);
            h.update(&b[12..]);
            h.finish()
        };
        b[8..12].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Celda de hoja: [len_sufijo varint][sufijo][len_valor varint][valor]
    fn leaf_cell(suffix: &[u8], value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut c = alloc::vec::Vec::new();
        let mut tmp = [0u8; 10];
        let n = crate::varint::write(&mut tmp, suffix.len() as u64);
        c.extend_from_slice(&tmp[..n]);
        c.extend_from_slice(suffix);
        let n = crate::varint::write(&mut tmp, value.len() as u64);
        c.extend_from_slice(&tmp[..n]);
        c.extend_from_slice(value);
        c
    }

    #[test]
    fn parses_a_well_formed_page() {
        let cells = [leaf_cell(b"aa", b"1"), leaf_cell(b"bb", b"2")];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let raw = raw_leaf(b"pre", &refs);
        let p = PageRef::parse(&raw, 3).unwrap();
        assert_eq!(p.page_type(), PageType::Leaf);
        assert_eq!(p.n_slots(), 2);
        assert_eq!(p.prefix(), b"pre");
        assert_eq!(p.cell(0), cells[0].as_slice());
        assert_eq!(p.cell(1), cells[1].as_slice());
    }

    #[test]
    fn rejects_a_page_with_a_bad_checksum() {
        let mut raw = raw_leaf(b"", &[]);
        raw[30] ^= 0xff;
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::Checksum })
        );
    }

    #[test]
    fn rejects_an_unknown_page_type() {
        let mut raw = raw_leaf(b"", &[]);
        raw[0] = 9;
        fix_crc(&mut raw);
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::PageType })
        );
    }

    #[test]
    fn rejects_a_slot_pointing_outside_the_page() {
        let cells = [leaf_cell(b"aa", b"1")];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let mut raw = raw_leaf(b"", &refs);
        raw[20..22].copy_from_slice(&600u16.to_le_bytes());
        fix_crc(&mut raw);
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::SlotOffset })
        );
    }

    #[test]
    fn binary_search_finds_present_and_missing_suffixes() {
        let cells = [
            leaf_cell(b"aa", b"1"),
            leaf_cell(b"cc", b"2"),
            leaf_cell(b"ee", b"3"),
        ];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let raw = raw_leaf(b"k", &refs);
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.search(b"cc"), Ok(1));
        assert_eq!(p.search(b"aa"), Ok(0));
        assert_eq!(p.search(b"ee"), Ok(2));
        assert_eq!(p.search(b"bb"), Err(1));
        assert_eq!(p.search(b"a"), Err(0));
        assert_eq!(p.search(b"zz"), Err(3));
    }

    /// `ascending` sustituye a `<` sobre slices en el bucle de validación de
    /// slots por un motivo de coste, así que tiene que ser el MISMO orden,
    /// no uno parecido. Se compara contra el operador sobre todos los pares
    /// de un conjunto elegido para cubrir lo que un bucle escrito a mano
    /// suele equivocar: el vacío contra todo, un prefijo contra su
    /// extensión (donde la respuesta la decide la longitud, no ningún byte),
    /// pares iguales (que deben dar `false` en los dos sentidos), el byte
    /// alto con el bit de signo puesto (`0xff` es MAYOR que `0x00`, no
    /// menor: comparar como `i8` es el error clásico) y longitudes
    /// distintas con el primer byte ya distinto.
    #[test]
    fn manual_suffix_order_matches_the_slice_operator() {
        let cases: [&[u8]; 14] = [
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x01",
            b"\x7f",
            b"\x80",
            b"\xff",
            b"\xff\x00",
            b"\xff\xff",
            b"a",
            b"ab",
            b"abc",
            b"b",
            b"ba",
        ];
        for a in cases {
            for b in cases {
                assert_eq!(
                    ascending(a, b),
                    a < b,
                    "orden distinto para {a:?} contra {b:?}"
                );
            }
        }
    }

    fn fix_crc(b: &mut [u8]) {
        let mut h = crate::crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        let crc = h.finish();
        b[8..12].copy_from_slice(&crc.to_le_bytes());
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn common_prefix_of_shared_keys() {
        assert_eq!(common_prefix(&[b"abcd".as_slice(), b"abce", b"abzz"]), 2);
        assert_eq!(common_prefix(&[b"abc".as_slice(), b"abc"]), 3);
        assert_eq!(common_prefix(&[b"x".as_slice(), b"y"]), 0);
        assert_eq!(common_prefix(&[b"solo".as_slice()]), 4);
        assert_eq!(common_prefix(&[]), 0);
    }

    #[test]
    fn built_leaf_page_reads_back_identical() {
        let entries: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"logs/0001".as_slice(), CellPayload::Value(b"uno")),
            (b"logs/0002".as_slice(), CellPayload::Value(b"dos")),
            (b"logs/0003".as_slice(), CellPayload::Value(b"tres")),
        ];
        let raw = PageBuilder::new(512, PageType::Leaf).build(&entries).unwrap();
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.prefix(), b"logs/000");
        assert_eq!(p.n_slots(), 3);
        assert_eq!(p.search(b"2"), Ok(1));
    }

    /// El camino rápido tiene que producir una página que `parse` acepte y
    /// que se lea EXACTAMENTE igual que si se hubiera reconstruido con
    /// `build`: es la única garantía que lo hace intercambiable con el
    /// camino lento.
    #[test]
    fn appending_in_place_matches_a_full_rebuild() {
        let three: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"logs/0001".as_slice(), CellPayload::Value(b"uno")),
            (b"logs/0002".as_slice(), CellPayload::Value(b"dos")),
            (b"logs/0003".as_slice(), CellPayload::Value(b"tres")),
        ];
        let mut raw = PageBuilder::new(512, PageType::Leaf).build(&three).unwrap();
        assert!(append_in_place(&mut raw, b"logs/0004", CellPayload::Value(b"cuatro")));

        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.n_slots(), 4);
        let expected = [
            ("logs/0001", "uno"),
            ("logs/0002", "dos"),
            ("logs/0003", "tres"),
            ("logs/0004", "cuatro"),
        ];
        for (i, (k, v)) in expected.iter().enumerate() {
            assert_eq!(p.key(i), k.as_bytes());
            assert_eq!(p.leaf_value(i), LeafValue::Inline(v.as_bytes()));
        }

        // Y el mismo contenido reconstruido desde cero se lee igual. Los
        // bytes NO tienen por qué coincidir —anexar no vuelve a comprimir el
        // prefijo—, así que se compara lo que se lee, no la representación.
        let four: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"logs/0001".as_slice(), CellPayload::Value(b"uno")),
            (b"logs/0002".as_slice(), CellPayload::Value(b"dos")),
            (b"logs/0003".as_slice(), CellPayload::Value(b"tres")),
            (b"logs/0004".as_slice(), CellPayload::Value(b"cuatro")),
        ];
        let rebuilt = PageBuilder::new(512, PageType::Leaf).build(&four).unwrap();
        let q = PageRef::parse(&rebuilt, 1).unwrap();
        assert_eq!(p.n_slots(), q.n_slots());
        for i in 0..q.n_slots() {
            assert_eq!(p.key(i), q.key(i));
            assert_eq!(p.leaf_value(i), q.leaf_value(i));
        }
    }

    /// Una celda de overflow es de tamaño fijo y también se anexa: es el caso
    /// dominante del registro del edge, donde toda fila supera el umbral.
    #[test]
    fn appending_an_overflow_cell_in_place_reads_back() {
        let two: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"k0".as_slice(), CellPayload::Overflow { len: 900, first: 7 }),
            (b"k1".as_slice(), CellPayload::Overflow { len: 950, first: 8 }),
        ];
        let mut raw = PageBuilder::new(512, PageType::Leaf).build(&two).unwrap();
        assert!(append_in_place(&mut raw, b"k2", CellPayload::Overflow { len: 1200, first: 9 }));
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.n_slots(), 3);
        assert_eq!(p.leaf_value(2), LeafValue::Overflow { len: 1200, first: 9 });
    }

    /// **El límite del camino rápido, y no es un caso raro.** El prefijo
    /// común de una página de UNA entrada es su clave entera, así que ninguna
    /// otra clave lo comparte y todo anexado se rechaza. Ocurre de verdad:
    /// justo después de una división, la mitad derecha nace con una sola
    /// entrada. El árbol se recupera solo —el rechazo cae al camino lento,
    /// que reconstruye con el prefijo común de las dos claves, ya más corto,
    /// y a partir de ahí los anexados vuelven a entrar por el camino
    /// rápido—, pero conviene tenerlo escrito: el camino rápido no cubre el
    /// 100% de los anexados, y por eso el lento no puede quitarse.
    #[test]
    fn a_single_entry_page_has_the_whole_key_as_prefix_and_refuses() {
        let one: Vec<(&[u8], CellPayload)> =
            alloc::vec![(b"k0".as_slice(), CellPayload::Value(b"v"))];
        let raw = PageBuilder::new(512, PageType::Leaf).build(&one).unwrap();
        assert_eq!(PageRef::parse(&raw, 1).unwrap().prefix(), b"k0");

        let mut mutated = raw.clone();
        assert!(!append_in_place(&mut mutated, b"k1", CellPayload::Value(b"v")));
        assert_eq!(mutated, raw);
    }

    /// Los cuatro rechazos. En todos, la página debe quedar BYTE A BYTE como
    /// estaba: el llamante reconstruye a partir de ella, así que una página
    /// medio escrita sería corrupción silenciosa.
    #[test]
    fn append_in_place_refuses_and_leaves_the_page_untouched() {
        let entries: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"logs/0001".as_slice(), CellPayload::Value(b"uno")),
            (b"logs/0002".as_slice(), CellPayload::Value(b"dos")),
        ];
        let original = PageBuilder::new(512, PageType::Leaf).build(&entries).unwrap();

        // Prefijo distinto: reconstruir acortaría el prefijo común.
        let mut raw = original.clone();
        assert!(!append_in_place(&mut raw, b"otra/clave", CellPayload::Value(b"x")));
        assert_eq!(raw, original);

        // Fuera de orden: no es un anexado.
        let mut raw = original.clone();
        assert!(!append_in_place(&mut raw, b"logs/0000", CellPayload::Value(b"x")));
        assert_eq!(raw, original);

        // Duplicada: `ascending` es estricto, una clave igual no es mayor.
        let mut raw = original.clone();
        assert!(!append_in_place(&mut raw, b"logs/0002", CellPayload::Value(b"x")));
        assert_eq!(raw, original);

        // No cabe.
        let mut raw = original.clone();
        let big = alloc::vec![b'z'; 480];
        assert!(!append_in_place(&mut raw, b"logs/0003", CellPayload::Value(&big)));
        assert_eq!(raw, original);
    }

    /// Anexar hasta llenar: la página debe seguir siendo válida en cada paso
    /// y el primer anexado que no cabe debe rechazarse limpiamente, no
    /// escribir a medias.
    #[test]
    fn appending_until_full_stays_valid_and_then_refuses() {
        // Dos entradas de arranque que ya dejan el prefijo común en `k`, para
        // que el bucle mida el llenado y no el prefijo (ver
        // `a_single_entry_page_has_the_whole_key_as_prefix_and_refuses`).
        let seed: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"k0".as_slice(), CellPayload::Value(b"payload-de-relleno")),
            (b"k1".as_slice(), CellPayload::Value(b"payload-de-relleno")),
        ];
        let mut raw = PageBuilder::new(512, PageType::Leaf).build(&seed).unwrap();
        let mut n = 2;
        let mut refused = false;
        for c in b'2'..=b'~' {
            let key = [b'k', c];
            let before = raw.clone();
            if !append_in_place(&mut raw, &key, CellPayload::Value(b"payload-de-relleno")) {
                assert_eq!(raw, before, "un rechazo no puede dejar la página a medias");
                refused = true;
                break;
            }
            n += 1;
            assert_eq!(PageRef::parse(&raw, 1).unwrap().n_slots(), n);
        }
        assert!(n > 2, "debería haber cabido más de una entrada anexada");
        assert!(refused, "debería haberse llenado antes de agotar el alfabeto");
    }

    #[test]
    fn built_internal_page_keeps_children_and_rightmost() {
        let entries: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"m".as_slice(), CellPayload::Child(10)),
            (b"t".as_slice(), CellPayload::Child(11)),
        ];
        let mut b = PageBuilder::new(512, PageType::Internal);
        b.set_extra(12);
        let raw = b.build(&entries).unwrap();
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.extra(), 12);
        assert_eq!(p.child(0), 10);
        assert_eq!(p.child(1), 11);
    }

    /// Tarea 15, ronda 1 de revisión, hallazgos 1+2: `children_plain` debe
    /// sobrevivir un ciclo `build`/`parse` completo en los dos sentidos, y
    /// `false` (el valor por defecto de un `PageBuilder` nuevo, `flags: 0`
    /// en `new`) debe ser el resultado si nadie lo toca — la lectura
    /// conservadora, "no hay garantía", que `free_subtree` (`tree.rs`)
    /// necesita como caso por defecto seguro.
    #[test]
    fn children_plain_flag_roundtrips_and_defaults_to_false() {
        let entries: Vec<(&[u8], CellPayload)> =
            alloc::vec![(b"m".as_slice(), CellPayload::Child(10))];

        let raw_default = PageBuilder::new(512, PageType::Internal).build(&entries).unwrap();
        assert!(!PageRef::parse(&raw_default, 1).unwrap().children_plain());

        let mut b_false = PageBuilder::new(512, PageType::Internal);
        b_false.set_children_plain(false);
        let raw_false = b_false.build(&entries).unwrap();
        assert!(!PageRef::parse(&raw_false, 1).unwrap().children_plain());

        let mut b_true = PageBuilder::new(512, PageType::Internal);
        b_true.set_children_plain(true);
        let raw_true = b_true.build(&entries).unwrap();
        assert!(PageRef::parse(&raw_true, 1).unwrap().children_plain());
    }

    /// Precondición de `build`: entradas ordenadas y sin duplicados. Con
    /// `debug_assertions` activas (perfil de pruebas por defecto), pasar
    /// entradas desordenadas debe entrar en pánico en vez de seguir hasta el
    /// slice fuera de rango de `&key[prefix_len..]`.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "no es mayor que la anterior")]
    fn build_panics_on_unsorted_entries_in_debug() {
        let entries: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"b".as_slice(), CellPayload::Value(b"1")),
            (b"a".as_slice(), CellPayload::Value(b"2")),
        ];
        let _ = PageBuilder::new(512, PageType::Leaf).build(&entries);
    }

    #[test]
    fn build_returns_none_when_entries_do_not_fit() {
        let big = alloc::vec![0u8; 400];
        let entries: Vec<(&[u8], CellPayload)> = alloc::vec![
            (b"a".as_slice(), CellPayload::Value(&big)),
            (b"b".as_slice(), CellPayload::Value(&big)),
        ];
        assert!(PageBuilder::new(512, PageType::Leaf).build(&entries).is_none());
    }

    #[test]
    fn a_single_key_page_stores_the_whole_key_as_prefix() {
        let entries: Vec<(&[u8], CellPayload)> =
            alloc::vec![(b"clave".as_slice(), CellPayload::Value(b"v"))];
        let raw = PageBuilder::new(512, PageType::Leaf).build(&entries).unwrap();
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.prefix(), b"clave");
        assert_eq!(p.suffix(0), b"");
        assert_eq!(p.value(0), b"v");
    }

    /// `PageBuilder` no conoce `header::MAX_PAGE_SIZE` (32 KB): acepta
    /// cualquier `u32` como `page_size`, así que su propia comprobación de
    /// límite de `u16` es defensa en profundidad, no solo un reflejo del
    /// límite actual de `Geometry`. A `page_size == 65536` una página vacía
    /// dejaría `cursor` en exactamente 65536, que no cabe en el campo
    /// `cell_start` de 2 bytes. Antes de la comprobación de límite, `build`
    /// serializaba esto como 0 y producía una página que `PageRef::parse`
    /// rechazaba: una ruptura del contrato build/parse. `Geometry` ya no
    /// deja llegar a este `page_size` por la vía normal (tarea 6, cambio
    /// posterior que bajó `MAX_PAGE_SIZE` a 32 KB), pero `build` debe seguir
    /// rechazándolo si algún llamante lo pasara de todos modos.
    #[test]
    fn build_refuses_a_page_whose_offsets_would_not_fit_in_u16() {
        let entries: Vec<(&[u8], CellPayload)> = Vec::new();
        assert!(PageBuilder::new(65536, PageType::Leaf).build(&entries).is_none());
    }

    /// El mismo límite de `u16` con contenido real sí debe construirse y
    /// releerse sin problema: el límite anterior no debe alcanzarse en el
    /// caso normal.
    #[test]
    fn build_at_the_u16_offset_boundary_with_entries_round_trips() {
        let entries: Vec<(&[u8], CellPayload)> =
            alloc::vec![(b"k".as_slice(), CellPayload::Value(b"v"))];
        let raw = PageBuilder::new(65536, PageType::Leaf).build(&entries).unwrap();
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.n_slots(), 1);
        assert_eq!(p.value(0), b"v");
    }
}
