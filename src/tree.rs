use alloc::vec::Vec;

use crate::page::{CellPayload, LeafValue, PageBuilder, PageRef, PageType, PAGE_HEADER_SIZE};
use crate::tx::{PageSource, WriteTxn};
use crate::{CorruptKind, Error, PageNo, Result};

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

/// Umbral a partir del cual un valor va a páginas de overflow: un cuarto de
/// página, de modo que siempre quepan al menos cuatro entradas por hoja y la
/// división pueda avanzar. Mismo límite, por la misma razón, que `put` le
/// impone al tamaño de una clave (ver el chequeo al principio de `put`):
/// mantener los dos iguales los mantiene comprensibles.
pub fn overflow_threshold(page_size: u32) -> usize {
    page_size as usize / 4
}

/// Bytes de datos que caben en una página de overflow: la página menos su
/// cabecera estándar, cuyo campo `extra` encadena con la siguiente.
fn overflow_capacity(page_size: u32) -> usize {
    page_size as usize - PAGE_HEADER_SIZE
}

/// Escribe `value` en una cadena nueva de páginas de overflow y devuelve su
/// longitud real y la primera página de la cadena: la referencia que
/// `insert_rec` guarda en la celda de hoja.
///
/// Se asignan todas las páginas antes de escribir ninguna, para poder
/// enlazar cada una con la siguiente (su `next`, en el campo `extra` de la
/// cabecera) en una sola pasada.
pub fn write_overflow(tx: &mut WriteTxn, value: &[u8]) -> Result<(u64, PageNo)> {
    let page_size = tx.logical_page_size();
    let capacity = overflow_capacity(page_size);
    let chunks: Vec<&[u8]> = value.chunks(capacity).collect();

    let mut pages = Vec::with_capacity(chunks.len());
    for _ in 0..chunks.len() {
        pages.push(tx.alloc()?);
    }

    for (i, chunk) in chunks.iter().enumerate() {
        let next = pages.get(i + 1).copied().unwrap_or(0);
        let mut b = alloc::vec![0u8; page_size as usize];
        b[0] = PageType::Overflow as u8;
        b[12..16].copy_from_slice(&next.to_le_bytes());
        b[4..6].copy_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        b[6..8].copy_from_slice(&(page_size as u16).to_le_bytes());
        b[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
        let mut h = crate::crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());
        tx.write_page(pages[i], &b)?;
    }

    // `pages.first()`, no `pages[0]`: con `value` vacío, `chunks` (y por
    // tanto `pages`) está vacío. `insert_rec` nunca llama a esta función con
    // un valor así — solo lo hace por encima de `overflow_threshold`, que
    // nunca es cero — pero `write_overflow` es pública y nada impide a otro
    // llamante pasarle `&[]`; con `pages[0]` eso entraría en pánico en vez
    // de devolver, con sentido, `(0, 0)`: longitud real cero, sin cadena.
    Ok((value.len() as u64, pages.first().copied().unwrap_or(0)))
}

/// Lee de vuelta los `len` bytes de una cadena de overflow que empieza en
/// `first`.
///
/// Acotado en el número de páginas que recorre, no solo en el resultado: es
/// el mismo requisito que ya vale para `descend` (todo recorrido de punteros
/// leídos de disco debe estarlo), pero aquí hay una cota más ajustada que la
/// de `descend` porque `len` se conoce de antemano. Una cadena legítima
/// nunca necesita más páginas que `ceil(len / capacidad_por_página)` —
/// exactamente las que trocea `write_overflow`, ni una más. La capacidad se
/// calcula a partir del tamaño real de la primera página leída: todas las
/// páginas del mismo fichero comparten tamaño, así que basta calcularla una
/// vez.
///
/// **La cota de saltos, sola, NO basta para rechazar un ciclo**: con
/// capacidad uniforme por página, cada vuelta de un ciclo aporta la misma
/// cantidad fija de bytes tanto si la página es nueva como si es una
/// repetida, así que un ciclo alcanza `len` bytes en exactamente el mismo
/// número de saltos que una cadena legítima de ese tamaño — la cota nunca
/// llega a dispararse, y el bucle terminaría con `Ok` y datos repetidos en
/// vez de los reales. Verificado con
/// `read_overflow_terminates_on_a_cycle_instead_of_hanging`, que fabrica esa
/// cadena a mano.
///
/// Lo que sí lo detecta es una comprobación distinta, tras el bucle:
/// `write_overflow` deja `next == 0` únicamente en la ÚLTIMA página de una
/// cadena legítima (ver su bucle de escritura), así que reunir `len` bytes
/// agotando de verdad la cadena real siempre deja `current == 0`. Un ciclo
/// no contiene ninguna página con `next == 0`, así que un recorrido que
/// termina por haber reunido `len` bytes sin que la cadena llegara a su
/// propio final deja `current` distinto de cero — sea la causa un ciclo, una
/// `len` almacenada menor que el número real de páginas, o cualquier otra
/// forma de alias entre cadenas. Es la comprobación que de verdad cierra el
/// hueco de corrección: sin ella, esta función podía devolver `Ok` con bytes
/// que no son el valor real, rompiendo la regla que sostiene el motor desde
/// la tarea 5 (entrada corrupta se reporta como `Err`, nunca como una
/// respuesta incorrecta silenciosa).
///
/// La cota de saltos se conserva de todos modos, no como mecanismo de
/// corrección (ya no lo es, ver arriba) sino como cota EXPLÍCITA de
/// recorrido: con páginas de tamaño uniforme —cierto para cualquier `Pager`
/// real de este crate, que fija un único `page_size` por fichero— el propio
/// `while current != 0 && out.len() < len` ya termina en, como mucho,
/// `ceil(len/capacidad)` vueltas, cicle o no. Pero `read_overflow` recibe
/// `src: &impl PageSource`, no un `Pager` concreto, y el trait no promete
/// tamaño uniforme entre lecturas. Un `PageSource` que devolviera páginas de
/// tamaño decreciente (nada en la firma lo impide, aunque ningún
/// implementador de este crate lo haga) podría hacer que la capacidad
/// efectiva por vuelta cayera a un puñado de bytes, y entonces sí haría
/// falta un número de vueltas sin cota conocida de antemano para agotar
/// `len` — exactamente el escenario que `todo recorrido de punteros leídos
/// de disco va acotado` pide cerrar, sin depender de una propiedad de
/// `Pager` que esta función no puede exigir por su propia firma.
pub fn read_overflow(src: &impl PageSource, len: u64, first: PageNo) -> Result<Vec<u8>> {
    // Sin `with_capacity(len as usize)`: `len` viene de una celda leída de
    // disco, y si esa celda está corrompida (deliberadamente o no, pero con
    // CRC válido) `len` puede ser arbitrariamente grande — hasta `u64::MAX`.
    // Reservar esa cantidad de golpe intentaría una asignación enorme antes
    // de leer una sola página de la cadena, mucho antes de que la cota de
    // pasos de abajo tuviera ocasión de detectar nada. Crecer con
    // `extend_from_slice` reparte el coste entre iteraciones reales.
    let mut out = Vec::new();
    let mut current = first;
    let mut hops: u64 = 0;
    let mut max_hops: Option<u64> = None;
    while current != 0 && (out.len() as u64) < len {
        let bytes = src.read_page(current)?;
        let page = PageRef::parse(&bytes, current)?;
        if page.page_type() != PageType::Overflow {
            return Err(Error::Corrupt { page: current, kind: CorruptKind::PageType });
        }
        let available = bytes.len() - PAGE_HEADER_SIZE;
        let max = *max_hops.get_or_insert_with(|| {
            let capacity = core::cmp::max(available as u64, 1);
            len.div_ceil(capacity).max(1)
        });
        hops += 1;
        if hops > max {
            return Err(Error::Corrupt { page: first, kind: CorruptKind::OverflowLoop });
        }
        let remaining = (len - out.len() as u64) as usize;
        let take = core::cmp::min(remaining, available);
        out.extend_from_slice(&bytes[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + take]);
        current = page.extra();
    }
    // La comprobación que de verdad detecta un ciclo (o cualquier alias que
    // deje la cadena sin agotarse): ver el comentario de la función. Debe ir
    // ANTES de la comprobación de longitud de abajo — cuando el bucle
    // termina con `current != 0` es precisamente porque `out.len()` ya
    // alcanzó `len` (la otra mitad de la condición del `while`), así que esa
    // comprobación de longitud, por sí sola, no vería nada raro.
    if current != 0 {
        return Err(Error::Corrupt { page: first, kind: CorruptKind::OverflowLoop });
    }
    if out.len() as u64 != len {
        return Err(Error::Corrupt { page: first, kind: CorruptKind::CellBounds });
    }
    Ok(out)
}

/// Libera toda la cadena de páginas de overflow que empieza en `first`, que
/// almacenaba un valor de `len` bytes.
///
/// **Desviación deliberada de la interfaz de la tarea**: el brief fija esta
/// firma como `free_overflow(&mut WriteTxn, first: PageNo) -> Result<()>`,
/// sin `len`. La ronda de revisión posterior a la primera entrega pidió
/// añadirlo para acotar el recorrido igual de ajustado que `read_overflow`
/// (`ceil(len / capacidad_por_página)`, no `tx.n_pages()`) y así encoger la
/// ventana del hallazgo de abajo sobre `tx.free()` repetido. Los dos
/// llamantes (`insert_rec`, `delete_rec`) ya desestructuran
/// `LeafValue::Overflow { len, first }`; antes descartaban `len`, ahora lo
/// pasan.
///
/// Acotado en el número de páginas que recorre, igual que `read_overflow` y
/// por la misma razón general (`descend`): todo recorrido de punteros
/// leídos de disco debe estarlo. A diferencia de `read_overflow`, esta
/// función no necesita además la comprobación de `current != 0` al final:
/// no tiene una segunda condición de salida basada en cuánto ha acumulado
/// (no acumula nada, solo libera páginas), así que su único camino de
/// salida normal (sin `Err`) es precisamente `current == 0` — no hay hueco
/// de corrección equivalente que cerrar aquí.
///
/// Si un ciclo dispara el `Err` de más abajo, esta función ya habrá llamado
/// a `tx.free()` varias veces sobre las mismas páginas repetidas del ciclo —
/// no hay forma de evitarlo sin memoria adicional para recordar qué páginas
/// se han visto. Es inofensivo solo porque el contrato ya establecido para
/// cualquier `Err` de esta transacción (ver la nota de `put`) es abandonarla
/// sin `commit`: `own_free`, donde van a parar esas liberaciones repetidas
/// por ser páginas asignadas por esta misma transacción, es puramente local
/// a `WriteTxn` y desaparece con ella si nunca confirma. La cota ajustada
/// por `len` (en vez del número total de páginas del fichero, la cota de la
/// primera entrega, expuesta entonces como `WriteTxn::n_pages` y ya
/// retirada por no tener más usos) no elimina esa ventana, pero la encoge:
/// sobre una base con muchas páginas, la cota anterior podía tardar miles de
/// llamadas a `tx.free()` repetidas en disparar el error; `ceil(len /
/// capacidad)` la limita al tamaño real del valor que se está liberando.
pub fn free_overflow(tx: &mut WriteTxn, len: u64, first: PageNo) -> Result<()> {
    let capacity = core::cmp::max(tx.logical_page_size() as u64 - PAGE_HEADER_SIZE as u64, 1);
    let max_hops = len.div_ceil(capacity).max(1);
    let mut current = first;
    let mut hops: u64 = 0;
    while current != 0 {
        hops += 1;
        if hops > max_hops {
            return Err(Error::Corrupt { page: first, kind: CorruptKind::OverflowLoop });
        }
        let bytes = tx.read_page(current)?;
        let page = PageRef::parse(&bytes, current)?;
        // Como en `read_overflow`: sin comprobar el tipo, una cadena `first`
        // corrupta que apuntara a una página viva del árbol (hoja o
        // interna) liberaría esa página en vez de fallar — el campo
        // `extra()` existe en todos los tipos de página, así que seguiría
        // "avanzando" sobre estructura que no es una cadena de overflow en
        // absoluto.
        if page.page_type() != PageType::Overflow {
            return Err(Error::Corrupt { page: current, kind: CorruptKind::PageType });
        }
        let next = page.extra();
        tx.free(current);
        current = next;
    }
    Ok(())
}

/// Valor de hoja pendiente de escribir tras reconstruir sus entradas:
/// copiado en memoria si está en línea, o solo la referencia si ya vive en
/// una cadena de overflow. Reconstruir una hoja para tocar UNA entrada no
/// debe copiar los bytes de un valor grande de otra entrada que ni siquiera
/// cambia — con overflow esos bytes pueden ser megabytes.
enum LeafPayload {
    Inline(Vec<u8>),
    Overflow { len: u64, first: PageNo },
}

impl LeafPayload {
    fn as_cell_payload(&self) -> CellPayload<'_> {
        match self {
            LeafPayload::Inline(v) => CellPayload::Value(v.as_slice()),
            LeafPayload::Overflow { len, first } => {
                CellPayload::Overflow { len: *len, first: *first }
            }
        }
    }
}

impl<'a> From<LeafValue<'a>> for LeafPayload {
    fn from(v: LeafValue<'a>) -> Self {
        match v {
            LeafValue::Inline(b) => LeafPayload::Inline(b.to_vec()),
            LeafValue::Overflow { len, first } => LeafPayload::Overflow { len, first },
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
        Ok(i) => Ok(Some(match page.leaf_value(i) {
            LeafValue::Inline(v) => v.to_vec(),
            LeafValue::Overflow { len, first } => read_overflow(src, len, first)?,
        })),
        Err(_) => Ok(None),
    }
}

/// Vista prestada de `entries` que le pasa `emit` a `PageBuilder::build`.
type BorrowedEntries<'a> = [(&'a [u8], CellPayload<'a>)];

/// Resultado de insertar en un subárbol.
///
/// **Ronda 1 de revisión de la tarea 15, hallazgos 1+2**: cada variante que
/// produce una página nueva lleva además `plain: bool` — "¿es esta página (o,
/// en `Split`, esta mitad) una HOJA sin ninguna entrada de overflow?" — sin
/// coste de lectura adicional: `emit` YA conoce `page_type` (es su propio
/// parámetro) y YA tiene `entries` en memoria, así que calcularlo es gratis.
/// Es la información que permite a la llamada de nivel superior mantener al
/// día, también gratis, el bit `children_plain` (`page.rs`) del nodo interno
/// que está reconstruyendo — ver el comentario de `free_subtree`, que es
/// quien de verdad consume ese bit.
enum Insertion {
    /// El subárbol sigue cabiendo en una página; esta es la nueva.
    Updated(PageNo, bool),
    /// El subárbol se dividió. `sep` es la primera clave de `right`.
    Split { left: PageNo, left_plain: bool, sep: Vec<u8>, right: PageNo, right_plain: bool },
}

/// `true` si `entries` (los que va a recibir una página de tipo `page_type`)
/// no contienen ninguna entrada de overflow — solo puede ser cierto para
/// hojas, nunca para nodos internos (cuyas celdas son punteros a hijos, no
/// valores). Compartido por las dos ramas de `emit` (cabe entera / se
/// divide) para no repetir la lógica.
fn entries_are_plain(page_type: PageType, entries: &BorrowedEntries) -> bool {
    page_type == PageType::Leaf
        && entries.iter().all(|(_, p)| !matches!(p, CellPayload::Overflow { .. }))
}

/// Escribe `entries` en una página nueva, o en dos si no caben, liberando la
/// página `old`. Es el único punto del árbol que asigna páginas de nodo, de
/// modo que la política de división vive en un solo sitio.
///
/// `children_plain` solo importa cuando `page_type == PageType::Internal`:
/// es el bit que el LLAMANTE ya calculó (ver el comentario de `Insertion`)
/// para los hijos de la página que está reconstruyendo, y `emit` se limita a
/// guardarlo en la cabecera (`PageBuilder::set_children_plain`) — `emit` no
/// tiene forma de calcularlo por sí mismo, porque `entries` para un nodo
/// interno solo trae `CellPayload::Child(PageNo)`, sin el tipo del hijo. Se
/// ignora sin efecto para cualquier otro `page_type`.
fn emit(
    tx: &mut WriteTxn,
    old: Option<PageNo>,
    page_type: PageType,
    extra: u32,
    entries: &[(Vec<u8>, CellPayload)],
    children_plain: bool,
) -> Result<Insertion> {
    let page_size = tx.logical_page_size();
    let borrowed: Vec<(&[u8], CellPayload)> =
        entries.iter().map(|(k, p)| (k.as_slice(), *p)).collect();

    let mut builder = PageBuilder::new(page_size, page_type);
    builder.set_extra(extra);
    if page_type == PageType::Internal {
        builder.set_children_plain(children_plain);
    }
    if let Some(bytes) = builder.build(&borrowed) {
        let page_no = tx.alloc()?;
        tx.write_page(page_no, &bytes)?;
        if let Some(old) = old {
            tx.free(old);
        }
        return Ok(Insertion::Updated(page_no, entries_are_plain(page_type, &borrowed)));
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
            // Cuerpo fijo de 22 bytes (marca varint de 10 + 8 de longitud +
            // 4 de primera página, ver `CellPayload::Overflow` en
            // `page.rs`): con el límite de `page_size / 4` que ya impone
            // `put` sobre la clave, una sola celda de overflow siempre cabe
            // sola en una página nueva, así que esta rama es inalcanzable en
            // la práctica — se deja completa por si ese límite cambiara.
            CellPayload::Overflow { .. } => entries[0].0.len() + 22,
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
                    CellPayload::Overflow { .. } => {
                        unreachable!("nodo interno con valor de overflow")
                    }
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

    // Dividir una página interna reparte sus MISMOS hijos entre las dos
    // mitades: ninguno cambia de tipo ni gana overflow por el mero hecho de
    // mudarse de página, así que las dos mitades heredan el mismo
    // `children_plain` que iba a tener la página sin dividir — no hay nada
    // que recalcular.
    let mut lb = PageBuilder::new(page_size, page_type);
    lb.set_extra(left_extra);
    if page_type == PageType::Internal {
        lb.set_children_plain(children_plain);
    }
    let left_bytes = lb.build(left_entries).ok_or(Error::KeyTooLarge {
        len: entries[0].0.len() as u32,
        max: page_size,
    })?;

    let mut rb = PageBuilder::new(page_size, page_type);
    rb.set_extra(extra);
    if page_type == PageType::Internal {
        rb.set_children_plain(children_plain);
    }
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
    Ok(Insertion::Split {
        left,
        left_plain: entries_are_plain(page_type, left_entries),
        sep,
        right,
        right_plain: entries_are_plain(page_type, right_entries),
    })
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
            // Convertir el valor entrante antes de tocar las entradas de la
            // hoja: si es grande, escribe su propia cadena de overflow y
            // aquí solo se guarda la referencia. `Option` porque se consume
            // una única vez, al insertarlo en su posición final más abajo
            // (en `Ok(i)` reemplaza; en `Err(i)` se inserta nuevo) —
            // moverlo evita clonar un valor potencialmente enorme.
            let mut new_payload = Some(if value.len() > overflow_threshold(tx.logical_page_size()) {
                let (len, first) = write_overflow(tx, value)?;
                LeafPayload::Overflow { len, first }
            } else {
                LeafPayload::Inline(value.to_vec())
            });

            let mut keys: Vec<Vec<u8>> = Vec::with_capacity(page.n_slots() + 1);
            let mut payloads: Vec<LeafPayload> = Vec::with_capacity(page.n_slots() + 1);
            match search_key(&page, key) {
                Ok(i) => {
                    for j in 0..page.n_slots() {
                        keys.push(page.key(j));
                        if j == i {
                            // Se reemplaza esta entrada: su cadena de
                            // overflow anterior, si tenía una, ya no la
                            // referencia nadie.
                            if let LeafValue::Overflow { len, first } = page.leaf_value(j) {
                                free_overflow(tx, len, first)?;
                            }
                            payloads.push(new_payload.take().expect("se consume una sola vez"));
                        } else {
                            payloads.push(LeafPayload::from(page.leaf_value(j)));
                        }
                    }
                }
                Err(i) => {
                    for j in 0..i {
                        keys.push(page.key(j));
                        payloads.push(LeafPayload::from(page.leaf_value(j)));
                    }
                    keys.push(key.to_vec());
                    payloads.push(new_payload.take().expect("se consume una sola vez"));
                    for j in i..page.n_slots() {
                        keys.push(page.key(j));
                        payloads.push(LeafPayload::from(page.leaf_value(j)));
                    }
                }
            }
            let entries: Vec<(Vec<u8>, CellPayload)> = keys
                .iter()
                .zip(payloads.iter())
                .map(|(k, p)| (k.clone(), p.as_cell_payload()))
                .collect();
            // `children_plain` no significa nada en una hoja: `emit` lo
            // ignora salvo para `PageType::Internal` (ver su comentario).
            emit(tx, Some(page_no), PageType::Leaf, 0, &entries, false)
        }

        PageType::Internal => {
            let idx = child_index(&page, key);
            let child = child_at(&page, idx);
            let result = insert_rec(tx, child, key, value, depth + 1)?;

            let mut entries: Vec<(Vec<u8>, CellPayload)> = Vec::with_capacity(page.n_slots() + 2);
            let mut extra = page.extra();
            // Punto de partida conservador: si ya no todos los hijos de
            // ESTA página eran planos, tocar uno solo no puede demostrar
            // que los demás también lo sean sin volver a comprobarlos —
            // se queda en `false` y punto. Si SÍ lo eran, insertar no
            // puede haber convertido a un hermano no tocado en algo
            // distinto de una hoja plana (ver el comentario de
            // `Insertion`), así que solo el resultado del hijo tocado
            // puede bajarlo a `false`.
            let mut children_plain = page.children_plain();

            for j in 0..page.n_slots() {
                entries.push((page.key(j), CellPayload::Child(page.child(j))));
            }

            match result {
                Insertion::Updated(new_child, plain) => {
                    children_plain &= plain;
                    if idx < page.n_slots() {
                        entries[idx].1 = CellPayload::Child(new_child);
                    } else {
                        extra = new_child;
                    }
                }
                Insertion::Split { left, left_plain, sep, right, right_plain } => {
                    children_plain &= left_plain && right_plain;
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

            emit(tx, Some(page_no), PageType::Internal, extra, &entries, children_plain)
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
    let page_size = tx.logical_page_size();
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
        // Árbol vacío: este camino no pasa por `insert_rec`, así que tiene
        // que convertir el valor a overflow por su cuenta — de lo
        // contrario, la primera inserción de un valor grande en una base
        // nueva reconstruiría la hoja con el valor entero en línea y
        // `emit` la rechazaría con `KeyTooLarge`, exactamente el defecto
        // que este árbol de páginas de overflow existe para evitar.
        let payload = if value.len() > overflow_threshold(page_size) {
            let (len, first) = write_overflow(tx, value)?;
            CellPayload::Overflow { len, first }
        } else {
            CellPayload::Value(value)
        };
        let entries = alloc::vec![(key.to_vec(), payload)];
        return match emit(tx, None, PageType::Leaf, 0, &entries, false)? {
            Insertion::Updated(p, _) => Ok(p),
            Insertion::Split { .. } => unreachable!(
                "emit con una sola entrada nunca divide: cabe (Updated) o falla dentro de \
                 emit (Err), nunca Split"
            ),
        };
    }

    match insert_rec(tx, root, key, value, 1)? {
        Insertion::Updated(p, _) => Ok(p),
        Insertion::Split { left, left_plain, sep, right, right_plain } => {
            // El árbol crece por arriba: raíz nueva con un solo separador.
            // Sus dos hijos son exactamente `left`/`right`, la partición de
            // lo que antes era la raíz — `left_plain && right_plain`, que
            // `insert_rec` ya calculó sin coste adicional (ver el
            // comentario de `Insertion`), es exactamente si esos dos hijos
            // son ambos hojas planas.
            let entries = alloc::vec![(sep, CellPayload::Child(left))];
            let children_plain = left_plain && right_plain;
            match emit(tx, None, PageType::Internal, right, &entries, children_plain)? {
                Insertion::Updated(p, _) => Ok(p),
                Insertion::Split { .. } => unreachable!("una raíz de una entrada siempre cabe"),
            }
        }
    }
}

/// Resultado de borrar en un subárbol.
///
/// Como `Insertion` (ronda 1 de revisión de la tarea 15, hallazgos 1+2),
/// `Updated` lleva `plain: bool` — la página resultante, ¿es una hoja sin
/// overflow? — para que el nivel de arriba mantenga al día, sin lecturas
/// extra, el bit `children_plain` del nodo interno que reconstruye.
enum Removal {
    /// Sin cambios: la clave no estaba. La página original sigue siendo válida.
    Unchanged,
    /// El subárbol sigue existiendo en esta página nueva.
    Updated(PageNo, bool),
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
            // La cadena de overflow de la entrada borrada, si tenía una, ya
            // no la referencia nadie: liberarla en los dos caminos de
            // salida (hoja que se queda vacía, y hoja que se reconstruye
            // sin ella).
            if let LeafValue::Overflow { len, first } = page.leaf_value(hit) {
                free_overflow(tx, len, first)?;
            }
            if page.n_slots() == 1 {
                tx.free(page_no);
                return Ok(Removal::Gone);
            }
            let mut keys = Vec::with_capacity(page.n_slots() - 1);
            let mut payloads: Vec<LeafPayload> = Vec::with_capacity(page.n_slots() - 1);
            for j in 0..page.n_slots() {
                if j != hit {
                    keys.push(page.key(j));
                    payloads.push(LeafPayload::from(page.leaf_value(j)));
                }
            }
            let entries: Vec<(Vec<u8>, CellPayload)> = keys
                .iter()
                .zip(payloads.iter())
                .map(|(k, p)| (k.clone(), p.as_cell_payload()))
                .collect();
            match emit(tx, Some(page_no), PageType::Leaf, 0, &entries, false)? {
                Insertion::Updated(p, plain) => Ok(Removal::Updated(p, plain)),
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
            // Como en `insert_rec`: conservador por defecto, solo el
            // resultado del hijo tocado puede bajarlo a `false` (nunca
            // subirlo — borrar tampoco puede "des-mezclar" un nodo que ya
            // era mixto sin volver a comprobar los hermanos que no se
            // tocan).
            let mut children_plain = page.children_plain();

            match result {
                Removal::Updated(new_child, plain) => {
                    children_plain &= plain;
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
                            Some((_, CellPayload::Value(_) | CellPayload::Overflow { .. })) => {
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
            //
            // **Corrección, ronda 2 de revisión de la tarea 15 ("también
            // corregir").** Este comentario decía antes que el hijo que se
            // promueve (`extra`) "es siempre uno que esta llamada NO tocó",
            // y por eso usaba directamente `page.children_plain()` (el
            // valor VIEJO, sin pasar por `children_plain`, la variable que
            // sí se actualiza con el resultado fresco del hijo tocado) para
            // etiquetar el `Removal::Updated` de abajo. Es falso en un caso:
            // si `page.n_slots() == 0` (un nodo interno corrupto sin
            // separadores — imposible de producir por `emit`, que nunca
            // construye uno así, pero no comprobado al leer una página
            // ajena), `child_index` resuelve a la posición `extra` para
            // CUALQUIER clave, así que el hijo tocado por esta llamada Y el
            // que acaba en `extra` son el MISMO — exactamente el caso que
            // el comentario decía que no podía pasar. Con `page.n_slots() ==
            // 0`, `entries` ya estaba vacío ANTES de procesar `result`
            // (el bucle de más arriba no tiene nada que copiar), así que
            // esta rama se alcanza también con `Removal::Updated` (no solo
            // con el `Gone` que colapsa un nodo bien formado), y en ese
            // caso `page.children_plain()` (el valor de ANTES de tocar
            // nada) puede ser `true` mientras el resultado fresco del hijo
            // tocado (`plain`, ya incorporado en `children_plain` por el
            // `&=` de la rama `Updated`, más arriba) sea `false` — el hijo
            // promovido quedaría etiquetado como plano sin serlo, la
            // dirección insegura que las rondas 1 y 2 de revisión llevan
            // cerrando en todos los demás sitios.
            //
            // La corrección real, no solo de comentario: usar
            // `children_plain` (la variable local, ya actualizada) en vez
            // de volver a leer `page.children_plain()`. Para un árbol bien
            // formado (`page.n_slots() >= 1`) esta rama solo se alcanza vía
            // `Removal::Gone` — que nunca toca `children_plain`, así que en
            // ese caso `children_plain == page.children_plain()` siempre —
            // así que el cambio no altera ningún resultado ya correcto,
            // solo cierra el caso corrupto.
            if entries.is_empty() {
                tx.free(page_no);
                return Ok(if extra == 0 {
                    Removal::Gone
                } else {
                    Removal::Updated(extra, children_plain)
                });
            }

            // `plain` que devuelve `emit` aquí es siempre `false` (un nodo
            // interno nunca es él mismo una hoja plana, ver
            // `entries_are_plain`): se reenvía tal cual, no hace falta
            // recalcularlo.
            match emit(tx, Some(page_no), PageType::Internal, extra, &entries, children_plain)? {
                Insertion::Updated(p, plain) => Ok(Removal::Updated(p, plain)),
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
        Removal::Updated(p, _) => Ok((p, true)),
        Removal::Gone => Ok((0, true)),
    }
}

/// Cota de trabajo compartida por TODA una llamada a `delete_range`: cuenta
/// las páginas leídas tanto por `delete_range_rec` como por cada llamada a
/// `free_subtree` que dispare, sea cual sea su profundidad de recursión —
/// un único contador, no uno por función, porque ambas son mutuamente
/// recursivas y un DAG corrupto puede desviar el ataque de una a la otra
/// sin que un contador partido lo viera venir.
///
/// **Por qué hace falta, además de `MAX_DEPTH`.** `MAX_DEPTH` (la misma
/// cota que ya usan `descend`, `insert_rec`, `delete_rec` y el cursor)
/// basta para que la recursión de `free_subtree` no desborde la pila —
/// como mucho 128 marcos, unos pocos KB — pero NO basta para acotar el
/// número TOTAL de páginas leídas. Un DAG corrupto acíclico (hijos
/// compartidos entre nodos distintos, no un ciclo) mantiene cada camino
/// individual corto mientras el número de caminos DISTINTOS crece
/// exponencialmente con la profundidad: el mismo fenómeno que
/// `MAX_NEXT_WORK` cierra para `Cursor::next` (ver su comentario, y
/// `a_corrupt_dag_with_repeated_children_is_rejected_quickly_not_slowly`
/// más abajo, que lo demuestra en la práctica). `free_subtree` está más
/// expuesto todavía que el cursor: visita CADA hijo de cada nodo interno
/// que recorre, no uno solo por nivel, y `delete_range_rec` también — el
/// caso "no contenido del todo" de un nodo interno recorre TODOS sus
/// hijos, exactamente la misma forma de recorrido.
///
/// **Por qué la cota no es una constante pequeña, a diferencia de
/// `MAX_NEXT_WORK`.** Un `next()` legítimo solo necesita recorrer del
/// orden de la profundidad del árbol (una hoja agotada, subir, bajar por
/// el hermano), así que una constante pequeña (`8 · MAX_DEPTH`) nunca
/// rechaza un uso real. Liberar un subárbol legítimo es distinto por
/// diseño: esta tarea existe precisamente para que se puedan leer, de
/// verdad, del orden de miles de páginas internas en una poda diaria — una
/// constante pequeña rechazaría ese caso de uso central, no solo el
/// ataque.
///
/// **Por qué `n_pages()` del fichero sí sirve.** En un árbol PROPIO (sin
/// aliasing: cada página con un único padre), el número de páginas
/// internas visitables desde cualquier raíz nunca puede superar el número
/// total de páginas que existen en el fichero — cada una se visita como
/// mucho una vez, porque cada una tiene un solo padre. Así que usar
/// `tx.n_pages()` como cota nunca rechaza un recorrido legítimo, sea cual
/// sea su tamaño, y sigue disparando con rapidez frente al ataque
/// exponencial: un DAG corrupto que necesitara superar, por ejemplo, un
/// millón de páginas para hacer saltar el error, lo consigue en ~20
/// niveles (2^20 ≈ 1×10⁶) — muy por debajo de `MAX_DEPTH` — no en un
/// número de niveles que dependa de cuántas páginas reales tenga el
/// fichero.
///
/// **Corrección, ronda 1 de revisión de la tarea 15, hallazgo 4.** Esta
/// nota afirmaba antes que "ni `delete_range_rec` ni `free_subtree`
/// asignan páginas (solo liberan)" para justificar capturar `n_pages()`
/// una sola vez al principio de `delete_range`. Es cierto para
/// `free_subtree` (que nunca llama a `alloc`), pero es FALSO para
/// `delete_range_rec`: su rama que reconstruye una hoja o un nodo interno
/// parcialmente conservado llama a `emit`, que sí asigna páginas nuevas
/// (`tx.alloc()`, más arriba). Capturar `n_pages()` una sola vez sigue
/// siendo correcto, pero por otra razón: una página que ESTA llamada asigna
/// nunca vuelve a leerla ELLA MISMA — `emit` la escribe y devuelve su
/// número, y ni `delete_range_rec` ni `free_subtree` la abren de nuevo
/// dentro de la misma operación — así que las páginas nuevas no compiten
/// por presupuesto de lectura, solo las que YA existían al empezar. El
/// `n_pages()` capturado al principio sigue acotando exactamente eso.
struct RangeBudget {
    work: u32,
    max: u32,
}

impl RangeBudget {
    /// `core::cmp::max(max, 1)`: con un árbol de una sola página (`n_pages`
    /// mínimo tras `Db::create`, ver `meta_b_page` en `tx.rs`, es varias
    /// páginas en la práctica, pero nada en esta función depende de eso) la
    /// cota nunca debe ser cero, o la primera carga legítima ya la
    /// dispararía.
    fn new(max_pages: u32) -> Self {
        Self { work: 0, max: core::cmp::max(max_pages, 1) }
    }

    fn charge(&mut self, page: PageNo) -> Result<()> {
        self.work += 1;
        if self.work > self.max {
            return Err(Error::Corrupt { page, kind: CorruptKind::TreeLoop });
        }
        Ok(())
    }
}

/// Verifica que `child`, leído de un nodo interno, es un número de página
/// plausible antes de fiarse de él para liberar (`free_subtree`) o para
/// descender (`delete_range_rec`).
///
/// **Ronda 1 de revisión de la tarea 15, hallazgo 3 — CRÍTICO.** Antes de
/// esta comprobación, el camino que vuelca hijos a la lista de libres en
/// bloque (`tx.free(child)`, sin abrir `child` para comprobar nada) no
/// validaba el número de página en absoluto: un nodo interno corrupto con,
/// por ejemplo, `extra == 0` hacía que `free_subtree` devolviera `Ok(())`
/// tras empujar la página **0** — la cabecera del fichero — a la lista de
/// libres. Confirmado de punta a punta: tras el `commit`, `alloc()` volvía
/// a repartir `0` como página libre, y la siguiente escritura destruía la
/// cabecera. `free_overflow` (más arriba) ya se protege de un fallo
/// análogo, aunque de otra forma — abre la página y comprueba su tipo antes
/// de fiarse de su `extra()` como "siguiente puntero" — porque una cadena
/// de overflow SÍ trata `0` como un valor legítimo (fin de cadena). Un
/// puntero a hijo de un nodo interno NUNCA es legítimamente `0`: `alloc()`
/// jamás reparte la página `0` (reservada para la cabecera) ni ninguna
/// anterior a `n_pages` en el momento de la asignación, así que cualquier
/// hijo `== 0` o `>= n_pages` es, sin ambigüedad, corrupción.
///
/// **Ronda 2 de revisión de la tarea 15, hallazgo 1 — clase todavía
/// abierta.** La comprobación original solo rechazaba `0`, pero `1..=2`
/// (la ranura de meta A en la página `1`, la ranura de meta B en su
/// posición inicial, la `2`) son EXACTAMENTE tan inválidas como la `0` —
/// ninguna es una página de nodo legítima, por la misma razón (`alloc`
/// nunca las reparte). Confirmado de punta a punta con `extra == 1` (la
/// ranura de meta A): `free_subtree` la volcaba a la lista de libres sin
/// más, y tras el commit `alloc()` volvía a repartir la página `1` — la
/// siguiente escritura destruye esa ranura de meta, mismo desenlace que con
/// la `0`, una página más allá.
///
/// **Tarea 18 — dos rondas de corrección propias, las dos con hallazgos
/// caros porque cada una "arregla" la ronda anterior de forma incompleta.**
///
/// Primer intento: comparar contra `meta_b_page` LEÍDO DE LA GEOMETRÍA
/// (`WriteTxn::last_reserved_page` de entonces), sin cambiar nada más —
/// razonable mientras esa página era estática de por vida, pero
/// `relocate_meta_b` la mueve de `INITIAL_META_B_PAGE` (`2`) a
/// `final_meta_b_page` una vez el fichero crece más allá de 4 KB, y las
/// páginas `3..final_meta_b_page` (con `page_size` de 512 B, la `3` a la
/// `7`) SÍ son datos legítimos del árbol mientras tanto — `alloc` las
/// reparte con toda normalidad; la única página que de verdad nunca reparte
/// es el DESTINO final (ver `skip_meta_b_target` en `tx.rs`). Comparar
/// contra el `meta_b_page` dinámico como un ÚNICO umbral (`child <=
/// meta_b_page`) rechazaba, tras cada reubicación real, cualquier hijo
/// legítimo `3..=7` que el árbol hubiera asignado ANTES de que la
/// reubicación ocurriera — confirmado de punta a punta: catorce pruebas con
/// árboles de miles de entradas fallaron con `Corrupt { kind: CellBounds }`
/// al introducir la reubicación, todas leyendo una página que la propia
/// prueba acababa de escribir como nodo válido unas líneas antes.
///
/// Segundo intento: separar el prefijo fijo (`0..=2`, con el `2` como
/// CONSTANTE — `WriteTxn::last_reserved_page` de esa versión— no leído de la
/// geometría) de la página destino suelta (`WriteTxn::meta_b_relocation_target`,
/// siempre excluida). Arregla el hallazgo anterior, pero introduce uno
/// nuevo: `relocate_meta_b` también libera de verdad la posición VIEJA una
/// vez completa la reubicación (`self.free`, ver su comentario en `tx.rs`)
/// — sin eso, esa página se perdía para siempre, un hallazgo propio de la
/// contabilidad de fugas de este mismo módulo — así que la `2` SÍ vuelve a
/// ser un hijo legítimo después de reubicar, y una constante fija la
/// rechaza para siempre incluso reciclada. Confirmado de punta a punta con
/// árboles lo bastante grandes como para que la meta B reubicada se
/// reciclara y volviera a usarse
/// (`an_overflow_value_ever_written_costs_its_node_the_fast_path_permanently`,
/// `it_does_not_touch_other_keyspaces`).
///
/// **La cota correcta son TRES comprobaciones, no dos**, porque en ningún
/// punto de la vida del fichero hay más que dos páginas con algún papel de
/// meta B (la inicial y la final, nunca las dos con el mismo papel a la
/// vez) pero una de ellas cambia de estado:
/// - el prefijo fijo `0..=1` (`WriteTxn::last_reserved_page`) — la cabecera
///   y la meta A, que no cambian jamás;
/// - la página de la meta B AHORA MISMO (`WriteTxn::current_meta_b_page`,
///   de verdad dinámica: `INITIAL_META_B_PAGE` antes de reubicar, el
///   destino después) — cubre la inicial mientras todavía cumple ese papel,
///   y dejar de cubrirla en cuanto `relocate_meta_b` la libera es
///   precisamente lo que la vuelve a aceptar como hijo legítimo;
/// - la página destino de la reubicación (`WriteTxn::meta_b_relocation_target`,
///   siempre excluida, ANTES de que la reubicación ocurra de verdad
///   también) — sin ella, un hijo corrupto apuntando al destino se aceptaría
///   mientras `current_meta_b_page` todavía vale la inicial, justo el hueco
///   que el primer intento de esta ronda no cerraba.
fn validate_child(tx: &WriteTxn, page_no: PageNo, child: PageNo) -> Result<()> {
    if child <= tx.last_reserved_page()
        || child == tx.current_meta_b_page()
        || child == tx.meta_b_relocation_target()
        || child >= tx.n_pages()
    {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::CellBounds });
    }
    Ok(())
}

/// Comprueba que los `n_slots() + 1` punteros a hijo de un nodo interno
/// (las `n_slots()` celdas normales más `extra`) no contienen ningún
/// duplicado.
///
/// **Ronda 2 de revisión de la tarea 15, hallazgo 2.** Un nodo interno
/// corrupto con, por ejemplo, `child(0) == extra`, hace que la misma
/// página se libere DOS VECES dentro de la misma llamada a
/// `free_subtree`/`delete_range_rec` — dos dueños de una sola página tras
/// el siguiente `alloc()`, la clase de corrupción que este motor combate
/// desde la tarea 9. `validate_child` (más arriba) no cierra esto: valida
/// que CADA hijo, por separado, sea un número de página plausible, pero
/// dos hijos pueden ser cada uno perfectamente plausibles y a la vez el
/// MISMO número.
///
/// Se llama en LAS DOS ramas de `free_subtree` (con `children_plain()`
/// cierto o falso), no solo en la de bloque, porque un duplicado hace daño
/// por los dos caminos: en la de bloque, `tx.free(child)` se llama dos
/// veces directamente sobre el mismo número, sin ninguna otra
/// comprobación de por medio — el camino que se salta la recursión, así
/// que también el que hace MÁS daño, sin ni siquiera necesitar abrir la
/// página repetida una segunda vez. En la recursiva, `free_subtree` se
/// invoca dos veces sobre la MISMA página — cada invocación acaba en su
/// propio `tx.free(page_no)` al terminar, así que el resultado es el
/// mismo doble-free, solo que tarda una lectura de página más en
/// manifestarse en vez de ser instantáneo. El coste de comprobar aquí es
/// lineal en el número de hijos de ESTE nodo — unas pocas decenas como
/// mucho, dado el límite de `page_size / 4` sobre el tamaño de clave que
/// ya impone `put` — nada frente a la lectura de página que esta función
/// ya ha pagado para llegar aquí.
fn validate_no_duplicate_children(page_no: PageNo, page: &PageRef<'_>) -> Result<()> {
    let mut children: Vec<PageNo> = (0..=page.n_slots()).map(|i| child_at(page, i)).collect();
    children.sort_unstable();
    if children.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::CellBounds });
    }
    Ok(())
}

/// Libera un subárbol completo. Cuando `children_plain` lo confirma, los
/// hijos directos son hojas sin overflow y se vuelcan a la lista de libres
/// sin abrirlas — el ahorro que existe esta tarea para conseguir.
///
/// **Ronda 1 de revisión de la tarea 15, hallazgos 1+2 — CRÍTICOS.** La
/// versión original de esta función asumía el árbol equilibrado en altura
/// (bastaba abrir un hijo, el `0`, para saber si TODOS eran hojas) y, si lo
/// eran, los liberaba sin comprobar overflow. Las dos suposiciones son
/// falsas por razones documentadas en este propio fichero:
/// - `MAX_DEPTH` (más arriba) ya explica que `delete_rec` colapsa nodos
///   internos de un solo hijo sin fusionarlos con sus hermanos, así que dos
///   ramas del mismo árbol pueden acabar con profundidades distintas — y,
///   peor para esta función, un nodo interno puede acabar con una hoja en
///   una posición y un nodo interno en otra, si el hijo promovido en un
///   colapso resulta ser una hoja mientras sus hermanos siguen siendo
///   internos. Verificado por fuzzing de `put`/`delete`/`delete_range`
///   sobre un árbol de fanout bajo: 8 semillas × 150 pasos produjeron 4
///   pasos con fuga, 15 páginas perdidas — el caso mínimo pierde las hojas
///   122 y 125 en un árbol con profundidades de hoja {3, 4, 5}. Con la
///   version original, esos hermanos internos se liberaban como si fueran
///   hojas: sus subárboles enteros quedaban huérfanos (ni alcanzables ni en
///   la lista de libres) para siempre — la poda diaria de retención pierde
///   páginas de forma permanente en cualquier base que alguna vez haya
///   usado `delete`.
/// - Aunque el árbol SÍ estuviera equilibrado, una hoja liberada sin abrir
///   nunca comprueba si tiene valores de overflow — sus cadenas quedan
///   huérfanas igual. Reproducido: 3000 claves con 15 valores de 2000
///   bytes, `delete_range` sobre un tercio → 15 páginas huérfanas, exactas
///   3 cadenas × 5 páginas cada una.
///
/// La corrección: `children_plain` (`PageRef`, `page.rs`) es un bit
/// mantenido al día por CADA función que reconstruye un nodo interno
/// (`insert_rec`, `delete_rec`, `delete_range_rec`, `put`) sin lecturas
/// adicionales — ver el comentario de `Insertion` — que dice con certeza
/// "todos mis hijos DIRECTOS son hojas sin overflow". Cuando es cierto, esta
/// función libera en bloque, sin abrir nada, exactamente el atajo que
/// justifica la tarea. Cuando NO lo es (incluye tanto "hay al menos un hijo
/// interno" como "hay al menos una hoja con overflow" — las dos cierran en
/// UN solo bit, no dos, porque las dos exigen la MISMA respuesta: abrir el
/// hijo para saber qué hacer con él), recurre de verdad en cada hijo: la
/// propia llamada recursiva lee el hijo, descubre su tipo real, y si
/// resulta ser una hoja, su rama `PageType::Leaf` ya libera cualquier
/// cadena de overflow que tenga — así que el camino de "no es plano" cierra
/// los dos hallazgos a la vez con el mismo código.
///
/// **Cotas.** `depth` (profundidad de recursión real, no solo un contador:
/// esta función SÍ se llama a sí misma) se compara contra `MAX_DEPTH` antes
/// de leer nada, igual que `insert_rec`/`delete_rec`: sin ella, un ciclo de
/// páginas corruptas desbordaría la pila en vez de devolver `TreeLoop` —
/// aquí eso importa más que en las otras dos, porque esta función recurre
/// de verdad (no un bucle con pila explícita), así que desbordar la pila es
/// un fallo del propio proceso, no solo un cuelgue. `budget` (compartido
/// con `delete_range_rec`, ver `RangeBudget`) acota además el trabajo
/// TOTAL, para el caso — imposible de cerrar solo con `depth` — de un DAG
/// corrupto acíclico con hijos compartidos. Cada página se carga contra el
/// presupuesto EXACTAMENTE una vez, en la línea `budget.charge(page_no)`
/// de más arriba: a diferencia de la versión original (que además cargaba
/// el "hijo 0" por separado al comprobarlo, contándolo dos veces si luego
/// recurría sobre él), esta ya no necesita esa comprobación aparte —
/// `children_plain` viene de la propia `page` ya leída, sin ninguna lectura
/// extra.
fn free_subtree(
    tx: &mut WriteTxn,
    page_no: PageNo,
    depth: u32,
    budget: &mut RangeBudget,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::TreeLoop });
    }
    budget.charge(page_no)?;
    let bytes = tx.read_page(page_no)?;
    let page = PageRef::parse(&bytes, page_no)?;
    match page.page_type() {
        PageType::Leaf => {
            // Las cadenas de overflow sí exigen abrir la hoja, porque sus
            // páginas no aparecen en ningún padre. Solo ocurre si la hoja
            // tiene valores grandes.
            for i in 0..page.n_slots() {
                if let LeafValue::Overflow { len, first } = page.leaf_value(i) {
                    free_overflow(tx, len, first)?;
                }
            }
            tx.free(page_no);
        }
        PageType::Internal => {
            validate_no_duplicate_children(page_no, &page)?;
            let plain = page.children_plain();
            for i in 0..=page.n_slots() {
                let child = child_at(&page, i);
                validate_child(tx, page_no, child)?;
                if plain {
                    // Aquí está el ahorro: se liberan sin leerlas, porque
                    // `children_plain` ya garantiza que son hojas sin
                    // overflow.
                    tx.free(child);
                } else {
                    free_subtree(tx, child, depth + 1, budget)?;
                }
            }
            tx.free(page_no);
        }
        _ => return Err(Error::Corrupt { page: page_no, kind: CorruptKind::PageType }),
    }
    Ok(())
}

/// Rango `[from, to)` a borrar. Agrupa dos parámetros de `delete_range_rec`
/// para no acercarse al límite de argumentos de `clippy::too_many_arguments`
/// (el brief los pasa sueltos; con `depth` y `budget` añadidos para acotar
/// el recorrido, sueltos habrían sido ocho). `Copy`: se reconstruye una vez
/// por nivel de recursión, sobre referencias, así que copiarlo es tan barato
/// como pasarlo por referencia y evita una indirección más en cada llamada.
#[derive(Clone, Copy)]
struct Range<'a> {
    from: &'a [u8],
    to: &'a [u8],
}

/// `low` y `high` acotan el rango de claves que el subárbol de esta llamada
/// puede contener, derivados de los separadores de sus ancestros. Sirven
/// para decidir si el subárbol cae entero dentro del rango a borrar, sin
/// tener que leerlo para saberlo. `high: None` significa "sin cota
/// superior conocida" (el borde derecho del árbol entero); no hay
/// equivalente para `low` porque el borde izquierdo del árbol entero es
/// justo el segmento vacío, que ya representa "sin cota inferior" con
/// normalidad.
struct Bounds<'a> {
    low: &'a [u8],
    high: Option<&'a [u8]>,
}

/// Borra todas las claves de `[from, to)`. Devuelve la raíz nueva.
pub fn delete_range(tx: &mut WriteTxn, root: PageNo, from: &[u8], to: &[u8]) -> Result<PageNo> {
    if root == 0 || from >= to {
        return Ok(root);
    }
    let mut budget = RangeBudget::new(tx.n_pages());
    let range = Range { from, to };
    let bounds = Bounds { low: &[], high: None };
    match delete_range_rec(tx, root, range, bounds, 1, &mut budget)? {
        Removal::Unchanged => Ok(root),
        Removal::Updated(p, _) => Ok(p),
        Removal::Gone => Ok(0),
    }
}

/// Recorre un subárbol borrando `[range.from, range.to)`. `bounds` acota lo
/// que este subárbol puede contener (ver `Bounds`): cuando cae entero
/// dentro del rango a borrar, se descarta con `free_subtree` sin descender
/// más de lo imprescindible para saberlo.
///
/// **Cotas.** Como `insert_rec`/`delete_rec`, sigue punteros a hijos leídos
/// del disco, así que necesita la misma cota de PROFUNDIDAD (`MAX_DEPTH`):
/// sin ella, un ciclo desbordaría la pila. Pero a diferencia de esas dos
/// funciones (que descienden por un único hijo por nivel), el caso "no
/// contenido del todo" de un nodo interno recorre TODOS sus hijos — la
/// misma forma de recorrido que `free_subtree`, y expuesto al mismo DAG
/// acíclico que una cota de profundidad no ve venir. De ahí `budget`,
/// compartido con `free_subtree` — ver `RangeBudget` para el razonamiento
/// completo de las dos cotas.
fn delete_range_rec(
    tx: &mut WriteTxn,
    page_no: PageNo,
    range: Range<'_>,
    bounds: Bounds<'_>,
    depth: u32,
    budget: &mut RangeBudget,
) -> Result<Removal> {
    if depth > MAX_DEPTH {
        return Err(Error::Corrupt { page: page_no, kind: CorruptKind::TreeLoop });
    }

    // Subárbol contenido por completo: se descarta entero, sin descender
    // más de lo imprescindible.
    if bounds.low >= range.from && bounds.high.is_some_and(|h| h <= range.to) {
        free_subtree(tx, page_no, depth, budget)?;
        return Ok(Removal::Gone);
    }

    // **Corrección sobre el brief**: el suyo solo contempla el atajo de
    // arriba (contenido por completo) y no este — un subárbol que no solapa
    // el rango EN ABSOLUTO (enteramente antes de `from` o enteramente
    // después de `to`) se leía y recorría entero de todos modos, porque "no
    // cae dentro" y "cae fuera del todo" no son la misma comprobación. Sin
    // este atajo, un borrado PARCIAL en mitad de un árbol grande —el caso
    // habitual de retención, no el "borrar todo" que ya cubren las pruebas
    // del brief— lee y desciende por cada subárbol hermano que no toca el
    // rango, hasta sus hojas: `a_partial_range_delete_also_reads_far_fewer_pages_than_a_full_scan_would`
    // (`range_tests`, autorrevisión del paso 5) medía 479 páginas para
    // borrar un tercio de 20.000 entradas antes de este cambio — muy por
    // encima del techo de 200 que ya cumplía el propio borrado del árbol
    // ENTERO, la prueba del brief, precisamente porque ese caso no tiene
    // ningún subárbol "fuera del todo" que se pudiera saltar. Con el atajo,
    // la misma prueba baja a un puñado de páginas: proporcional a los
    // nodos internos que de verdad tocan el borde del rango, no al tamaño
    // del árbol entero.
    if bounds.high.is_some_and(|h| h <= range.from) || bounds.low >= range.to {
        return Ok(Removal::Unchanged);
    }

    budget.charge(page_no)?;
    let bytes = tx.read_page(page_no)?;
    let page = PageRef::parse(&bytes, page_no)?;

    match page.page_type() {
        PageType::Leaf => {
            let mut keys = Vec::new();
            let mut values = Vec::new();
            let mut changed = false;
            for i in 0..page.n_slots() {
                let k = page.key(i);
                if k.as_slice() >= range.from && k.as_slice() < range.to {
                    if let LeafValue::Overflow { len, first } = page.leaf_value(i) {
                        free_overflow(tx, len, first)?;
                    }
                    changed = true;
                    continue;
                }
                keys.push(k);
                values.push(match page.leaf_value(i) {
                    LeafValue::Inline(v) => CellPayload::Value(v),
                    LeafValue::Overflow { len, first } => CellPayload::Overflow { len, first },
                });
            }
            if !changed {
                return Ok(Removal::Unchanged);
            }
            if keys.is_empty() {
                tx.free(page_no);
                return Ok(Removal::Gone);
            }
            let entries: Vec<(Vec<u8>, CellPayload)> = keys.into_iter().zip(values).collect();
            match emit(tx, Some(page_no), PageType::Leaf, 0, &entries, false)? {
                Insertion::Updated(p, plain) => Ok(Removal::Updated(p, plain)),
                Insertion::Split { .. } => unreachable!("borrar no divide"),
            }
        }

        PageType::Internal => {
            // **Desviación deliberada del brief**: el suyo recorre los
            // hijos de derecha a izquierda y aplica cada resultado a
            // `entries` por índice (`entries[i]`, `entries.remove(i)`)
            // sobre la marcha, razonando que ir de derecha a izquierda
            // basta para que esos índices sigan siendo válidos al
            // eliminar. Eso vale para `delete_rec` (que solo toca UN
            // hijo), pero aquí puede tocar TODOS, y hay una interacción
            // que ese razonamiento no cubre: cuando el hijo `extra`
            // (posición `n`, la PRIMERA que procesa ese orden) resulta
            // `Gone`, su manejo hace `entries.pop()` de inmediato para
            // promover la última pareja a `extra` — pero en ese instante
            // esa pareja todavía es la ORIGINAL de la página (posición
            // `n-1`), porque el resultado PROPIO de la posición `n-1`
            // (que puede ser `Updated`/`Gone`, un cambio independiente del
            // de `extra`) no se calcula hasta la iteración SIGUIENTE. Esa
            // iteración entonces intenta `entries.remove(n-1)` sobre un
            // vector que el `pop()` anterior ya dejó con `n-1` elementos
            // — índice fuera de rango, pánico. Reproducido de verdad:
            // `deleting_the_whole_range_empties_the_tree` entraba en
            // pánico con "removal index (is 37) should be < len (is 37)"
            // antes de este cambio.
            //
            // La corrección: no mutar `entries` por índice sobre la
            // marcha. Se recogen los `n + 1` resultados primero (el orden
            // de recorrido ya no importa para la corrección, porque cada
            // llamada recursiva solo lee de `page`, inmutable, nunca de
            // `entries`), y LUEGO se reconstruye en una single pasada:
            // primero las `n` parejas normales (filtrando las `Gone`, sin
            // tocar índices de un vector que va cambiando de tamaño),
            // y solo al final el resultado de `extra`, que si es `Gone`
            // promueve lo que de verdad haya sobrevivido en la última
            // posición de la reconstrucción — ya con el resultado propio
            // de esa posición incorporado, no el original sin tocar.
            // Ronda 2 de revisión de la tarea 15, hallazgo 2: comprobación
            // de duplicados igual que en `free_subtree` — un `child_at`
            // repetido entre estos `n + 1` hijos procesaría la MISMA
            // página dos veces en dos llamadas recursivas distintas, cada
            // una con su propio resultado (`Updated`/`Gone`) aplicado a
            // esta reconstrucción, y potencialmente su propio `tx.free()`
            // si alguna de las dos concluye `Gone` — el mismo doble-free
            // que en `free_subtree`, por el mismo motivo estructural.
            let n = page.n_slots();
            validate_no_duplicate_children(page_no, &page)?;
            let mut results: Vec<Removal> = Vec::with_capacity(n + 1);
            for i in 0..=n {
                let child = child_at(&page, i);
                validate_child(tx, page_no, child)?;
                let child_low: &[u8] = if i == 0 { bounds.low } else { &page.key(i - 1) };
                let child_high: Option<Vec<u8>> =
                    if i == n { bounds.high.map(|h| h.to_vec()) } else { Some(page.key(i)) };

                let child_low_owned = child_low.to_vec();
                let result = delete_range_rec(
                    tx,
                    child,
                    range,
                    Bounds { low: &child_low_owned, high: child_high.as_deref() },
                    depth + 1,
                    budget,
                )?;
                results.push(result);
            }

            if results.iter().all(|r| matches!(r, Removal::Unchanged)) {
                return Ok(Removal::Unchanged);
            }

            // **Ronda 1 de revisión de la tarea 15, hallazgos 1+2**: a
            // diferencia de `insert_rec`/`delete_rec` (que solo tocan UN
            // hijo, así que basta un `bool` agregado que solo puede bajar a
            // `false`), aquí puede tocarse MÁS de un hijo en la misma
            // llamada, y el hijo que acaba promovido a `extra` en un
            // colapso puede ser exactamente uno de los que SÍ se tocó — no
            // siempre el hermano intacto, como en `delete_rec` (ver su
            // comentario). Por eso aquí cada entrada lleva su propia
            // etiqueta `plain` en vez de una sola agregada: `page.key(i)`
            // /`page.child(i)`/`plain_i`, donde `plain_i` es el resultado
            // fresco de la llamada recursiva si el hijo `i` se tocó, o
            // `page.children_plain()` (lo que YA se sabía de esta página)
            // si no se tocó — la misma aproximación conservadora que las
            // otras dos funciones, solo que por entrada en vez de una vez.
            let extra_result = results.pop().expect("se empujaron n + 1 >= 1 resultados");
            let mut entries: Vec<(Vec<u8>, CellPayload, bool)> = Vec::with_capacity(results.len());
            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Removal::Unchanged => entries.push((
                        page.key(i),
                        CellPayload::Child(page.child(i)),
                        page.children_plain(),
                    )),
                    Removal::Updated(p, plain) => {
                        entries.push((page.key(i), CellPayload::Child(p), plain))
                    }
                    Removal::Gone => {}
                }
            }
            let (extra, extra_plain) = match extra_result {
                Removal::Unchanged => (page.extra(), page.children_plain()),
                Removal::Updated(p, plain) => (p, plain),
                Removal::Gone => match entries.pop() {
                    Some((_, CellPayload::Child(c), plain)) => (c, plain),
                    Some((_, CellPayload::Value(_) | CellPayload::Overflow { .. }, _)) => {
                        unreachable!(
                            "nodo interno con valor: `entries` solo contiene `CellPayload::Child`"
                        )
                    }
                    None => (0, false),
                },
            };

            if entries.is_empty() {
                tx.free(page_no);
                return Ok(if extra == 0 {
                    Removal::Gone
                } else {
                    Removal::Updated(extra, extra_plain)
                });
            }
            let children_plain = extra_plain && entries.iter().all(|(_, _, plain)| *plain);
            let plain_entries: Vec<(Vec<u8>, CellPayload)> =
                entries.into_iter().map(|(k, c, _)| (k, c)).collect();
            match emit(
                tx,
                Some(page_no),
                PageType::Internal,
                extra,
                &plain_entries,
                children_plain,
            )? {
                Insertion::Updated(p, plain) => Ok(Removal::Updated(p, plain)),
                Insertion::Split { .. } => unreachable!("borrar no divide"),
            }
        }

        _ => Err(Error::Corrupt { page: page_no, kind: CorruptKind::PageType }),
    }
}

/// Cota de trabajo (páginas leídas) que UN SOLO `next()` puede hacer.
///
/// **Ronda 1 de revisión, hallazgo 2**: la cota de profundidad (`MAX_DEPTH`)
/// por sí sola no basta. Acota cuánto puede CRECER la pila, pero no cuántas
/// veces puede LLAMARSE `advance_to_next_leaf` dentro de una sola invocación
/// de `next()`. Un DAG corrupto (no un ciclo: cada camino individual
/// respeta `MAX_DEPTH`) derrota esa cota: `k` páginas internas donde
/// `child(0) == extra`, cada una apuntando a la siguiente y terminando en
/// una hoja vacía, mantienen todo camino raíz-hoja en `k + 1` niveles —
/// dentro de `MAX_DEPTH` sin rozar `TreeLoop` — pero hay 2^k caminos
/// DISTINTOS de esa profundidad, y `next()`, al reintentar tras cada hoja
/// vacía, los recorre todos. Medido de verdad (no supuesto): k=18 tarda
/// 1,9 s, k=20 6,3 s, k=22 25 s — duplica con cada nivel, como predice 2^k
/// — y k=45 no termina en un tiempo razonable
/// (`a_corrupt_dag_with_repeated_children_is_rejected_quickly_not_slowly`,
/// más abajo, verifica esto tanto sin la cota — con un `k` pequeño, bajo
/// `timeout` — como con ella, con un `k` que sin cota sería intratable).
/// La cota de profundidad convertía esto en "acotado" en sentido
/// matemático (2^128 es un número finito), pero no en la práctica: nada
/// distinguía esa cota de un cuelgue real. Corrección del propio informe de
/// la tarea 14, que afirmaba "acotado, no un cuelgue" sin haberlo medido.
///
/// La cota de trabajo cierra esto acotando el número TOTAL de páginas
/// leídas dentro de una sola llamada a `next()`, sumando las de
/// `next_uncommitted` y las de TODAS las llamadas a `advance_to_next_leaf`
/// que haga esa invocación — no solo la primera (`work` es una variable
/// LOCAL a `next_uncommitted`, pasada por referencia a cada llamada de
/// `advance_to_next_leaf` dentro del mismo `next()`, así que el contador
/// persiste entre reintentos consecutivos pero se reinicia en la siguiente
/// llamada pública a `next`).
///
/// Elegir el límite exige saber cuánto trabajo hace un `next()` LEGÍTIMO en
/// el peor caso, para no rechazar nunca un recorrido válido:
/// - En un árbol que solo ha pasado por `insert_rec`/`delete_rec` no hay
///   hojas vacías, así que una hoja que `advance_to_next_leaf` alcanza de
///   verdad SIEMPRE tiene al menos una entrada. Por tanto el bucle de
///   `next_uncommitted` nunca reintenta: como mucho UNA llamada a
///   `advance_to_next_leaf` por invocación de `next()`.
/// - Esa única llamada, en el peor caso, sube por TODA la pila actual
///   (hasta `MAX_DEPTH` lecturas, bucle exterior) y vuelve a bajar por la
///   rama hermana más profunda posible (hasta `MAX_DEPTH` lecturas más,
///   bucle interior): `2 · MAX_DEPTH` como cota superior legítima de esa
///   llamada.
/// - Más la lectura inicial de la hoja agotada en `next_uncommitted`:
///   `2 · MAX_DEPTH + 1` = 257 con `MAX_DEPTH = 128`.
///
/// `8 · MAX_DEPTH` = 1024 deja margen de sobra (~4× ese peor caso legítimo)
/// sin acercarse ni de lejos a los pasos que hacen falta para que el ataque
/// exponencial sea notable: con esta cota, la construcción de 2^k caminos
/// del hallazgo 2 falla con `Err` en cuanto la suma de trabajo acumulado
/// (que crece como 2^i para los primeros `i` niveles explorados, sea cual
/// sea `k`) supera 1024 — sobre `i ≈ 10`, muy por debajo de cualquier `k`
/// razonable, así que el coste de rechazar el ataque es constante, no
/// función de `k`.
const MAX_NEXT_WORK: u32 = 8 * MAX_DEPTH;

/// Recorrido ordenado. Mantiene la pila de descenso porque las hojas no están
/// encadenadas: encadenarlas obligaría, en copy-on-write, a reescribir la hoja
/// anterior cada vez que su sucesora cambia de página.
///
/// `pub`, aunque vive en un módulo `pub(crate)` (ronda 3 de revisión de la
/// tarea 16): `ReadTxn::scan` lo devuelve, así que tiene que poder nombrarse
/// desde fuera del crate aunque `tree` no sea navegable — se reexporta suelto
/// como `inro::Cursor` en `lib.rs`. `#[allow(private_bounds)]`: el aviso del
/// compilador es real (`PageSource` es `pub(crate)`, más privado que este
/// `struct` `pub`) pero inofensivo aquí — la única forma de conseguir un
/// `Cursor` es `ReadTxn::scan`, que fija `S = ReadTxn<'_>` en concreto, así
/// que nadie fuera del crate necesita nombrar `PageSource` ni puede
/// implementarlo para su propio tipo; lo que sí gana con `Cursor` público es
/// poder tipar una variable o un campo con él, que es justo lo que pide
/// nombrarlo.
#[allow(private_bounds)]
pub struct Cursor<'a, S: PageSource> {
    src: &'a S,
    /// Raíz con la que se construyó el cursor. Se recuerda para que `seek`
    /// (ronda 1 de revisión, hallazgo 4) pueda volver a descender sin que el
    /// llamante tenga que pasarla de nuevo.
    root: PageNo,
    /// Espacio de claves del cursor: `Some(ns)` para uno construido con
    /// `new` (antepone y recorta el byte `ns`), `None` para uno "crudo"
    /// construido con `new_raw` (opera directamente sobre las claves del
    /// árbol, sin transformación).
    ///
    /// **Ronda 1 de revisión, hallazgo 3**: antes había un `strip: usize`
    /// independiente del `from`/`to` que el llamante ya había escapado con
    /// `scoped` en `tx.rs` — nada impedía pasar uno sin el otro (`strip = 1`
    /// con límites sin escapar habría truncado en silencio cada clave).
    /// Guardar `ns` en vez de `strip` hace ese desajuste irrepresentable:
    /// `new` calcula `scoped(ns, from)`/`scoped(ns, to)` Y recuerda el mismo
    /// `ns` en el mismo sitio, así que el recorte (`strip_len`, más abajo) y
    /// el prefijo antepuesto nunca pueden discrepar. También cierra la fuga
    /// de diseño de que `Cursor::new` fuera público y devolviera claves con
    /// el prefijo interno de `scoped` incluido a cualquier llamante externo:
    /// ahora solo `new_raw` (`pub(crate)`, invisible fuera del crate) puede
    /// hacer eso, y solo lo usan las pruebas de este módulo.
    ns: Option<u8>,
    /// Cada nivel: página, y siguiente índice a visitar en ella.
    stack: Vec<(PageNo, usize)>,
    end: Vec<u8>,
    done: bool,
    /// `Some(e)` en cuanto cualquier operación ha devuelto `Err` una vez:
    /// el cursor queda envenenado de forma permanente y toda llamada
    /// posterior a `next` repite el MISMO error en vez de intentar seguir.
    ///
    /// **Ronda 1 de revisión, hallazgo 1**: `advance_to_next_leaf` muta
    /// `self.stack` (el `pop()` inicial del bucle exterior, el `push` del
    /// interior) ANTES de que el resto de la operación pueda fallar. Sin
    /// envenenamiento, un error a mitad de esa función deja la pila
    /// apuntando a una página que `next` da por hecho que es una hoja sin
    /// comprobarlo — puede ser una interna, cuyo formato de celda comparte
    /// el prefijo `[len_sufijo][sufijo]` con el de hoja pero no lo que
    /// sigue (`page.key` sale bien, pero `page.leaf_value` reinterpreta los
    /// 4 bytes del puntero al hijo como `[len_valor varint][valor]`, dando
    /// basura silenciosa o un pánico de slice fuera de rango si esa
    /// "longitud" no cabe en la página). Confirmado con un fallo
    /// transitorio de E/S inyectado justo en esa lectura
    /// (`a_transient_read_error_poisons_the_cursor_instead_of_returning_wrong_data`,
    /// más abajo): sin envenenar, un reintento tras el error devolvía la
    /// clave real con un valor corrupto en vez de otro `Err`. `seek` es la
    /// única forma de limpiar `poison`: es una operación nueva y deliberada
    /// del llamante, no un reintento silencioso de `next`.
    poison: Option<Error>,
}

#[allow(private_bounds)] // ver el comentario de la definición del struct, arriba.
impl<'a, S: PageSource> Cursor<'a, S> {
    /// Recorrido de `[from, to)` dentro del espacio de claves `ns`. `from` y
    /// `to` son claves SIN el byte de espacio, igual que en
    /// `get`/`put`/`delete` — el cursor antepone `ns` internamente con
    /// `scoped` (la misma transformación que usa el resto de la API) y lo
    /// recorta de cada clave que devuelve `next`.
    ///
    /// `pub(crate)` (ronda 3 de revisión de la tarea 16, más allá del cierre
    /// de la fuga de `ns` de la ronda 1 — ver el comentario de `ns` en la
    /// definición del struct): un constructor público habría dejado
    /// reconstruir un `Cursor` con cualquier `root: PageNo`, sin pasar por
    /// `ReadTxn::scan` ni por la raíz de la transacción — otro camino para
    /// leer el árbol saltándose `Db`, la misma familia de fuga que
    /// `WriteTxn::write_page`/`set_root` (ver su comentario en `tx.rs`), solo
    /// que de lectura en vez de escritura. La única vía sancionada para
    /// conseguir un `Cursor` es `ReadTxn::scan`.
    pub(crate) fn new(src: &'a S, root: PageNo, ns: u8, from: &[u8], to: &[u8]) -> Result<Self> {
        let scoped_from = crate::tx::scoped(ns, from);
        let scoped_to = crate::tx::scoped(ns, to);
        let mut c = Self::new_raw(src, root, &scoped_from, &scoped_to)?;
        c.ns = Some(ns);
        Ok(c)
    }

    /// Como `new`, pero sin anteponer ni recortar ningún byte: opera
    /// directamente sobre las claves tal como viven en el árbol.
    /// `pub(crate)`: ningún código fuera de este crate debe ver claves con
    /// el prefijo de espacio incluido, así que solo las pruebas de este
    /// módulo (que construyen árboles a mano con claves que no pasan por
    /// `scoped`) tienen acceso a este constructor.
    pub(crate) fn new_raw(src: &'a S, root: PageNo, from: &[u8], to: &[u8]) -> Result<Self> {
        let mut c = Self {
            src,
            root,
            ns: None,
            stack: Vec::new(),
            end: to.to_vec(),
            done: root == 0,
            poison: None,
        };
        if root != 0 {
            c.seek_from(root, from)?;
        }
        Ok(c)
    }

    /// Bytes a omitir del principio de cada clave que devuelve `next`:
    /// derivado de `ns` en vez de almacenado aparte — ver el comentario del
    /// campo `ns`.
    fn strip_len(&self) -> usize {
        self.ns.is_some() as usize
    }

    /// Reposiciona el cursor en la primera entrada mayor o igual que `key`,
    /// conservando el límite superior (`to`) y el espacio de claves con los
    /// que se construyó. `key` es una clave SIN el byte de espacio, igual
    /// que `from`/`to` en `new` — se antepone el mismo `ns` internamente si
    /// el cursor lo tiene (`None` para uno construido con `new_raw`).
    ///
    /// **Ronda 1 de revisión, hallazgo 4**: el brief lista
    /// `Cursor::seek(&mut self, &[u8])` en su bloque de interfaces, pero su
    /// propio código del paso 3 nunca la define — solo la `seek_from`
    /// privada, que además recibe la raíz como parámetro en vez de
    /// recordarla. Añadida como envoltorio delgado sobre `seek_from`
    /// (de ahí que el cursor ahora guarde `self.root`), limpiando `done` y
    /// `poison`: es una operación nueva que el llamante elige hacer
    /// explícitamente, a diferencia de reintentar `next` tras un error, que
    /// `next` sigue rechazando mientras el cursor esté envenenado.
    pub fn seek(&mut self, key: &[u8]) -> Result<()> {
        let scoped_key;
        let full: &[u8] = match self.ns {
            Some(ns) => {
                scoped_key = crate::tx::scoped(ns, key);
                &scoped_key
            }
            None => key,
        };
        self.poison = None;
        self.done = self.root == 0;
        if self.root != 0
            && let Err(e) = self.seek_from(self.root, full)
        {
            self.poison = Some(e);
            return Err(e);
        }
        Ok(())
    }

    /// Desciende hasta la primera entrada mayor o igual que `key`.
    ///
    /// Sigue punteros a hijos leídos del disco, igual que `descend`, así que
    /// necesita la misma cota de profundidad: sin ella, un ciclo de páginas
    /// corruptas lo dejaría descendiendo para siempre en vez de devolver
    /// `TreeLoop`. `depth` cuenta la página actual, igual que en `descend` (la
    /// raíz entra con `depth == 1`) — válido aquí porque `self.stack` se
    /// vacía justo antes (`clear()`), así que `depth` y `self.stack.len()`
    /// coinciden en todo momento del bucle.
    fn seek_from(&mut self, root: PageNo, key: &[u8]) -> Result<()> {
        self.stack.clear();
        let mut current = root;
        let mut depth = 0u32;
        loop {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(Error::Corrupt { page: current, kind: CorruptKind::TreeLoop });
            }
            let bytes = self.src.read_page(current)?;
            let page = PageRef::parse(&bytes, current)?;
            match page.page_type() {
                PageType::Leaf => {
                    let idx = match search_key(&page, key) {
                        Ok(i) => i,
                        Err(i) => i,
                    };
                    self.stack.push((current, idx));
                    return Ok(());
                }
                PageType::Internal => {
                    let idx = child_index(&page, key);
                    self.stack.push((current, idx));
                    current = child_at(&page, idx);
                }
                _ => return Err(Error::Corrupt { page: current, kind: CorruptKind::PageType }),
            }
        }
    }

    /// Cuenta una lectura de página contra el presupuesto de trabajo de la
    /// invocación actual de `next()` — ver `MAX_NEXT_WORK`.
    fn charge(work: &mut u32, page: PageNo) -> Result<()> {
        *work += 1;
        if *work > MAX_NEXT_WORK {
            return Err(Error::Corrupt { page, kind: CorruptKind::TreeLoop });
        }
        Ok(())
    }

    /// Sube por la pila hasta encontrar un nodo con hijos pendientes y vuelve
    /// a bajar por su borde izquierdo. `work` es el presupuesto compartido
    /// de la llamada a `next()` que originó esta invocación — ver
    /// `MAX_NEXT_WORK` y `next_uncommitted`.
    ///
    /// El bucle EXTERIOR (el que sube) está acotado por construcción, sin
    /// necesitar contador: cada vuelta empieza con un `pop()` incondicional,
    /// así que no puede dar más vueltas que elementos tenía la pila al
    /// entrar — decrece en uno por iteración hasta vaciarse, sin importar si
    /// los datos están corruptos.
    ///
    /// El bucle INTERIOR (el que baja por el borde izquierdo de un hermano)
    /// SÍ sigue punteros a hijos leídos del disco y, como `seek_from` y
    /// `descend`, necesita cota de profundidad — sin ella, un ciclo entre
    /// páginas corruptas alcanzables solo desde un hermano (no desde la
    /// posición inicial que validó `seek_from`) lo dejaría bajando para
    /// siempre. La diferencia importante con `seek_from` es dónde EMPIEZA el
    /// contador: aquí `depth` arranca en `self.stack.len()`, la profundidad
    /// YA alcanzada por la pila existente, no en cero. Arrancar en cero
    /// sería un error sutil: acotaría cada llamada a `advance_to_next_leaf`
    /// por separado a 128 empujes, pero nada impediría que la pila total
    /// creciera sin límite a través de MUCHAS llamadas sucesivas (cada una
    /// saca al menos un nivel y puede volver a empujar hasta 128), porque el
    /// contador nunca se enteraría de cuánto había ya acumulado. Arrancar en
    /// `self.stack.len()` mantiene la invariante real que importa —
    /// `self.stack` es un camino raíz-a-hoja y nunca debe superar
    /// `MAX_DEPTH` niveles, exactamente lo que ya garantiza `descend` para un
    /// único descenso— válida en todo momento de la vida del cursor, no solo
    /// dentro de una llamada.
    ///
    /// Esa cota de profundidad, por sí sola, NO basta contra un DAG corrupto
    /// (no un ciclo) donde cada camino individual respeta `MAX_DEPTH` pero
    /// hay exponencialmente muchos caminos distintos — de ahí `work` y
    /// `MAX_NEXT_WORK`, ver su comentario.
    fn advance_to_next_leaf(&mut self, work: &mut u32) -> Result<bool> {
        loop {
            self.stack.pop();
            let Some((page_no, idx)) = self.stack.last_mut() else {
                return Ok(false);
            };
            let page_no = *page_no;
            Self::charge(work, page_no)?;
            let bytes = self.src.read_page(page_no)?;
            let page = PageRef::parse(&bytes, page_no)?;
            // `extra` es el hijo con índice `n_slots`, así que hay hijo
            // siguiente mientras el índice no lo haya superado.
            if *idx >= page.n_slots() {
                continue;
            }
            *idx += 1;
            let mut current = child_at(&page, *idx);
            let mut depth = self.stack.len() as u32;
            loop {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(Error::Corrupt { page: current, kind: CorruptKind::TreeLoop });
                }
                Self::charge(work, current)?;
                let bytes = self.src.read_page(current)?;
                let p = PageRef::parse(&bytes, current)?;
                self.stack.push((current, 0));
                match p.page_type() {
                    PageType::Leaf => return Ok(true),
                    PageType::Internal => current = child_at(&p, 0),
                    _ => return Err(Error::Corrupt { page: current, kind: CorruptKind::PageType }),
                }
            }
        }
    }

    /// `Cursor` no implementa `Iterator` a propósito: cada paso puede fallar
    /// (E/S, corrupción — ver `MAX_DEPTH` en `seek_from` y
    /// `advance_to_next_leaf`), y `Iterator::next` no tiene sitio para
    /// devolver un `Err`. `Result<Option<_>>` es el patrón establecido para
    /// iteración falible; el nombre `next` es el que fija la interfaz de
    /// esta tarea. `should_implement_trait` confunde esto con
    /// `Iterator::next`, que devolvería `Option<_>` sin más — deliberado,
    /// no un descuido.
    ///
    /// Envoltorio delgado sobre `next_uncommitted` (ronda 1 de revisión,
    /// hallazgo 1): si esa función devuelve `Err`, por lo que sea, este es
    /// el ÚNICO sitio que hace falta tocar para envenenar el cursor —
    /// cualquier `?` nuevo que se añada dentro de `next_uncommitted` o de
    /// `advance_to_next_leaf` en el futuro queda cubierto automáticamente,
    /// sin tener que acordarse de marcar `poison` en cada punto de retorno
    /// disperso por esas dos funciones.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if let Some(e) = self.poison {
            return Err(e);
        }
        let result = self.next_uncommitted();
        if let Err(e) = result {
            self.poison = Some(e);
        }
        result
    }

    /// Cuerpo real de `next`, sin el envenenamiento — separado para que
    /// `next` pueda interceptar CUALQUIER `Err` que salga de aquí (incluidos
    /// los que vengan de `advance_to_next_leaf`) en un solo sitio.
    fn next_uncommitted(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut work = 0u32;
        loop {
            if self.done {
                return Ok(None);
            }
            let Some(&(leaf, idx)) = self.stack.last() else {
                self.done = true;
                return Ok(None);
            };
            Self::charge(&mut work, leaf)?;
            let bytes = self.src.read_page(leaf)?;
            let page = PageRef::parse(&bytes, leaf)?;

            if idx >= page.n_slots() {
                if !self.advance_to_next_leaf(&mut work)? {
                    self.done = true;
                    return Ok(None);
                }
                continue;
            }

            if let Some((_, i)) = self.stack.last_mut() {
                *i += 1;
            }

            let key = page.key(idx);
            // La comparación con `end` es sobre la clave COMPLETA tal como
            // vive en el árbol (con cualquier prefijo de `scoped` incluido,
            // porque `end` también lo lleva — ver `new`), no sobre la que
            // se devuelve más abajo: recortar antes rompería el orden en
            // cuanto `strip_len()` fuera mayor que cero.
            if key.as_slice() >= self.end.as_slice() {
                self.done = true;
                return Ok(None);
            }
            let value = match page.leaf_value(idx) {
                LeafValue::Inline(v) => v.to_vec(),
                LeafValue::Overflow { len, first } => read_overflow(self.src, len, first)?,
            };
            let strip = self.strip_len();
            debug_assert!(
                strip <= key.len(),
                "strip ({strip}) no puede superar la longitud de la clave ({})",
                key.len()
            );
            return Ok(Some((key[strip.min(key.len())..].to_vec(), value)));
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

    /// Regresión del hallazgo 3 de la revisión de la tarea 11, ACTUALIZADA
    /// por la tarea 13. Entonces, cuando `emit` no podía construir una hoja
    /// de una sola entrada porque el VALOR era demasiado grande (no la
    /// clave, diminuta aquí), `put` fallaba con `KeyTooLarge` reportando la
    /// longitud de la celda completa. Con páginas de overflow ese camino ya
    /// no es alcanzable para un valor por sí solo: `put` lo convierte en una
    /// referencia de ~22 bytes (ver `overflow_threshold`) antes de que
    /// `emit` llegue a verlo, así que la inserción debe tener éxito y el
    /// valor debe leerse de vuelta intacto — la propiedad que comprueba
    /// ahora esta prueba. Se conserva el valor de 2000 bytes del caso
    /// original para que quede constancia de qué escenario dejó de fallar.
    #[test]
    fn a_value_too_large_for_a_single_page_now_succeeds_via_overflow() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let huge_value = alloc::vec![0u8; 2000];
        let root = put(&mut tx, 0, b"k", &huge_value).unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().unwrap(), huge_value);
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

    /// `true` si `child` es, de verdad, una hoja sin ninguna entrada de
    /// overflow — abriéndola para comprobarlo, al contrario que
    /// `free_subtree`, que existe precisamente para no tener que hacerlo.
    /// Aquí, en una prueba, sí toca: es el criterio de verdad contra el que
    /// `check_invariants` contrasta el bit `children_plain()`.
    fn child_is_actually_plain(tx: &impl PageSource, child: PageNo) -> bool {
        let bytes = tx.read_page(child).unwrap();
        let page = PageRef::parse(&bytes, child).unwrap();
        page.page_type() == PageType::Leaf
            && (0..page.n_slots())
                .all(|i| !matches!(page.leaf_value(i), LeafValue::Overflow { .. }))
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
                // Un nodo interno con cero separadores tiene un único hijo:
                // no ramifica, añade profundidad sin ningún beneficio, y es
                // exactamente el nodo degenerado del que depende el
                // argumento de `MAX_DEPTH`. `put` nunca lo produce (una
                // división interna necesita al menos tres entradas, ver el
                // `debug_assert` de `emit`) y `delete_rec` lo colapsa en vez
                // de dejarlo persistir (la rama `entries.is_empty()`). Sin
                // esta comprobación, `check_invariants` recorrería ese nodo
                // igual que cualquier otro y nunca vería el propio caso que
                // debería delatar.
                assert!(
                    page.n_slots() >= 1,
                    "nodo interno {page_no} sin separadores: un solo hijo, degenerado"
                );
                // Tarea 15, ronda 1 de revisión, hallazgos 1+2: si esta
                // página afirma `children_plain()`, TODOS sus hijos
                // DIRECTOS deben ser hojas sin overflow de verdad —
                // `free_subtree` (`tree.rs`) se fía de este bit para
                // liberarlos sin abrirlos, así que un falso positivo aquí
                // es exactamente el defecto que causó las dos fugas
                // críticas. Reutilizar `check_invariants` para esta
                // comprobación es deliberado: ya se llama tras cargas de
                // churn aleatorio extensas en varias pruebas de este
                // fichero (inserción/borrado intercalados, órdenes
                // aleatorios), así que cualquier caso en el que
                // `insert_rec`/`delete_rec`/`delete_range_rec` calculen mal
                // el bit se delata aquí, gratis, sin necesitar una prueba
                // dedicada por cada camino que lo actualiza.
                if page.children_plain() {
                    for i in 0..page.n_slots() {
                        assert!(
                            child_is_actually_plain(tx, page.child(i)),
                            "nodo interno {page_no} afirma children_plain() pero el hijo \
                             {} (página {}) no es una hoja sin overflow",
                            i,
                            page.child(i)
                        );
                    }
                    assert!(
                        child_is_actually_plain(tx, page.extra()),
                        "nodo interno {page_no} afirma children_plain() pero su hijo extra \
                         (página {}) no es una hoja sin overflow",
                        page.extra()
                    );
                }
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

    /// Repetir puts sobre la MISMA clave, DENTRO de la misma transacción sin
    /// confirmar, no debe hacer crecer el fichero proporcionalmente al
    /// número de actualizaciones.
    ///
    /// Es la propiedad que motivó el hallazgo 1 de la ronda 2 de revisión de
    /// esta tarea: el camino de inserción copy-on-write libera la página
    /// vieja en cada `put`, así que 2000 actualizaciones de la misma clave
    /// liberan 2000 páginas — casi todas asignadas por esta misma
    /// transacción un instante antes. Sin el conjunto propio de páginas
    /// (`WriteTxn::own_free` / `self_allocated`, `src/tx.rs`), que
    /// distingue "página que esta transacción asignó y ya liberó ella
    /// misma" (reciclable de inmediato, nunca la vio la meta confirmada) de
    /// "página heredada del árbol confirmado" (protegida hasta el commit,
    /// hallazgo 1 de la ronda 1), cada una de esas 2000 páginas habría
    /// consumido una página nueva del fichero en vez de reciclar la
    /// anterior — el escenario exacto del lote de mil registros que describe
    /// el hallazgo: miles de páginas por transacción, casi todas liberadas,
    /// ninguna reciclable hasta el commit.
    #[test]
    fn repeated_updates_to_one_key_do_not_leak_pages_within_one_transaction() {
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
        // serializarse (la PRIMERA página, heredada del commit anterior a
        // esta transacción, sí queda protegida hasta que ESTA transacción
        // confirme — eso cuenta como una página adicional, no como 2000):
        // nada que crezca proporcionalmente al número de puts.
        assert!(
            size_after_2000_updates <= size_after_first_commit + 4096,
            "el fichero creció de {size_after_first_commit} a {size_after_2000_updates} bytes \
             tras 2000 actualizaciones de la misma clave en una sola transacción: páginas \
             filtradas en vez de recicladas dentro de la transacción"
        );
    }

    /// Repetir puts sobre la MISMA clave, en UNA transacción confirmada
    /// aparte de la que hace las 2000 actualizaciones, no debe hacer crecer
    /// el fichero proporcionalmente a ellas. Complementa (no sustituye) a
    /// `repeated_updates_to_one_key_do_not_leak_pages_within_one_transaction`,
    /// que prueba el reciclado DENTRO de una misma transacción sin
    /// confirmar (`WriteTxn::own_free`, hallazgo 1 de la ronda 2 de
    /// revisión de la tarea 12): esta prueba, en cambio, arranca una
    /// SEGUNDA ronda de 2000 actualizaciones en una transacción NUEVA
    /// después de que la primera ronda confirme, y comprueba que esa
    /// segunda ronda recicla lo que liberó la primera — porque para
    /// entonces esas páginas ya son parte de una transacción confirmada
    /// más antigua que la actual, no de la que las liberó (hallazgo 1 de
    /// la ronda 1). Las dos propiedades — reciclado intra-transacción y
    /// reciclado entre transacciones confirmadas — son independientes y
    /// las dos importan; de ahí las dos pruebas.
    #[test]
    fn repeated_updates_to_one_key_do_not_leak_pages_once_committed() {
        let storage = alloc::sync::Arc::new(MemStorage::new());
        let db =
            Db::create(alloc::boxed::Box::new(ArcStorage(storage.clone())), Options::default())
                .unwrap();

        let mut tx = db.begin_write().unwrap();
        let mut root = put(&mut tx, 0, b"k", b"0").unwrap();
        tx.set_root(root);
        tx.commit().unwrap();

        // Primera ronda: 2000 actualizaciones en una única transacción sin
        // confirmar hasta el final. El fichero SÍ crece durante esta ronda
        // — ninguna de las páginas que libera es reciclable todavía — y eso
        // es esperado, no lo que se comprueba.
        let mut tx = db.begin_write().unwrap();
        for i in 0..2000u32 {
            root = put(&mut tx, root, b"k", &i.to_le_bytes()).unwrap();
        }
        tx.set_root(root);
        tx.commit().unwrap();
        let size_after_first_round = storage.snapshot().len();

        // Segunda ronda, idéntica, en una transacción NUEVA: ahora las 2000
        // páginas que liberó la primera ronda ya son parte de una
        // transacción confirmada más antigua, así que esta ronda debería
        // reciclarlas casi todas en vez de extender el fichero otra vez.
        let mut tx = db.begin_write().unwrap();
        for i in 2000..4000u32 {
            root = put(&mut tx, root, b"k", &i.to_le_bytes()).unwrap();
        }
        tx.set_root(root);
        tx.commit().unwrap();
        let size_after_second_round = storage.snapshot().len();

        let r = db.begin_read();
        assert_eq!(get(&r, r.root(), b"k").unwrap().as_deref(), Some(&3999u32.to_le_bytes()[..]));
        // Una hoja de una sola clave no debería requerir más páginas que al
        // final de la primera ronda, salvo lo que ocupa volcar a disco la
        // propia lista de libres: `Freelist::flush` reescribe el grupo
        // recién liberado entero en páginas nuevas cada vez que confirma
        // (nunca reutiliza mientras serializa, para no ser recursivo, ver
        // su comentario en `freelist.rs`), así que confirmar la liberación
        // de 2000 páginas cuesta unas ~17 páginas de lista de libres por sí
        // solo. Ese coste es proporcional al TAMAÑO de un commit, no al
        // NÚMERO de operaciones dentro de él — muy por debajo de la escala
        // (cientos de KB, crecimiento sin límite) que delataría una fuga de
        // verdad.
        assert!(
            size_after_second_round <= size_after_first_round + 16384,
            "el fichero creció de {size_after_first_round} a {size_after_second_round} bytes \
             en la segunda ronda: páginas de una transacción ya confirmada que no se \
             reciclaron"
        );
    }

    /// La carga que justifica el hallazgo 1 de la ronda 2 de revisión de la
    /// tarea 12: un lote de 1000 registros de log DISTINTOS, en una sola
    /// transacción, tal como escribiría el escritor de borde real que
    /// menciona el hallazgo. Cada `put` de clave nueva recorre y libera el
    /// camino raíz→hoja que acaba de tocar (copia en escritura), así que
    /// 1000 puts liberan miles de páginas — casi todas asignadas por esta
    /// misma transacción un instante antes.
    ///
    /// Medido a mano antes de esta prueba (`cargo test
    /// probe_batch_growth_before_round_2`, sobre el commit anterior a esta
    /// ronda, sin `own_free`/`self_allocated`): 1 480 704 bytes, 2892
    /// páginas de 512 — sin reciclar dentro de la transacción, casi 3
    /// páginas por `put`. Con el conjunto propio de páginas: 94 208 bytes,
    /// 184 páginas — una reducción de ~15,7×. El techo de esta prueba dejó
    /// bastante margen sobre las 184 medidas y bien por debajo de las 2892
    /// de antes, para que un futuro cambio que rompa el reciclado intra-
    /// transacción falle aquí, ruidosamente.
    #[test]
    fn a_batch_of_many_distinct_puts_does_not_grow_the_file_a_page_per_put() {
        let storage = alloc::sync::Arc::new(MemStorage::new());
        let db =
            Db::create(alloc::boxed::Box::new(ArcStorage(storage.clone())), Options::default())
                .unwrap();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in 0..1000u32 {
            root = put(
                &mut tx,
                root,
                alloc::format!("log/{i:06}").as_bytes(),
                b"registro de ejemplo de la carga real",
            )
            .unwrap();
        }
        tx.set_root(root);
        tx.commit().unwrap();
        let size = storage.snapshot().len();
        let page_size = 512usize;
        assert!(
            size <= 400 * page_size,
            "el fichero mide {size} bytes ({} páginas de {page_size}) tras 1000 puts \
             distintos en una sola transacción: muy por encima de las ~184 que hacen falta de \
             verdad, señal de que el reciclado intra-transacción dejó de funcionar",
            size / page_size
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
    /// seguidas, DENTRO de la misma transacción sin confirmar (un commit
    /// por ciclo, no dos), no debe hacer crecer el fichero sin límite.
    ///
    /// Es la propiedad que motivó el hallazgo 1 de la ronda 2 de revisión de
    /// esta tarea: borrar 400 claves libera del orden de 400+ páginas
    /// (hojas vacías y nodos internos colapsados), casi todas asignadas por
    /// la construcción original o por ciclos anteriores — es decir,
    /// heredadas de una transacción confirmada previa la primera vez, pero
    /// una vez que esta transacción las reasigna en la fase de reinserción
    /// del MISMO ciclo, quedan marcadas como propias (`self_allocated`) y
    /// cualquier borrado posterior DENTRO de esta misma transacción las
    /// recicla de inmediato via `own_free`, sin esperar a un commit.
    #[test]
    fn deleting_everything_then_reinserting_does_not_leak_pages_within_one_transaction() {
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
            // Borrado y reinserción en la MISMA transacción, un solo
            // commit al final del ciclo.
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

        // Solo el PRIMER borrado de cada ciclo libera páginas heredadas de
        // fuera de esta transacción (protegidas hasta que confirme); el
        // resto, dentro del mismo ciclo, son páginas que la propia
        // reinserción del ciclo anterior ya había vuelto a asignar — y esas
        // sí se reciclan de inmediato. El margen cubre el coste legítimo de
        // volcar la lista de libres en los tres commits, no una fuga.
        assert!(
            size_after_cycles <= size_after_build + 16384,
            "el fichero creció de {size_after_build} a {size_after_cycles} bytes tras ciclos \
             de borrado + reinserción en una sola transacción cada uno: páginas filtradas en \
             vez de recicladas dentro de la transacción"
        );
    }

    /// Borrar TODAS las claves de un árbol y reinsertarlas, varias veces
    /// seguidas, EN TRANSACCIONES SEPARADAS (borrado y reinserción de cada
    /// ciclo, cada una con su propio commit), no debe hacer crecer el
    /// fichero sin límite.
    ///
    /// Complementa (no sustituye) a
    /// `deleting_everything_then_reinserting_does_not_leak_pages_within_one_transaction`,
    /// que prueba el reciclado DENTRO de una misma transacción sin
    /// confirmar (hallazgo 1 de la ronda 2 de revisión de la tarea 12,
    /// `WriteTxn::own_free`): esta prueba, en cambio, demuestra que el
    /// reciclado también funciona ENTRE transacciones confirmadas — la
    /// meta confirmada es un lector implícito de sus propias páginas solo
    /// hasta que la transacción que las libera confirme (hallazgo 1 de la
    /// ronda 1), así que la reinserción de un ciclo, en su propia
    /// transacción después de que el borrado del mismo ciclo confirme, sí
    /// puede reciclar lo que ese borrado liberó. Las dos propiedades son
    /// independientes y las dos importan.
    #[test]
    fn deleting_everything_then_reinserting_does_not_leak_pages_across_commits() {
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
            // Fase de borrado, en su propia transacción y su propio commit:
            // deja las 400 páginas del árbol previamente confirmado libres
            // y, en cuanto confirma, reciclables.
            let mut tx = db.begin_write().unwrap();
            let mut root = tx.root();
            for i in 0..n {
                let (r, existed) =
                    delete(&mut tx, root, alloc::format!("k/{i:05}").as_bytes()).unwrap();
                assert!(existed, "clave {i}");
                root = r;
            }
            assert_eq!(root, 0, "el árbol vacío no deja raíz");
            tx.set_root(root);
            tx.commit().unwrap();

            // Fase de reinserción, en una transacción NUEVA: para esta
            // transacción, las páginas que acaba de liberar el borrado ya
            // pertenecen a una transacción confirmada más antigua que ella
            // misma, así que sí son reciclables.
            let mut tx = db.begin_write().unwrap();
            let mut root = 0;
            for i in 0..n {
                root = put(&mut tx, root, alloc::format!("k/{i:05}").as_bytes(), b"v").unwrap();
            }
            tx.set_root(root);
            tx.commit().unwrap();
        }
        let size_after_cycles = storage.snapshot().len();

        // Igual que en `repeated_updates_to_one_key_do_not_leak_pages_once_committed`:
        // el margen cubre el coste legítimo de volcar la lista de libres en
        // cada uno de los seis commits (borrado + reinserción, tres
        // ciclos), no una fuga — sigue muy por debajo de lo que costaría
        // que las páginas de un ciclo entero (400 claves) dejaran de
        // reciclarse.
        assert!(
            size_after_cycles <= size_after_build + 65536,
            "el fichero creció de {size_after_build} a {size_after_cycles} bytes tras ciclos \
             completos de borrado + reinserción: páginas filtradas en vez de recicladas"
        );
    }

    /// Regresión del hallazgo 2 de la revisión de la tarea 12: colapsar un
    /// nodo interno de un solo hijo rompe el balance de altura (ver el
    /// comentario de `MAX_DEPTH`), así que el churn sostenido debe medirse,
    /// no darse por acotado con la fórmula de un árbol balanceado.
    ///
    /// Construye un árbol de 800 claves cercanas al límite de `page_size /
    /// 4` (el peor caso de ramificación: sin prefijo común, separadores
    /// grandes), lo somete a 15 000 ciclos de "desalojo aleatorio +
    /// inserción en el borde" — el patrón de retención con desorden que
    /// dispersa los colapsos por varios nodos internos en vez de
    /// concentrarlos siempre en la misma rama — y comprueba tanto que la
    /// profundidad SÍ crece (si dejara de hacerlo, esta prueba habría
    /// dejado de ejercitar el fenómeno) como que se queda por debajo de un
    /// techo medido. Un cambio futuro que empeore la deriva debe fallar
    /// aquí, ruidosamente, en vez de comerse en silencio el margen que le
    /// queda a `MAX_DEPTH`.
    #[test]
    fn churn_grows_depth_but_stays_within_the_measured_ceiling() {
        let key_for = |i: u32| -> Vec<u8> {
            let mut k = alloc::format!("{i:07}").into_bytes();
            k.resize(127, b'k');
            k
        };
        let n = 800u32;
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        for i in 0..n {
            root = put(&mut tx, root, &key_for(i), b"v").unwrap();
        }

        // Profundidad máxima sobre una muestra de hasta 200 claves vivas,
        // repartidas uniformemente por el conjunto (no solo las primeras):
        // recorrer las 800/15800 enteras en cada medición sería
        // desproporcionado frente al propio churn.
        let sampled_max_depth = |tx: &WriteTxn, root: PageNo, live: &[u32]| -> usize {
            let mut max_depth = 0usize;
            for (sampled, &i) in live.iter().enumerate() {
                if sampled % (live.len() / 200).max(1) != 0 {
                    continue;
                }
                let (_, path) = descend(tx, root, &key_for(i)).unwrap().unwrap();
                max_depth = max_depth.max(path.len() + 1);
            }
            max_depth
        };

        let initial: Vec<u32> = (0..n).collect();
        let balanced = sampled_max_depth(&tx, root, &initial);

        let mut rng = Rng(0xDEAD_BEEF);
        let mut live: Vec<u32> = (0..n).collect();
        for newest in (n..).take(15_000usize) {
            let idx = (rng.next() as usize) % live.len();
            let victim = live.swap_remove(idx);
            let (r, existed) = delete(&mut tx, root, &key_for(victim)).unwrap();
            assert!(existed, "clave {victim}");
            root = put(&mut tx, r, &key_for(newest), b"v").unwrap();
            live.push(newest);
        }

        let churned = sampled_max_depth(&tx, root, &live);
        assert!(
            churned > balanced,
            "el churn no aumentó la profundidad ({balanced} -> {churned}): esta prueba dejó de \
             ejercitar la deriva de balance que motivó el hallazgo 2"
        );
        assert!(
            churned <= 14,
            "profundidad {churned} tras el churn (balanceada: {balanced}): muy por encima del \
             techo medido con esta semilla (9) — o `MAX_DEPTH` (128) deja de tener margen real, \
             o algo empeoró la deriva sin que nadie se enterase"
        );

        let mut visited = alloc::collections::BTreeSet::new();
        check_invariants(&tx, root, None, None, &mut visited);
    }
}

/// Nota sobre `#[cfg]`: el brief de la tarea 13 escribe este módulo con
/// `#[cfg(test)]` a secas. Se usa aquí `#[cfg(all(test, feature = "std"))]`
/// en su lugar, igual que el resto de módulos de prueba de este fichero
/// (`tests`, `put_tests`, `invariant_tests`, `delete_tests`,
/// `delete_invariant_tests`): `tree.rs` entero solo se compila con la
/// característica `std` (ver `lib.rs`), así que es redundante en la
/// práctica, pero mantiene el fichero consistente consigo mismo.
#[cfg(all(test, feature = "std"))]
mod overflow_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    #[test]
    fn threshold_is_a_quarter_of_the_page() {
        assert_eq!(overflow_threshold(512), 128);
        assert_eq!(overflow_threshold(4096), 1024);
    }

    #[test]
    fn a_large_value_roundtrips_through_the_overflow_chain() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let root = put(&mut tx, 0, b"grande", &big).unwrap();
        assert_eq!(get(&tx, root, b"grande").unwrap().unwrap(), big);
    }

    #[test]
    fn an_empty_value_is_not_treated_as_overflow() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let root = put(&mut tx, 0, b"vacio", b"").unwrap();
        assert_eq!(get(&tx, root, b"vacio").unwrap().as_deref(), Some(b"".as_slice()));
    }

    #[test]
    fn overwriting_a_large_value_frees_the_old_chain() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let big = alloc::vec![7u8; 5000];
        let root = put(&mut tx, 0, b"k", &big).unwrap();
        let before = tx.pages_in_use();
        let root = put(&mut tx, root, b"k", b"pequeno").unwrap();
        assert!(tx.pages_in_use() < before, "la cadena antigua se libera");
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(b"pequeno".as_slice()));
    }

    #[test]
    fn deleting_a_large_value_frees_the_chain() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let big = alloc::vec![7u8; 20_000];
        let root = put(&mut tx, 0, b"k", &big).unwrap();
        let before = tx.pages_in_use();
        let (root, _) = delete(&mut tx, root, b"k").unwrap();
        assert_eq!(root, 0);
        assert!(tx.pages_in_use() < before);
    }

    /// Contrato completo del auto-review de la tarea 13: sustituir un valor
    /// grande por uno pequeño, ese por otro grande, y borrarlo, no debe
    /// dejar ni una página de más (fuga) ni de menos (liberación doble)
    /// respecto al árbol vacío del que se partió. `baseline` se toma ANTES
    /// del primer `put`, no después: comparar contra el estado
    /// verdaderamente vacío es lo que hace la aserción final exacta
    /// (`==`), no solo una cota.
    #[test]
    fn replacing_large_with_small_then_large_again_then_deleting_returns_to_baseline() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();

        let big1 = alloc::vec![1u8; 5000];
        let root = put(&mut tx, 0, b"k", &big1).unwrap();
        let after_big1 = tx.pages_in_use();
        assert!(after_big1 > baseline, "la cadena de overflow de big1 debe consumir páginas");

        let root = put(&mut tx, root, b"k", b"pequeno").unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(b"pequeno".as_slice()));
        let after_small = tx.pages_in_use();
        assert!(after_small < after_big1, "la cadena de big1 debe liberarse al reemplazarlo");

        let big2 = alloc::vec![2u8; 9000];
        let root = put(&mut tx, root, b"k", &big2).unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().unwrap(), big2);
        let after_big2 = tx.pages_in_use();
        assert!(after_big2 > after_small, "la nueva cadena grande debe consumir páginas");

        let (root, existed) = delete(&mut tx, root, b"k").unwrap();
        assert!(existed);
        assert_eq!(root, 0);
        let after_delete = tx.pages_in_use();
        assert_eq!(
            after_delete, baseline,
            "tras sustituir un valor grande por uno pequeño, por otro grande, y borrarlo, no \
             debe quedar ni una página de más ni de menos respecto al árbol vacío original"
        );
    }

    /// Borrar una hoja entera con VARIOS valores grandes debe liberar TODAS
    /// sus cadenas, no solo la de la primera clave que se borre. Las tres
    /// claves son de un solo byte y comparten hoja (caben de sobra en una
    /// sola página: cada celda de overflow ocupa un puñado de bytes fijos,
    /// nunca el valor entero).
    #[test]
    fn deleting_a_leaf_with_several_large_values_frees_every_chain() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let mut root = 0;
        let keys = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
        let values: Vec<Vec<u8>> =
            (0..keys.len()).map(|i| alloc::vec![(i + 1) as u8; 3000]).collect();
        for (k, v) in keys.iter().zip(values.iter()) {
            root = put(&mut tx, root, k, v).unwrap();
        }
        for (k, v) in keys.iter().zip(values.iter()) {
            assert_eq!(get(&tx, root, k).unwrap().as_deref(), Some(v.as_slice()));
        }
        let before = tx.pages_in_use();
        for k in keys.iter() {
            let (r, existed) = delete(&mut tx, root, k).unwrap();
            assert!(existed, "clave {k:?}");
            root = r;
        }
        assert_eq!(root, 0);
        let after = tx.pages_in_use();
        // Cota floja a propósito (no exacta): lo que importa es que se
        // libere bastante más que solo las hojas — cada valor de 3000
        // bytes necesita varias páginas de overflow (492 bytes de
        // capacidad por página a 512 de tamaño de página) — no una idea
        // frágil de cuántas exactas.
        assert!(
            after + 6 <= before,
            "borrar tres valores de ~3000 bytes debe liberar bastante más que solo la hoja: \
             antes {before}, después {after}"
        );
    }

    /// Frontera del umbral: un valor de exactamente `overflow_threshold`
    /// bytes se guarda EN LÍNEA, no en overflow — el límite es `>`, no
    /// `>=`, igual que el que `put` ya le impone a las claves (tarea 11).
    /// `pages_in_use` lo delata: en línea, reemplazar el valor solo cambia
    /// la hoja (copy-on-write, +1/-1 páginas); con overflow, además
    /// consume página(s) de cadena.
    #[test]
    fn value_exactly_at_the_threshold_stays_inline_one_byte_over_goes_to_overflow() {
        let db = db();
        assert_eq!(overflow_threshold(512), 128);

        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();
        let at_threshold = alloc::vec![9u8; 128];
        let root = put(&mut tx, 0, b"k", &at_threshold).unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(at_threshold.as_slice()));
        let pages_inline = tx.pages_in_use();
        assert_eq!(pages_inline, baseline + 1, "128 bytes en línea: solo la página de la hoja");

        let over_threshold = alloc::vec![9u8; 129];
        let root = put(&mut tx, root, b"k", &over_threshold).unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().unwrap(), over_threshold);
        let pages_overflow = tx.pages_in_use();
        assert!(
            pages_overflow > pages_inline,
            "129 bytes debe ir a overflow y consumir al menos una página más que 128 en línea"
        );
    }

    /// Un byte por debajo del umbral también se queda en línea: mismo coste
    /// en páginas que en el límite exacto (solo la hoja).
    #[test]
    fn value_one_byte_under_the_threshold_stays_inline() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();
        let under = alloc::vec![9u8; 127];
        let root = put(&mut tx, 0, b"k", &under).unwrap();
        assert_eq!(get(&tx, root, b"k").unwrap().as_deref(), Some(under.as_slice()));
        assert_eq!(tx.pages_in_use(), baseline + 1, "127 bytes en línea: solo la página de la hoja");
    }

    /// Construye a mano una página de overflow cruda, con el mismo formato
    /// que produce `write_overflow`, para poder fabricar cadenas corruptas
    /// (un ciclo) que ese código nunca produciría por sí solo.
    fn raw_overflow_page(page_size: u32, next: PageNo, data: &[u8]) -> Vec<u8> {
        let mut b = alloc::vec![0u8; page_size as usize];
        b[0] = PageType::Overflow as u8;
        b[12..16].copy_from_slice(&next.to_le_bytes());
        b[4..6].copy_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        b[6..8].copy_from_slice(&(page_size as u16).to_le_bytes());
        b[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + data.len()].copy_from_slice(data);
        let mut h = crate::crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        b[8..12].copy_from_slice(&h.finish().to_le_bytes());
        b
    }

    /// Dos páginas de overflow que se apuntan la una a la otra: no hay
    /// ninguna página con `next == 0` alcanzable. `free_overflow` no
    /// acumula nada (solo libera páginas), así que su única condición de
    /// salida normal es `current == 0` — sin la cota de `ceil(len /
    /// capacidad)`, este bucle sería literalmente infinito, no solo lento.
    /// `len` aquí es arbitrario (cinco páginas de capacidad): solo fija
    /// cuántas vueltas tolera antes de rendirse, no cambia que el ciclo
    /// nunca deja `current == 0` por sí solo.
    #[test]
    fn free_overflow_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let a = tx.alloc().unwrap();
        let b = tx.alloc().unwrap();
        let page_size = tx.logical_page_size();

        tx.write_page(a, &raw_overflow_page(page_size, b, b"aa")).unwrap();
        tx.write_page(b, &raw_overflow_page(page_size, a, b"bb")).unwrap();

        let capacity = (page_size as usize - PAGE_HEADER_SIZE) as u64;
        let len = capacity * 5;
        let err = free_overflow(&mut tx, len, a).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::OverflowLoop, .. }),
            "se esperaba OverflowLoop, se obtuvo {err:?}"
        );
    }

    /// Misma cadena cíclica que la prueba anterior, pero ejercitando
    /// `read_overflow`. Fija la regresión de la ronda de revisión posterior
    /// a la primera entrega (hallazgo 1): antes de la comprobación
    /// `current != 0` que añadió esa ronda, esta misma llamada devolvía
    /// `Ok` con 2460 bytes repetidos (`A,B,A,B,A`) en vez de fallar — la
    /// cota de saltos por sí sola no distingue un ciclo de páginas
    /// uniformes de una cadena legítima de ese tamaño (ver el comentario de
    /// `read_overflow`). Ahora debe devolver `OverflowLoop`: la cadena
    /// nunca llega a su propia `next == 0`.
    #[test]
    fn read_overflow_rejects_a_cycle_instead_of_returning_wrong_data() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let a = tx.alloc().unwrap();
        let b = tx.alloc().unwrap();
        let page_size = tx.logical_page_size();

        tx.write_page(a, &raw_overflow_page(page_size, b, b"aa")).unwrap();
        tx.write_page(b, &raw_overflow_page(page_size, a, b"bb")).unwrap();

        let capacity = (page_size as usize - PAGE_HEADER_SIZE) as u64;
        let len = capacity * 5;
        let err = read_overflow(&tx, len, a).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::OverflowLoop, .. }),
            "se esperaba OverflowLoop, se obtuvo {err:?}"
        );
    }
}

#[cfg(all(test, feature = "std"))]
mod cursor_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    fn seeded() -> Db {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..1000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), &i.to_le_bytes()).unwrap();
        }
        tx.put(0x02, b"otro", b"espacio").unwrap();
        tx.commit().unwrap();
        db
    }

    #[test]
    fn scan_visits_every_key_in_order() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"", b"\xff\xff\xff\xff\xff\xff").unwrap();
        let mut seen = 0u32;
        while let Some((k, v)) = c.next().unwrap() {
            assert_eq!(k, alloc::format!("{seen:06}").as_bytes());
            assert_eq!(v, seen.to_le_bytes());
            seen += 1;
        }
        assert_eq!(seen, 1000);
    }

    #[test]
    fn scan_respects_the_range_bounds() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"000100", b"000110").unwrap();
        let mut keys = alloc::vec::Vec::new();
        while let Some((k, _)) = c.next().unwrap() {
            keys.push(k);
        }
        assert_eq!(keys.len(), 10, "el límite superior es exclusivo");
        assert_eq!(keys[0], b"000100");
        assert_eq!(keys[9], b"000109");
    }

    #[test]
    fn a_scan_never_crosses_into_another_keyspace() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"", b"\xff\xff\xff\xff\xff\xff").unwrap();
        let mut n = 0;
        while c.next().unwrap().is_some() {
            n += 1;
        }
        assert_eq!(n, 1000, "la clave del espacio 0x02 no aparece");
    }

    #[test]
    fn get_is_scoped_by_keyspace() {
        let db = seeded();
        let r = db.begin_read();
        assert_eq!(r.get(0x02, b"otro").unwrap().as_deref(), Some(b"espacio".as_slice()));
        assert_eq!(r.get(0x01, b"otro").unwrap(), None);
    }

    // --- Auto-review: contrato falsable de la tarea 14 --------------------
    //
    // "Un recorrido sobre [from, to) produce exactamente las claves de ese
    // rango, en orden ascendente, cada una una sola vez, y nunca una clave
    // de otro espacio de claves." Las cuatro pruebas del brief ya cubren
    // varios casos (recorrido completo, límites internos, aislamiento de
    // espacio, `get` con espacio). Las que siguen cubren el resto de casos
    // pedidos explícitamente por el auto-review: árbol vacío, rango vacío,
    // coincidencia de una sola clave, cruce de un límite de hoja real
    // (verificado con `descend`, no supuesto), y un valor de overflow leído
    // a través del cursor.

    #[test]
    fn scan_on_an_empty_tree_yields_nothing() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"", b"\xff").unwrap();
        assert_eq!(c.next().unwrap(), None);
    }

    /// `from == to`: el rango `[from, to)` está vacío por definición, así que
    /// no debe visitarse ninguna clave — ni siquiera una que exista de
    /// verdad exactamente en ese punto.
    #[test]
    fn scan_with_from_equal_to_to_yields_nothing() {
        let db = seeded();
        let r = db.begin_read();
        assert!(r.get(0x01, b"000500").unwrap().is_some(), "la clave existe de verdad");
        let mut c = r.scan(0x01, b"000500", b"000500").unwrap();
        assert_eq!(c.next().unwrap(), None);
    }

    /// Rango que solo contiene una clave: `to` es el sucesor inmediato de
    /// `from` en el espacio de claves sembrado.
    #[test]
    fn scan_matching_exactly_one_key() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"000500", b"000501").unwrap();
        assert_eq!(c.next().unwrap(), Some((b"000500".to_vec(), 500u32.to_le_bytes().to_vec())));
        assert_eq!(c.next().unwrap(), None);
    }

    /// Localiza, entre las 1000 claves sembradas, un punto donde dos claves
    /// consecutivas viven en hojas físicamente distintas — sin asumirlo, se
    /// comprueba con `descend`, el mismo mecanismo que usa el árbol para
    /// descender. Con páginas de 512 bytes y 1000 claves de ~12 bytes por
    /// celda, ese punto existe de sobra bastante antes del final.
    #[test]
    fn scan_crosses_a_real_leaf_boundary_correctly() {
        let db = seeded();
        let r = db.begin_read();
        let keys: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..1000u32).map(|i| alloc::format!("{i:06}").into_bytes()).collect();

        let boundary = (0..keys.len() - 1)
            .find(|&i| {
                let scoped_a = {
                    let mut k = alloc::vec![0x01u8];
                    k.extend_from_slice(&keys[i]);
                    k
                };
                let scoped_b = {
                    let mut k = alloc::vec![0x01u8];
                    k.extend_from_slice(&keys[i + 1]);
                    k
                };
                let (leaf_a, _) = descend(&r, r.root(), &scoped_a).unwrap().unwrap();
                let (leaf_b, _) = descend(&r, r.root(), &scoped_b).unwrap().unwrap();
                leaf_a != leaf_b
            })
            .expect("con 1000 claves en páginas de 512 bytes debe haber al menos un límite de hoja");

        // Un pequeño rango a caballo entre las dos hojas: dos claves antes
        // del límite y tres después.
        let from_i = boundary.saturating_sub(2);
        let to_i = core::cmp::min(boundary + 3, keys.len() - 1);
        let mut c = r.scan(0x01, &keys[from_i], &keys[to_i]).unwrap();
        let mut seen = alloc::vec::Vec::new();
        while let Some((k, v)) = c.next().unwrap() {
            seen.push((k, v));
        }
        let expected: alloc::vec::Vec<_> = (from_i..to_i)
            .map(|i| (keys[i].clone(), (i as u32).to_le_bytes().to_vec()))
            .collect();
        assert_eq!(seen, expected, "límite de hoja en {boundary}: hojas {from_i}..{to_i}");
    }

    /// El valor de una clave puede vivir en una cadena de overflow (tarea
    /// 13). `next` debe devolverlo completo igual que si estuviera en línea
    /// — se ejercita explícitamente la rama `LeafValue::Overflow` de
    /// `next`, no se asume que el camino en línea la cubre.
    #[test]
    fn scan_returns_a_value_stored_via_overflow() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        tx.put(0x01, b"grande", &big).unwrap();
        tx.put(0x01, b"pequeno", b"x").unwrap();
        tx.put(0x01, b"zzz", b"y").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        let mut c = r.scan(0x01, b"", b"\xff").unwrap();
        let mut found = alloc::collections::BTreeMap::new();
        while let Some((k, v)) = c.next().unwrap() {
            found.insert(k, v);
        }
        assert_eq!(found.len(), 3);
        assert_eq!(found.get(b"grande".as_slice()).unwrap(), &big);
        assert_eq!(found.get(b"pequeno".as_slice()).unwrap().as_slice(), b"x");
        assert_eq!(found.get(b"zzz".as_slice()).unwrap().as_slice(), b"y");
    }

    /// Construye a mano dos páginas internas que se apuntan la una a la
    /// otra, alcanzables SOLO desde un hermano (no desde el camino inicial
    /// que valida `seek_from`), para forzar el paso por el bucle interior de
    /// `advance_to_next_leaf`. Sin la cota de profundidad que ese bucle
    /// necesita igual que `descend` y `seek_from`, esta prueba colgaría el
    /// proceso en vez de terminar con `TreeLoop`.
    #[test]
    fn advance_to_next_leaf_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let l1 = tx.alloc().unwrap();
        let cycle_a = tx.alloc().unwrap();
        let cycle_b = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let leaf =
            PageBuilder::new(512, PageType::Leaf).build(&[(b"aa".as_slice(), CellPayload::Value(b"1"))]).unwrap();

        let mut ab = PageBuilder::new(512, PageType::Internal);
        ab.set_extra(cycle_b);
        let pa = ab.build(&[]).unwrap();

        let mut bb = PageBuilder::new(512, PageType::Internal);
        bb.set_extra(cycle_a);
        let pb = bb.build(&[]).unwrap();

        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(cycle_a);
        let rt = rb.build(&[(b"b".as_slice(), CellPayload::Child(l1))]).unwrap();

        tx.write_page(l1, &leaf).unwrap();
        tx.write_page(cycle_a, &pa).unwrap();
        tx.write_page(cycle_b, &pb).unwrap();
        tx.write_page(root, &rt).unwrap();
        tx.set_root(root);
        tx.commit().unwrap();

        let r = db.begin_read();
        let mut c = Cursor::new_raw(&r, r.root(), b"", b"\xff").unwrap();
        // La primera clave viene del subárbol normal, sin tocar el ciclo.
        assert_eq!(c.next().unwrap(), Some((b"aa".to_vec(), b"1".to_vec())));
        // Agotar `l1` obliga a `advance_to_next_leaf` a subir hasta la raíz
        // y bajar por su `extra`, que es donde vive el ciclo.
        let err = c.next().unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    /// Mismo ciclo que la prueba anterior, pero alcanzable directamente
    /// desde la raíz: ejercita la cota de `seek_from`, no la de
    /// `advance_to_next_leaf`.
    #[test]
    fn seek_from_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let cycle_a = tx.alloc().unwrap();
        let cycle_b = tx.alloc().unwrap();

        let mut ab = PageBuilder::new(512, PageType::Internal);
        ab.set_extra(cycle_b);
        let pa = ab.build(&[]).unwrap();

        let mut bb = PageBuilder::new(512, PageType::Internal);
        bb.set_extra(cycle_a);
        let pb = bb.build(&[]).unwrap();

        tx.write_page(cycle_a, &pa).unwrap();
        tx.write_page(cycle_b, &pb).unwrap();
        tx.set_root(cycle_a);
        tx.commit().unwrap();

        let r = db.begin_read();
        let err = match Cursor::new_raw(&r, r.root(), b"", b"\xff") {
            Ok(_) => panic!("se esperaba TreeLoop, el cursor se construyó sin error"),
            Err(e) => e,
        };
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    // --- Ronda 1 de revisión: pruebas de los cuatro hallazgos ------------

    /// `PageSource` de pruebas que delega en uno real, pero devuelve
    /// `Error::Io` en la llamada a `read_page` número `fail_at`, una sola
    /// vez, para simular un fallo transitorio de E/S en medio de un
    /// recorrido — sin depender del inyector de fallos de la tarea 20, que
    /// todavía no existe.
    struct FlakySource<'a, S: PageSource> {
        inner: &'a S,
        calls: core::cell::Cell<u32>,
        fail_at: u32,
    }

    impl<'a, S: PageSource> PageSource for FlakySource<'a, S> {
        fn read_page(&self, page: PageNo) -> Result<alloc::sync::Arc<[u8]>> {
            let n = self.calls.get() + 1;
            self.calls.set(n);
            if n == self.fail_at {
                return Err(crate::Error::Io(crate::error::IoError::Other(5)));
            }
            self.inner.read_page(page)
        }
    }

    /// Hallazgo 1: reconstruye el mecanismo exacto que encontró la
    /// revisión. Un árbol de tres páginas — `root` (interno, una entrada:
    /// separador "b" -> hijo `l1`, `extra` = `l2`), `l1` (hoja, una
    /// entrada) y `l2` (hoja, una entrada) — sin nada corrupto.
    ///
    /// Cuenta de lecturas hasta el punto exacto (verificada a mano, no
    /// supuesta): `Cursor::new` (que llama a `seek_from`) lee `root` (1) y
    /// `l1` (2); el primer `next()` relee `l1` (3) y devuelve su única
    /// entrada; el segundo `next()` relee `l1` (4, agotada) y entra en
    /// `advance_to_next_leaf`, cuya primera lectura (5) es la del padre
    /// (`root`) en el bucle EXTERIOR — la lectura que decide si queda algún
    /// hermano pendiente. Inyectar el fallo justo ahí deja la pila con
    /// `(root, 0)` en la posición que `next` SIEMPRE trata como hoja, sin
    /// comprobar `page_type()`.
    ///
    /// Sin el envenenamiento del hallazgo 1, un reintento posterior
    /// releería `root` (esta vez con éxito, simulando que el fallo
    /// transitorio ya pasó), lo trataría como una hoja, y devolvería la
    /// clave real "b" (el formato `[len_sufijo][sufijo]` es compartido
    /// entre celda de hoja e interna, así que esa parte sale bien) con un
    /// "valor" formado por los 4 bytes crudos del puntero al hijo `l1`,
    /// reinterpretados como `[len_valor varint][valor]` — basura silenciosa
    /// sobre un árbol perfectamente válido, exactamente lo que el `.expect`
    /// que se quitó de `scan` (tarea 14) pretendía evitar pero no evitaba
    /// del todo.
    #[test]
    fn a_transient_read_error_poisons_the_cursor_instead_of_returning_wrong_data() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let l1 = tx.alloc().unwrap();
        let l2 = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let leaf1 =
            PageBuilder::new(512, PageType::Leaf).build(&[(b"aa".as_slice(), CellPayload::Value(b"1"))]).unwrap();
        let leaf2 =
            PageBuilder::new(512, PageType::Leaf).build(&[(b"zz".as_slice(), CellPayload::Value(b"2"))]).unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(l2);
        let rt = rb.build(&[(b"b".as_slice(), CellPayload::Child(l1))]).unwrap();

        tx.write_page(l1, &leaf1).unwrap();
        tx.write_page(l2, &leaf2).unwrap();
        tx.write_page(root, &rt).unwrap();
        tx.set_root(root);
        tx.commit().unwrap();

        let r = db.begin_read();
        let flaky = FlakySource { inner: &r, calls: core::cell::Cell::new(0), fail_at: 5 };
        let mut c = Cursor::new_raw(&flaky, r.root(), b"", b"\xff").unwrap();

        assert_eq!(c.next().unwrap(), Some((b"aa".to_vec(), b"1".to_vec())));

        let err = match c.next() {
            Err(e) => e,
            Ok(v) => panic!("se esperaba Err por el fallo inyectado, se obtuvo {v:?}"),
        };
        assert!(matches!(err, crate::Error::Io(_)), "se esperaba Io, se obtuvo {err:?}");

        // La parte que importa: el cursor debe quedar envenenado. Sin ello,
        // esta llamada devolvía `Ok(Some((b"b", <basura>)))` en vez de
        // repetir el error.
        match c.next() {
            Err(e2) => assert_eq!(e2, err, "un cursor envenenado debe repetir el mismo error"),
            Ok(v) => panic!("el cursor envenenado devolvió un valor en vez de repetir el error: {v:?}"),
        }
        // Y se queda así: no es un fallo de una sola vez que se olvida.
        match c.next() {
            Err(e3) => assert_eq!(e3, err),
            Ok(v) => panic!("el cursor envenenado devolvió un valor en la tercera llamada: {v:?}"),
        }
    }

    /// Hallazgo 2: `k` páginas internas con `child(0) == extra`, cada una
    /// apuntando a la siguiente, terminando en una hoja vacía. Cada camino
    /// raíz-hoja tiene solo `k + 1` niveles — muy por debajo de `MAX_DEPTH`
    /// — pero hay 2^k caminos distintos de esa profundidad, y `next()`, al
    /// reintentar tras cada hoja vacía, los recorre todos si nada más lo
    /// detiene. Con `k = 60`, 2^60 es intratable — la prueba en sí ya
    /// demuestra que la cota de trabajo funciona con creces si termina en
    /// un tiempo razonable, sin necesidad de medir microsegundos exactos.
    ///
    /// La versión sin cota de trabajo de esta prueba (con `k` mucho menor,
    /// para que sea medible) SÍ se verificó por separado, revirtiendo
    /// temporalmente `MAX_NEXT_WORK` y cronometrando bajo `timeout` — ver el
    /// informe de la ronda 1 para los números.
    #[test]
    fn a_corrupt_dag_with_repeated_children_is_rejected_quickly_not_slowly() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();

        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let k = 60u32; // muy por debajo de MAX_DEPTH (128); 2^60 caminos.
        let mut next_page = leaf;
        let mut root = leaf;
        for _ in 0..k {
            let p = tx.alloc().unwrap();
            let mut b = PageBuilder::new(512, PageType::Internal);
            b.set_extra(next_page);
            let bytes = b.build(&[(b"k".as_slice(), CellPayload::Child(next_page))]).unwrap();
            tx.write_page(p, &bytes).unwrap();
            next_page = p;
            root = p;
        }
        tx.set_root(root);
        tx.commit().unwrap();

        let r = db.begin_read();
        let mut c = Cursor::new_raw(&r, r.root(), b"", b"\xff").unwrap();
        let start = std::time::Instant::now();
        let err = match c.next() {
            Err(e) => e,
            Ok(v) => panic!("se esperaba Err por exceso de trabajo, se obtuvo {v:?}"),
        };
        let elapsed = start.elapsed();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
        assert!(
            elapsed.as_secs() < 2,
            "con la cota de trabajo esto debe fallar rápido, no explorar 2^{k} caminos: tardó {elapsed:?}"
        );
    }

    /// Hallazgo 4: `Cursor::seek` reposiciona un cursor ya construido sin
    /// tener que crear otro. Sobre un cursor con espacio de claves (`ns` =
    /// `Some`), `seek` recibe la clave SIN el prefijo, igual que `from`/`to`
    /// en `new`. `seek` reposiciona solo el punto de partida — el límite
    /// superior `to` con el que se construyó el cursor no cambia (la firma
    /// del brief, `seek(&mut self, &[u8])`, solo tiene sitio para una
    /// clave) — así que aquí se usa un `to` que cubre de sobra el punto al
    /// que se reposiciona, no uno más estrecho como el de `scan` de la
    /// primera parte de la prueba.
    #[test]
    fn seek_repositions_an_already_constructed_cursor() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"", b"\xff").unwrap();
        assert_eq!(c.next().unwrap(), Some((b"000000".to_vec(), 0u32.to_le_bytes().to_vec())));

        c.seek(b"000500").unwrap();
        assert_eq!(
            c.next().unwrap(),
            Some((b"000500".to_vec(), 500u32.to_le_bytes().to_vec())),
            "seek debe reposicionar, no seguir donde se quedó"
        );
        assert_eq!(c.next().unwrap(), Some((b"000501".to_vec(), 501u32.to_le_bytes().to_vec())));
    }

    /// `seek` también debe limpiar `done`: seguir de un cursor que ya había
    /// terminado (por agotar el árbol, no el límite superior — con `to =
    /// "\xff"` el único modo de agotarse es que `advance_to_next_leaf`
    /// devuelva `false`, es decir, recorrer de verdad hasta la última clave
    /// del espacio) sin que quede "pegado" a `None` para siempre. `from =
    /// "000998"` deja solo dos claves reales antes de ese final, para no
    /// tener que consumir las 1000 sembradas.
    #[test]
    fn seek_clears_done_on_an_exhausted_cursor() {
        let db = seeded();
        let r = db.begin_read();
        let mut c = r.scan(0x01, b"000998", b"\xff").unwrap();
        assert_eq!(c.next().unwrap(), Some((b"000998".to_vec(), 998u32.to_le_bytes().to_vec())));
        assert_eq!(c.next().unwrap(), Some((b"000999".to_vec(), 999u32.to_le_bytes().to_vec())));
        assert_eq!(c.next().unwrap(), None, "el cursor agotó el árbol de verdad");

        c.seek(b"000010").unwrap();
        assert_eq!(
            c.next().unwrap(),
            Some((b"000010".to_vec(), 10u32.to_le_bytes().to_vec())),
            "seek debe revivir un cursor agotado"
        );
    }

    /// `seek` también debe limpiar `poison`: es la única forma documentada
    /// de recuperar un cursor tras un error, y debe funcionar de verdad.
    #[test]
    fn seek_clears_poison_on_a_failed_cursor() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        let l1 = tx.alloc().unwrap();
        let l2 = tx.alloc().unwrap();
        let root = tx.alloc().unwrap();

        let leaf1 =
            PageBuilder::new(512, PageType::Leaf).build(&[(b"aa".as_slice(), CellPayload::Value(b"1"))]).unwrap();
        let leaf2 =
            PageBuilder::new(512, PageType::Leaf).build(&[(b"zz".as_slice(), CellPayload::Value(b"2"))]).unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(l2);
        let rt = rb.build(&[(b"b".as_slice(), CellPayload::Child(l1))]).unwrap();

        tx.write_page(l1, &leaf1).unwrap();
        tx.write_page(l2, &leaf2).unwrap();
        tx.write_page(root, &rt).unwrap();
        tx.set_root(root);
        tx.commit().unwrap();

        let r = db.begin_read();
        let flaky = FlakySource { inner: &r, calls: core::cell::Cell::new(0), fail_at: 5 };
        let mut c = Cursor::new_raw(&flaky, r.root(), b"", b"\xff").unwrap();
        assert_eq!(c.next().unwrap(), Some((b"aa".to_vec(), b"1".to_vec())));
        assert!(c.next().is_err(), "el fallo inyectado debe envenenar el cursor");
        assert!(c.next().is_err(), "sigue envenenado sin haber hecho seek");

        // `seek` no vuelve a tocar la lectura fallida (ya la consumió
        // `FlakySource`): a partir de aquí las lecturas tienen éxito, así
        // que reposicionar debe funcionar con normalidad.
        c.seek(b"zz").unwrap();
        assert_eq!(c.next().unwrap(), Some((b"zz".to_vec(), b"2".to_vec())));
    }
}

/// Tarea 15, paso 1: pruebas del brief tal cual, con la única desviación de
/// usar `#[cfg(all(test, feature = "std"))]` en vez de `#[cfg(test)]` a
/// secas — igual que el resto de módulos de prueba de este fichero (ver el
/// comentario de `overflow_tests`): `tree.rs` entero solo se compila con la
/// característica `std`, así que es redundante en la práctica pero mantiene
/// el fichero consistente consigo mismo.
#[cfg(all(test, feature = "std"))]
mod range_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    fn seeded(n: u32) -> Db {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..n {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.commit().unwrap();
        db
    }

    /// Tarea 15, ronda 2 de revisión, hallazgo 3: `children_plain` es
    /// monótono e IRREVERSIBLE por nodo (ver el comentario de
    /// `CHILDREN_PLAIN_FLAG` en `page.rs`, donde viven los números
    /// medidos que esta prueba guarda como regresión permanente). Dos
    /// afirmaciones, cada una con su propia asserción:
    /// - El churn puro (borrar y reinsertar valores normales, sin
    ///   overflow) NO envenena el árbol: el coste tras 4000 ciclos se
    ///   queda cerca del de un árbol recién sembrado.
    /// - Un valor de overflow escrito una sola vez bajo un nodo, aunque se
    ///   borre después, SÍ le cuesta a ese nodo su camino rápido para
    ///   siempre — el coste sube con el número de nodos que llegaron a
    ///   tocar un valor así, no con el número de entradas borradas.
    #[test]
    fn an_overflow_value_ever_written_costs_its_node_the_fast_path_permanently() {
        let read_middle_third = |db: &Db| -> u64 {
            let before = db.pages_read();
            let mut tx = db.begin_write().unwrap();
            tx.delete_range(0x01, b"006000", b"013000").unwrap();
            let read = db.pages_read() - before;
            tx.commit().unwrap();
            read
        };

        let fresh = seeded(20_000);
        let fresh_read = read_middle_third(&fresh);

        let churned = seeded(20_000);
        let mut tx = churned.begin_write().unwrap();
        for i in 0..4000u32 {
            tx.delete(0x01, alloc::format!("{i:06}").as_bytes()).unwrap();
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.commit().unwrap();
        let churned_read = read_middle_third(&churned);
        assert!(
            churned_read <= fresh_read + 20,
            "el churn sin overflow envenenó el árbol: fresco={fresh_read}, tras 4000 \
             ciclos={churned_read}"
        );

        let one_poisoned_leaf = seeded(20_000);
        let mut tx = one_poisoned_leaf.begin_write().unwrap();
        tx.put(0x01, b"010000", &alloc::vec![7u8; 2000]).unwrap();
        tx.delete(0x01, b"010000").unwrap();
        tx.commit().unwrap();
        let one_poisoned_read = read_middle_third(&one_poisoned_leaf);
        assert!(
            one_poisoned_read > fresh_read,
            "una sola hoja que tuvo overflow, ya borrado, no subió el coste: \
             fresco={fresh_read}, con una hoja envenenada={one_poisoned_read}"
        );

        let all_poisoned = seeded(20_000);
        let mut tx = all_poisoned.begin_write().unwrap();
        for i in 0..20_000u32 {
            let key = alloc::format!("{i:06}");
            tx.put(0x01, key.as_bytes(), &alloc::vec![7u8; 2000]).unwrap();
            tx.delete(0x01, key.as_bytes()).unwrap();
            tx.put(0x01, key.as_bytes(), b"v").unwrap();
        }
        tx.commit().unwrap();
        let all_poisoned_read = read_middle_third(&all_poisoned);
        assert!(
            all_poisoned_read > 4 * fresh_read,
            "todas las hojas tuvieron overflow, ya borrado, pero el coste no subió ni 4×: \
             fresco={fresh_read}, con todas envenenadas={all_poisoned_read}"
        );
    }

    #[test]
    fn deletes_exactly_the_requested_range() {
        let db = seeded(2000);
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"000500", b"001500").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..2000u32 {
            let key = alloc::format!("{i:06}");
            let present = r.get(0x01, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, !(500..1500).contains(&i), "clave {key}");
        }
    }

    /// `delete_range(ns, b"", b"\xff\xff\xff\xff")` es el idioma del brief
    /// para "todo el espacio de claves `ns`", y se repite tal cual en varias
    /// pruebas de este módulo. **Hallazgo 7 del informe de revisión de la
    /// ronda 1**: NO es literalmente "todo" — deja fuera cualquier clave
    /// `>= b"\xff\xff\xff\xff"` (por ejemplo `b"\xff\xff\xff\xff\x00"` o
    /// `b"\xff\xff\xff\xff\xff"`), porque `to` es un límite EXCLUSIVO de 4
    /// bytes concretos, no "infinito". Se conserva el idioma tal cual lo da
    /// el brief — es exacto para las claves que sí siembran las pruebas de
    /// este módulo (como mucho 7 bytes, "NNNNNN" o variantes cortas, todas
    /// muy por debajo de ese límite) — pero el nombre de la prueba
    /// ("_the_whole_range_", no "todo el espacio de claves posible") es la
    /// afirmación correcta: vacía el árbol PORQUE ninguna clave sembrada
    /// llega a `\xff\xff\xff\xff`, no porque el idioma cubra el espacio de
    /// claves entero en general.
    #[test]
    fn deleting_the_whole_range_empties_the_tree() {
        let db = seeded(2000);
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"", b"\xff\xff\xff\xff").unwrap();
        tx.commit().unwrap();
        assert_eq!(db.begin_read().root(), 0);
    }

    #[test]
    fn it_does_not_touch_other_keyspaces() {
        let db = seeded(500);
        let mut tx = db.begin_write().unwrap();
        tx.put(0x02, b"vecino", b"intacto").unwrap();
        tx.delete_range(0x01, b"", b"\xff\xff\xff\xff").unwrap();
        tx.commit().unwrap();
        let r = db.begin_read();
        assert_eq!(r.get(0x02, b"vecino").unwrap().as_deref(), Some(b"intacto".as_slice()));
    }

    #[test]
    fn it_reads_far_fewer_pages_than_it_frees() {
        let db = seeded(20_000);
        let before = db.pages_read();
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"", b"\xff\xff\xff\xff").unwrap();
        let read = db.pages_read() - before;
        tx.commit().unwrap();
        // Con 20.000 entradas hay del orden de 1.500 hojas de 512 B. Leer
        // menos de 200 páginas demuestra que no se recorren las hojas.
        assert!(read < 200, "se leyeron {read} páginas");
    }

    #[test]
    fn freed_pages_come_back_into_use() {
        let db = seeded(5000);
        let mut tx = db.begin_write().unwrap();
        let before = tx.pages_in_use();
        tx.delete_range(0x01, b"", b"\xff\xff\xff\xff").unwrap();
        assert!(tx.pages_in_use() < before / 2, "se libera la mayor parte del árbol");
        tx.commit().unwrap();
    }

    // A partir de aquí, autorrevisión del paso 5: casos adversariales que el
    // brief no pide, elegidos para poner a prueba el contrato falsable
    // ("`delete_range(from, to)` borra exactamente `[from, to)`, deja
    // legible todo lo demás, libera cada página de cada subárbol borrado
    // exactamente una vez, y lee un número de páginas proporcional a los
    // nodos internos") en sus bordes: rango vacío, un rango de una sola
    // clave, límites alineados y desalineados con hojas/subárboles, un
    // rango que cae entero dentro de una única hoja, valores de overflow, y
    // aislamiento de espacio de claves en el borde `0xff`.

    #[test]
    fn an_empty_range_is_a_no_op() {
        let db = seeded(200);
        let mut tx = db.begin_write().unwrap();
        let root_before = tx.root();
        tx.delete_range(0x01, b"000050", b"000050").unwrap();
        assert_eq!(tx.root(), root_before, "from == to no debe tocar el árbol");
        tx.delete_range(0x01, b"000100", b"000050").unwrap();
        assert_eq!(tx.root(), root_before, "from > to no debe tocar el árbol");
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..200u32 {
            let key = alloc::format!("{i:06}");
            assert!(r.get(0x01, key.as_bytes()).unwrap().is_some(), "clave {key}");
        }
    }

    #[test]
    fn a_range_covering_exactly_one_key_removes_only_that_key() {
        let db = seeded(200);
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"000099", b"000100").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..200u32 {
            let key = alloc::format!("{i:06}");
            let present = r.get(0x01, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, i != 99, "clave {key}");
        }
    }

    /// Pocas entradas cortas: el árbol entero cabe en una sola hoja, así que
    /// la raíz es directamente esa hoja, sin nodos internos. Ejercita el
    /// camino donde la raíz nunca puede acogerse al atajo de "subárbol
    /// contenido entero" (su `high` heredado es siempre `None`, ver el
    /// comentario de `delete_range_rec`) y se procesa entrada por entrada.
    #[test]
    fn a_range_entirely_inside_a_single_leaf_removes_only_those_keys() {
        let db = seeded(10);
        let mut tx = db.begin_write().unwrap();
        let root = tx.root();
        let bytes = tx.read_page(root).unwrap();
        assert_eq!(
            PageRef::parse(&bytes, root).unwrap().page_type(),
            PageType::Leaf,
            "la prueba asume que 10 claves cortas caben en una sola hoja"
        );
        tx.delete_range(0x01, b"000003", b"000007").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..10u32 {
            let key = alloc::format!("{i:06}");
            let present = r.get(0x01, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, !(3..7).contains(&i), "clave {key}");
        }
    }

    /// `from`/`to` coinciden con claves reales del árbol (posibles
    /// separadores), no con puntos intermedios: el caso alineado, frente al
    /// desalineado que ya ejercitan `deletes_exactly_the_requested_range` y
    /// `a_range_covering_exactly_one_key_removes_only_that_key`.
    #[test]
    fn range_boundaries_exactly_on_real_keys_are_still_half_open() {
        let db = seeded(3000);
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"001000", b"002000").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert!(r.get(0x01, b"000999").unwrap().is_some(), "justo antes de from, debe sobrevivir");
        assert_eq!(r.get(0x01, b"001000").unwrap(), None, "from es inclusivo");
        assert_eq!(r.get(0x01, b"001999").unwrap(), None, "justo antes de to, debe borrarse");
        assert!(r.get(0x01, b"002000").unwrap().is_some(), "to es exclusivo, debe sobrevivir");
    }

    /// Valores grandes bien dentro de un tramo que se borra ENTERO
    /// (500..2500 de 3000): si su hoja cae dentro de un subárbol
    /// completamente contenido, la libera `free_subtree`, no el camino de
    /// hoja límite de `delete_range_rec` — el camino de overflow de
    /// `free_subtree` (`if let LeafValue::Overflow ... free_overflow`, en su
    /// rama `PageType::Leaf`) necesita un caso que lo ejercite aparte del de
    /// una hoja límite.
    #[test]
    fn overflow_values_inside_a_bulk_freed_subtree_are_freed_too() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..3000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        for i in 1000..1006u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), &alloc::vec![7u8; 2000]).unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();
        let before = tx.pages_in_use();
        tx.delete_range(0x01, b"000500", b"002500").unwrap();
        let after = tx.pages_in_use();
        tx.commit().unwrap();

        // Cada valor de 2000 bytes ocupa varias páginas de overflow (~5 a
        // 512 B de página); si `free_subtree` no las liberase, esta resta
        // apenas bajaría de lo que explican las hojas/internos por sí
        // solos.
        assert!(
            before - after > 25,
            "antes {before}, después {after}: no parecen haberse liberado las cadenas de overflow"
        );

        let r = db.begin_read();
        for i in [0u32, 499, 2500, 2999] {
            let key = alloc::format!("{i:06}");
            assert!(
                r.get(0x01, key.as_bytes()).unwrap().is_some(),
                "clave {key} debería sobrevivir"
            );
        }
        for i in 1000..1006u32 {
            let key = alloc::format!("{i:06}");
            assert_eq!(
                r.get(0x01, key.as_bytes()).unwrap(),
                None,
                "clave de overflow {key} debería haberse borrado"
            );
        }
    }

    /// Como la prueba anterior, pero con el valor de overflow justo en el
    /// borde superior del rango (`to`): esa hoja contiene también claves
    /// `>= to`, así que no puede caer entera dentro del rango — la procesa
    /// `delete_range_rec` entrada por entrada, no `free_subtree`. Ejercita
    /// el otro camino que libera overflow (dentro de la rama `PageType::Leaf`
    /// de `delete_range_rec` mismo).
    #[test]
    fn overflow_values_at_a_range_boundary_leaf_are_freed_too() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..3000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.put(0x01, b"001499a", &alloc::vec![9u8; 2000]).unwrap();
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"000500", b"001500").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_eq!(r.get(0x01, b"001499a").unwrap(), None);
        assert!(r.get(0x01, b"000499").unwrap().is_some());
        assert!(r.get(0x01, b"001500").unwrap().is_some());
    }

    /// La cota de páginas leídas no es solo para "borrar todo": un tramo
    /// intermedio, ni alineado con el principio ni con el final del árbol,
    /// también debe leer un número de páginas proporcional a los nodos
    /// internos que toca, no a las 7000 entradas que borra ni a las 20.000
    /// que tiene el árbol entero.
    #[test]
    fn a_partial_range_delete_also_reads_far_fewer_pages_than_a_full_scan_would() {
        let db = seeded(20_000);
        let before = db.pages_read();
        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0x01, b"006000", b"013000").unwrap();
        let read = db.pages_read() - before;
        tx.commit().unwrap();
        assert!(read < 200, "se leyeron {read} páginas para borrar un tercio de 20.000 entradas");
    }

    /// Aislamiento de espacio de claves en el borde `0xff`: el espacio
    /// borrado (`0xfe`) es inmediatamente inferior al que debe sobrevivir
    /// (`0xff`), el mayor byte de espacio posible.
    #[test]
    fn keyspace_isolation_holds_at_the_0xff_boundary() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..300u32 {
            tx.put(0xfe, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.put(0xff, b"centinela", b"intacto").unwrap();
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0xfe, b"", b"\xff\xff\xff\xff").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..300u32 {
            let key = alloc::format!("{i:06}");
            assert_eq!(r.get(0xfe, key.as_bytes()).unwrap(), None, "clave {key}");
        }
        assert_eq!(
            r.get(0xff, b"centinela").unwrap().as_deref(),
            Some(b"intacto".as_slice()),
            "el espacio 0xff no debe tocarse"
        );
    }

    /// Complementa la prueba anterior por el otro lado: el espacio que se
    /// BORRA es el propio `0xff`, el mayor byte posible — para descartar
    /// cualquier problema de desbordamiento o de comparación especial en
    /// ese extremo, no solo en el vecino inmediatamente inferior.
    #[test]
    fn keyspace_isolation_when_the_deleted_namespace_is_0xff_itself() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.put(0xfe, b"vecino", b"intacto").unwrap();
        for i in 0..300u32 {
            tx.put(0xff, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();
        tx.delete_range(0xff, b"", b"\xff\xff\xff\xff").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        for i in 0..300u32 {
            let key = alloc::format!("{i:06}");
            assert_eq!(r.get(0xff, key.as_bytes()).unwrap(), None, "clave {key}");
        }
        assert_eq!(r.get(0xfe, b"vecino").unwrap().as_deref(), Some(b"intacto".as_slice()));
    }

    /// Reutiliza `check_invariants` (tarea 11-12): tras un borrado de rango
    /// parcial, el árbol resultante debe seguir siendo un B-árbol válido —
    /// cada separador sigue particionando bien a sus hijos, ninguna página
    /// queda referenciada dos veces — no solo "las claves que sobreviven se
    /// leen bien".
    #[test]
    fn a_range_delete_leaves_a_well_formed_tree() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..4000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        tx.delete_range(0x01, b"000777", b"002222").unwrap();
        tx.commit().unwrap();

        let r = db.begin_read();
        assert_ne!(r.root(), 0);
        let mut visited = alloc::collections::BTreeSet::new();
        super::invariant_tests::check_invariants(&r, r.root(), None, None, &mut visited);

        for i in 0..4000u32 {
            let key = alloc::format!("{i:06}");
            let present = r.get(0x01, key.as_bytes()).unwrap().is_some();
            assert_eq!(present, !(777..2222).contains(&i), "clave {key}");
        }
    }
}

/// Cotas de recorrido de `free_subtree` y `delete_range_rec` (`RangeBudget`,
/// `MAX_DEPTH`): un ciclo genuino debe fallar por profundidad, y un DAG
/// corrupto (acíclico, hijos compartidos) debe fallar por trabajo total —
/// ninguna de las dos cotas por sí sola basta, igual que ya estableció la
/// tarea 14 para el cursor (`MAX_NEXT_WORK`, ver su comentario).
#[cfg(all(test, feature = "std"))]
mod range_bound_tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};

    /// Construye una cadena "gemela" de `k` niveles que ejercita el mismo
    /// fenómeno de 2^k caminos que el hallazgo 2 de la tarea 14
    /// (`child(0) == extra` repetido en cada nivel), pero SIN que ningún
    /// nodo tenga hijos duplicados dentro de sí mismo.
    ///
    /// **Por qué cambió respecto a la construcción original.** La ronda 2
    /// de revisión de la tarea 15 (hallazgo 2) añadió
    /// `validate_no_duplicate_children`, que rechaza `child(0) == extra`
    /// de inmediato, con `CellBounds`, antes de que la cota de TRABAJO
    /// tenga ocasión de intervenir — exactamente la construcción que
    /// usaban las pruebas de este módulo antes de esa corrección, así que
    /// dejaron de fallar con `TreeLoop` (empezaron a fallar más rápido
    /// todavía, con `CellBounds`, pero eso ya no ejercita `RangeBudget`,
    /// que es lo que estas pruebas existen para comprobar).
    ///
    /// La construcción de aquí comparte páginas ENTRE hermanos, no DENTRO
    /// de un mismo nodo: en cada nivel `i` hay dos páginas, `left` y
    /// `right`, y el nivel `i+1` las referencia cruzadas —
    /// `new_left.child(0) = left`, `new_left.extra = right`;
    /// `new_right.child(0) = right`, `new_right.extra = left` — así que
    /// NINGÚN nodo individual repite un hijo (`left != right` siempre, son
    /// páginas distintas), pero procesar `new_left` visita tanto `left`
    /// como `right`, y procesar `new_right` visita las MISMAS dos — el
    /// mismo par de páginas, alcanzado por dos caminos distintos. Con `k`
    /// niveles así apilados, la profundidad `d` acumula 2^d invocaciones
    /// aunque solo existan `2k + 2` páginas de verdad — el mismo ataque de
    /// fondo, con una fachada estructural distinta.
    fn build_twin_chain_dag(tx: &mut WriteTxn, k: u32) -> PageNo {
        let leaf_a = tx.alloc().unwrap();
        let leaf_a_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf_a, &leaf_a_bytes).unwrap();
        let leaf_b = tx.alloc().unwrap();
        let leaf_b_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf_b, &leaf_b_bytes).unwrap();

        let (mut left, mut right) = (leaf_a, leaf_b);
        for _ in 0..k {
            let new_left = tx.alloc().unwrap();
            let mut lb = PageBuilder::new(512, PageType::Internal);
            lb.set_extra(right);
            let l_bytes = lb.build(&[(b"k".as_slice(), CellPayload::Child(left))]).unwrap();
            tx.write_page(new_left, &l_bytes).unwrap();

            let new_right = tx.alloc().unwrap();
            let mut rb = PageBuilder::new(512, PageType::Internal);
            rb.set_extra(left);
            let r_bytes = rb.build(&[(b"k".as_slice(), CellPayload::Child(right))]).unwrap();
            tx.write_page(new_right, &r_bytes).unwrap();

            left = new_left;
            right = new_right;
        }
        left
    }

    /// Dos nodos internos cuyo `extra` se apunta el uno al otro: sin la
    /// cota de profundidad, `free_subtree` (que SÍ se llama a sí misma,
    /// a diferencia del cursor) desbordaría la pila de verdad, no solo
    /// tardaría mucho.
    #[test]
    fn free_subtree_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
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

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, a, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    /// `build_twin_chain_dag` de `k` niveles — el mismo fenómeno de fondo
    /// que el DAG del hallazgo 2 de la tarea 14
    /// (`a_corrupt_dag_with_repeated_children_is_rejected_quickly_not_slowly`,
    /// en `cursor_tests`), reutilizado aquí porque `free_subtree` está
    /// expuesto exactamente al mismo fenómeno: cada camino raíz-hoja mide
    /// `k + 1` niveles (muy por debajo de `MAX_DEPTH`), pero hay 2^k
    /// caminos distintos, y `free_subtree` los recorre TODOS si nada más lo
    /// impide, porque visita CADA hijo de cada nodo interno.
    #[test]
    fn free_subtree_rejects_a_corrupt_dag_quickly_instead_of_exploring_exponentially_many_paths() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();

        let k = 60u32; // muy por debajo de MAX_DEPTH (128); 2^60 caminos.
        let root = build_twin_chain_dag(&mut tx, k);

        let mut budget = RangeBudget::new(tx.n_pages());
        let start = std::time::Instant::now();
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
        assert!(
            elapsed.as_secs() < 2,
            "con la cota de trabajo esto debe fallar rápido, no explorar 2^{k} caminos: \
             tardó {elapsed:?}"
        );
    }

    /// Como `free_subtree_returns_an_error_instead_of_looping_forever_on_a_cycle`,
    /// pero a través de la función pública `delete_range`: `delete_range_rec`
    /// también recurre en TODOS los hijos de un nodo no contenido del todo
    /// (no en uno solo, como `insert_rec`/`delete_rec`), así que necesita su
    /// propia comprobación de profundidad, independiente de la de
    /// `free_subtree`. `from = b"\x00"` (no vacío): la cota inferior
    /// heredada por el hijo más a la izquierda es siempre `[]` (ver el
    /// comentario de `Bounds`), así que con un `from` no vacío ese hijo
    /// nunca se acoge al atajo de "subárbol contenido" y `delete_range_rec`
    /// se ve forzada a descender de verdad, ejercitando su propia cota en
    /// vez de la de `free_subtree`.
    #[test]
    fn delete_range_returns_an_error_instead_of_looping_forever_on_a_cycle() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
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

        let err = delete_range(&mut tx, a, b"\x00", b"\xff").unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
    }

    /// Como `free_subtree_rejects_a_corrupt_dag_quickly_instead_of_exploring_exponentially_many_paths`,
    /// pero a través de `delete_range`: con `from` no vacío, ni el hijo
    /// `i == 0` (cota inferior `[]` heredada) ni el hijo `extra` (cota
    /// superior `None` heredada) se acogen nunca al atajo de "subárbol
    /// contenido" en NINGÚN nivel de la cadena — los dos fuerzan descenso
    /// real en cada nivel, así que `delete_range_rec` recorre el mismo DAG
    /// exponencial que la prueba análoga de `free_subtree`, y necesita el
    /// mismo `budget` compartido para no explorarlo entero.
    #[test]
    fn delete_range_rejects_a_corrupt_dag_quickly_instead_of_exploring_exponentially_many_paths() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let mut tx = db.begin_write().unwrap();

        let k = 60u32;
        let root = build_twin_chain_dag(&mut tx, k);

        let start = std::time::Instant::now();
        let err = delete_range(&mut tx, root, b"\x00", b"\xff").unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: CorruptKind::TreeLoop, .. }),
            "se esperaba TreeLoop, se obtuvo {err:?}"
        );
        assert!(
            elapsed.as_secs() < 2,
            "con la cota de trabajo esto debe fallar rápido, no explorar 2^{k} caminos: \
             tardó {elapsed:?}"
        );
    }
}

/// Ronda 1 de revisión de la tarea 15: los dos hallazgos críticos (1 y 2)
/// eran fugas de página — páginas que el asignador seguía contando como "en
/// uso" pero que ningún camino desde la raíz alcanzaba ya. `check_invariants`
/// (tareas 11-12), que reutiliza `range_tests`, NO podía verlas: solo
/// recorre el árbol RESULTANTE, así que confirma que lo que sobrevive está
/// bien formado, pero es ciego a lo que debería haberse liberado y no lo
/// fue — precisamente el hueco por el que sobrevivieron los dos hallazgos a
/// la autorrevisión original de esta tarea (hallazgo 6 del informe de
/// revisión). Este módulo añade la comprobación que sí las habría visto:
/// contar las páginas alcanzables desde la raíz (árbol MÁS cadenas de
/// overflow) y compararlas contra `WriteTxn::pages_in_use` — un desajuste
/// por debajo es una fuga, por encima un doble-free.
#[cfg(all(test, feature = "std"))]
mod range_accounting_tests {
    use super::invariant_tests::{check_invariants, Rng};
    use super::*;
    use crate::storage::MemStorage;
    use crate::tx::{Db, Options};
    use alloc::collections::BTreeSet;

    fn db() -> Db {
        Db::create(Box::new(MemStorage::new()), Options::default()).unwrap()
    }

    /// Recorre el árbol entero desde `root` y devuelve el conjunto de
    /// páginas alcanzables: las del propio árbol (hojas e internos) MÁS las
    /// de cada cadena de overflow que cuelgue de una hoja — a diferencia de
    /// `check_invariants`, que solo mira la estructura del árbol y nunca
    /// abre una cadena de overflow.
    fn reachable_pages(tx: &impl PageSource, root: PageNo) -> BTreeSet<PageNo> {
        let mut seen = BTreeSet::new();
        if root != 0 {
            walk_reachable(tx, root, &mut seen);
        }
        seen
    }

    fn walk_reachable(tx: &impl PageSource, page_no: PageNo, seen: &mut BTreeSet<PageNo>) {
        // `insert` devuelve `false` si ya estaba: evita un bucle infinito
        // si la propia prueba, por error, construyera algo cíclico — no es
        // la cota de profundidad del árbol real (esta función es solo para
        // pruebas, sobre árboles que las propias pruebas construyen).
        if !seen.insert(page_no) {
            return;
        }
        let bytes = tx.read_page(page_no).unwrap();
        let page = PageRef::parse(&bytes, page_no).unwrap();
        match page.page_type() {
            PageType::Leaf => {
                for i in 0..page.n_slots() {
                    if let LeafValue::Overflow { first, .. } = page.leaf_value(i) {
                        let mut current = first;
                        while current != 0 && seen.insert(current) {
                            let b = tx.read_page(current).unwrap();
                            let p = PageRef::parse(&b, current).unwrap();
                            current = p.extra();
                        }
                    }
                }
            }
            PageType::Internal => {
                for i in 0..page.n_slots() {
                    walk_reachable(tx, page.child(i), seen);
                }
                walk_reachable(tx, page.extra(), seen);
            }
            _ => panic!("tipo de página inesperado en el árbol: {:?}", page.page_type()),
        }
    }

    /// Las páginas que el asignador cuenta como "en uso" deben ser
    /// EXACTAMENTE las alcanzables desde `root`, salvo el `baseline` fijo de
    /// páginas de arranque (cabecera y las dos ranuras de meta —
    /// `meta_b_page + 1` en `tx.rs`, 9 con el `page_size` por defecto) que
    /// `pages_in_use()` cuenta pero que NUNCA forman parte del árbol, así
    /// que `reachable_pages` nunca las ve. `baseline` debe capturarse con
    /// `tx.pages_in_use()` justo tras `begin_write()`, antes de tocar el
    /// árbol — así la resta aísla exactamente lo que este árbol añadió. Ni
    /// una fuga ni un doble-free: es la comprobación de contabilidad de la
    /// ronda 1 de revisión, como test helper permanente (hallazgo 6 de su
    /// informe).
    fn assert_accounting_matches(tx: &mut WriteTxn, root: PageNo, baseline: u32, ctx: &str) {
        let reachable = reachable_pages(tx, root).len() as u32;
        let in_use = tx.pages_in_use() - baseline;
        assert_eq!(
            reachable, in_use,
            "{ctx}: páginas alcanzables ({reachable}) no coincide con páginas en uso según \
             el asignador, descontando el arranque ({in_use}) — {} páginas {}",
            in_use.abs_diff(reachable),
            if in_use > reachable { "perdidas (fuga)" } else { "liberadas por duplicado" }
        );
    }

    /// Hallazgo 1 del informe de revisión, CRÍTICO: reproduce exactamente
    /// los números del informe (3000 claves, 15 valores de 2000 bytes,
    /// `delete_range` sobre un tercio → 15 páginas huérfanas antes de la
    /// corrección) pero usando la comprobación de contabilidad en vez de
    /// `before - after > 25` (la prueba original, que el propio informe
    /// señala que no podía distinguir "se liberaron ~150 hojas" de "se
    /// liberaron ~150 hojas Y SE PERDIERON 15 páginas de overflow" — pasaba
    /// igual en los dos casos).
    #[test]
    fn overflow_inside_a_bulk_freed_subtree_leaves_no_orphan_pages() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();
        for i in 0..3000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        for i in 1000..1015u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), &alloc::vec![7u8; 2000]).unwrap();
        }
        tx.delete_range(0x01, b"000500", b"002500").unwrap();
        let root = tx.root();
        assert_accounting_matches(
            &mut tx,
            root,
            baseline,
            "tras delete_range con overflow en bloque",
        );
        tx.commit().unwrap();
    }

    /// Hallazgo 2 del informe de revisión, CRÍTICO: `put`/`delete` sobre un
    /// árbol de fanout bajo (claves de 127 bytes, cerca del límite de
    /// `page_size / 4` — el mismo truco que usa
    /// `churn_grows_depth_but_stays_within_the_measured_ceiling`, tarea 12,
    /// para forzar poca ramificación con el `page_size` mínimo) produce, al
    /// cabo de suficiente churn de borrado/reinserción, nodos internos con
    /// hijos de tipo mixto (una hoja en una posición, un nodo interno en
    /// otra) — el colapso de un solo hijo que documenta `MAX_DEPTH` más
    /// arriba. Antes de la corrección del hallazgo 2, un `delete_range` que
    /// alcanzara uno de esos nodos mixtos liberaba sus hermanos internos
    /// como si fueran hojas, perdiendo sus subárboles enteros para
    /// siempre. La comprobación de contabilidad tras CADA `delete_range`
    /// intercalado con el churn es lo que lo delataría.
    #[test]
    fn churn_then_range_delete_on_a_low_fanout_tree_leaves_no_orphan_pages() {
        let key_for = |i: u32| -> Vec<u8> {
            let mut k = alloc::format!("{i:07}").into_bytes();
            k.resize(127, b'k');
            k
        };
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();
        let mut root = 0;
        let n = 300u32;
        for i in 0..n {
            root = put(&mut tx, root, &key_for(i), b"v").unwrap();
        }
        tx.set_root(root);

        // Semilla elegida a propósito, no la primera que se probó:
        // verificada a mano (revirtiendo temporalmente la corrección del
        // hallazgo 2 y confirmando que ESTA prueba falla con la versión
        // rota, con un desajuste de 11 páginas en el paso 149) para que
        // sea de verdad un guardián de regresión, no una prueba que por
        // casualidad nunca llega a tocar un nodo mixto con esta semilla
        // concreta — varias semillas candidatas (por ejemplo
        // `0x5EED_1234`) SÍ pasaban incluso con el defecto presente.
        let mut rng = Rng(0xC0FFEE);
        let mut live: Vec<u32> = (0..n).collect();
        for step in 0..2000u32 {
            let idx = (rng.next() as usize) % live.len();
            let victim = live.swap_remove(idx);
            let cur_root = tx.root();
            let (r, existed) = delete(&mut tx, cur_root, &key_for(victim)).unwrap();
            assert!(existed, "clave {victim}");
            tx.set_root(r);
            let newest = n + step;
            let cur_root = tx.root();
            let r = put(&mut tx, cur_root, &key_for(newest), b"v").unwrap();
            tx.set_root(r);
            live.push(newest);

            // Cada pocos pasos, un borrado de rango sobre un tramo
            // aleatorio de las claves VIVAS — bastante para alcanzar
            // nodos mixtos según van apareciendo por el churn, pero sin
            // convertir la prueba en desproporcionadamente lenta.
            if step % 50 == 49 {
                live.sort_unstable();
                let a = (rng.next() as usize) % live.len();
                let b = (rng.next() as usize) % live.len();
                let (lo, hi) = (a.min(b), a.max(b));
                if lo < hi {
                    let from = key_for(live[lo]);
                    let to = key_for(live[hi]);
                    // `delete_range` de `tree.rs` (sin espacio de claves),
                    // no `tx.delete_range`: el árbol de esta prueba se
                    // construye con `put`/`delete` crudos (sin el prefijo
                    // de `scoped`), así que mezclar `tx.delete_range` (que
                    // SÍ antepone `ns = 0x01`) buscaría un prefijo que
                    // ninguna clave real tiene.
                    let cur_root = tx.root();
                    let new_root = delete_range(&mut tx, cur_root, &from, &to).unwrap();
                    tx.set_root(new_root);
                    let cur_root = tx.root();
                    assert_accounting_matches(
                        &mut tx,
                        cur_root,
                        baseline,
                        &alloc::format!("paso {step}, borrado de rango {lo}..{hi}"),
                    );
                    live.retain(|&k| {
                        let key = key_for(k);
                        key.as_slice() < from.as_slice() || key.as_slice() >= to.as_slice()
                    });
                }
            }
        }

        let mut visited = BTreeSet::new();
        let final_root = tx.root();
        check_invariants(&tx, final_root, None, None, &mut visited);
        assert_accounting_matches(&mut tx, final_root, baseline, "final");
    }

    /// Construye a mano un nodo interno con dos hijos de tipo DISTINTO — una
    /// hoja y un nodo interno con sus propias hojas — y `children_plain`
    /// puesto deliberadamente a `false` (el valor correcto para esta
    /// estructura, y también el que pone `PageBuilder` por defecto si nadie
    /// lo toca). Comprueba directamente que `free_subtree` no confía en un
    /// único hijo para todos: recorre cada uno según su tipo real y libera
    /// el subárbol entero sin perder ninguna página, aunque el "hijo 0" (el
    /// que la versión original de la tarea usaba como única muestra) sea
    /// del tipo que NO delataría al hermano mixto.
    #[test]
    fn free_subtree_handles_a_hand_built_node_with_mixed_child_types() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let baseline = tx.pages_in_use();

        // Hijo 0: una hoja normal, sin overflow.
        let leaf0 = tx.alloc().unwrap();
        let leaf0_bytes = PageBuilder::new(512, PageType::Leaf)
            .build(&[(b"aa".as_slice(), CellPayload::Value(b"1"))])
            .unwrap();
        tx.write_page(leaf0, &leaf0_bytes).unwrap();

        // Hijo 1 (extra): un nodo INTERNO de verdad, con dos hojas propias.
        let grandleaf_a = tx.alloc().unwrap();
        let ga_bytes = PageBuilder::new(512, PageType::Leaf)
            .build(&[(b"ma".as_slice(), CellPayload::Value(b"2"))])
            .unwrap();
        tx.write_page(grandleaf_a, &ga_bytes).unwrap();
        let grandleaf_b = tx.alloc().unwrap();
        let gb_bytes = PageBuilder::new(512, PageType::Leaf)
            .build(&[(b"za".as_slice(), CellPayload::Value(b"3"))])
            .unwrap();
        tx.write_page(grandleaf_b, &gb_bytes).unwrap();

        let internal_child = tx.alloc().unwrap();
        let mut icb = PageBuilder::new(512, PageType::Internal);
        icb.set_extra(grandleaf_b);
        icb.set_children_plain(true); // ESTE sí es homogéneo: sus dos hijos son hojas planas.
        let ic_bytes = icb.build(&[(b"za".as_slice(), CellPayload::Child(grandleaf_a))]).unwrap();
        tx.write_page(internal_child, &ic_bytes).unwrap();

        // La raíz: hijo 0 = hoja, extra = interno. Mixta de verdad, y
        // `children_plain` puesto a `false` a propósito.
        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(internal_child);
        rb.set_children_plain(false);
        let root_bytes = rb.build(&[(b"ma".as_slice(), CellPayload::Child(leaf0))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();
        tx.set_root(root);

        let mut budget = RangeBudget::new(tx.n_pages());
        free_subtree(&mut tx, root, 1, &mut budget).unwrap();

        // Las cinco páginas construidas a mano (raíz, hoja0, interno-hijo,
        // sus dos hojas) deben haber vuelto todas a la lista de libres —
        // de vuelta exactamente al `baseline` de antes de construir nada.
        assert_eq!(
            tx.pages_in_use(),
            baseline,
            "algo del subárbol mixto no se liberó: quedan {} páginas de más en uso",
            tx.pages_in_use() - baseline
        );
    }

    /// Hallazgo 3 del informe de revisión, CRÍTICO: un nodo interno
    /// corrupto con `extra == 0` no debe hacer que `free_subtree` empuje la
    /// página 0 (la cabecera del fichero) a la lista de libres. Antes de
    /// `validate_child`, esto pasaba en silencio (`Ok(())`) y la siguiente
    /// escritura destruía la cabecera.
    #[test]
    fn free_subtree_rejects_a_corrupt_node_with_a_zero_child_instead_of_freeing_page_zero() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        // `extra == 0`: corrupción — ningún `alloc()` legítimo reparte la
        // página 0. `children_plain` a `true` para forzar el camino que
        // vuelca hijos sin abrirlos, el que el hallazgo 3 encontró sin
        // validar nada.
        rb.set_extra(0);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[(b"m".as_slice(), CellPayload::Child(leaf))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Mismo hallazgo 3, pero con un hijo que apunta MÁS ALLÁ del final del
    /// fichero (`>= n_pages`) en vez de a la página reservada `0`.
    #[test]
    fn free_subtree_rejects_a_child_pointing_past_the_end_of_the_file() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let n_pages = tx.n_pages();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(n_pages + 1000); // ninguna página así existe todavía
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Ronda 2 de revisión de la tarea 15, hallazgo 1: `validate_child`
    /// rechazaba `child == 0`, pero `1..=meta_b_page` — las ranuras de
    /// meta — son exactamente tan inválidas. `extra == 1` (la ranura de
    /// meta A) es la reproducción exacta del informe: antes de esta
    /// corrección, `free_subtree` la volcaba a la lista de libres, y la
    /// siguiente escritura habría destruido esa ranura de meta. La prueba
    /// afirma `Err(Corrupt)` directamente — no observa lo que `alloc()`
    /// devuelve después, que es justo el síntoma indirecto que dejó pasar
    /// esta clase de defecto la primera vez.
    #[test]
    fn free_subtree_rejects_a_child_pointing_at_a_reserved_meta_slot() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        // `extra == 1`: la ranura de meta A, no la página `0` — la
        // reproducción exacta del hallazgo 1. `children_plain` a `true`
        // para forzar el camino en bloque, el que la corrección de la
        // ronda 1 dejó protegido solo contra `child == 0`.
        rb.set_extra(1);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[(b"m".as_slice(), CellPayload::Child(leaf))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Igual que la prueba anterior, pero justo en el límite:
    /// `last_reserved_page()` (`meta_b_page`) debe rechazarse, no solo las
    /// páginas estrictamente por debajo — la comparación correcta es
    /// `child <= meta_b_page`, no `child < meta_b_page`.
    #[test]
    fn free_subtree_rejects_a_child_at_exactly_the_last_reserved_page() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let last_reserved = tx.last_reserved_page();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(last_reserved);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Cubre el tercer término de `validate_child`
    /// (`child == tx.meta_b_relocation_target()`) de forma aislada TANTO del
    /// segundo (`current_meta_b_page`) COMO del cuarto (`child >=
    /// tx.n_pages()`) — la primera versión de esta prueba (ronda de
    /// revisión posterior a la entrega) no aislaba el cuarto: en una base
    /// fresca `n_pages` vale `3`, así que `target` (`8`) ya caía fuera por
    /// `child >= n_pages` sin necesitar el tercer término en absoluto —
    /// borrarlo no cambiaba el resultado, exactamente el hallazgo LOW que
    /// esta prueba existe para cerrar. Reservar pocas páginas a mano deja
    /// `n_pages` en 10 (por encima de `target`) SIN reubicar de verdad
    /// (`current_meta_b_page()` sigue en `2`, porque `relocate_meta_b` solo
    /// corre dentro de `commit()`, que esta prueba nunca llama) — así los
    /// dos valores que importan (`current_meta_b_page` y
    /// `meta_b_relocation_target`) siguen siendo distintos, y `n_pages` ya
    /// no puede enmascarar el término bajo prueba.
    #[test]
    fn free_subtree_rejects_a_child_at_the_relocation_target_before_any_relocation() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        for _ in 0..6 {
            tx.alloc().unwrap();
        }
        let target = tx.meta_b_relocation_target();
        assert_ne!(
            target,
            tx.current_meta_b_page(),
            "esta prueba necesita que las dos posiciones difieran para aislar el termino que \
             cubre"
        );
        assert!(
            tx.n_pages() > target,
            "esta prueba necesita n_pages > target para que 'child >= n_pages' no enmascare \
             el termino bajo prueba"
        );

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(target);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Tarea 18, autorrevisión: una vez `relocate_meta_b` libera de verdad
    /// la posición VIEJA de la meta B (página `2`, con `page_size` de
    /// 512 B), esa página vuelve a la lista de libres y puede reciclarse
    /// como cualquier otra — `validate_child` NO debe seguir rechazándola
    /// para siempre. Construida para fallar contra la versión de
    /// `validate_child` que solo comprobaba el prefijo fijo `0..=1` y el
    /// destino final, sin la comprobación dinámica de
    /// `current_meta_b_page` — sin ella, la página `2` reciclada se
    /// rechazaba como si siguiera siendo meta, y CUALQUIER `delete_range`/
    /// poda posterior a la primera reubicación de una base cuya página `2`
    /// hubiera llegado a reciclarse fallaría con `Corrupt` sobre datos
    /// perfectamente legítimos.
    #[test]
    fn free_subtree_accepts_a_child_at_the_old_meta_b_page_once_it_has_been_recycled() {
        let db = db();
        let mut tx = db.begin_write().unwrap();

        // Cruza los 4 KB (mismo patrón que
        // `freelist_serialization_never_hands_out_the_meta_b_relocation_target_either`
        // en `tx.rs`): cinco páginas a mano dejan `n_pages` en 8, y una
        // sexta (que `skip_meta_b_target` desvía a la 9) lo empuja a 10 —
        // dispara `relocate_meta_b`, que libera la página `2`.
        let mut pages = alloc::vec::Vec::new();
        for _ in 0..5 {
            let p = tx.alloc().unwrap();
            tx.write_page(p, &alloc::vec![1u8; 512]).unwrap();
            pages.push(p);
        }
        tx.set_root(pages[0]);
        let last = tx.alloc().unwrap();
        tx.write_page(last, &alloc::vec![1u8; 512]).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            db.begin_write().unwrap().current_meta_b_page(), 8,
            "la reubicacion debio ocurrir"
        );

        // La página `2` vieja debe estar libre ahora: el siguiente `alloc`
        // la recicla en vez de extender el fichero.
        let mut tx = db.begin_write().unwrap();
        let recycled = tx.alloc().unwrap();
        assert_eq!(recycled, 2, "la pagina vieja de la meta B debio reciclarse, no extenderse");

        // La escribe como una hoja legítima y la cuelga de un nodo interno
        // — exactamente el papel que `validate_child` tiene que aceptar
        // ahora que ya no es meta.
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(recycled, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(recycled);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        free_subtree(&mut tx, root, 1, &mut budget)
            .expect("una pagina reciclada, ya no meta, debe aceptarse como hijo legitimo");
    }

    /// Regresión real (no la mal citada) del hallazgo de fuga de
    /// `WriteTxn::relocate_meta_b` — ver la corrección de atribución en su
    /// comentario, `tx.rs`. A diferencia de las pruebas de contabilidad
    /// vecinas de este módulo, aquí SÍ hay un `commit()` real de por medio
    /// (`seeded`, que puebla el árbol dentro de la ÚNICA transacción que
    /// después confirma), así que `relocate_meta_b` se ejecuta de verdad —
    /// es la condición que las pruebas mal citadas nunca cumplían. Con el
    /// `self.free` de la posición vieja revertido, esto falla con "1 página
    /// perdida (fuga)" — comprobado a mano contra esa reversión.
    #[test]
    fn relocation_reclaims_the_old_meta_b_page_without_leaking_it() {
        let db = Db::create(Box::new(MemStorage::new()), Options::default()).unwrap();
        let baseline = db.begin_write().unwrap().pages_in_use();

        let mut tx = db.begin_write().unwrap();
        for i in 0..2000u32 {
            tx.put(0x01, alloc::format!("{i:06}").as_bytes(), b"v").unwrap();
        }
        let root = tx.root();
        tx.commit().unwrap();
        assert_eq!(
            db.begin_write().unwrap().current_meta_b_page(), 8,
            "la reubicacion debio ocurrir para que esta prueba ejercite algo"
        );

        let mut tx = db.begin_write().unwrap();
        assert_accounting_matches(&mut tx, root, baseline, "tras una reubicacion real (commit)");
    }

    /// Ronda 2 de revisión de la tarea 15, hallazgo 2: un nodo interno
    /// corrupto con `child(0) == extra` no debe hacer que `free_subtree`
    /// libere la misma página dos veces — dos dueños de una sola página
    /// tras el siguiente `alloc()`, sin que nada lo detecte. Camino en
    /// bloque (`children_plain() == true`): el que hace más daño, porque
    /// libera sin abrir nada.
    #[test]
    fn free_subtree_rejects_duplicate_child_pointers_on_the_bulk_path() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        // `extra == leaf` a la vez que `child(0) == leaf`: el mismo número
        // de página aparece dos veces entre los hijos de este nodo.
        rb.set_extra(leaf);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[(b"m".as_slice(), CellPayload::Child(leaf))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Misma corrupción que la prueba anterior, pero con
    /// `children_plain() == false`, para confirmar que la comprobación de
    /// duplicados no se salta el camino recursivo — ahí el doble-free
    /// tardaría una lectura de página más en manifestarse (dos llamadas a
    /// `free_subtree` sobre la misma página, cada una con su propio
    /// `tx.free()` al terminar), pero sigue siendo el mismo defecto.
    #[test]
    fn free_subtree_rejects_duplicate_child_pointers_on_the_recursive_path() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(leaf);
        rb.set_children_plain(false);
        let root_bytes = rb.build(&[(b"m".as_slice(), CellPayload::Child(leaf))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let mut budget = RangeBudget::new(tx.n_pages());
        let err = free_subtree(&mut tx, root, 1, &mut budget).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// La comprobación de duplicados también debe cubrir `delete_range_rec`,
    /// no solo `free_subtree`: aquí el árbol tiene profundidad suficiente
    /// para que la raíz no se acoja al atajo de "subárbol contenido"
    /// (`from` no vacío, igual que en `range_bound_tests`), así que la
    /// corrupción se alcanza por el camino de reconstrucción, no por el de
    /// liberación en bloque.
    #[test]
    fn delete_range_rejects_duplicate_child_pointers() {
        let db = db();
        let mut tx = db.begin_write().unwrap();
        let leaf = tx.alloc().unwrap();
        let leaf_bytes = PageBuilder::new(512, PageType::Leaf).build(&[]).unwrap();
        tx.write_page(leaf, &leaf_bytes).unwrap();

        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(leaf);
        let root_bytes = rb.build(&[(b"m".as_slice(), CellPayload::Child(leaf))]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        let err = delete_range(&mut tx, root, b"\x00", b"\xff").unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { kind: crate::CorruptKind::CellBounds, .. }),
            "se esperaba CellBounds, se obtuvo {err:?}"
        );
    }

    /// Ronda 2 de revisión de la tarea 15 ("también corregir"), sin
    /// prueba hasta ahora: el colapso de `delete_rec`
    /// (`page.n_slots() == 0`) usaba `page.children_plain()` — el valor
    /// VIEJO, releído de la página corrupta — en vez de `children_plain`,
    /// la variable local que sí incorpora el resultado fresco del hijo que
    /// esta llamada acaba de tocar. Nada de lo que existe hoy puede
    /// alcanzar esta rama por fuzzing: un árbol bien formado nunca produce
    /// un nodo interno con cero entradas (`emit` nunca construye uno así)
    /// — exactamente por qué el defecto sobrevivió hasta que corregir el
    /// comentario lo expuso, y por qué hace falta construir la corrupción
    /// a mano, como aquí.
    ///
    /// Construcción: una raíz corrupta con `n_slots() == 0` (así que
    /// CUALQUIER clave enruta a su `extra`, per `child_index` — ver el
    /// comentario de la corrección en `delete_rec`) y `children_plain`
    /// puesto a `true` — la mentira exacta del hallazgo. Su `extra` es un
    /// nodo interno BIEN FORMADO (dos hojas planas, sin overflow) con
    /// suficientes claves para que borrar una no lo colapse — así que su
    /// propio resultado es `Removal::Updated`, no `Gone`. Al ser un nodo
    /// INTERNO, ese resultado SIEMPRE lleva `plain = false`
    /// (`entries_are_plain` exige `PageType::Leaf`), sea cual sea el
    /// estado de sus propios hijos: es la señal fresca que debería
    /// prevalecer sobre el `children_plain` viejo y corrupto de la raíz.
    #[test]
    fn delete_rec_uses_the_fresh_result_not_the_stale_bit_when_promoting_a_touched_child() {
        let db = db();
        let mut tx = db.begin_write().unwrap();

        // Hoja con dos claves: tras borrar una, sigue teniendo la otra —
        // el nodo interno que la contiene no colapsa, así que su propio
        // resultado es `Updated`, no `Gone`.
        let leaf_a = tx.alloc().unwrap();
        let leaf_a_bytes = PageBuilder::new(512, PageType::Leaf)
            .build(&[
                (b"a1".as_slice(), CellPayload::Value(b"1")),
                (b"a2".as_slice(), CellPayload::Value(b"2")),
            ])
            .unwrap();
        tx.write_page(leaf_a, &leaf_a_bytes).unwrap();

        let leaf_b = tx.alloc().unwrap();
        let leaf_b_bytes = PageBuilder::new(512, PageType::Leaf)
            .build(&[(b"b1".as_slice(), CellPayload::Value(b"3"))])
            .unwrap();
        tx.write_page(leaf_b, &leaf_b_bytes).unwrap();

        // Nodo interno BIEN FORMADO: dos hojas planas, sin overflow.
        // `children_plain` correcto aquí (`true`) no importa para lo que
        // se está probando — lo que importa es que este nodo ES interno,
        // así que su propio resultado siempre lleva `plain = false`.
        let child_internal = tx.alloc().unwrap();
        let mut cb = PageBuilder::new(512, PageType::Internal);
        cb.set_extra(leaf_b);
        cb.set_children_plain(true);
        let child_bytes = cb.build(&[(b"b".as_slice(), CellPayload::Child(leaf_a))]).unwrap();
        tx.write_page(child_internal, &child_bytes).unwrap();

        // La raíz CORRUPTA: cero separadores (`emit` nunca construye
        // esto), así que cualquier clave enruta a `extra` — el nodo
        // interno de arriba. `children_plain` puesto a `true` con un hijo
        // interno como único hijo: la mentira exacta del hallazgo.
        let root = tx.alloc().unwrap();
        let mut rb = PageBuilder::new(512, PageType::Internal);
        rb.set_extra(child_internal);
        rb.set_children_plain(true);
        let root_bytes = rb.build(&[]).unwrap();
        tx.write_page(root, &root_bytes).unwrap();

        match delete_rec(&mut tx, root, b"a1", 1).unwrap() {
            Removal::Updated(_, plain) => assert!(
                !plain,
                "el hijo promovido en el colapso es un nodo INTERNO, nunca una hoja \
                 plana: `plain` debería ser `false`; se obtuvo `true` — se está usando \
                 el `children_plain` viejo de la raíz corrupta en vez del resultado \
                 fresco del hijo que sí se tocó"
            ),
            Removal::Unchanged => panic!(
                "se esperaba Removal::Updated: la construcción de la prueba no borró nada"
            ),
            Removal::Gone => panic!(
                "se esperaba Removal::Updated, no Gone: la construcción de la prueba \
                 colapsó de más"
            ),
        }
    }
}
