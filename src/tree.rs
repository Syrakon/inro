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
    let page_size = tx.page_size();
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
    let capacity = core::cmp::max(tx.page_size() as u64 - PAGE_HEADER_SIZE as u64, 1);
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
            // Convertir el valor entrante antes de tocar las entradas de la
            // hoja: si es grande, escribe su propia cadena de overflow y
            // aquí solo se guarda la referencia. `Option` porque se consume
            // una única vez, al insertarlo en su posición final más abajo
            // (en `Ok(i)` reemplaza; en `Err(i)` se inserta nuevo) —
            // moverlo evita clonar un valor potencialmente enorme.
            let mut new_payload = Some(if value.len() > overflow_threshold(tx.page_size()) {
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
        let page_size = tx.page_size();

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
        let page_size = tx.page_size();

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
