//! Capa de agregación temporal: `inro-rollup`.
//!
//! Implementa la sección 12.3 de la especificación. El motor guarda **34,14
//! bytes por registro crudo** medidos, que está cerca del suelo de una fila;
//! lo que queda por ganar no es guardar menos bytes por fila sino **dejar de
//! guardar casi todas las filas**. Con los crudos viviendo 6 horas y los
//! agregados sobreviviéndolos, un informe de dos años se sirve sin que exista
//! ni uno solo de los registros que lo respaldan.
//!
//! # Módulo dentro de `inro`, y no un crate aparte del *workspace*
//!
//! La especificación (sección 12) habla de «el crate `inro-rollup`». Aquí es
//! un módulo tras la *feature* `rollup`, activada por defecto. El argumento,
//! porque la decisión era del implementador:
//!
//! - **Capacidad: no hace falta.** Esta capa escribe con `WriteTxn::put`,
//!   lee con `ReadTxn::scan`/`WriteTxn::scan` y poda con
//!   `WriteTxn::delete_range`, todo API pública, sobre el espacio de claves
//!   `0x02` que el motor documenta como **datos de usuario**
//!   (`arquitectura.md`: `0x01..0x7F`). No toca `put_raw`, ni `tree`, ni
//!   `pager`, ni nada `pub(crate)`. Es decir: **podría ser un crate aparte
//!   mañana sin cambiar una línea de este código**, y por eso la decisión es
//!   de empaquetado y no de arquitectura. La única pieza que faltaba —
//!   `WriteTxn::scan`, para releer dentro de la propia transacción lo que se
//!   va a sobrescribir — se ha añadido **pública**, precisamente para que esa
//!   afirmación siga siendo cierta.
//! - **Empaquetado: un crate aparte cuesta y no compra nada hoy.** `inro`
//!   0.1.0 ya está reservado en crates.io; partir en *workspace* obliga a
//!   reservar un segundo nombre, a publicar en dos pasos (un
//!   `inro-rollup = { path = ".." }` no se puede publicar hasta que `inro`
//!   lo esté), a duplicar licencias e `include`, y a mantener dos versiones
//!   en paso. A cambio, `unsafe_code = "forbid"`, la regla de cero
//!   dependencias de ejecución y los cinco comandos de verificación se
//!   heredan aquí sin escribir nada.
//! - **Coste para quien no la quiera: cero, y explícito.** Igual que
//!   `audit`, es una *feature*. `--no-default-features` no compila ni un byte
//!   de este módulo.
//!
//! # La agregación va en el MISMO commit
//!
//! No hay hilo de fondo ni tarea programada. `Rollup::observe` toma la
//! transacción de escritura del llamante; `Rollup::flush` vuelca en ella los
//! agregados afectados justo antes del `commit` que ya iba a ocurrir. El
//! agregado hereda así, tal cual, las garantías de consistencia ante cortes
//! del motor: o se confirman el crudo y su agregado, o ninguno de los dos.
//!
//! ```ignore
//! let mut tx = db.begin_write()?;
//! for r in lote {
//!     tx.put(0x01, &clave_cruda(r), &valor_crudo(r))?;
//!     rollup.observe(&mut tx, &observacion(r))?;
//! }
//! rollup.flush(&mut tx)?;
//! tx.commit()?;
//! ```
//!
//! **Contrato de error, calcado del que el motor ya impone (invariante 14):
//! si la transacción NO llega a confirmar después de un `flush` —porque
//! `commit` devolvió `Err`, o porque se abandonó— hay que llamar a
//! `Rollup::reset()`.** El estado en RAM da por escritas cosas que no
//! llegaron al medio, y `reset` lo tira entero: el volcado siguiente vuelve a
//! leer de disco y reconstruye. Sin él, el borrado de una fila desalojada
//! podría quedarse sin aplicar mientras su contenido ya está en el cajón, y
//! esa fila se contaría dos veces al leer.
//!
//! # Retenciones
//!
//! | Resolución | Dimensiones | Retención por defecto |
//! |---|---|---|
//! | Minuto | totales y códigos de estado | 48 horas |
//! | Hora | todas | 30 días |
//! | Día | todas | dos años |
//!
//! **La política de cuándo podar es del llamante**, no de esta capa: aquí
//! están `Resolution::default_retention_secs`, `Resolution::cutoff_bucket` y
//! `prune_before`, que es todo lo que una poda necesita. No hay ningún
//! planificador, y no lo habrá desde aquí.

pub mod bucket;
pub mod hist;
pub mod key;
pub mod topk;

pub use bucket::Bucket;
pub use hist::{Histogram, Percentile};
pub use key::AGG_NS;
pub use topk::{MAX_DIM_LEN, TopK};

use crate::error::{Error, Result};
use alloc::vec::Vec;

/// Resolución temporal de un agregado.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Resolution {
    Minute = 0,
    Hour = 1,
    Day = 2,
}

/// Las tres, en el orden en que se codifican.
pub const RESOLUTIONS: [Resolution; 3] = [Resolution::Minute, Resolution::Hour, Resolution::Day];

impl Resolution {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(c: u8) -> Result<Resolution> {
        match c {
            0 => Ok(Resolution::Minute),
            1 => Ok(Resolution::Hour),
            2 => Ok(Resolution::Day),
            _ => Err(Error::BadFormat),
        }
    }

    /// Segundos que abarca una celda.
    pub fn seconds(self) -> u64 {
        match self {
            Resolution::Minute => 60,
            Resolution::Hour => 3_600,
            Resolution::Day => 86_400,
        }
    }

    /// Retención por defecto de la sección 12.3. **Un valor por defecto, no
    /// una política**: quien poda decide.
    pub fn default_retention_secs(self) -> u64 {
        match self {
            Resolution::Minute => 48 * 3_600,
            Resolution::Hour => 30 * 86_400,
            Resolution::Day => 730 * 86_400,
        }
    }

    /// Índice de celda de un instante unix en segundos.
    ///
    /// `None` si no cabe en `u32`, que es el ancho que la especificación fija
    /// para `ts_bucket`. Con resolución de minuto eso da hasta el año 10136;
    /// truncar en vez de rechazar haría que un reloj disparatado escribiera
    /// en una celda del pasado, que es una respuesta equivocada silenciosa.
    pub fn bucket_of(self, unix_secs: u64) -> Option<u32> {
        u32::try_from(unix_secs / self.seconds()).ok()
    }

    /// Primera celda que sobrevive a una retención de `retention_secs` vista
    /// desde `now_secs`. Es el argumento de `prune_before`.
    pub fn cutoff_bucket(self, now_secs: u64, retention_secs: u64) -> Option<u32> {
        self.bucket_of(now_secs.saturating_sub(retention_secs))
    }

    /// Dimensiones que esta resolución mantiene, aparte del total.
    ///
    /// El minuto solo guarda totales y códigos de estado (sección 12.3): es
    /// la resolución que alimenta el zoom en tiempo real del panel, y las
    /// dimensiones de alta cardinalidad multiplicarían por cuatro un número
    /// de celdas que ya es sesenta veces el horario.
    pub fn dimensions(self) -> &'static [Dimension] {
        match self {
            Resolution::Minute => &[Dimension::Status],
            _ => &[Dimension::Status, Dimension::Endpoint, Dimension::Country, Dimension::User],
        }
    }
}

/// Dimensión de un agregado.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Dimension {
    /// La fila de totales de la celda. No lleva valor ni pasa por el top-K.
    Total = 0,
    Status = 1,
    Endpoint = 2,
    Country = 3,
    User = 4,
}

const DIM_SLOTS: usize = 5;

impl Dimension {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(c: u8) -> Result<Dimension> {
        match c {
            0 => Ok(Dimension::Total),
            1 => Ok(Dimension::Status),
            2 => Ok(Dimension::Endpoint),
            3 => Ok(Dimension::Country),
            4 => Ok(Dimension::User),
            _ => Err(Error::BadFormat),
        }
    }
}

/// Una petición observada.
///
/// `error` lo decide la aplicación: qué cuenta como error no es una propiedad
/// del código de estado (un 404 esperado puede no serlo) y adivinarlo aquí
/// impondría una política que esta capa no tiene por qué tener.
#[derive(Clone, Copy, Debug)]
pub struct Observation<'a> {
    /// Instante unix en segundos.
    pub ts: u64,
    pub latency_ms: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status: u16,
    pub error: bool,
    pub endpoint: &'a [u8],
    pub country: &'a [u8],
    pub user: &'a [u8],
}

/// Ajustes de la capa.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    /// Entradas por dimensión y celda. Es a la vez el tope de RAM y el de
    /// filas en disco: `k + 1` filas por `(resolución, celda, dimensión)`,
    /// cajón incluido.
    pub top_k: u16,
    pub minute: bool,
    pub hour: bool,
    pub day: bool,
    /// Celdas abiertas a la vez por resolución. Con marcas de tiempo que
    /// avanzan —lo normal— basta 2: la celda en curso y la que acaba de
    /// cerrarse mientras el lote la cruza. Es un tope DURO de RAM: al abrir
    /// una más, la más antigua se escribe en la transacción en curso y se
    /// suelta.
    pub max_open_cells: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config { top_k: 32, minute: true, hour: true, day: true, max_open_cells: 2 }
    }
}

impl Config {
    fn keeps(&self, res: Resolution) -> bool {
        match res {
            Resolution::Minute => self.minute,
            Resolution::Hour => self.hour,
            Resolution::Day => self.day,
        }
    }
}

/// Filas escritas y borradas por un volcado. Sirve para medir la
/// amplificación de escritura que esta capa añade, que es su coste principal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FlushStats {
    pub rows_written: u64,
    pub rows_deleted: u64,
    pub bytes_written: u64,
}

impl FlushStats {
    fn add(&mut self, other: FlushStats) {
        self.rows_written += other.rows_written;
        self.rows_deleted += other.rows_deleted;
        self.bytes_written += other.bytes_written;
    }
}

/// Una fila de agregado leída del disco.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Row {
    pub ts_bucket: u32,
    pub dim: Dimension,
    /// `None` en la fila de totales y en el cajón `otros`; `dim` los separa.
    pub value: Option<Vec<u8>>,
    pub bucket: Bucket,
}

impl Row {
    /// El cajón `otros` de su dimensión.
    pub fn is_drawer(&self) -> bool {
        self.dim != Dimension::Total && self.value.is_none()
    }
}

/// Celda `(resolución, ts_bucket)` en curso, en RAM.
#[derive(Clone, Debug)]
struct Cell {
    total: Bucket,
    total_on_disk: bool,
    total_dirty: bool,
    dims: [Option<TopK>; DIM_SLOTS],
}

impl Cell {
    fn new() -> Self {
        Cell {
            total: Bucket::new(),
            total_on_disk: false,
            total_dirty: false,
            dims: [const { None }; DIM_SLOTS],
        }
    }

    fn dim_mut(&mut self, d: Dimension, k: u16) -> &mut TopK {
        self.dims[d.code() as usize].get_or_insert_with(|| TopK::new(k))
    }

    fn ram_bytes(&self) -> usize {
        let mut n = core::mem::size_of::<Self>();
        for d in self.dims.iter().flatten() {
            n += d.ram_bytes();
        }
        n
    }
}

/// El agregador. Vive en el escritor agrupado del llamante, no en el motor.
#[derive(Clone, Debug)]
pub struct Rollup {
    cfg: Config,
    /// Celdas abiertas por resolución, ordenadas por `ts_bucket` — de ahí que
    /// sea un `BTreeMap`: desalojar «la más antigua» es mirar la primera
    /// clave, sin recorrer nada.
    cells: [alloc::collections::BTreeMap<u32, Cell>; 3],
}

impl Rollup {
    pub fn new(cfg: Config) -> Self {
        Rollup {
            cfg,
            cells: [
                alloc::collections::BTreeMap::new(),
                alloc::collections::BTreeMap::new(),
                alloc::collections::BTreeMap::new(),
            ],
        }
    }

    pub fn config(&self) -> Config {
        self.cfg
    }

    /// Tira todo el estado en RAM sin escribir nada.
    ///
    /// **Hay que llamarlo si la transacción no confirma después de un
    /// `flush`** — ver el contrato de error del comentario de módulo. Es
    /// seguro llamarlo siempre: lo único que se pierde es el trabajo de
    /// releer de disco lo que ya estaba ahí.
    pub fn reset(&mut self) {
        for c in &mut self.cells {
            c.clear();
        }
    }

    /// Bytes de RAM que ocupa el estado en curso. Se calcula recorriendo lo
    /// que hay, no se estima.
    pub fn ram_bytes(&self) -> usize {
        let mut n = core::mem::size_of::<Self>();
        for m in &self.cells {
            for c in m.values() {
                n += c.ram_bytes() + core::mem::size_of::<u32>() + 16;
            }
        }
        n
    }

    /// Celdas abiertas ahora mismo, por resolución.
    pub fn open_cells(&self) -> [usize; 3] {
        [self.cells[0].len(), self.cells[1].len(), self.cells[2].len()]
    }
}

// ---------------------------------------------------------------------------
// Integración con el motor. Tras `std` porque `WriteTxn`/`ReadTxn` no existen
// sin ella; todo lo de arriba —codificación, histograma, top-K— es `alloc` a
// secas y compila bajo `no_std`.
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod engine {
    use super::*;
    use crate::tree::Cursor;
    use crate::tx::PageSource;
    use crate::tx::{ReadTxn, WriteTxn};

    /// Tope de filas que se leen al cargar una celda de disco.
    ///
    /// Esta capa escribe como mucho `4·(k+1) + 1` filas por celda, así que con
    /// `k = 32` son 133 y este tope da dos órdenes de holgura. Existe porque
    /// **`0x02` es un espacio de datos de usuario** (ver `AGG_NS`): cualquiera
    /// puede plantar ahí un millón de filas con `put`, y sin tope la carga de
    /// una celda las leería todas. Pasado el tope se devuelve `Err` en vez de
    /// leer a medias: media celda cargada sobrescribiría con un agregado
    /// incompleto la mitad que no se llegó a leer.
    const MAX_LOAD_ROWS: usize = 4_096;

    /// Vuelca un cursor a memoria. El cursor toma prestada la transacción, así
    /// que hay que soltarlo antes de poder escribir en ella.
    fn collect<S: PageSource>(
        mut cur: Cursor<'_, S>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        while let Some(kv) = cur.next()? {
            if out.len() >= limit {
                return Err(Error::BadFormat);
            }
            out.push(kv);
        }
        Ok(out)
    }

    fn decode_row(k: &[u8], v: &[u8]) -> Result<Row> {
        let p = key::parse(k, Dimension::Total.code())?;
        let dim = Dimension::from_code(p.dim)?;
        if p.is_total != (dim == Dimension::Total) {
            return Err(Error::BadFormat);
        }
        Ok(Row {
            ts_bucket: p.ts_bucket,
            dim,
            value: p.value.map(|b| b.to_vec()),
            bucket: Bucket::decode(v)?,
        })
    }

    impl Rollup {
        /// Registra una petición en todas las resoluciones activas.
        ///
        /// Toma la transacción porque puede necesitarla: al abrir una celda
        /// lee de disco lo que ya hubiera de ella, y al pasar de
        /// `max_open_cells` escribe la más antigua y la suelta. Las dos cosas
        /// dentro de la transacción del llamante, nunca fuera.
        pub fn observe(&mut self, tx: &mut WriteTxn<'_>, obs: &Observation<'_>) -> Result<()> {
            let status_bytes = obs.status.to_be_bytes();
            for res in RESOLUTIONS {
                if !self.cfg.keeps(res) {
                    continue;
                }
                let ri = res.code() as usize;
                let tsb = res.bucket_of(obs.ts).ok_or(Error::BadFormat)?;
                self.ensure_cell(tx, res, tsb)?;
                let k = self.cfg.top_k;
                let cell = match self.cells[ri].get_mut(&tsb) {
                    Some(c) => c,
                    // Inalcanzable tras `ensure_cell`, pero un `unwrap` aquí
                    // sería un pánico en el camino caliente por un fallo de
                    // lógica interna. `Err` es estrictamente mejor.
                    None => return Err(Error::BadFormat),
                };
                cell.total.record(obs.latency_ms, obs.bytes_in, obs.bytes_out, obs.error)?;
                cell.total_dirty = true;
                for d in res.dimensions() {
                    let value: &[u8] = match d {
                        Dimension::Status => &status_bytes,
                        Dimension::Endpoint => obs.endpoint,
                        Dimension::Country => obs.country,
                        Dimension::User => obs.user,
                        Dimension::Total => continue,
                    };
                    cell.dim_mut(*d, k).record(
                        value,
                        obs.latency_ms,
                        obs.bytes_in,
                        obs.bytes_out,
                        obs.error,
                    )?;
                }
            }
            Ok(())
        }

        /// Abre la celda si no lo estaba: desaloja lo que sobre y carga de
        /// disco lo que ya hubiera.
        fn ensure_cell(
            &mut self,
            tx: &mut WriteTxn<'_>,
            res: Resolution,
            tsb: u32,
        ) -> Result<()> {
            let ri = res.code() as usize;
            if self.cells[ri].contains_key(&tsb) {
                return Ok(());
            }
            let cap = self.cfg.max_open_cells.max(1) as usize;
            while self.cells[ri].len() >= cap {
                let oldest = match self.cells[ri].keys().next().copied() {
                    Some(t) => t,
                    None => break,
                };
                if let Some(mut cell) = self.cells[ri].remove(&oldest) {
                    Self::write_cell(tx, res, oldest, &mut cell)?;
                }
            }

            let mut cell = Cell::new();
            // Carga: lo que ya hay en disco de esta celda entra en el estado
            // en RAM ANTES de que nadie observe nada. Sin esto, un reinicio a
            // mitad de hora haría que el primer volcado sobrescribiera la
            // fila de disco con solo lo visto desde el arranque — pérdida
            // silenciosa de la primera mitad de la hora.
            let (from, to) = key::cell_range(res.code(), tsb);
            let rows = collect(tx.scan(AGG_NS, &from, &to)?, MAX_LOAD_ROWS)?;
            let k = self.cfg.top_k;
            for (rk, rv) in rows {
                let row = decode_row(&rk, &rv)?;
                if row.ts_bucket != tsb {
                    return Err(Error::BadFormat);
                }
                match row.dim {
                    Dimension::Total => {
                        cell.total.merge(&row.bucket)?;
                        cell.total_on_disk = true;
                    }
                    d => {
                        let t = cell.dim_mut(d, k);
                        match &row.value {
                            None => {
                                t.drawer.merge(&row.bucket)?;
                                t.drawer_on_disk = true;
                            }
                            Some(v) => t.merge_value(v, &row.bucket, true)?,
                        }
                    }
                }
            }
            self.cells[ri].insert(tsb, cell);
            Ok(())
        }

        /// Escribe en `tx` todo lo pendiente, sin soltar el estado en RAM.
        ///
        /// Llamar justo antes del `commit` del lote. Solo escribe lo que ha
        /// cambiado desde el volcado anterior: sin ese filtro, un lote que
        /// toca 40 endpoints reescribiría las 133 filas de la celda.
        pub fn flush(&mut self, tx: &mut WriteTxn<'_>) -> Result<FlushStats> {
            let mut stats = FlushStats::default();
            for res in RESOLUTIONS {
                let ri = res.code() as usize;
                let keys: Vec<u32> = self.cells[ri].keys().copied().collect();
                for tsb in keys {
                    if let Some(cell) = self.cells[ri].get_mut(&tsb) {
                        stats.add(Self::write_cell(tx, res, tsb, cell)?);
                    }
                }
            }
            Ok(stats)
        }

        /// Vuelca una celda. Borrados primero y escrituras después, y ese
        /// orden **no es intercambiable**: un valor puede haber sido
        /// desalojado y readmitido entre dos volcados, de modo que está a la
        /// vez en la lista de borrados y en la tabla. Al revés se borraría la
        /// fila recién escrita.
        fn write_cell(
            tx: &mut WriteTxn<'_>,
            res: Resolution,
            tsb: u32,
            cell: &mut Cell,
        ) -> Result<FlushStats> {
            let mut stats = FlushStats::default();
            let rc = res.code();

            for slot in 0..DIM_SLOTS {
                let Some(t) = cell.dims[slot].as_mut() else { continue };
                let dim = Dimension::from_code(slot as u8)?;
                for v in t.pending_deletes() {
                    let k = key::dim_key(rc, tsb, dim.code(), Some(v));
                    if tx.delete(AGG_NS, &k)? {
                        stats.rows_deleted += 1;
                    }
                }
                t.clear_pending_deletes();

                for i in 0..t.entries().len() {
                    if !t.entries()[i].dirty {
                        continue;
                    }
                    let (k, v) = {
                        let e = &t.entries()[i];
                        (
                            key::dim_key(rc, tsb, dim.code(), Some(&e.value)),
                            e.bucket.encode(),
                        )
                    };
                    tx.put(AGG_NS, &k, &v)?;
                    stats.rows_written += 1;
                    stats.bytes_written += (k.len() + v.len() + 1) as u64;
                    let e = &mut t.entries_mut()[i];
                    e.dirty = false;
                    e.on_disk = true;
                }

                if t.drawer_dirty && !t.drawer.is_empty() {
                    let k = key::dim_key(rc, tsb, dim.code(), None);
                    let v = t.drawer.encode();
                    tx.put(AGG_NS, &k, &v)?;
                    stats.rows_written += 1;
                    stats.bytes_written += (k.len() + v.len() + 1) as u64;
                    t.drawer_dirty = false;
                    t.drawer_on_disk = true;
                }
            }

            if cell.total_dirty && !cell.total.is_empty() {
                let k = key::total_key(rc, tsb, Dimension::Total.code());
                let v = cell.total.encode();
                tx.put(AGG_NS, &k, &v)?;
                stats.rows_written += 1;
                stats.bytes_written += (k.len() + v.len() + 1) as u64;
                cell.total_dirty = false;
                cell.total_on_disk = true;
            }
            Ok(stats)
        }
    }

    /// Fila de totales de una celda.
    pub fn read_total(
        txn: &ReadTxn<'_>,
        res: Resolution,
        ts_bucket: u32,
    ) -> Result<Option<Bucket>> {
        let k = key::total_key(res.code(), ts_bucket, Dimension::Total.code());
        match txn.get(AGG_NS, &k)? {
            None => Ok(None),
            Some(v) => Ok(Some(Bucket::decode(&v)?)),
        }
    }

    /// Todas las filas de una dimensión en una celda: las K entradas y el
    /// cajón `otros`, en un solo recorrido de rango.
    pub fn read_dimension(
        txn: &ReadTxn<'_>,
        res: Resolution,
        ts_bucket: u32,
        dim: Dimension,
    ) -> Result<Vec<Row>> {
        let (from, to) = key::dim_range(res.code(), ts_bucket, dim.code());
        let rows = collect(txn.scan(AGG_NS, &from, &to)?, MAX_LOAD_ROWS)?;
        rows.iter().map(|(k, v)| decode_row(k, v)).collect()
    }

    /// Todas las filas de una resolución en `[from_bucket, to_bucket)`.
    ///
    /// `limit` acota el trabajo: un rango de dos años en resolución de minuto
    /// son un millón de celdas, y devolverlas todas en un `Vec` es justo la
    /// clase de asignación sin cota que la invariante 2 prohíbe. Pasado el
    /// tope se devuelve `Err`, no un resultado truncado que parecería
    /// completo.
    pub fn read_range(
        txn: &ReadTxn<'_>,
        res: Resolution,
        from_bucket: u32,
        to_bucket: u32,
        limit: usize,
    ) -> Result<Vec<Row>> {
        let (from, to) = key::bucket_range(res.code(), from_bucket, to_bucket);
        let rows = collect(txn.scan(AGG_NS, &from, &to)?, limit)?;
        rows.iter().map(|(k, v)| decode_row(k, v)).collect()
    }

    /// Borra todas las celdas de `res` anteriores a `ts_bucket`.
    ///
    /// Un `delete_range` sobre un rango contiguo, que es lo que compra el
    /// `ts_bucket` en big-endian: libera subárboles enteros sin visitar
    /// entrada por entrada.
    ///
    /// **No podes una celda que siga abierta en RAM**: el volcado siguiente
    /// la reescribiría con lo que llevara acumulado, resucitando media celda.
    /// Con cualquier retención razonable —la más corta son 48 horas— eso no
    /// puede pasar.
    pub fn prune_before(
        tx: &mut WriteTxn<'_>,
        res: Resolution,
        ts_bucket: u32,
    ) -> Result<()> {
        let (from, to) = key::bucket_range(res.code(), 0, ts_bucket);
        tx.delete_range(AGG_NS, &from, &to)
    }
}

#[cfg(feature = "std")]
pub use engine::{prune_before, read_dimension, read_range, read_total};

#[cfg(test)]
mod tests;
