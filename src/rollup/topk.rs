//! Top-K por dimensión con cajón `otros`, en RAM acotada.
//!
//! **Este módulo es la defensa contra el modo de fallo que llena discos.** Una
//! ruta con identificadores incrustados (`/users/48213/orders`) lleva una
//! dimensión de 200 valores por hora a millones (sección 12.4 de la
//! especificación). Contar todo y quedarse luego con los K mayores NO sirve:
//! sostiene en memoria cada valor distinto antes de descartarlo, que es
//! exactamente el ataque, solo que contra la RAM en vez de contra el disco.
//!
//! ## El algoritmo: Space-Saving con el contador partido
//!
//! Space-Saving (Metwally, Agrawal y El Abbadi, 2005) mantiene **exactamente
//! K contadores**, pase lo que pase con la cardinalidad. Al llegar un valor
//! que no está y con los K llenos, desaloja el de cuenta mínima y le da su
//! sitio al nuevo con `cuenta = mínimo + 1`. De ahí sale su garantía: la
//! cuenta guardada nunca se queda corta, se pasa como mucho en `N/K`, y por
//! tanto **ningún valor con frecuencia por encima de `N/K` puede faltar**.
//!
//! Aquí cada entrada no es una cuenta sino un `Bucket` entero (peticiones,
//! errores, bytes, latencia máxima e histograma), y eso obliga a una
//! variante. Si el valor nuevo heredara el `Bucket` del desalojado —que es lo
//! que hace Space-Saving literal con su contador— un endpoint aparecería en el
//! panel con los bytes y la latencia de otro. Es un error sin cota: un
//! `/health` con cuatro peticiones puede heredar los 4 GB de un `/download`.
//!
//! Por eso el contador se parte en dos:
//!
//! | Campo | Qué es | Quién lo ve |
//! |---|---|---|
//! | `debt` | La cuenta heredada del desalojado. Fantasma: no corresponde a ninguna petición de este valor | Nadie. Solo ordena desalojos |
//! | `bucket` | Las peticiones REALES de este valor desde su última admisión | Quien lee el agregado |
//!
//! La prioridad de desalojo es `debt + bucket.requests`, que es **exactamente**
//! el contador de Space-Saving: la dinámica de admisiones y desalojos es
//! idéntica, letra por letra, a la del algoritmo publicado. Lo que cambia es
//! qué se informa. Y el `Bucket` del desalojado no se tira: se funde en el
//! cajón `otros`.
//!
//! ## Error que produce, con su demostración
//!
//! Sea `N` el total de observaciones de la dimensión en esta celda y `K` el
//! número de contadores.
//!
//! - **Conservación exacta.** `Σ entradas + otros == N`, campo a campo
//!   (peticiones, errores, bytes, histograma). Ninguna observación se pierde
//!   ni se cuenta dos veces: cada una entra en exactamente un `Bucket`, y un
//!   desalojo mueve un `Bucket` entero al cajón sin tocar su contenido.
//!   Comprobado en `conservation_holds_under_an_adversarial_cardinality_flood`.
//! - **Nunca se exagera.** Lo que se informa de un valor son observaciones
//!   suyas y de nadie más. `informado <= verdadero`, siempre.
//! - **Cuánto se queda corto.** `verdadero − informado <= debt <= N/K`. La
//!   parte que falta no se pierde: está en `otros`. (Demostración: la suma de
//!   prioridades es invariante ante desalojos y sube en 1 por observación,
//!   luego vale `N`; con K entradas el mínimo es `<= N/K`. Y la garantía de
//!   Space-Saving da `debt + requests >= verdadero`.)
//! - **Ningún pesado se pierde.** Todo valor con frecuencia `> N/K` está en la
//!   tabla al final. Es la garantía de Space-Saving, y se hereda entera porque
//!   la prioridad es su contador. Comprobado en
//!   `a_heavy_hitter_survives_an_adversarial_interleaving`.
//!
//! El caso que esta variante NO cubre y el Space-Saving literal sí: saber la
//! cuenta total de un valor pesado sin sumarle nada del cajón. Se paga a
//! cambio de que ninguna cifra informada esté contaminada por otro valor, que
//! para un panel es el intercambio correcto — una cifra que se queda corta con
//! el resto visible en `otros` se puede leer; una cifra inventada, no.
//!
//! ## RAM
//!
//! `K` entradas exactas por `(resolución, ts_bucket, dimensión)`, más el
//! cajón. Cada entrada son el valor (acotado a `MAX_DIM_LEN` bytes), el
//! `Bucket` (unos 176 bytes, dominados por los 128 del histograma) y la deuda.
//! **Independiente por completo del número de valores distintos**, que es la
//! propiedad que se buscaba. El número medido está en el informe.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Result;
use crate::rollup::bucket::Bucket;

/// Longitud máxima del valor de una dimensión.
///
/// Dos motivos, y el segundo es el que fija el número. (1) Acota la RAM de una
/// entrada. (2) La clave completa de un agregado es
/// `[ns][res][ts×4][dim][tag] ++ valor` = 8 bytes más el valor, y el motor
/// rechaza cualquier clave por encima de un cuarto de página LÓGICA
/// (invariante 15): con páginas de 512 bytes y cifrado eso son 118 bytes, así
/// que 64 + 8 = 72 cabe con holgura en la geometría más apretada que el motor
/// admite. Subirlo a 128 rompería las bases de 512 bytes cifradas — el tier
/// micro, precisamente.
pub const MAX_DIM_LEN: usize = 64;

/// Una entrada del top-K.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Valor de la dimensión. Nunca más largo que `MAX_DIM_LEN`.
    pub value: Vec<u8>,
    /// Agregado REAL de este valor desde su última admisión.
    pub bucket: Bucket,
    /// Cuenta heredada al admitirlo. Fantasma, nunca se informa.
    pub debt: u64,
    /// El valor ya existe como fila en disco por un volcado anterior de este
    /// mismo proceso. Decide si al desalojarlo hay que borrar esa fila.
    pub on_disk: bool,
    /// Ha cambiado desde el último volcado. Sin este filtro, un lote que toca
    /// cuarenta endpoints reescribiría las K+1 filas de la dimensión entera:
    /// es la diferencia entre añadir un 4% de escrituras y añadir un 13%.
    pub dirty: bool,
}

impl Entry {
    fn priority(&self) -> u64 {
        self.debt.saturating_add(self.bucket.requests)
    }
}

/// Top-K de una dimensión dentro de una celda `(resolución, ts_bucket)`.
#[derive(Clone, Debug)]
pub struct TopK {
    k: u16,
    entries: Vec<Entry>,
    /// Índice `valor → posición en entries`. Evita recorrer las K entradas en
    /// cada observación; el recorrido lineal solo queda en el desalojo, que
    /// ocurre como mucho una vez por observación y en la práctica casi nunca.
    index: BTreeMap<Vec<u8>, usize>,
    /// El cajón `otros`: todo lo desalojado, fundido.
    pub drawer: Bucket,
    /// El cajón ya existe como fila en disco.
    pub drawer_on_disk: bool,
    /// El cajón ha cambiado desde el último volcado.
    pub drawer_dirty: bool,
    /// Valores cuya fila de disco hay que borrar en el próximo volcado
    /// porque se desalojaron. Subconjunto de los que alguna vez se
    /// escribieron, así que su tamaño está acotado por `k`.
    pending_deletes: Vec<Vec<u8>>,
}

impl TopK {
    /// `k` se satura a 1 por abajo: un top-0 no tendría dónde poner nada y
    /// mandaría el 100% del tráfico al cajón sin decirlo.
    pub fn new(k: u16) -> Self {
        TopK {
            k: k.max(1),
            entries: Vec::new(),
            index: BTreeMap::new(),
            drawer: Bucket::new(),
            drawer_on_disk: false,
            drawer_dirty: false,
            pending_deletes: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entries_mut(&mut self) -> &mut [Entry] {
        &mut self.entries
    }

    pub fn pending_deletes(&self) -> &[Vec<u8>] {
        &self.pending_deletes
    }

    pub fn clear_pending_deletes(&mut self) {
        self.pending_deletes.clear();
    }

    /// Bytes de RAM que ocupa esta tabla ahora mismo, contando lo que hay
    /// dentro de los `Vec`. Aproximado pero honesto: es la cifra que se
    /// publica en el informe, así que se calcula en vez de estimarse.
    pub fn ram_bytes(&self) -> usize {
        let entry = core::mem::size_of::<Entry>();
        let mut n = core::mem::size_of::<Self>() + self.entries.capacity() * entry;
        for e in &self.entries {
            n += e.value.capacity();
            // Nodo del BTreeMap: la clave duplicada más el índice.
            n += e.value.len() + core::mem::size_of::<usize>() + 16;
        }
        for d in &self.pending_deletes {
            n += d.capacity();
        }
        n
    }

    /// Índice de la entrada de prioridad mínima. `None` si está vacía.
    fn min_index(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, e) in self.entries.iter().enumerate() {
            let p = e.priority();
            match best {
                Some((_, bp)) if bp <= p => {}
                _ => best = Some((i, p)),
            }
        }
        best.map(|(i, _)| i)
    }

    /// Localiza el hueco donde deben ir las observaciones de `value`,
    /// admitiéndolo si hace falta, y devuelve `Some(posición)` — o `None` si
    /// el valor tiene que ir al cajón por ser demasiado largo.
    ///
    /// **Un valor por encima de `MAX_DIM_LEN` va al cajón, no a un error.**
    /// Es la decisión que mantiene los totales exactos ante el caso que más
    /// importa: una ruta con un identificador incrustado y largo es
    /// precisamente el ataque de cardinalidad, y el cajón es donde pertenece.
    /// Devolver `Err` haría que la petición no se contara en ningún sitio, que
    /// es peor: un total que no cuadra.
    fn slot_for(&mut self, value: &[u8]) -> Option<usize> {
        if value.len() > MAX_DIM_LEN {
            return None;
        }
        if let Some(&i) = self.index.get(value) {
            return Some(i);
        }
        if self.entries.len() < self.k as usize {
            let i = self.entries.len();
            self.entries.push(Entry {
                value: value.to_vec(),
                bucket: Bucket::new(),
                debt: 0,
                on_disk: false,
                dirty: false,
            });
            self.index.insert(value.to_vec(), i);
            return Some(i);
        }
        // Tabla llena: desalojo Space-Saving.
        let victim = self.min_index()?;
        let min_priority = self.entries[victim].priority();
        // El agregado real del desalojado va al cajón. Que `merge` pueda
        // fallar por desbordamiento se propaga como un cajón que no crece:
        // aquí no hay `Result` que devolver sin convertir el camino caliente
        // en fallible, y un desbordamiento de `u64` en un contador de
        // peticiones de una sola celda horaria es inalcanzable. Se deja
        // explícito en vez de con `unwrap`, que sí sería un pánico.
        let _ = self.drawer.merge(&self.entries[victim].bucket);
        self.drawer_dirty = true;
        let old = core::mem::replace(&mut self.entries[victim].value, value.to_vec());
        self.index.remove(&old);
        if self.entries[victim].on_disk {
            self.pending_deletes.push(old);
        }
        self.entries[victim].bucket = Bucket::new();
        self.entries[victim].debt = min_priority;
        self.entries[victim].on_disk = false;
        self.entries[victim].dirty = false;
        self.index.insert(value.to_vec(), victim);
        Some(victim)
    }

    /// Registra una petición bajo `value`.
    pub fn record(
        &mut self,
        value: &[u8],
        latency_ms: u32,
        bytes_in: u64,
        bytes_out: u64,
        error: bool,
    ) -> Result<()> {
        match self.slot_for(value) {
            Some(i) => {
                self.entries[i].dirty = true;
                self.entries[i].bucket.record(latency_ms, bytes_in, bytes_out, error)
            }
            None => {
                self.drawer_dirty = true;
                self.drawer.record(latency_ms, bytes_in, bytes_out, error)
            }
        }
    }

    /// Funde un `Bucket` ya formado bajo `value` — el camino de la carga
    /// desde disco, donde la unidad no es una petición sino una fila entera.
    ///
    /// Generalización con peso de la admisión de Space-Saving: si hay sitio,
    /// entra con deuda cero; si no, desaloja el mínimo y entra con
    /// `deuda = mínimo`, de forma que su prioridad queda `mínimo + peso`,
    /// exactamente lo que prescribe la versión con pesos del algoritmo.
    pub fn merge_value(&mut self, value: &[u8], b: &Bucket, on_disk: bool) -> Result<()> {
        match self.slot_for(value) {
            Some(i) => {
                self.entries[i].bucket.merge(b)?;
                self.entries[i].on_disk |= on_disk;
                Ok(())
            }
            None => {
                self.drawer_dirty = true;
                self.drawer.merge(b)
            }
        }
    }

    /// Marca que `value` sigue vivo en disco tras un volcado.
    pub fn mark_on_disk(&mut self, i: usize) {
        self.entries[i].on_disk = true;
    }

    /// Total de peticiones vistas por esta tabla, cajón incluido. Es el `N`
    /// de las cotas del comentario de módulo.
    pub fn observed(&self) -> u64 {
        self.entries
            .iter()
            .fold(self.drawer.requests, |a, e| a.saturating_add(e.bucket.requests))
    }

    /// Cota superior del error de subestimación de cualquier entrada:
    /// `N/K` cuando la tabla está llena, cero mientras no lo esté (sin
    /// desalojos no hay deuda posible).
    pub fn understatement_bound(&self) -> u64 {
        if self.entries.len() < self.k as usize {
            0
        } else {
            self.observed() / self.k as u64
        }
    }

    /// Comprobación interna, no del llamante: la deuda de ninguna entrada
    /// supera la cota anunciada. Solo la usan las pruebas y el auditor.
    pub fn debt_within_bound(&self) -> bool {
        let bound = self.understatement_bound();
        self.entries.iter().all(|e| e.debt <= bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn obs(t: &mut TopK, v: &[u8]) {
        t.record(v, 5, 10, 100, false).unwrap();
    }

    #[test]
    fn ram_stays_flat_while_cardinality_explodes() {
        // El ataque literal de la sección 12.4: un identificador incrustado
        // en la ruta.
        let mut t = TopK::new(32);
        let mut sizes = Vec::new();
        for i in 0..50_000u32 {
            obs(&mut t, format!("/users/{i}/orders").as_bytes());
            // La primera muestra se toma con la tabla YA llena: comparar
            // contra el arranque mediría el llenado inicial, no el efecto de
            // la cardinalidad, que es lo que esta prueba existe para acotar.
            if i >= 10_000 && i % 10_000 == 0 {
                sizes.push(t.ram_bytes());
            }
        }
        assert_eq!(t.entries().len(), 32, "la tabla nunca pasa de K entradas");
        let first = sizes[0];
        for s in &sizes {
            assert!(
                *s <= first + 4096,
                "la RAM creció de {first} a {s} bytes con la cardinalidad: {sizes:?}"
            );
        }
        // Y en términos absolutos: 32 entradas con valores cortos.
        assert!(first < 16 * 1024, "{first} bytes para 32 entradas");
    }

    #[test]
    fn conservation_holds_under_an_adversarial_cardinality_flood() {
        let mut t = TopK::new(16);
        let mut n = 0u64;
        for i in 0..20_000u32 {
            // Mezcla: un puñado de pesados y una riada de valores únicos.
            let v = if i % 3 == 0 {
                format!("/api/v1/{}", i % 4)
            } else {
                format!("/users/{i}/orders")
            };
            t.record(v.as_bytes(), i % 300, 7, 11, i % 50 == 0).unwrap();
            n += 1;
        }
        let sum_req: u64 = t.entries().iter().map(|e| e.bucket.requests).sum();
        let sum_err: u64 = t.entries().iter().map(|e| e.bucket.errors).sum();
        let sum_in: u64 = t.entries().iter().map(|e| e.bucket.bytes_in).sum();
        let sum_hist: u64 = t.entries().iter().map(|e| e.bucket.hist.total()).sum();
        assert_eq!(sum_req + t.drawer.requests, n, "peticiones no conservadas");
        // 20.000 observaciones con `i % 50 == 0` son exactamente 400.
        assert_eq!(sum_err + t.drawer.errors, 400, "errores no conservados");
        assert_eq!(sum_in + t.drawer.bytes_in, n * 7, "bytes_in no conservados");
        assert_eq!(sum_hist + t.drawer.hist.total(), n, "muestras de latencia no conservadas");
        assert!(t.debt_within_bound(), "alguna deuda supera N/K");
    }

    #[test]
    fn a_heavy_hitter_survives_an_adversarial_interleaving() {
        // El caso que hunde a un top-K ingenuo con reinicio a 1: pesado,
        // único, pesado, único... Un desalojo por observación, y el pesado
        // siempre el más reciente y por tanto el mínimo si no heredara la
        // deuda.
        let mut t = TopK::new(8);
        for i in 0..20_000u32 {
            if i % 2 == 0 {
                obs(&mut t, b"/pesado");
            } else {
                obs(&mut t, format!("/unico/{i}").as_bytes());
            }
        }
        let heavy = t.entries().iter().find(|e| e.value == b"/pesado");
        assert!(heavy.is_some(), "el pesado (50% del tráfico) se perdió de la tabla");
        let heavy = heavy.unwrap();
        assert!(heavy.bucket.requests > 0);
        // Y la cota: lo que le falta está en el cajón, y no pasa de N/K.
        let bound = t.understatement_bound();
        assert!(
            10_000 - heavy.bucket.requests <= bound,
            "subestimación de {} por encima de la cota N/K = {bound}",
            10_000 - heavy.bucket.requests
        );
    }

    #[test]
    fn no_entry_is_ever_contaminated_by_another_value() {
        // La propiedad que justifica partir el contador: `/barato` no puede
        // heredar los bytes de `/caro`.
        let mut t = TopK::new(2);
        t.record(b"/caro", 10, 0, 1_000_000, false).unwrap();
        t.record(b"/caro", 10, 0, 1_000_000, false).unwrap();
        t.record(b"/medio", 10, 0, 10, false).unwrap();
        // `/barato` desaloja al mínimo (`/medio`).
        t.record(b"/barato", 10, 0, 1, false).unwrap();
        let barato = t.entries().iter().find(|e| e.value == b"/barato").unwrap();
        assert_eq!(barato.bucket.bytes_out, 1, "heredó bytes de otro valor");
        assert_eq!(barato.bucket.requests, 1);
        assert!(barato.debt > 0, "pero sí hereda la prioridad, que es lo que lo protege");
        assert_eq!(t.drawer.bytes_out, 10, "los bytes del desalojado están en el cajón");
    }

    #[test]
    fn an_oversized_value_goes_to_the_drawer_and_not_to_an_error() {
        let mut t = TopK::new(4);
        let long = alloc::vec![b'x'; MAX_DIM_LEN + 1];
        t.record(&long, 3, 1, 2, false).unwrap();
        assert!(t.entries().is_empty());
        assert_eq!(t.drawer.requests, 1);
        let ok = alloc::vec![b'x'; MAX_DIM_LEN];
        t.record(&ok, 3, 1, 2, false).unwrap();
        assert_eq!(t.entries().len(), 1, "justo en el límite sí entra");
    }

    #[test]
    fn evicting_a_value_that_lives_on_disk_queues_its_deletion() {
        let mut t = TopK::new(1);
        obs(&mut t, b"a");
        t.mark_on_disk(0);
        obs(&mut t, b"b");
        assert_eq!(t.pending_deletes(), &[b"a".to_vec()]);
        t.clear_pending_deletes();
        assert!(t.pending_deletes().is_empty());
    }

    #[test]
    fn evicting_a_value_never_written_queues_nothing() {
        let mut t = TopK::new(1);
        obs(&mut t, b"a");
        obs(&mut t, b"b");
        assert!(t.pending_deletes().is_empty(), "borrar una fila que no existe sería trabajo inútil");
    }

    #[test]
    fn merge_value_admits_with_weight_like_space_saving() {
        let mut t = TopK::new(2);
        let mut heavy = Bucket::new();
        for _ in 0..100 {
            heavy.record(5, 1, 1, false).unwrap();
        }
        t.merge_value(b"a", &heavy, true).unwrap();
        t.merge_value(b"b", &heavy, true).unwrap();
        // Con la tabla llena, uno nuevo desaloja al mínimo y hereda su
        // prioridad.
        let mut light = Bucket::new();
        light.record(5, 1, 1, false).unwrap();
        t.merge_value(b"c", &light, false).unwrap();
        let c = t.entries().iter().find(|e| e.value == b"c").unwrap();
        assert_eq!(c.bucket.requests, 1, "no hereda las peticiones");
        assert_eq!(c.debt, 100, "pero sí la prioridad");
        assert_eq!(t.drawer.requests, 100, "lo desalojado está entero en el cajón");
    }

    #[test]
    fn k_of_zero_is_clamped_instead_of_sending_everything_to_the_drawer() {
        let mut t = TopK::new(0);
        obs(&mut t, b"a");
        assert_eq!(t.entries().len(), 1);
    }

    /// Generador congruencial lineal propio; `rand` sería una dependencia.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 11
        }
    }

    /// Reparto zipf-iano por rangos con pesos ENTEROS `1.000.000 / r`: el de
    /// las rutas de una API real, y el que de verdad decide cuánto acierta un
    /// top-K. Un reparto uniforme haría la pregunta fácil y no es el caso que
    /// importa. Sin coma flotante, para que la prueba corra también bajo
    /// `no_std`.
    struct Zipf {
        cum: Vec<u64>,
    }

    impl Zipf {
        fn new(n: u32) -> Self {
            let mut cum = Vec::with_capacity(n as usize);
            let mut acc = 0u64;
            for r in 1..=n as u64 {
                acc += 1_000_000 / r;
                cum.push(acc);
            }
            Zipf { cum }
        }
        fn total(&self) -> u64 {
            *self.cum.last().unwrap()
        }
        fn pick(&self, x: u64) -> usize {
            let t = x % self.total();
            match self.cum.binary_search(&t) {
                Ok(i) => i + 1,
                Err(i) => i,
            }
        }
    }

    /// **Las tres garantías del módulo con el `K = 4` del perfil por defecto**,
    /// sobre el reparto que se encuentra de verdad. Con `K = 32` la cota `N/K`
    /// era ocho veces más apretada; que la cota se afloje no puede convertir
    /// ninguna de las tres en falsa, y eso es justo lo que aquí se comprueba.
    #[test]
    fn at_the_default_k_of_four_a_zipfish_dimension_keeps_every_guarantee() {
        const N: u64 = 20_000;
        let z = Zipf::new(200);
        let mut rng = Lcg(0x5eed);
        let mut t = TopK::new(4);
        let mut truth: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for i in 0..N {
            let v = format!("/api/v1/{}", z.pick(rng.next()));
            *truth.entry(v.as_bytes().to_vec()).or_insert(0) += 1;
            t.record(v.as_bytes(), (i % 400) as u32, 7, 11, i % 50 == 0).unwrap();
        }

        // 1. Conservación exacta, campo a campo.
        let sum = |f: fn(&Entry) -> u64| t.entries().iter().map(f).sum::<u64>();
        assert_eq!(sum(|e| e.bucket.requests) + t.drawer.requests, N);
        assert_eq!(sum(|e| e.bucket.errors) + t.drawer.errors, N / 50);
        assert_eq!(sum(|e| e.bucket.bytes_in) + t.drawer.bytes_in, N * 7);
        assert_eq!(sum(|e| e.bucket.hist.total()) + t.drawer.hist.total(), N);

        // 2. Nunca se exagera.
        for e in t.entries() {
            let real = truth.get(&e.value).copied().unwrap_or(0);
            assert!(
                e.bucket.requests <= real,
                "informado {} por encima del verdadero {real}",
                e.bucket.requests
            );
        }

        // 3. Ningún pesado por encima de N/K se pierde, con la cota ocho veces
        //    más floja.
        assert_eq!(t.understatement_bound(), N / 4);
        for (v, real) in &truth {
            if *real > N / 4 {
                assert!(
                    t.entries().iter().any(|e| e.value == *v),
                    "un valor con {real} de {N} peticiones no está en la tabla"
                );
            }
        }
        assert!(t.debt_within_bound());
    }

    #[test]
    fn the_understatement_bound_is_zero_until_the_table_fills() {
        let mut t = TopK::new(4);
        obs(&mut t, b"a");
        obs(&mut t, b"b");
        assert_eq!(t.understatement_bound(), 0, "sin desalojos no hay subestimación posible");
    }
}
