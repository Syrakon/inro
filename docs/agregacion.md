# Agregación temporal — `inro::rollup`

La capa que hace que los informes sobrevivan a los registros que los
respaldan. Implementa la sección 12.3 de la especificación de diseño.

El motor guarda **34,14 bytes por registro crudo**, medidos, y eso está cerca
del suelo de una fila. Lo que queda por ganar no es guardar menos bytes por
fila: es **dejar de guardar casi todas las filas**. Con los crudos viviendo 6
horas y los agregados sobreviviéndolos, un informe de dos años se sirve sin
que exista ni uno solo de los registros que lo respaldan.

Tras la *feature* `rollup`, activada por defecto.

---

## 1. Qué es y qué no es

| Sí | No |
|---|---|
| Codificación de agregados, histograma de latencia, top-K acotado | Cadena de hashes de facturación (sección 12.3, tarea aparte) |
| Agregación en la MISMA transacción que el crudo | Diccionarios de interning (`0x03`) |
| Lectura de agregados por rango de tiempo | Planificador de poda: la política es del llamante |
| Lo que una poda necesita (`prune_before`, `cutoff_bucket`) | Poda del espacio crudo: la hace el llamante con `delete_range` |

**No hay hilo de fondo ni tarea programada.** El agregado en curso vive en RAM
y se escribe en la transacción del llamante, así que hereda tal cual las
garantías de consistencia ante cortes del motor: o se confirman el crudo y su
agregado, o ninguno de los dos.

---

## 2. Uso

```rust
use inro::rollup::{Config, Observation, Rollup, RAW_NS_RECOMMENDED};

let mut rollup = Rollup::new(Config::default());

let mut tx = db.begin_write()?;
for r in lote {
    tx.put(RAW_NS_RECOMMENDED, &clave_cruda(r), &valor_crudo(r))?;
    rollup.observe(&mut tx, &Observation {
        ts: r.ts_segundos,
        latency_ms: r.latencia,
        bytes_in: r.bytes_recibidos,
        bytes_out: r.bytes_enviados,
        status: r.codigo,
        error: r.es_error,          // lo decide la aplicación, no esta capa
        endpoint: r.ruta.as_bytes(),
        country: r.pais.as_bytes(),
        user: r.usuario.as_bytes(),
    })?;
}
rollup.flush(&mut tx)?;
tx.commit()?;
```

Lectura:

```rust
use inro::rollup::{Dimension, Resolution, read_dimension, read_range, read_total};

let rd = db.begin_read();
let celda = Resolution::Hour.bucket_of(ahora).unwrap();

let total = read_total(&rd, Resolution::Hour, celda)?;      // una fila
let p99 = total.unwrap().percentile(990);                    // intervalo + punto

let top = read_dimension(&rd, Resolution::Hour, celda, Dimension::Endpoint)?;
for fila in &top {
    if fila.is_drawer() { /* el cajón `otros` */ }
}

// Un rango de tiempo entero, con tope de filas explícito.
let serie = read_range(&rd, Resolution::Hour, desde, hasta, 10_000)?;
```

Poda (la política —cuándo— es del llamante):

```rust
let corte = Resolution::Hour.cutoff_bucket(ahora, Resolution::Hour.default_retention_secs());
let mut tx = db.begin_write()?;
inro::rollup::prune_before(&mut tx, Resolution::Hour, corte.unwrap())?;
tx.commit()?;
```

### Contrato de error, y no es opcional

**Si la transacción NO llega a confirmar después de un `flush` —porque
`commit` devolvió `Err`, o porque se abandonó— hay que llamar a
`Rollup::reset()`.** Es el mismo contrato que el motor ya impone para
`put`/`delete` (invariante 14). El estado en RAM da por escritas cosas que no
llegaron al medio; `reset` lo tira entero y el volcado siguiente reconstruye
desde disco. Sin él, el borrado de una fila desalojada puede quedarse sin
aplicar mientras su contenido ya está en el cajón, y esa fila se contaría dos
veces al leer.

---

## 3. El espacio de claves del crudo importa, y mucho

**Pon los registros crudos en un espacio de claves POR ENCIMA del de los
agregados.** `RAW_NS_RECOMMENDED` (`0x7f`) es el valor sugerido.

`tree.rs` reparte una hoja desbordada por el punto medio **salvo** cuando la
clave que entra es la mayor de TODO el árbol y la hoja es la de más a la
derecha (`SplitBias::Append`). Ese sesgo es lo que bajó el crudo de 67,72 a
34,14 bytes por entrada, porque un log se inserta siempre por el final. El
motor antepone el byte de espacio de claves a cada clave, así que **el orden
de los espacios es el orden del árbol**: con el crudo en `0x01` y los
agregados en `0x02`, basta UNA fila de agregado para que ninguna clave cruda
vuelva a ser la mayor del árbol.

Medido (`tests/rollup_size.rs`,
`one_aggregate_row_costs_the_raw_path_its_append_split_bias`; 20.000 entradas,
páginas de 4 KB):

| Disposición | B/entrada |
|---|---|
| Crudo en `0x01`, nada en `0x02` | 39,94 |
| Crudo en `0x01`, **una** fila en `0x02` | **84,99** (+112,8%) |
| Crudo en `0x7f`, una fila en `0x02` | 38,91 (−2,6%) |

Es una desviación deliberada del mapa de espacios de la sección 10 de la
especificación, que pone el crudo en `0x01`. El arreglo de fondo sería que
`SplitBias` razonara por espacio de claves y no por «mayor clave del árbol»,
pero cambiar la política de partición de nodos es una tarea propia con su
propia revisión — la propia sección 12.2 lo dice.

---

## 4. Formato en disco

### Clave

```
[0x02][res u8][ts_bucket u32 BE][dim u8]                     ← fila de totales
[0x02][res u8][ts_bucket u32 BE][dim u8][tag u8][valor...]   ← fila de dimensión
```

`0x02` lo antepone el motor (`WriteTxn::put(ns, ...)`); el resto es la clave
que construye `rollup::key`.

- `res`: 0 minuto, 1 hora, 2 día.
- `ts_bucket`: instante unix dividido por la anchura de la celda, **big-endian**
  — orden lexicográfico igual a orden cronológico, que es lo que hace que leer
  un intervalo sea un recorrido contiguo y podar sea un solo `delete_range`.
- `dim`: 0 total, 1 estado, 2 endpoint, 3 país, 4 usuario.
- `tag`: `0x00` el cajón `otros` (sin nada detrás), `0x01` un valor literal.
  El byte cuesta uno por fila y evita que una dimensión vacía (un país
  desconocido, por ejemplo) se confunda con el cajón. Con el cajón en `0x00`
  ordena el primero dentro de su dimensión, así que un solo recorrido de
  `[res][ts][dim]` a `[res][ts][dim+1]` lo trae junto con las K entradas.

Valor de dimensión: como mucho `MAX_DIM_LEN` = 64 bytes. Uno más largo va al
cajón — no da error: una ruta larga con un identificador incrustado es
precisamente el ataque de cardinalidad, y el cajón es su sitio; rechazarla
dejaría la petición sin contar en ningún lado.

### Valor

```
[versión u8 = 1]
[requests varint][errors varint][bytes_in varint][bytes_out varint]
[max_latency varint]
[máscara varint]                 bit k = 1 ⇔ la cubeta k del histograma no está vacía
[cuenta varint] × popcount(máscara)
```

**Sin CRC propio**: la página ya lleva CRC32 sobre todo su contenido y
`PageRef::parse` es la única frontera de validación de una página (invariante
1). Para que estos bytes lleguen manipulados a `decode`, la página entera ha
tenido que pasar su propio CRC.

**Lo que `decode` comprueba además de la sintaxis**, y las tres son ciertas
por construcción en cualquier bucket que esta capa escriba:

1. `errors <= requests`.
2. `suma del histograma == requests` — cada petición aporta exactamente una
   muestra de latencia.
3. `bucket_of(max_latency) == cubeta no vacía más alta` — `max_latency` es una
   de las muestras y ninguna la supera. Es la que atrapa un solo byte cambiado
   en `max_latency`, que las otras dos dejarían pasar.

Cualquier desviación —versión desconocida, varint truncado, bytes de sobra al
final, máscara con bits imposibles, un bit puesto con cuenta cero— sale como
`Err`, nunca como un bucket a medias.

---

## 5. Histograma de latencia

16 cubetas logarítmicas, como fija la especificación:

```
cubeta  0 → [0, 0]
cubeta  k → [2^(k-1), 2^k − 1]   para k = 1..14
cubeta 15 → [16384, ∞)           cerrada por `max_latency`
```

Con 16 cubetas, rango y precisión se oponen directamente: cubrir hasta el
orden del *timeout* de un HTTP obliga a la base 2. Una escalera de base √2
daría la mitad de anchura relativa pero solo llegaría a 256 ms.

`Bucket::percentile(permille)` devuelve **un intervalo y un punto**:

- `lo`/`hi` son una **garantía**: el percentil exacto de las muestras cae ahí
  dentro, siempre. Es contención exacta por construcción y se comprueba contra
  percentiles exactos sobre siete repartos distintos.
- `estimate` es un punto dentro del intervalo, por comodidad. Nada más.

Cotas y medición (`rollup::hist::tests`):

| Métrica | Valor |
|---|---|
| Contención del percentil exacto en `[lo, hi]` | **100%**, garantía dura |
| Anchura del intervalo, cubetas cerradas | `hi < 2·lo` |
| Error de un punto óptimo (`4/3·lo`) | ≤ **33,3%** |
| Error medido de la estimación interpolada, peor caso | **33,3%** (p50 bimodal) |
| Error medido, mediana de quince casos | **< 5%** |
| Coste del histograma en una celda horaria real | **≤ 20 bytes** |

`max_latency` recorta el techo de *cualquier* cubeta, no solo de la abierta:
ninguna muestra lo supera. Con todas las muestras a 5 ms, la cubeta 3 es
`[4, 7]` pero el intervalo devuelto es `[4, 5]`.

Sin coma flotante en ninguna parte: `f64::ceil` es de `std` y este módulo
compila bajo `no_std`. El percentil se pide en **por mil** (`500`, `950`,
`990`) para no necesitar un flotante ni en la interfaz.

---

## 6. Top-K con cajón `otros`

Una ruta con identificadores incrustados (`/users/48213/orders`) lleva una
dimensión de 200 valores por hora a millones. Contar todo y quedarse luego con
los K mayores **no sirve**: sostiene en memoria cada valor distinto antes de
descartarlo, que es el mismo ataque contra la RAM en vez de contra el disco.

**Algoritmo: Space-Saving (Metwally, Agrawal y El Abbadi, 2005) con el
contador partido.** El contador de cada entrada se parte en dos:

| Campo | Qué es | Quién lo ve |
|---|---|---|
| `debt` | La cuenta heredada del desalojado. Fantasma | Nadie: solo ordena desalojos |
| `bucket` | Las peticiones reales desde su última admisión | Quien lee el agregado |

La prioridad de desalojo es `debt + bucket.requests`, que es **exactamente** el
contador de Space-Saving: la dinámica de admisiones y desalojos es idéntica a
la del algoritmo publicado. Lo que cambia es qué se informa, y el `Bucket` del
desalojado no se tira: se funde en el cajón `otros`.

Sin esa partición, el valor nuevo heredaría el `Bucket` del desalojado y un
endpoint aparecería en el panel con los bytes y la latencia de otro — un error
sin cota: un `/health` con cuatro peticiones puede heredar los 4 GB de un
`/download`.

### Garantías, con `N` observaciones y `K` contadores

- **Conservación exacta.** `Σ entradas + otros == N`, campo a campo
  (peticiones, errores, bytes, histograma). Ninguna observación se pierde ni se
  cuenta dos veces.
- **Nunca se exagera.** `informado <= verdadero`, siempre. Lo que se informa de
  un valor son observaciones suyas y de nadie más.
- **Cuánto se queda corto.** `verdadero − informado <= debt <= N/K`. Lo que
  falta está en el cajón, visible.
- **Ningún pesado se pierde.** Todo valor con frecuencia `> N/K` está en la
  tabla al final.

Lo que esta variante NO da y el Space-Saving literal sí: la cuenta total de un
valor pesado sin mirar el cajón. Se paga a cambio de que ninguna cifra
informada esté contaminada por otro valor — para un panel, el intercambio
correcto: una cifra corta con el resto visible en `otros` se puede leer; una
cifra inventada, no.

### RAM

`K` entradas exactas por `(resolución, celda, dimensión)`, **independiente por
completo del número de valores distintos**. Medido con 10.000 valores
distintos por dimensión, `K = 32`, las tres resoluciones activas: **66.572
bytes de pico**. Con 50.000 rutas distintas seguidas, la tabla se queda en 32
entradas y su tamaño no se mueve.

`Config::max_open_cells` (2 por defecto) es el otro tope duro: al abrir una
celda de más, la más antigua se escribe en la transacción en curso y se
suelta.

---

## 7. Retenciones

| Resolución | Dimensiones | Retención por defecto |
|---|---|---|
| Minuto | totales y códigos de estado | 48 horas |
| Hora | todas | 30 días |
| Día | todas | dos años |

`Resolution::default_retention_secs` y `cutoff_bucket` son valores por defecto
y aritmética, no política. **Quién poda y cuándo es del llamante.**

---

## 8. Coste medido

### Amplificación de escritura

20.000 registros, lotes de mil, 150 rps (el escenario de la sección 12.4),
páginas de 4 KB, crudo en `0x7f`:

| | Crecimiento del fichero | B/entrada | Amplificación |
|---|---|---|---|
| Solo crudo | 39.936 B/commit | 39,94 | 1,16× |
| **Crudo + agregado (esta capa)** | **49.971 B/commit** | **49,97** | **1,45×** |
| Agregado cada 10 commits (fase 2, no implementado) | 40.960 B/commit | 40,96 | 1,19× |

**La capa añade 10.035 B por commit de mil registros: 0,29× sobre los bytes
útiles, un +25,1% sobre el crudo solo.** La sección 12.4 estimaba 32 KB por
commit para los agregados y una amplificación total de 3,3×; medido, los
agregados cuestan 10 KB y el total sale **1,45×**, por debajo de la
estimación — el crudo mejoró más (de 66 a 40 KB por commit, gracias a
`SplitBias`) de lo que empeoró el agregado.

Tráfico físico de escritura, que la sección 12.4 no separaba del crecimiento
del fichero y que es lo que decide la vida de una tarjeta SD:

| | Bytes al `Storage` por commit |
|---|---|
| Solo crudo | 8.203.878 |
| Crudo + agregado | 11.640.422 (**+41,9%**) |
| Agregado cada 10 commits | 8.488.140 (+3,5%) |

Son 14.500 bytes de escritura física por cada fila de agregado escrita: el
copy-on-write reescribe el camino raíz-hoja en **cada** `put`, así que cada
fila arrastra su propio descenso. Es exactamente el aviso de la sección 12.4,
ahora con número.

### Camino de lectura del crudo

Los agregados viven en el mismo árbol, así que añaden altura. 50.000 entradas:

| | `get` puntual | Recorrido completo |
|---|---|---|
| Sin agregados | 0,83 µs | 0,0090 s |
| Con agregados | 0,92 µs (+11%) | 0,0093 s (+3%) |

### Disco por tier

Filas por celda **medidas** contra un `Rollup` real con la cardinalidad del
edge (200 endpoints, 12 estados, 40 países, 10.000 usuarios): 13 en minuto,
112 en hora y en día con `K = 32`.

**Perfil de la sección 12.3** (K = 32; 48 h de minuto, 30 d de hora, 2 años de
día):

| Tier | Hoy | Crudo 6 h | Agregados | Total | Proyección del dueño |
|---|---|---|---|---|---|
| micro | 445 KB | 56 KB | 6.000 KB | **6.056 KB** | ~95 KB |
| starter | 6.668 KB | 556 KB | 6.776 KB | **7.332 KB** | ~610 KB |
| pro | 83.350 KB | 4.167 KB | 7.544 KB | **11.711 KB** | ~4.400 KB |
| enterprise | 388.965 KB | 13.892 KB | 7.856 KB | **21.748 KB** | ~15.000 KB |

Flota de 2.700 con mezcla 55/30/13/2: **19,28 GB** (hoy 58 GB).

**Perfil mínimo** (K = 4; sin resolución de minuto, 7 d de hora, 90 d de día):

| Tier | Crudo 6 h | Agregados | Total | Proyección |
|---|---|---|---|---|
| micro | 56 KB | 212 KB | **268 KB** | ~95 KB |
| starter | 556 KB | 236 KB | **792 KB** | ~610 KB |
| pro | 4.167 KB | 248 KB | **4.415 KB** | ~4.400 KB |
| enterprise | 13.892 KB | 268 KB | **14.160 KB** | ~15.000 KB |

Flota: **3,20 GB**.

**La lectura honesta de estas dos tablas:** el coste de un nodo deja de
depender del tráfico y pasa a depender del **número de celdas × filas por
celda**, que es casi igual para un micro y para un enterprise. Con las
retenciones de la sección 12.3 al pie de la letra, un nodo micro gasta más en
agregados (6 MB) que lo que hoy gasta en crudo (445 KB): la agregación le
cuesta disco, no se lo ahorra. La proyección del dueño se alcanza —a menos de
un 30%— solo con el perfil mínimo, que renuncia a la resolución de minuto, a
los dos años de historia diaria y a 28 de las 32 entradas del top-K.

Las palancas, todas del llamante y sin tocar esta capa: `Config::top_k`, qué
resoluciones se activan (`Config::minute`/`hour`/`day`) y cada cuánto se poda
cada una.

---

## 9. Límites conocidos

- **`0x02` es un espacio de datos de usuario**, no reservado del motor
  (`arquitectura.md`: `0x01..0x7F`). Cualquiera puede escribir ahí con `put`.
  La capa no puede impedirlo; lo que hace es no tragárselo: una fila ajena da
  `Err`, nunca una respuesta equivocada. La carga de una celda está acotada a
  4.096 filas por el mismo motivo.
- **`reset()` tras un aborto es contrato del llamante**, no algo que la capa
  pueda imponer.
- **No hay `flush` implícito.** Si el llamante no llama a `flush` antes de
  `commit`, el agregado se queda en RAM y un corte se lleva lo no volcado
  (reconstruible desde el crudo mientras siga dentro de su ventana).
- **Podar una celda todavía abierta en RAM la resucita** en el volcado
  siguiente. Con cualquier retención razonable —la más corta son 48 horas— no
  puede pasar.
- **La cardinalidad de una dimensión con más de `K` valores nunca se conoce
  exactamente**: el cajón dice cuánto tráfico hubo fuera del top-K, no cuántos
  valores distintos.
