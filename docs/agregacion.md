# Agregación temporal — `inro::rollup`

La capa que hace que los informes sobrevivan a los registros que los
respaldan. Implementa la sección 12.3 de la especificación de diseño.

El motor guarda **34,14 bytes por registro crudo**, medidos, y eso está cerca
del suelo de una fila. Lo que queda por ganar no es guardar menos bytes por
fila: es **dejar de guardar casi todas las filas**. Con los crudos viviendo 6
horas y los agregados sobreviviéndolos, un informe de noventa días se sirve sin
que exista ni uno solo de los registros que lo respaldan (de dos años, con el
perfil `Realtime`).

**El perfil por defecto ya no es el de la sección 12.3**: es el mínimo —sin
resolución de minuto y con `K = 4`—, porque el de la especificación le costaba
disco a un nodo pequeño en vez de ahorrárselo. La elección tiene un coste de
precisión que está medido en §8.4 y que conviene leer antes de aceptar el
valor por defecto. Los tres perfiles están en §7.

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

**Lo primero es el perfil** (§7): `Config::default()` es `Reports` —sin
resolución de minuto, retenciones cortas y `K = 32`—, que conserva casi todo el
ahorro de disco sin pagar precisión. `Config::minimal()` baja `K` a 4 y ahorra
2,1 GB más de flota, a cambio de dejar el desglose por dimensión inservible;
`Config::realtime()` añade la resolución de minuto para el zoom del panel.

```rust
use inro::rollup::{Config, Observation, Rollup};

let mut rollup = Rollup::new(Config::default());   // Profile::Reports
// let mut rollup = Rollup::new(Config::minimal());  // 2,1 GB menos, sin top-K util
// let mut rollup = Rollup::new(Config::realtime()); // + zoom de minuto

let mut tx = db.begin_write()?;
for r in lote {
    tx.put(0x01, &clave_cruda(r), &valor_crudo(r))?;   // el ns de tu esquema
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

Poda (la política —cuándo— sigue siendo del llamante):

```rust
use inro::rollup::{RawTime, RawWindow};

let ventana = RawWindow::six_hours(0x01, RawTime::Seconds);   // el ns de tu crudo

let mut tx = db.begin_write()?;                    // 1
let st = rollup.retain(&mut tx, ahora, Some(ventana))?;  // 2  vuelca + poda todo
tx.commit()?;                                      // 3
let devueltos = db.reclaim_tail()?;                // 4  fuera de la transacción
```

**Los cuatro pasos son el ciclo entero**, y el orden importa por una razón que
no es de estilo: los agregados se derivan del crudo y **no se pueden
reconstruir cuando el crudo ya no está**. Lo que cierra esa ventana no es el
orden de las llamadas sino que el volcado y la poda vayan en **la misma
transacción**, que es justo lo que `retain` deja de poder equivocar. El paso 4
va fuera porque `reclaim_tail` toma el candado de escritor y abre sus propias
transacciones.

`retain` devuelve `RetentionStats` con lo **aplicado**, no lo pedido: el corte
de cada resolución, la cota del crudo, y si algún corte hubo que recortarlo
porque una celda seguía abierta en RAM (`clamped`, el caso de quien reprocesa
historia hacia atrás). Poda menos, nunca más, y lo dice.

Las piezas sueltas siguen ahí para quien quiera montar otra cosa —
`Config::cutoff_bucket`, `prune_before`, `WriteTxn::delete_range`,
`Db::reclaim_tail`—; `retain` no es más que las cuatro en el único orden que no
destruye datos:

```rust
let corte = rollup.config().cutoff_bucket(Resolution::Hour, ahora).unwrap();
let mut tx = db.begin_write()?;
inro::rollup::prune_before(&mut tx, Resolution::Hour, corte)?;
tx.commit()?;
```

**La retención se le pregunta a la configuración, no a la resolución.** Una
versión anterior tenía `Resolution::default_retention_secs()`: con dos perfiles
que retienen la hora 7 y 30 días, una función que no sabe cuál está en uso
devuelve la retención del perfil equivocado sin decirlo, y podar de más borra
informes que nadie puede reconstruir.

### La unidad del instante de la clave cruda, que sí puede destruir datos

`RawWindow` pide `RawTime::Seconds` o `RawTime::Millis` porque la clave cruda
del esquema de referencia es `[ts BE u64][seq u16]` y el `ts` va en
milisegundos en unos sitios y en segundos en otros. Confundirlos **no da un
error**:

| | Efecto |
|---|---|
| Claves en ms, corte en segundos | El corte sale 1.000× pequeño: **no borra nada**, el fichero crece sin cota |
| Claves en segundos, corte en ms | El corte sale 1.000× grande: **borra el log entero**, incluido lo de hace un segundo |

Si tu clave cruda **no** empieza por el instante, pasa `None` y haz tu propio
`delete_range` en la misma transacción, después de `retain`.

Por lo mismo, `retain` **rechaza un reloj imposible** con `Error::BadFormat` en
vez de saturar: con `RawTime::Millis` y un `now` por encima de 1,8·10¹⁶ la
conversión de unidad desborda, y un corte saturado borra el log entero. Eso sí
se distingue de una política legítima de «bórralo todo», que se escribe con
`RawWindow::new(ns, 0, unidad)` y no desborda nada.

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

## 3. El espacio de claves del crudo: ya no importa, y por qué lo contamos

**Usa el `ns` que diga tu esquema** — `0x01` para el crudo en el mapa de la
sección 10 de la especificación. No hay ninguna razón de rendimiento para
preferir uno u otro.

Esto merece contarse porque durante un tiempo sí importaba, y la trampa era de
las que ninguna prueba de integración continua puede ver.

`tree.rs` reparte una hoja desbordada por el punto medio **salvo** cuando la
clave que entra va al final (`SplitBias::Append`). Ese sesgo es lo que bajó el
crudo de 67,72 a 34,14 bytes por entrada, porque un log se inserta siempre por
el final. La condición **antigua** exigía que la clave fuera la mayor de TODO
el árbol. Y como el motor antepone el byte de espacio de claves, **el orden de
los espacios es el orden del árbol**: con el crudo en `0x01` y los agregados
en `0x02`, bastaba UNA fila de agregado para que ninguna clave cruda volviera a
ser la mayor. El sesgo dejaba de dispararse y el llenado de hoja volvía al ~50%.

| Disposición | Antes | Después |
|---|---|---|
| Crudo en `0x01`, nada en `0x02` | 33,77 | 33,77 |
| Crudo en `0x01`, **una** fila en `0x02` | **78,83** (+133%) | **33,96** |
| Crudo en `0x01`, capa de agregación corriendo | 76,80 | 35,96 |
| Crudo en `0x7f`, una fila en `0x02` | 33,87 | 33,87 |

Por qué la CI no podía atraparlo: `tests/size.rs` escribe **un solo espacio de
claves**. El motor habría salido a producción a 78,83 B/entrada, casi el doble
de su umbral de 40, con los cuatro bancos en verde.

La mitigación fue poner el crudo por encima de todo (`RAW_NS_RECOMMENDED` valía
`0x7f`). El arreglo de fondo llegó después: hoy `tree::put` recibe una **cota
superior exclusiva** y `put_raw` le pasa `[ns+1]`, así que el sesgo se dispara
dentro de cada espacio con independencia de lo que exista por encima —y
`tree.rs` sigue sin saber nada de espacios de claves, solo recibe una cota
sobre claves opacas. `RAW_NS_RECOMMENDED` se conserva por compatibilidad y hoy
vale `0x01`.

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
  tabla al final. Al revés también hay que leerlo: **lo que no llega a `N/K` no
  tiene ninguna garantía de quedarse**, y con el `K = 4` del perfil por defecto
  ese umbral es el 25% del tráfico de la celda, que en una dimensión de 200
  endpoints no alcanza ninguno. Está medido en §8.4 y es la razón de que exista
  `Config::reports()`.

Lo que esta variante NO da y el Space-Saving literal sí: la cuenta total de un
valor pesado sin mirar el cajón. Se paga a cambio de que ninguna cifra
informada esté contaminada por otro valor — para un panel, el intercambio
correcto: una cifra corta con el resto visible en `otros` se puede leer; una
cifra inventada, no.

### RAM

`K` entradas exactas por `(resolución, celda, dimensión)`, **independiente por
completo del número de valores distintos**. Medido con 10.000 valores distintos
por dimensión: **18.668 bytes de pico con el perfil por defecto** (`K = 4`, dos
resoluciones) y **66.596 con el de tiempo real** (`K = 32`, tres). Con 50.000
rutas distintas seguidas, la tabla se queda en `K` entradas y su tamaño no se
mueve.

`Config::max_open_cells` (2 por defecto) es el otro tope duro: al abrir una
celda de más, la más antigua se escribe en la transacción en curso y se
suelta.

---

## 7. Perfiles y retenciones

**El perfil es la palanca de disco de esta capa y la única decisión que le
cambia el orden de magnitud.** Hay tres, y la elección se lee en el sitio donde
se construye el `Rollup`:

| | `Minimal` — `Config::minimal()` | `Reports` — `Config::default()` | `Realtime` — `Config::realtime()` |
|---|---|---|---|
| `top_k` | **4** | 32 | 32 |
| Minuto (totales y estados) | **apagada** | apagada | 48 horas |
| Hora (todas las dimensiones) | **7 días** | 7 días | 30 días |
| Día (todas) | **90 días** | 90 días | 2 años |
| Filas por celda horaria (medidas) | **21** | 112 | 112 |
| Disco de un nodo micro | **268 KB** | 1.052 KB | 6.056 KB |
| Flota de 2.700 nodos | **3,20 GB** | 5,32 GB | 19,28 GB |
| Pico de RAM del agregador | **18.668 B** | ~66 KB | 66.596 B |
| Top-4 por endpoint acertado | **0,5%** | 97,5-100% | 97,5-100% |
| Zoom en tiempo real del panel | no | no | **sí** |

`Minimal` es el de por defecto porque **el coste de esta capa no lo pone el
tráfico sino el número de celdas × filas por celda**, que es casi el mismo para
un micro y para un enterprise: con el perfil de la sección 12.3, un micro gasta
6 MB de agregados para resumir 445 KB de crudo.

**Lo que `Minimal` cuesta está medido y es grande** (§8.4): con `K = 4` el
informe por endpoint deja de servir. Quien lo necesite tiene `Config::reports()`
—mismas retenciones, `K = 32`, 784 KB más por nodo micro— y quien necesite
además el zoom de minuto, `Config::realtime()`.

`Config::retention` y `Config::cutoff_bucket` son valores por defecto y
aritmética, no política. **Quién poda y cuándo es del llamante.**

---

## 8. Coste medido

Todas las cifras de esta sección son **del perfil por defecto** salvo donde se
diga otra cosa; las del de tiempo real se dan al lado para poder comparar.

### 8.1 Amplificación de escritura

20.000 registros, lotes de mil, 150 rps (el escenario de la sección 12.4),
páginas de 4 KB (crudo en `0x7f`, que antes del arreglo del sesgo de anexado
era la única disposición sin penalización; hoy `0x01` da lo mismo):

| | Crecimiento del fichero | B/entrada | Amplificación |
|---|---|---|---|
| Solo crudo | 39.936 B/commit | 39,94 | 1,16× |
| **Crudo + agregado, perfil por defecto** | **43.212 B/commit** | **43,21** | **1,26×** |
| Crudo + agregado, perfil de tiempo real | 49.971 B/commit | 49,97 | 1,45× |
| Por defecto, volcando cada 10 commits (fase 2, no implementado) | 40.345 B/commit | 40,35 | 1,17× |

**El perfil por defecto añade 3.276 B por commit de mil registros: 0,10× sobre
los bytes útiles, un +8,2% sobre el crudo solo** (el de tiempo real añadía
10.035 B y un +25,1%). La razón es directa: 42 filas de agregado por commit en
vez de 237, porque la celda tiene 21 filas en vez de 112 y no hay resolución de
minuto rotando sesenta veces más deprisa.

Tráfico físico de escritura, que la sección 12.4 no separaba del crecimiento
del fichero y que es lo que decide la vida de una tarjeta SD:

| | Bytes al `Storage` por commit |
|---|---|
| Solo crudo | 8.203.878 |
| **Crudo + agregado, por defecto** | **8.781.619 (+7,0%)** |
| Crudo + agregado, tiempo real | 11.640.422 (+41,9%) |
| Por defecto, volcando cada 10 | 8.250.777 (+0,6%) |

Son **13.755 bytes de escritura física por cada fila de agregado escrita**: el
copy-on-write reescribe el camino raíz-hoja en **cada** `put`, así que cada
fila arrastra su propio descenso. El coste por fila no ha cambiado con el
perfil (14.500 B con el de tiempo real); lo que ha cambiado es cuántas filas se
escriben.

### 8.2 Camino de lectura del crudo

Los agregados viven en el mismo árbol, así que añaden altura. 50.000 entradas,
**mínimo de cinco corridas** porque la máquina mete un ±15% de ruido:

| | `get` puntual | Recorrido completo | Fichero |
|---|---|---|---|
| Sin agregados | 0,83 µs | 0,0089 s | 1.908.736 B |
| Con agregados, por defecto | 0,85 µs (+2%) | 0,0089 s (±0%) | 2.002.944 B (+4,9%) |
| Con agregados, tiempo real | 0,86 µs (+4%) | 0,0088 s (−1%) | 2.244.608 B (+17,6%) |

**Honestamente: el efecto está por debajo del ruido de la medición.** El
+11%/+3% que publicó la versión anterior de este documento no se reproduce ni
con el perfil de tiempo real; lo único que se mide de forma estable es el
crecimiento del fichero.

### 8.3 Disco por tier

Filas por celda **medidas** contra un `Rollup` real con la cardinalidad del
edge (200 endpoints, 12 estados, 40 países, 10.000 usuarios): 21 por celda de
hora y de día con `K = 4`; 112 con `K = 32`; 13 en la celda de minuto.

**Perfil por defecto** (`Minimal`: K = 4, sin minuto, 7 d de hora, 90 d de día):

| Tier | Hoy | Crudo 6 h | Agregados | Total | Proyección del dueño |
|---|---|---|---|---|---|
| micro | 445 KB | 56 KB | 212 KB | **268 KB** | ~95 KB |
| starter | 6.668 KB | 556 KB | 236 KB | **792 KB** | ~610 KB |
| pro | 83.350 KB | 4.167 KB | 248 KB | **4.415 KB** | ~4.400 KB |
| enterprise | 388.965 KB | 13.892 KB | 268 KB | **14.160 KB** | ~15.000 KB |

Flota con mezcla 55/30/13/2: **1,61 GB con 1.360 nodos y 3,20 GB con 2.700**.

**Los otros dos perfiles**, mismo cálculo:

| Perfil | micro | starter | pro | enterprise | Flota 1.360 | Flota 2.700 |
|---|---|---|---|---|---|---|
| `Minimal` (por defecto) | **268 KB** | **792 KB** | **4.415 KB** | **14.160 KB** | **1,61 GB** | **3,20 GB** |
| `Reports` (K = 32, sin minuto) | 1.052 KB | 1.628 KB | 5.367 KB | 15.140 KB | 2,68 GB | 5,32 GB |
| `Realtime` (sección 12.3) | 6.056 KB | 7.332 KB | 11.711 KB | 21.748 KB | 9,71 GB | 19,28 GB |

Y, como referencia intermedia, las retenciones del perfil por defecto con
`K = 16`: 652 / 1.196 / 4.883 / 14.640 KB, flota 2,13 y 4,23 GB.

**La lectura honesta de la tabla:** el coste de un nodo deja de depender del
tráfico y pasa a depender del **número de celdas × filas por celda**, que es
casi igual para un micro y para un enterprise. Con las retenciones de la
sección 12.3 al pie de la letra, un nodo micro gasta más en agregados (6 MB)
que lo que hoy gasta en crudo (445 KB): la agregación le cuesta disco, no se lo
ahorra. Y **el ahorro no lo trae `K`**: de los 16,1 GB de flota que el perfil
por defecto se ahorra frente al de tiempo real, 13,9 son de apagar el minuto y
acortar las retenciones y solo 2,1 de bajar `K` de 32 a 4.

Las palancas, todas del llamante y sin tocar esta capa: el perfil,
`Config::top_k`, qué resoluciones se activan (`Config::minute`/`hour`/`day`) y
cada cuánto se poda cada una.

### 8.4 Lo que cuesta `K = 4`: precisión del top-K

La cota del algoritmo es `verdadero − informado <= N/K`, así que pasar de
`K = 32` a `K = 4` la afloja **ocho veces**. Medido —no razonado— sobre
repartos zipf-ianos (el tráfico real está concentrado; un reparto uniforme
haría la pregunta fácil y no es el caso que importa), con los volúmenes de
celda horaria de cada plan y 8.384 corridas independientes
(`tests/rollup_size.rs`, `top_k_accuracy_at_the_default_k_of_four`):

**Endpoints, zipf s = 1,0 sobre 200 valores** (la cabeza se lleva el 35% del
tráfico):

| Volumen | K | Top-4 correcto | Top-1 correcto | Tráfico en `otros` | Cuentas exactas |
|---|---|---|---|---|---|
| micro, 277/hora | **4** | **0,5%** | 63,5% | **97,2%** | 17,8% |
| micro, 277/hora | 32 | 97,5% | 100% | 39,7% | 96,8% |
| starter, 2.777/hora | **4** | **0,5%** | 61,0% | **99,7%** | 0,4% |
| starter, 2.777/hora | 32 | 98,5% | 100% | 53,6% | 92,5% |
| pro, 20.833/hora | **4** | **1,0%** | 66,7% | **100,0%** | 0,0% |
| pro, 20.833/hora | 32 | 100% | 100% | 55,3% | 91,7% |
| enterprise, 69.444/hora | **4** | **0,0%** | 60,7% | **100,0%** | 0,0% |
| enterprise, 69.444/hora | 32 | 100% | 100% | 55,7% | 93,8% |

**Por qué es tan malo y no es un fallo de implementación:** solo sobrevive a
los desalojos un valor cuya frecuencia pase de `N/K`. Con `K = 4` eso es el 25%
del tráfico de la celda y el endpoint más pesado de un reparto zipf-1,0 sobre
200 valores se queda en el 17%: **ninguno lo alcanza**, todos se desalojan y se
readmiten sin parar, y como el contador partido manda al cajón el agregado real
de cada desalojado, el tráfico acaba entero en `otros`. El panel puede decir
cuánto tráfico hubo, pero no de quién.

Las dimensiones concentradas aguantan mejor, y siguen sin ser buenas:

| Dimensión | K = 4: top-4 correcto | Tráfico en `otros` | K mínimo que acierta el 100% |
|---|---|---|---|
| Códigos de estado (12 valores, s = 2,5) | 29-41% | 8-11% | **8** |
| User agents (25 valores, s = 1,4) | 6-9% | 54-59% | **16** |
| Endpoints (200 valores, s = 1,0) | 0-1% | 97-100% | **32** |
| Endpoints + 30% de rutas únicas (el ataque de 12.4) | 0-0,5% | 98-100% | 32 (y aun así 83-100%) |

**Lo que NO cambia al bajar `K`**, comprobado en las 8.384 corridas: cero
exageraciones (`informado <= verdadero`, siempre) y cero fallos de conservación
(`Σ entradas + otros == N`, campo a campo). El error de `K = 4` es de
subestimación y de identidad, nunca una cifra inventada.

**Decidido tras medirlo, y por eso el defecto cambió:** `Config::default()` es
`Reports`. `Minimal` se eligió sobre una cifra de disco, antes de medir la
precisión; con `K = 4` el informe por dimensión queda inservible y el ahorro que
aportaba `K` eran 2,1 GB de los 16,1 del perfil — los otros 13,9 vienen de
apagar el minuto y acortar retenciones, que `Reports` conserva. `Reports` cuesta
784 KB más por nodo micro (1,05 MB frente a 268 KB) y 2,1 GB más de flota a
2.700 nodos.

`Config::minimal()` sigue disponible y es defendible si de los agregados solo se
esperan totales, percentiles y códigos de estado, que son exactos y no dependen
de `K`.

### 8.5 La meseta medida, y por qué §8.3 se queda corta

**Las cifras de §8.3 están compuestas** —crudo a 34,14 B/entrada más un fichero
de agregados escrito aparte— y **no se sostienen contra una corrida real**.
`tests/retention_size.rs::the_file_reaches_a_plateau_under_a_steady_tenant`
simula un inquilino día a día con el ciclo de retención completo (`retain` cada
hora simulada, `reclaim_tail` cada día), volumen del tope mensual del plan,
perfil por defecto, `Sync::Never`:

<!--TABLA-->

**Forma del crecimiento**, idéntica en los cuatro tiers:

| | |
|---|---|
| Hora 6 | El crudo vivo llega a su ventana y **no vuelve a crecer nunca** |
| Días 1-7 | Rampa: 2.800 filas de agregado por día |
| **Día 8** | Entra la retención de hora (7 d): el agregado horario se congela en 18.816 filas |
| Días 8-90 | Solo crece el día: **+112 filas ≈ +5 KB al día** |
| **Día 90** | Entra la retención de día: el agregado se congela en **28.896 filas** |
| Días 90-120 | **Meseta plana**, con una ligera bajada al asentarse la lista de libres |

**A los 30 días la meseta todavía no está**: falta un 13-15 %. Quien mida un mes
y lo llame régimen permanente se equivoca en esa cantidad.

**Las 28.896 filas de agregado son las mismas en los cuatro tiers**, lo que
confirma la lectura central de §8.3: el coste de esta capa lo pone el número de
celdas × filas por celda, no el tráfico.

### 8.6 Dónde se va la diferencia

Dos causas, las dos medidas por separado.

**1. El llenado de hoja del espacio de agregados es del ~50 %, no del ~96 %.**
La proyección escribió las filas **una vez y en orden de clave**; un `Rollup`
real las emite por ranura de dimensión y, dentro, en el orden de la tabla del
top-K. Sobre exactamente las mismas 28.896 filas de la meseta
(`where_the_aggregate_space_loses_its_leaf_fill`):

| Orden de escritura | Páginas | Llenado |
|---|---|---|
| Orden de clave, una pasada (**el de la proyección**) | 248 | **96,1 %** |
| Revuelto dentro de la celda | 459 | **51,9 %** |
| Revuelto y con el día intercalado (**el real**) | 352 | **67,7 %** |
| Corrida viva de 120 días | ~346 | **~49 %** |

El sesgo de anexado de `tree.rs` solo se dispara con inserciones estrictamente
ascendentes. El crudo lo consigue (96 %); los agregados no. Es la misma trampa
que cuenta `RAW_NS_RECOMMENDED` un nivel más abajo, salvo que **dentro de un
espacio de claves no hay ninguna cota de anexado más fina**.

**2. El margen de `Sync::Never`.** Con la misma carga y `Sync::Commit`, micro se
queda en **1.684 KB** en vez de 2.328, con **las mismas 361 páginas vivas**: la
diferencia entera son páginas libres que el modo relajado no puede reutilizar
hasta que el punto durable las alcanza. Es el «margen constante» que documenta
el `enum Sync`, y aquí vale un **+38 %**.

### 8.7 `reclaim_tail` no ayuda en régimen permanente

Medido (`what_blocks_reclaim_tail_in_the_steady_state`): en régimen,
`reclaim_tail` devuelve **4 KB**. Borrar **todo** el crudo y volver a llamarla
devuelve **16 KB**. Borrar además los agregados devuelve el fichero entero (932
KB en micro, 1.872 en starter).

**Lo que está arriba son los agregados**: sobreviven al crudo y crecen de forma
monótona 90 días, así que sus páginas se asignan tarde mientras las del crudo se
liberan y se vuelven a pedir por abajo. `reclaim_tail` solo se lleva el sufijo
libre, y esa capa viva en lo alto lo bloquea entero. **Sirve para un cambio de
plan, no para la poda diaria** (`runbook.md` §7.5).

### 8.8 Lo que la poda repetida NO estropea

`delete_rec` no funde hojas medio vacías (`invariantes.md` §3), así que la
sospecha razonable era que miles de ciclos de poda dejaran el crudo lleno de
hojas raquíticas. **No pasa.** Con un ciclo de poda por hora simulada durante
103 días —2.472 ciclos— el crudo de un nodo starter se queda entre **33,68 y
34,17 bytes por entrada viva**, sin ninguna deriva
(`raw_leaf_fill_across_repeated_prune_cycles`). El sesgo de anexado y la cota
`[ns+1]` sobreviven a la poda pesada.

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
