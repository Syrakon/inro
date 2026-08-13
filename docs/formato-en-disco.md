# Formato en disco de `inro` — referencia

**Versión de formato descrita: 3** (`header::FORMAT_MAJOR`).
**Derivado del código, no de la especificación de diseño.**

Este documento describe byte a byte lo que `inro` escribe en un fichero. Está
pensado para que alguien sin acceso al código de este repositorio pueda
escribir un lector y un validador independientes: si algún día el motor no
compila, no arranca o nadie recuerda cómo funcionaba, esto es lo que hace
falta para recuperar los datos.

Todo lo que sigue se ha verificado leyendo `src/`. Donde el documento de
diseño (`docs/superpowers/specs/2026-08-10-inro-motor-kv-design.md`) dice otra
cosa, **manda el código**, y la discrepancia queda anotada al final (sección
12). El formato ha cambiado tres veces; los números de versión son la única
señal fiable de cuál está uno mirando.

Convenciones de este documento:

- Todos los enteros multibyte son **little-endian**, sin excepción.
- Los rangos se escriben `a..b`: incluye `a`, excluye `b`.
- «Página lógica» y «página física» no son lo mismo en una base cifrada. Ver
  la sección 9.

---

## 1. Geometría del fichero

Un fichero es una secuencia de páginas de tamaño fijo. El tamaño de página se
fija al crear la base y no cambia jamás.

| | |
|---|---|
| Tamaño de página | potencia de dos, de 512 B a 32 768 B (`header::MIN_PAGE_SIZE`/`MAX_PAGE_SIZE`) |
| Se almacena como | `log2`, un solo byte, valores válidos 9..=15 |
| Offset de la página `n` | `n * page_size` |
| Espacio de numeración | `u32`: 2^32 páginas (2 TB con páginas de 512 B, 16 TB con 4 KB) |

**32 KB y no 64 KB, deliberadamente.** El campo `cell_start` de la cabecera de
página es un `u16` y no puede representar 65536, así que una página vacía a ese
tamaño se truncaría a cero y el validador la rechazaría — lo que dejaría
inservibles las páginas de lista de libres y de overflow, que siempre escriben
`cell_start = page_size`. Bajar el máximo elimina la clase entera de fallo.

Prefijo reservado del fichero, en todo momento de su vida:

| Página | Contenido |
|---|---|
| 0 | Cabecera (bytes 0..64) y su espejo (bytes 64..128). El resto de la página es relleno a cero. |
| 1 | Meta-ranura A |
| `meta_b_page` | Meta-ranura B. Vale 2 al crear la base; se traslada una vez a `max(2, 4096 / page_size)`. Ver la sección 4. |

Las páginas 0 y 1 no vuelven jamás a la circulación. Ningún número de página
`<= 1` es legítimo en ningún sitio donde el motor lea uno del disco: ni como
hijo de un nodo interno, ni como entrada de lista de libres, ni como raíz.

---

## 2. Cabecera (64 bytes, offset 0)

Se escribe una sola vez al crear la base. La única operación que la reescribe
en toda la vida del fichero es la reubicación de la meta B (sección 4).

| Offset | Tam. | Tipo | Campo |
|---|---|---|---|
| 0..8 | 8 | bytes | Magic: `49 4E 52 4F 00 44 42 01` (`"INRO\0DB\x01"`) |
| 8..10 | 2 | u16 | `format_major` — 3 en el formato actual |
| 10..12 | 2 | u16 | `format_minor` — se escribe 0; **se lee y no se comprueba** |
| 12 | 1 | u8 | `log2(page_size)`, válido 9..=15 |
| 13 | 1 | u8 | `flags` (ver abajo) |
| 14..16 | 2 | — | Reservado, a cero |
| 16..32 | 16 | bytes | `db_id`: identidad de la base |
| 32..40 | 8 | u64 | `created_unix`: segundos desde la época Unix |
| 40..44 | 4 | u32 | `meta_a_page` — siempre 1 |
| 44..48 | 4 | u32 | `meta_b_page` — posición ACTUAL de la ranura B |
| 48..60 | 12 | — | Reservado, a cero |
| 60..64 | 4 | u32 | CRC32 sobre los bytes 0..60 |

### Bits de `flags`

| Bit | Nombre | Significado |
|---|---|---|
| 0x01 | `FLAG_ENCRYPTED` | Las páginas de datos están cifradas y la meta lleva clave envuelta y sellado. Fijo en la creación: activarlo después exigiría reescribir todas las páginas. |
| 0x02 | `FLAG_PREFIX_COMPRESSION` | **Definido en el formato pero NUNCA escrito.** `Db::create` solo escribe `FLAG_ENCRYPTED` o cero. La compresión de prefijo por página es incondicional: toda página construida por `PageBuilder` la aplica, mire nadie o no este bit. Un lector independiente debe ignorar este bit y asumir compresión de prefijo siempre. |

### `db_id`

Dieciséis bytes: los ocho primeros son los nanosegundos de la época Unix en el
instante de la creación, los ocho siguientes la dirección de una variable de
pila. **No es criptográfico ni pretende serlo**: solo debe distinguir ficheros.
Aun así es carga útil de seguridad — entra en los datos asociados del sellado
de la meta (sección 5.3), donde lo que hace falta es que sea *distinto* entre
bases, no que sea impredecible.

### Orden de validación al decodificar

Este orden importa y un lector independiente debe respetarlo:

1. Magic. Si no coincide → «no es un fichero inro».
2. **CRC32, antes que cualquier otro campo.** Sin él, una geometría corrupta se
   interpretaría como válida y todo lo demás se leería con el tamaño de página
   equivocado.
3. `format_major > 3` → demasiado nuevo, rechazar.
4. `format_major < 3` → demasiado viejo, rechazar (ver la sección 11).
5. `log2(page_size)` fuera de 9..=15 → rechazar.

Lo que **no** se comprueba: `format_minor`, los bits desconocidos de `flags`,
que los reservados estén a cero, ni que `meta_a_page`/`meta_b_page` sean
plausibles.

---

## 3. Espejo de la cabecera (64 bytes, offset 64)

Copia byte a byte de la cabecera, en un offset **fijo del fichero**, no
calculado a partir de `page_size`. Tenía que ser fijo: para leer la cabecera
hay que saber dónde está, y hacer depender su posición de `page_size` crearía
el mismo huevo-y-gallina que el espejo viene a resolver. Cabe siempre dentro de
la página 0 porque `MIN_PAGE_SIZE` (512) es muy superior a 128.

**Solo lo escribe la reubicación de la meta B.** En una base que nunca reubica
(cualquiera con `page_size >= 4096`, y cualquiera pequeña que nunca haya pasado
de 4 KB) esos 64 bytes son ceros y no son un espejo de nada.

Regla de lectura:

1. Decodificar la principal (offset 0). Si funciona, se usa **y el espejo ni se
   mira**.
2. Si no decodifica por cualquier motivo, intentar el espejo (offset 64).
3. Si el espejo tampoco, devolver el error de la **principal**, no el del
   espejo — es el error que quien llama espera, y un espejo que nunca se
   escribió da un error engañoso sobre un fichero corto.

Cuando el motor tiene que caer al espejo, **repara la principal de inmediato**
(la reescribe y sincroniza) para no gastar la redundancia sin devolverla. Esa
reparación es oportunista: si falla (medio de solo lectura, sector dañado), la
base abre igual y se reintenta en la apertura siguiente.

---

## 4. Ranuras de meta: dos, y dónde viven

El estado de commit vive en dos ranuras que se alternan. La ranura A está
siempre en la página 1. La B empieza en la página 2 y **se traslada una sola
vez** en la vida del fichero a `max(2, 4096 / page_size)`:

| `page_size` | Meta B inicial | Meta B definitiva | ¿Reubica? |
|---|---|---|---|
| 512 B | 2 | 8 | Sí, cuando el fichero supera 4 KB |
| 1024 B | 2 | 4 | Sí |
| 2048 B | 2 | 2 | No |
| 4096 B y mayores | 2 | 2 | No |

El motivo es físico: con páginas pequeñas, las páginas 1 y 2 caen en el mismo
sector de 4 KB del dispositivo, así que un fallo de sector se llevaría las dos
ranuras a la vez y el diseño de doble meta no protegería de nada. La página
destino nunca se reparte como página de datos, ni siquiera antes de que la
reubicación ocurra.

**Un lector independiente no debe suponer nada sobre dónde vive la meta B: debe
leer `meta_b_page` de la cabecera.** Esta suposición se ha roto tres veces en
la historia de este proyecto.

---

## 5. Ranura de meta (152 bytes útiles)

Vive al principio de su página (`meta_a_page * page_size` o
`meta_b_page * page_size`). El resto de la página es relleno a cero que el
motor nunca lee. **Las páginas de meta nunca se cifran**, ni siquiera en una
base cifrada: se escriben en claro (ver la sección 9).

| Offset | Tam. | Tipo | Campo |
|---|---|---|---|
| 0..8 | 8 | u64 | `txn_id` — monótono, nunca reutilizado |
| 8..12 | 4 | u32 | `root` — raíz del árbol de datos; **0 = árbol vacío** |
| 12..16 | 4 | u32 | `catalog_root` — **reservado, siempre 0** (ver abajo) |
| 16..20 | 4 | u32 | `freelist_head` — 0 si no hay cadena |
| 20..24 | 4 | u32 | `freelist_tail` |
| 24..28 | 4 | u32 | `n_pages` — páginas que esta transacción consideraba asignadas |
| 28 | 1 | u8 | `log2(page_size)` — copia de la geometría |
| 29 | 1 | u8 | `flags` — copia de la geometría |
| 30..32 | 2 | u16 | `format_major` — copia de la geometría |
| 32..40 | 8 | — | Reservado, a cero |
| 40..100 | 60 | bytes | Clave de datos envuelta. Presente si y solo si `flags & 0x01` |
| 100..108 | 8 | — | Reservado, a cero. **Aquí vivía `write_counter` en los formatos 1 y 2** |
| — | | | **`META_AUTH_END` = 108: fin de la región autenticada** |
| 108..132 | 24 | bytes | Nonce del sellado. Cero en base sin cifrar |
| 132..148 | 16 | bytes | Tag del sellado. Cero en base sin cifrar |
| 148..152 | 4 | u32 | CRC32 sobre los bytes 0..148 |

### `catalog_root` está reservado y no se usa

El campo existe en el formato y viaja intacto, pero el catálogo de índices no
vive en un árbol aparte: vive en el árbol normal, bajo el espacio de claves
`0x00` (sección 8). El campo se escribe siempre a cero. Un lector independiente
debe ignorarlo.

### El CRC32 sigue existiendo, también en una base cifrada

No es redundancia ociosa ni un resto del formato anterior. Es la única
comprobación de integridad que **no necesita clave**, y es lo que deja
distinguir dos fallos que merecen desenlaces opuestos:

- **CRC roto** = ranura *incompleta*. Los bytes del plato son mitad de una meta
  y mitad de otra: eso es lo que deja un corte de corriente a media escritura.
  El diseño de dos ranuras existe exactamente para absorberlo → se descarta en
  silencio y se monta por la otra.
- **CRC correcto pero tag que no valida** = ranura *entera* que la clave no
  avala. Nadie la partió: alguien la escribió y recalculó su CRC → se detiene
  la apertura, no se cae a la otra ranura. Caer ahí convertiría un ataque
  detectado en una vuelta atrás silenciosa.

### 5.1 Selección de ranura

1. Leer las dos ranuras. Si una no se puede leer del medio, se salta.
2. Decodificar cada una: longitud >= 152 y CRC32 correcto. Si no, se salta.
3. La ranura cuyo `log2(page_size)` **contradiga la cabecera** se salta: indica
   que se está leyendo con el tamaño de página equivocado, que es corrupción y
   no una ranura vieja.
4. Gana el `txn_id` **estrictamente mayor**. En caso de empate gana **A**, por
   ser la primera del recorrido. El empate solo ocurre en dos situaciones
   legítimas: una base recién creada (las dos ranuras se escriben idénticas) y
   el instante posterior a un recorte de fichero (ídem, a propósito).
5. Si ninguna sobrevive → corrupción (`MetaMismatch`).
6. Solo entonces se autentica la ganadora, si la base está cifrada. **Si falla,
   se para: no hay vuelta a la otra ranura.**

### 5.2 Clave de datos envuelta (bytes 40..100)

Sesenta bytes, y su formato **no depende del algoritmo de página**:

| Offset relativo | Tam. | Contenido |
|---|---|---|
| 0..12 | 12 | Nonce aleatorio de un solo uso |
| 12..44 | 32 | Clave de datos cifrada |
| 44..60 | 16 | Tag |

Siempre **ChaCha20-Poly1305** con nonce de 12 bytes y datos asociados vacíos,
bajo la **clave maestra** que aporta quien abre — sea cual sea el algoritmo con
el que se cifran las páginas. No es un descuido: este sellado ocurre una sola
vez en la vida de la base (`Db::create`) y se copia tal cual en cada escritura
de meta posterior, así que no hay ninguna secuencia que pueda colisionar y ni
el nonce extendido ni la resistencia a reutilización aportan nada. Mantenerlo
fijo deja además el envoltorio independiente del algoritmo de página, que es lo
que permite abrir el fichero y desenvolver la clave antes de saber nada más.

`wrapped_key` se lee **condicionado al bit `FLAG_ENCRYPTED`**, no a si la
región 40..100 es distinta de cero. En la práctica coincide (una base sin
cifrar nunca escribe ahí), pero basarse en el flag es exacto: todo ceros
también sería, en teoría, un envoltorio válido.

### 5.3 Sellado de la meta (bytes 108..148) — formato 3

Es un **MAC, no un cifrado**: el texto plano del AEAD está vacío y la meta
viaja en claro. Un observador sigue viendo `root`, `txn_id` y `n_pages`. Lo que
se compra es autenticidad — quien no tenga la clave no puede fabricar una meta
que el motor acepte — **no** confidencialidad.

Se calcula bajo la **clave de datos** (la que sale del envoltorio, no la
maestra), con el algoritmo de página, sobre estos datos asociados, concatenados
en este orden exacto (161 bytes en total):

| Tam. | Contenido |
|---|---|
| 12 | `"inro/meta/v3"` (etiqueta de dominio, ASCII) |
| 16 | `db_id` **de la cabecera**, no de la meta |
| 1 | Índice de ranura: `0` para A, `1` para B |
| 24 | El nonce de esta ranura (bytes 108..132) |
| 108 | La región autenticada, **bytes 0..108 tal como están en el plato** |

Qué ataque cierra cada pieza:

- **Etiqueta de dominio**: separa este tag del de una página. El nonce ya lo
  hace, pero un dominio explícito no depende de esa propiedad. Lleva la versión
  dentro: si algún día el contenido autenticado cambia de disposición sin
  cambiar de tamaño, un tag viejo deja de validar aunque el `format_major` de
  la cabecera —que no está autenticado, ni puede estarlo— se hubiera
  manipulado para mentir.
- **`db_id`**: ata la ranura a ESTE fichero. Sin él, una meta de otra base
  cifrada con la MISMA clave maestra se pega tal cual y valida — la clave de
  datos viaja dentro de la propia ranura, así que el atacante no necesita
  conocerla, solo mover los dos trozos juntos.
- **Índice de ranura**: ata la ranura a SU letra. Sin él, intercambiar el
  contenido de las dos ranuras produce dos ranuras que siguen validando, y con
  ellas el control sobre qué `txn_id` gana la selección.
- **Bytes crudos, no una recodificación**: la diferencia importa en los dos
  huecos reservados (32..40 y 100..108). Recodificar los pondría a cero antes
  de calcular el tag, así que un atacante podría meter ahí lo que quisiera,
  recalcular el CRC, y el tag seguiría validando.

Se ata la **letra** de la ranura y no su número de página a propósito: la
reubicación de la meta B mueve la ranura sin que su contenido cambie de
significado, así que atarlo al número obligaría a resellar y dejaría sin
validar la copia de la posición vieja durante la ventana del corte.

**Por qué esto no es un círculo vicioso** aunque la clave que autentica una
ranura viaje dentro de esa misma ranura: son dos claves distintas. Se lee la
ranura y se comprueba su CRC32 sin confiar en nada; se abre el envoltorio con
la clave **maestra**, y eso es un AEAD — un envoltorio que no produjera quien
tiene la maestra falla ahí; y con la clave de **datos** que sale se comprueba
el tag. Un atacante que trasplante el envoltorio de otra base cifrada con la
misma maestra pasa el segundo paso con una clave de datos que no es la de este
fichero y se estrella en el tercero.

### 5.4 Lo que el tag NO puede cubrir

- **La cabecera y su espejo.** Es huevo-y-gallina puro: hay que leerla para
  saber dónde viven las ranuras y de qué tamaño son, es decir antes de poder
  leer la clave envuelta que haría falta para autenticarla. Lo que sí se hace
  es atar la meta a ella por los dos lados: `db_id` entra en los datos
  asociados, y `page_size_log2`/`flags`/`format_major` viajan dentro de la
  región autenticada, donde se contrastan contra la cabecera. Una cabecera
  manipulada no consigue que se acepte una meta que no le corresponde:
  consigue, como mucho, que no se acepte ninguna.
- **El propio tag y el CRC32.** El tag es la salida y el CRC es función del
  resto: tocar cualquiera de los dos solo hace la ranura ilegible.
- **El relleno más allá del byte 152**, que el motor no lee jamás.
- **La vuelta atrás.** El tag certifica «esta ranura la escribió quien tiene la
  clave, para esta base y esta letra». No certifica «esta es la ranura MÁS
  RECIENTE». Restaurar una copia de seguridad completa y auténtica de ayer
  produce un fichero que valida perfectamente. Autenticación no es frescura.

---

## 6. Cabecera de página (20 bytes)

La comparten los cuatro tipos de página. Todo lo que sigue en esta sección
describe una **página lógica**: en una base cifrada, estos bytes son el texto
plano que aparece tras descifrar (sección 9).

| Offset | Tam. | Tipo | Campo |
|---|---|---|---|
| 0 | 1 | u8 | `page_type`: 0 Hoja, 1 Interna, 2 Overflow, 3 Lista de libres |
| 1 | 1 | u8 | `flags` (ver abajo) |
| 2..4 | 2 | u16 | `n_slots` |
| 4..6 | 2 | u16 | `free_start` |
| 6..8 | 2 | u16 | `cell_start` |
| 8..12 | 4 | u32 | CRC32 (ver abajo) |
| 12..16 | 4 | u32 | `extra` (ver abajo) |
| 16..18 | 2 | u16 | `prefix_len` |
| 18..20 | 2 | — | Reservado, a cero |

**El CRC32 cubre la página entera menos su propio campo**: se calcula sobre los
bytes `0..8` seguidos de los bytes `12..fin`, en ese orden, como un único flujo.
Un validador independiente debe alimentar el CRC con esos dos tramos
concatenados, no con la página entera.

`extra`, según el tipo:

| Tipo | `extra` |
|---|---|
| Interna | Número de página del hijo **más a la derecha** |
| Overflow | Siguiente página de la cadena; **0 = última** |
| Lista de libres | Siguiente página de la cadena; **0 = última** |
| Hoja | 0, sin significado |

`flags` (byte 1), único bit definido:

| Bit | Nombre | Significado |
|---|---|---|
| 0x01 | `CHILDREN_PLAIN` | **Solo en páginas internas.** `true` = todos mis hijos DIRECTOS son hojas sin ninguna entrada de overflow, así que pueden liberarse sin abrirlos. `false` **no afirma lo contrario**: es la lectura conservadora por defecto, «no hay garantía, compruébalo». En hojas está siempre a cero y no significa nada. |

El bit es **monótono por nodo**: una vez que pasa a `false`, solo una
reconstrucción completa del nodo lo devolvería a `true`, y ninguna operación
actual reconstruye un nodo solo para reevaluarlo. Borrar la entrada que causó
el overflow no lo restaura. Un lector independiente puede ignorarlo por
completo (es una optimización de liberación, no una afirmación necesaria para
leer datos); un validador no debe tratar `false` como señal de nada.

### 6.1 Disposición del cuerpo

```
0                   20         20+prefix_len        free_start      cell_start        page_size
+-------------------+----------+-------------------+---------------+-----------------+
| cabecera (20 B)   | prefijo  | slots (2 B c/u)   | hueco libre   | celdas          |
+-------------------+----------+-------------------+---------------+-----------------+
                                ^                                   ^
                                slots_at = 20+prefix_len            cell_start
```

- `slots_at = 20 + prefix_len`
- `free_start` **debe ser exactamente** `slots_at + 2 * n_slots`. Es redundante
  a propósito: se almacena para poder contrastarlo y detectar corrupción que el
  CRC no vería si afectase a varios campos a la vez.
- El array de slots son `n_slots` valores `u16` LE, cada uno el offset absoluto
  dentro de la página donde empieza esa celda.
- **Las celdas crecen desde el final de la página hacia abajo.** La entrada 0
  (la clave más pequeña) es la primera en reservar hueco y queda pegada al
  final; cada entrada siguiente ocupa un offset MENOR. Por tanto, en una página
  válida, `slot(i) < slot(i-1)`: los offsets bajan según sube la clave.
- `cell_start` es el offset de celda más bajo, o `page_size` si no hay celdas.

### 6.2 Compresión de prefijo por página

Los `prefix_len` bytes de `20..20+prefix_len` son el **prefijo común más largo**
de todas las claves de la página. Cada celda guarda solo su sufijo. La clave
completa de la celda `i` es `prefijo ++ sufijo(i)`.

Como todas las claves de una página comparten exactamente el mismo prefijo,
**comparar sufijos equivale a comparar claves completas**: la búsqueda binaria
opera sobre sufijos, con el prefijo ya recortado de la clave buscada.

Con una sola clave en la página, el prefijo común es la clave entera y el
sufijo queda vacío. Es correcto y ocurre en la práctica.

La compresión es **incondicional**: no hay ninguna página sin ella, y el bit
`FLAG_PREFIX_COMPRESSION` de la cabecera del fichero no se escribe nunca.

### 6.3 Codificación de celda

Todas las celdas empiezan igual: `[varint len_sufijo][sufijo]`. Lo que sigue
depende del tipo de página.

**Hoja, valor en línea:**
```
[varint len_sufijo][sufijo][varint len_valor][valor]
```

**Hoja, valor en cadena de overflow:**
```
[varint 0xFFFFFFFFFFFFFFFF][len_real u64 LE][primera_pagina u32 LE]
```
precedido, como siempre, de `[varint len_sufijo][sufijo]`.

El marcador es `u64::MAX`, que en LEB128 ocupa **siempre 10 bytes**
(`FF FF FF FF FF FF FF FF FF 01`), seguidos de exactamente 12 bytes de carga.
Un valor de longitud cero real se distingue sin ambigüedad porque `0` no es
`u64::MAX`: la celda termina justo tras el varint, como cualquier otro valor en
línea.

Es una **marca explícita, no una deducción a partir del tamaño de la celda**:
deducirlo crearía una dependencia circular, porque calcular el final de la
celda necesitaría saber si es de overflow, y saberlo requeriría conocer ya el
final.

**Interna:**
```
[varint len_sufijo][sufijo][hijo_izquierdo u32 LE]
```
El hijo de la celda `i` es el subárbol con claves **menores** que el separador
`i`. El hijo de las claves mayores o iguales al último separador es `extra`. Con
`n_slots` separadores hay `n_slots + 1` hijos.

**Overflow y lista de libres:** no usan celdas. Escriben `n_slots = 0`,
`free_start = 20`, `cell_start = page_size` y `prefix_len = 0`; su carga vive en
el hueco propio de su tipo (secciones 7 y 8).

---

## 7. Página de overflow (tipo 2)

Un valor mayor que `page_size_lógico / 4` no se guarda en línea: se trocea en
una cadena de páginas de overflow y la celda de hoja guarda solo la referencia.

| Offset | Contenido |
|---|---|
| 0..20 | Cabecera de página estándar, `page_type = 2`, `extra` = siguiente página o 0 |
| 20..page_size | Datos |

- Capacidad por página: `page_size_lógico - 20` bytes.
- Se escriben en orden: el trozo `i` va en la página `i`, y `extra` apunta a la
  `i+1`. La última tiene `extra == 0`.
- La longitud real del valor **no está en las páginas de overflow**: vive en la
  celda de hoja (`len_real u64`). La última página de la cadena lleva relleno a
  cero después de sus bytes útiles y no hay forma de saber cuántos son sin esa
  longitud.

**Regla para un lector independiente:** al recorrer la cadena hay que acotar el
número de saltos. La cota de «`ceil(len/capacidad)` páginas» **no basta por sí
sola** para detectar un ciclo: con capacidad uniforme, cada vuelta de un ciclo
aporta la misma cantidad de bytes que una página nueva, así que un ciclo alcanza
`len` bytes en exactamente el mismo número de saltos que una cadena legítima. Lo
que sí lo detecta es comprobar, **después** de reunir los `len` bytes, que la
cadena llegó de verdad a su final (`extra == 0`): un ciclo no contiene ninguna
página con `extra == 0`. Y `len` en sí no es de fiar — sale de una celda que el
validador de página no mira — así que la cota real debe ser el mínimo entre lo
que `len` implica y el número de páginas que el fichero tiene de verdad.

---

## 8. Página de lista de libres (tipo 3)

| Offset | Tam. | Tipo | Campo |
|---|---|---|---|
| 0..20 | 20 | — | Cabecera de página estándar, `page_type = 3`, `extra` = siguiente página de la cadena o 0 |
| 20..28 | 8 | u64 | `max_txn`: la transacción más reciente que liberó alguna de estas páginas |
| 28..30 | 2 | u16 | `count`: entradas válidas en esta página |
| 30..32 | 2 | — | Reservado, a cero |
| 32 + 4·i | 4 | u32 | Entrada `i`: número de página libre |

- `FREELIST_HEADER` = 32. Capacidad: `(page_size_lógico - 32) / 4` entradas.
- La cadena se recorre desde `freelist_head` siguiendo `extra`. `freelist_tail`
  es la última página de esa misma cadena.
- El orden es FIFO: la cabeza tiene las páginas liberadas hace más tiempo.
- Un grupo (mismo `max_txn`) puede ocupar varias páginas físicas.

**Un grupo se reutiliza entero o nada**: una página libre etiquetada con
`max_txn` no puede repartirse mientras exista algún lector cuyo snapshot sea
anterior a `max_txn`. Ese guardián es la mitad de la corrección del motor; ver
`invariantes.md`.

### 8.1 Qué debe rechazar un validador en cada entrada

Esta es la frontera de validación de la lista de libres, y su ausencia costó
caro (una entrada manipulada bastaba para que el motor repartiera la página 0 y
se sobrescribiera la cabecera con una hoja):

- `count` mayor que `(len - 32) / 4` → corrupción. Sin esta cota, un `count` de
  hasta 65535 hace leer muy más allá de la página.
- Entrada `<= 1` → corrupción. La cabecera y la meta A no vuelven jamás a la
  circulación.
- Entrada `== max(2, 4096/page_size)` (el destino de la reubicación de la meta
  B) → corrupción. Nadie asigna jamás esa página, así que nadie puede haberla
  liberado.
- Entrada `>= páginas que el fichero tiene de verdad` (longitud real medida
  ahora, no un contador de disco) → corrupción.
- Un salto `extra` que apunte a la propia página → ciclo.
- Más saltos que páginas tiene el fichero → ciclo.

**No** se rechaza la página de la meta B *actual*: mientras la B está en su
posición inicial, esa página es legítimamente liberable (la reubicación la
libera de verdad al completar), y un corte que deshiciera la escritura de la
cabecera dejaría una cadena válida con esa entrada dentro.

---

## 9. Cifrado por página

Cuando `FLAG_ENCRYPTED` está puesto, **cada página de datos** —árbol y lista de
libres— se almacena sellada. **No se cifran**: la cabecera, su espejo, ni las
dos ranuras de meta.

Disposición de una página física cifrada:

| Offset | Tam. | Contenido |
|---|---|---|
| 0..24 | 24 | Nonce, en claro |
| 24..40 | 16 | Tag |
| 40..page_size | `page_size - 40` | Texto cifrado de la página lógica |

`CIPHER_PREFIX` = 40. De ahí que:

```
page_size_lógico = page_size_físico - 40   (base cifrada)
page_size_lógico = page_size_físico        (base sin cifrar)
```

Con páginas de 512 B quedan 472 útiles; con 4096 B, 4056.

### 9.1 Datos asociados de una página

28 bytes, en este orden:

| Tam. | Contenido |
|---|---|
| 4 | Número de página, u32 LE |
| 24 | El nonce almacenado de esta misma página |

De ahí salen dos propiedades concretas:

- **Mover bytes de una página a otra se detecta.** Copiar la página 5 encima de
  la 9 falla al descifrar, porque la 9 se autentica con `9` en los datos
  asociados.
- **Ningún byte físico queda fuera del tag.** El campo de nonce mide 24 B
  siempre, pero AES-256-GCM-SIV solo usa 12; esos 12 bytes de relleno también
  entran en los datos asociados, así que tocarlos invalida el tag en vez de
  pasar inadvertidos.

### 9.2 El algoritmo NO viaja en el fichero

Solo el bit `FLAG_ENCRYPTED`. Quien abre debe aportar el algoritmo junto con la
clave maestra. Por eso el campo de nonce mide 24 bytes fijos para los dos
algoritmos: si su tamaño dependiera del algoritmo, el tamaño de página lógica
dependería de un dato que el fichero no contiene, y abrir con el algoritmo
equivocado dejaría de ser un fallo limpio de autenticación para convertirse en
una geometría distinta.

| Algoritmo | Nonce que usa | Construcción del nonce |
|---|---|---|
| XChaCha20-Poly1305 (por defecto) | los 24 bytes | `prefijo aleatorio (16) ++ contador u64 LE (8)` |
| AES-256-GCM-SIV | los 12 primeros | `prefijo aleatorio (8) ++ contador u32 LE (4)`, y los 12 restantes del campo a cero |

**El prefijo se sortea una vez por APERTURA**, no por escritura, y el contador
avanza dentro de esa apertura. Ver `invariantes.md` para por qué, y por qué la
alternativa (entropía por escritura) se rechazó.

**AES-GCM-SIV y no AES-GCM.** El nonce de 12 bytes de GCM no admite 16 de
prefijo más 8 de contador, así que el prefijo aleatorio que le cabe es corto y
una colisión entre dos aperturas deja de ser despreciable. Con GCM a secas esa
colisión sería catastrófica (mismo flujo de clave: los textos cifrados se
anulan al XOR, y sobre páginas de este motor —casi todo relleno a cero y
cabeceras iguales— eso equivale al texto plano). Con GCM-SIV, resistente a la
reutilización de nonce por construcción (RFC 8452), degrada a «un observador
aprende que dos textos planos eran iguales».

### 9.3 Descifrar una página, paso a paso

1. Leer los `page_size` bytes físicos de `n * page_size`.
2. Nonce = bytes 0..24. Tag = bytes 24..40.
3. AAD = `n` como u32 LE, seguido del nonce.
4. Descifrar `40..page_size` con la clave de **datos** (la desenvuelta de la
   meta) y el algoritmo que aportó el usuario.
5. El resultado son los `page_size - 40` bytes de la página lógica: es ahí
   donde empieza la cabecera de página de la sección 6.

---

## 10. Varint (LEB128 sin signo)

Escrito a mano; es la codificación más usada del motor.

- Grupos de 7 bits, del menos significativo al más significativo.
- Bit 0x80 = «hay más bytes».
- Un valor cabe en 1..10 bytes; `u64::MAX` ocupa siempre 10.

Decodificación, y qué debe rechazar un lector:

- Entrada agotada sin byte final (todos con el bit de continuación) → inválido.
- Desplazamiento acumulado de 64 bits o más → inválido (codificación más larga
  de lo que cabe en `u64`).

**Lo que NO se rechaza:** las codificaciones no mínimas. `80 00` decodifica como
0 en dos bytes y el motor lo acepta. Un lector independiente debe aceptarlas
también; escribirlas no es necesario (el codificador siempre emite la mínima),
pero rechazarlas divergería del motor.

---

## 11. Versiones de formato y negociación

| | |
|---|---|
| Versión que este binario **escribe** | 3 |
| Versión más antigua que **sabe leer** | 3 |

**No hay compatibilidad hacia atrás. Es deliberado.** Un fichero con
`format_major` distinto de 3 se rechaza con un error de versión —«demasiado
nuevo» o «demasiado viejo» — y no se intenta leer.

Qué cambió en cada versión:

- **Formato 1 → 2 (nonces aleatorios).** Dos rupturas a la vez: la disposición
  de una página cifrada pasó de `contador (8) || tag (16) || cifrado` a
  `nonce (24) || tag (16) || cifrado` (el prefijo en claro creció de 24 a 40
  bytes y la página lógica encogió otros 16), y la meta dejó de llevar el techo
  de contador de nonce en los bytes 100..108. **Ninguno de los dos cambios era
  detectable por CRC** — los dos producen ficheros perfectamente bien formados
  — así que el número de versión es la única señal que los distingue.
- **Formato 2 → 3 (meta autenticada).** Una ranura pasó de 112 a 152 bytes: el
  nonce y el tag del sellado aparecen en 108..148 y el CRC se muda de 108..112
  a 148..152. Una ranura del formato 2 leída con la disposición nueva falla el
  CRC —lo leería de bytes que ahí son relleno a cero— así que un fichero viejo
  no se malinterpretaría; pero fallaría como «corrupto», que es el diagnóstico
  equivocado para un fichero sano de otra versión.

**Por qué no se conserva una vía de lectura del formato 2, y el motivo es de
seguridad y no de comodidad.** Mantenerla habría significado conservar una
segunda disposición de ranura *y* una vía de apertura **sin autenticar**, que
es exactamente el agujero que el formato 3 cierra: un atacante bajaría el
`format_major` de la cabecera (que no está autenticada, ni puede estarlo) y
volvería a tener metas aceptadas con solo un CRC32 recalculado. Un rechazo
limpio por versión cierra esa puerta sin tener que autenticar la cabecera.

`format_minor` se escribe a 0 y **nunca se comprueba al leer**. Hoy no
constituye ningún mecanismo de negociación: es espacio reservado.

---

## 12. Dónde el código y el documento de diseño no coinciden

El documento de diseño
(`docs/superpowers/specs/2026-08-10-inro-motor-kv-design.md`) argumenta
decisiones y compara alternativas; **no es una referencia de formato y ha
estado equivocado antes**. Cuando discrepe con lo de arriba, manda el código.
Discrepancias conocidas en el momento de escribir esto:

### 12.1 Discrepancias que afectan al FORMATO

Estas son las que importan para escribir un lector independiente. **Si sigue el
diseño en cualquiera de ellas, su lector no funcionará.**

| El diseño dice | El código hace | Dónde verificarlo |
|---|---|---|
| §4.4: cabecera de página de «8 bytes más 4 de CRC», con el array de slots en el offset 12 | **20 bytes** (`PAGE_HEADER_SIZE`), con `extra` en 12..16, `prefix_len` en 16..18 y el array de slots en `20 + prefix_len` | `page.rs` |
| §4.4: el CRC32 de página está «ausente si hay cifrado» | **Nunca está ausente.** `PageRef::parse` lo comprueba incondicionalmente. El propio §9 del diseño ya dice lo contrario, así que se contradice a sí mismo | `page.rs` |
| §4.4: «con página de 512 B quedan unos 500 bytes útiles» | 492 antes del prefijo y los slots; **472** en una base cifrada | `page.rs`, `pager.rs` |
| §4.1: los `flags` de la cabecera fijan «checksums de página, compresión de prefijo, cifrado» | Solo existen dos bits, y **solo uno se escribe jamás**: `FLAG_ENCRYPTED`. No hay bit de checksum (el CRC es incondicional) y `FLAG_PREFIX_COMPRESSION` está muerto — la compresión de prefijo es incondicional | `header.rs`, `tx.rs` |
| §4.1: la cabecera «se escribe una vez y **nunca se reescribe**» | La reubicación de la meta B la reescribe. Y el diseño **no menciona en absoluto el espejo** de la cabecera (bytes 64..128 de la página 0), que es lo que impide que un desgarro de esa reescritura deje la base inabrible para siempre | `header.rs`, `tx.rs` |
| §9: «ChaCha20-Poly1305 por defecto, AES-256-GCM seleccionable» | **X**ChaCha20-Poly1305 (nonce de 24 B, que es lo que deja meter el prefijo aleatorio) y AES-256-**GCM-SIV**. `aes-gcm` desapareció del manifiesto. El propio §9 ya dice «GCM-SIV» unas líneas más abajo | `crypto.rs`, `Cargo.toml` |
| §9: «con ChaCha20-Poly1305 y con AES-GCM, [repetir nonce] rompe la confidencialidad de ambas páginas» | Cierto para XChaCha20; **falso para GCM-SIV**, resistente a la reutilización de nonce por construcción (RFC 8452). Es justo el motivo del cambio | `crypto.rs`, `Cargo.toml` |
| §9: «invariante del nonce: `página \|\| contador`» | El nonce es `prefijo aleatorio \|\| contador`. **El número de página no está en el nonce**: es dato asociado | `crypto.rs` |
| §4.1: solo describe el rechazo por versión «demasiado nueva» | También se rechaza una versión **más vieja**, y es una propiedad de seguridad, no de comodidad (ver la sección 11 de este documento) | `header.rs`, `error.rs` |
| §4.1: no dice cuál es el rango legal de `page_size` | 512 B a **32 768 B** (`MIN_PAGE_SIZE`/`MAX_PAGE_SIZE`), impuesto en `Geometry::decode` | `header.rs` |
| §4.2: describe la meta como una lista de campos, sin offsets ni tamaño, y **omite `catalog_root` y `freelist_tail`** | 152 bytes con la disposición de la sección 5 de este documento | `meta.rs` |

### 12.2 Discrepancias de comportamiento, no de formato

Relevantes para operar, no para leer bytes:

| El diseño dice | El código hace |
|---|---|
| §11: enumera nueve variantes de `Error` | Hay **diecisiete**, y ocho de las que faltan son las que más se ven en operación: `VersionTooOld`, `AlreadyOpen`, `WriterPoisoned`, `DuplicateKey`, `IndexNotDeclared`, `DeleteRangeIndexed`, `NonceReuse`, `NonceExhausted`. `CorruptKind` tiene nueve variantes y el diseño no enumera ninguna |
| §10: muestra un ejemplo de API | **No compila.** `Db::open` toma un `Box<dyn Storage>`, no una ruta; `Db::create` no aparece; `delete_range`/`scan` toman `(ns, from, to)` y no rangos de Rust; `begin_read` no devuelve `Result`; `scan_index` devuelve un `Vec` ya materializado |
| §7: ante un desajuste de versión de índice, «se niega a abrir o **reconstruye** el índice, según configuración» | Siempre `Err(IndexVersionMismatch)`. No hay opción de reconstrucción ni configuración que la active |
| §7: la unicidad se garantiza «por colisión de clave, sin comprobación adicional» | Hay una comprobación explícita y un error propio, `DuplicateKey` |
| §8: los índices sobre un espacio con retención deben incluir el componente temporal para que `delete_range` borre también un rango contiguo de índice | **No implementado.** `delete_range` sobre un `ns` indexado se rechaza con `DeleteRangeIndexed`, se declare el índice o no |
| §5: «el motor debe exponer una métrica del `txn_id` más antiguo retenido» | **No existe.** `Db::reuse_floor`, que es ese valor, es privado |
| §12.4: recuperar espacio es trabajo del llamante («truncar o recrear la base») | `Db::reclaim_tail` existe, con contrato completo |
| §6: «abrir cuesta tres lecturas» | **Cuatro**, medidas y fijadas por prueba (el §12.2 del propio diseño ya dice 4) |
| §6: con cifrado hay un `fsync` incondicional extra | Desapareció con los nonces por apertura. Una base cifrada paga hoy exactamente las mismas sincronizaciones que una sin cifrar |
| §13: la prueba de cifrado verifica que «ningún par (página, `txn_id`) se repite» | `txn_id` no interviene en el nonce. Lo que se comprueba es la inyectividad del flujo de nonces |
| §13: `cargo geiger` en integración continua | Retirado deliberadamente: `--forbid-only` no dice nada de este *crate*, porque la prohibición vive en `Cargo.toml` y no como atributo `#![forbid]` |
| §14: tabla de módulos con `node.rs` | `node.rs` **no existe**. Faltan `header.rs`, `crypto.rs`, `storage.rs`, `error.rs`, `crc32.rs`, `varint.rs`, y `meta.rs`/`pager.rs` están mal atribuidos |
| §14: «entre 4 000 y 6 000 líneas» | Más de 23 000 |
| §13/§14: no mencionan `Db::audit_pages` | Existe, tras la *feature* `audit`, activada por defecto |

### 12.3 Los 67,72 bytes por entrada, y todo lo que cuelga de ellos

El diseño cita **67,72 B/entrada en trece sitios** y construye sobre esa cifra
una cascada entera de números derivados: dimensionado de flota por plan,
amplificación de escritura, coste diario, criterios de salida y la comparativa
con SQLite. **La cifra actual medida es 34,14** — la partición sesgada al
anexar (`SplitBias::Append`, `tree.rs`) subió el llenado medio de hoja del
49,5 % al 99,5 %, y el criterio de salida de 40 B/entrada, que el diseño da por
incumplido, **hoy se cumple**.

Como regla práctica: todo número del diseño derivado de 67,72 **se divide
aproximadamente por dos** (34,14 / 67,72 ≈ 0,504). No los reproduzcas desde el
diseño; vuelve a medirlos.

Dos casos merecen mención aparte:

- **La comparativa con SQLite se invierte.** El diseño concluye que «SQLite
  gana en tamaño de fichero» con 56,06 B/fila frente a 67,72. Con 34,14 la
  conclusión se da la vuelta. **Aviso: el lado de SQLite no se ha vuelto a
  medir** — el banco comparativo imprime pero no fija ningún umbral, así que
  los 56,06 vienen de una corrida anterior. La comparación necesita volver a
  ejecutarse entera antes de publicar la conclusión nueva.
- **El control de orden de inserción.** El diseño dice que cambiar el orden
  mueve el cociente «de ~69 a ~99 bytes, un 44 %». Los valores actuales son
  **49,50 secuencial y 404,00 barajado, cociente 8,16**.

### 12.4 Fuera del diseño

- **`README.md`** sigue diciendo «The design is complete and implementation has
  not started. There is no public API yet.» Dejó de ser cierto hace tiempo.
- **`src/tx.rs`**, en el comentario de `Sync::Never`, sigue diciendo «y, con
  cifrado, para no reutilizar contadores». Ese `fsync` ya no existe (ver la
  fila correspondiente de la tabla 12.2).

---

## 13. Índice rápido de constantes

| Constante | Valor | Dónde |
|---|---|---|
| `HEADER_SIZE` | 64 | `header.rs` |
| `HEADER_MIRROR_OFFSET` | 64 | `header.rs` |
| `MAGIC` | `"INRO\0DB\x01"` | `header.rs` |
| `FORMAT_MAJOR` / `FORMAT_MIN_SUPPORTED` | 3 / 3 | `header.rs` |
| `MIN_PAGE_SIZE` / `MAX_PAGE_SIZE` | 512 / 32768 | `header.rs` |
| `META_AUTH_END` | 108 | `meta.rs` |
| `META_SIZE` | 152 | `meta.rs` |
| `WRAPPED_KEY_LEN` | 60 (12+32+16) | `crypto.rs` |
| `STORED_NONCE_LEN` | 24 | `crypto.rs` |
| `NONCE_PREFIX_LEN` | 16 | `crypto.rs` |
| `AES_NONCE_LEN` / `AES_PREFIX_LEN` | 12 / 8 | `crypto.rs` |
| `TAG_LEN` | 16 | `crypto.rs` |
| `CIPHER_PREFIX` | 40 | `crypto.rs` |
| `PAGE_HEADER_SIZE` | 20 | `page.rs` |
| `FREELIST_HEADER` | 32 | `freelist.rs` |
| Polinomio CRC32 | 0xEDB88320 reflejado, init 0xFFFFFFFF, XOR final 0xFFFFFFFF (CRC-32 IEEE, el de zlib) | `crc32.rs` |
| Umbral de overflow | `page_size_lógico / 4` | `tree.rs` |
| Clave máxima | `page_size_lógico / 4` | `tree.rs` |
| Profundidad máxima de árbol | 128 | `tree.rs` |
