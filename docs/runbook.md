# Runbook operativo de `inro`

Para quien recibe una alerta a las tres de la mañana y no escribió este motor.

**Contexto que hay que tener presente**: `inro` tiene **cero horas de
producción**. Todo lo que hay aquí sale de pruebas y de mediciones, no de
incidentes reales. Hay **un fichero por cliente**, así que un fallo suele
afectar a **un** cliente, no a la flota: comprobar el alcance es el primer paso
y casi siempre es la mejor noticia del turno.

Ver también: `formato-en-disco.md` (los bytes), `invariantes.md` (las reglas),
`arquitectura.md` (el mapa).

---

## 0. Lo primero, antes de tocar nada

1. **Copia el fichero.** `cp base.inro base.inro.incidente-YYYYMMDD`. Todo lo
   demás es reversible; perder la evidencia no.
2. **Para los escritores de esa base.** Si un proceso sigue escribiendo, el
   estado cambia bajo tus pies y el diagnóstico no vale.
3. **Comprueba el alcance.** ¿Un fichero o muchos? Un fichero apunta a un medio
   o a un cliente; muchos a la vez apuntan al motor, al despliegue o al disco.
4. **No reescribas el fichero para «arreglarlo».** En particular, no borres ni
   recrees la base hasta haber decidido si los datos son recuperables. Casi
   siempre lo son.

**Un motor que se niega a abrir un fichero legible es peor que el defecto que
la negativa pretendía evitar.** El diseño ya sigue ese criterio en varios
sitios (reparación de cabecera, degradación de la lista de libres); tu
diagnóstico debería seguirlo también.

---

## 1. Triaje en un minuto

**Antes de empezar, dos reglas que la intuición se salta**: un `commit` que
devolvió `Err` **puede** haber quedado duradero (§2, última subsección), y
`audit_pages() == true` **no** significa que la base esté sana (§5).

```
¿Db::open devuelve Ok?
├── SÍ, y las lecturas responden bien
│     → No es un problema de integridad. Mira §5 (audit_pages) y §7
│       (responsabilidades del llamante): lo más probable es un índice
│       divergido o espacio que no se recupera.
├── SÍ, pero faltan datos o hay datos de más
│     → §4.2: casi siempre es un índice mantenido sin declarar, o un modo de
│       sincronización relajado que perdió los últimos commits. Los datos que
│       sobreviven son un snapshot ENTERO, nunca uno con agujeros.
└── NO
      ├── Io(UnexpectedEof)    → §3.1. ¿Existía el fichero? Abrir una ruta
      │                          inexistente la CREA vacía y falla así.
      ├── BadFormat            → §3.3. ¿Es un fichero inro? ¿Va con clave?
      ├── VersionTooNew/TooOld → §3.4/§3.5. Binario equivocado. NO recuperes.
      ├── Corrupt{MetaAuth}    → §4.1. MANIPULACIÓN. Parar, no reintentar.
      ├── Corrupt{Checksum}    → §3.2 + §2. Casi siempre desgarro.
      ├── Corrupt{MetaMismatch}→ §4.9. Meta imposible frente al fichero real.
      ├── Decrypt              → §3.15. Clave equivocada, o página tocada.
      ├── AlreadyOpen          → §3.6. Fallo de despliegue, no de datos.
      └── Io(...)              → §3.1. Es el disco, no la base.
```

---

## 2. Distinguir un desgarro, una manipulación y un bug

Es la pregunta que decide todo lo demás, y hay una señal limpia para cada uno.

### Desgarro (corte de corriente, cierre brusco, disco que perdió la escritura)

**Firma:** un CRC32 que no cuadra, sobre una estructura que por lo demás tiene
sentido. En una meta-ranura eso es lo esperado y el motor lo absorbe solo: la
otra ranura monta, con un `txn_id` una unidad menor.

- Ocurrió **después** de un evento de energía, un OOM-kill, un `SIGKILL` o una
  máquina que se fue.
- El fichero es coherente hasta cierto punto y basura a partir de ahí.
- **El motor lo trata solo**: la base abre. Si abre y el `txn_id` es el
  anterior al último que tu aplicación creía confirmado, eso **no es un
  fallo**: es exactamente el contrato bajo `Sync::Interval`/`Never`.

**Acción:** ninguna. Anota cuántos commits se perdieron y revisa si la política
de sincronización es la que quieres.

### Manipulación (alguien escribió el fichero)

**Firma inequívoca: un CRC32 CORRECTO sobre un contenido imposible.** La
podredumbre de bits y un corte de corriente no saben recalcular un CRC32. Si el
CRC cuadra y el contenido es absurdo, alguien lo calculó.

Cómo se manifiesta:

- **Base cifrada:** `Corrupt { kind: MetaAuth }` al abrir. Esto es
  **definitivo**: la ranura está entera (nadie la partió) y la clave no la
  avala. También `Decrypt { page }` sobre una página cualquiera.
- **Base sin cifrar:** no hay autenticación de ninguna clase, así que solo se
  detecta por **implausibilidad**: `MetaMismatch` (una meta que declara más
  páginas de las que el fichero tiene, o una raíz fuera del fichero),
  `CellBounds` desde la lista de libres (una entrada que apunta a la página 0,
  a la meta A, o más allá del final). Todos ellos con el CRC en orden.

**Acción:** parar. No reintentar, no «reparar», no abrir con otro binario.
Preservar la copia y escalar como incidente de seguridad. **Restaurar desde
copia de seguridad es la única vía**, y hay que tener en cuenta que la
autenticación **no detecta una vuelta atrás**: una copia auténtica y antigua
valida perfectamente.

### Bug del motor

**Firma:** el motor devuelve `Ok` con una respuesta equivocada, o falla sobre un
fichero que **él mismo** escribió y nadie tocó.

- `TreeLoop`, `OverflowLoop`, `FreelistLoop` sobre un fichero que no ha salido
  de tus máquinas: son cotas defensivas contra ciclos, y en un fichero que
  escribió este motor no deberían dispararse jamás.
- `NonceReuse`: comprobación **puramente interna**. Con el diseño actual
  (contador monótono por apertura que no rebobina) es matemáticamente
  inalcanzable si el resto del motor es correcto. Si lo ves, es un bug.
- `audit_pages()` devolviendo `false` sobre una base que solo ha visto
  operaciones normales.
- Una consulta que devuelve una clave que nadie escribió, o `None` para una
  clave cuyo `commit` devolvió `Ok` **y ya estaba sincronizado**.

**Acción:** preservar el fichero **entero** (es la reproducción), anotar la
secuencia exacta de operaciones y la política de `Sync`, y escalar. Este motor
tiene un solo autor humano: el fichero vale más que cualquier descripción del
síntoma.

### Un `commit` que devolvió `Err` PUEDE haber quedado duradero

**No asumas que una transacción fallida no tuvo efecto.** La escritura de la
meta es siempre la última del commit, y una ranura mide 152 bytes útiles: el
resto de la página ya es relleno a cero en las dos versiones. Si un desgarro
deposita un prefijo **igual o mayor que esos 152 bytes**, lo que llega al plato
es **indistinguible de una escritura completa** — el commit es duradero de
verdad — y aun así la llamada devuelve `Err`, porque la escritura falló.

Correcto (los bytes llegaron), pero sorprendente para quien solo mire el
`Result`. Está fijado por su propia prueba:
`a_torn_write_of_the_meta_page_with_a_prefix_at_or_above_meta_size_lands_a_full_commit_anyway`.

**Consecuencia operativa:** tras un `commit` que devolvió `Err`, **relee** el
estado antes de decidir nada. Un reintento ciego puede duplicar el efecto de
una operación que ya se aplicó. La regla «si `commit` falla, la transacción no
ocurrió» **es falsa en este motor.**

---

## 3. Cada variante de `Error`

### 3.1 `Io(IoError)`

El medio de almacenamiento falló. **No es un problema de la base.**

| Variante | Significado | Causa más probable | Qué hacer |
|---|---|---|---|
| `NotFound` | Una ruta que no se puede abrir | **No es «el fichero no existe»**: `FileStorage::open` lo CREA si falta. Esto significa que falta un **directorio padre**, o que `/dev/urandom` no está (base cifrada) | Comprobar montaje y directorios, no el fichero |
| `PermissionDenied` | Sin permisos | Usuario/UID del servicio, SELinux, montaje de solo lectura | Permisos. También sale de `/dev/urandom` en una base cifrada |
| `UnexpectedEof` | Lectura corta: el fichero es más corto de lo que hace falta | **El caso más común: `Db::open` sobre una ruta que no existía.** Como se crea vacía, la lectura de la cabecera se queda corta. También: truncado externo, copia incompleta, disco lleno a mitad de escritura | Si la base es nueva, usa `Db::create`. Si no, ver §6.3 — **es fatal y no degrada** |
| `WriteZero` | Una escritura no progresó | Disco lleno, cuota, dispositivo desconectado | Espacio en disco. La transacción no confirmó: la base sigue en el commit anterior |
| `Other(errno)` | Cualquier otro error del sistema | Ver el `errno` | Según el `errno` |

**Recuperable:** sí, casi siempre. El estado en disco sigue siendo el del
último commit; un `Err` de escritura significa que esa transacción no
confirmó.

**Ojo con `UnexpectedEof`**: es el único `Io` que el motor **no** degrada con
gracia. Una cadena de lista de libres que apunta más allá del final da
`UnexpectedEof`, se propaga y la base no abre — a diferencia de un `Corrupt`,
que sí degrada. Ver §6.3.

### 3.2 `Corrupt { page, kind }`

Una página, o la meta, no valida. `page` dice cuál. El `kind` es el
diagnóstico: ver §4.

### 3.3 `BadFormat`

**La variante más sobrecargada del motor.** No significa una sola cosa:

| Origen | Significado |
|---|---|
| `Db::open` | El magic no coincide: **no es un fichero inro** |
| `Db::create` | `page_size` fuera de 512..32768, o no es potencia de dos |
| `Db::open` con clave sobre un fichero **sin cifrar** | Pediste cifrado a una base que no lo tiene |
| Binario compilado **sin** la *feature* `encryption` | Pediste cifrado, o el fichero dice estar cifrado, y este binario no lleva criptografía compilada |
| Binario compilado sin la *feature* `aes` | El algoritmo pedido es AES-256-GCM-SIV y este binario no lo lleva |
| `define_index` | `id >= 0x80`, o `ns == 0x00` (el catálogo), o `ns >= 0x80` (el espacio de un índice) |
| `scan_index` | Ese `id` no está registrado en **este** proceso. Llama a `define_index` primero |
| Lectura de una entrada de índice | Bytes basura en el espacio de claves de un índice |

**Qué hacer:** empieza por descartar el caso trivial — `file base.inro`, y
comprueba los ocho primeros bytes: `49 4E 52 4F 00 44 42 01`. Si están, es un
fichero inro y el problema es de *features* de compilación o de clave, no de
datos. **Recuperable:** sí; ninguno de estos casos toca el fichero.

### 3.4 `VersionTooNew { found, supported }`

El fichero lo escribió un binario más nuevo. **Estás usando el binario
equivocado**, casi siempre por un despliegue a medias o un *rollback* de la
aplicación sin *rollback* de los datos.

**Recuperable:** sí, con el binario correcto. **No intentes leerlo con este.**

### 3.5 `VersionTooOld { found, supported }`

El fichero es de un formato anterior al 3. **No hay compatibilidad hacia atrás
y es deliberado, por seguridad**: mantener una vía de lectura del formato 2
habría dejado abierta una vía de apertura **sin autenticar**, alcanzable
bajando el `format_major` de la cabecera (que no está autenticada, ni puede
estarlo).

**Recuperable:** solo migrando con un binario que sepa leer el formato viejo y
volviendo a escribir los datos. No hay herramienta de migración: el *crate*
está sin publicar y no debería existir ningún fichero de los formatos 1 o 2 en
el mundo. **Si aparece uno, eso en sí mismo es el incidente**: o alguien
conserva datos de una versión de desarrollo, o alguien bajó el `format_major`
a mano.

### 3.6 `AlreadyOpen`

**Este proceso** ya tiene abierto ese mismo fichero (comparando rutas
canonicalizadas: `./base` y `/abs/base` son la misma). Es un fallo de
despliegue o de código, **no de datos**.

Dos asas independientes son dos candados de escritor distintos: el escritor
único deja de serlo, y el copy-on-write de dos escritores concurrentes es
corrupción.

**Qué hacer:** encuentra el segundo `Db` y elimínalo. Un asa se libera cuando
se destruye, incluso si `Db::open` falló a medias.

**No cubre un segundo PROCESO.** Ver §7.1.

### 3.7 `WriterBusy`

Ya hay una transacción de escritura en curso en este proceso. **Reintentar
tiene sentido.** También lo devuelve `reclaim_tail`, que toma el mismo candado.

### 3.8 `WriterPoisoned`

Una transacción anterior **entró en pánico con el candado de escritor
tomado**. A diferencia de `WriterBusy`, este candado **no se libera nunca**:
todo `begin_write` posterior fallará igual hasta que el proceso se reinicie.

**Causa casi segura:** un extractor de índice (`IndexDef::extract`) que entró
en pánico. Es código del llamante, se ejecuta con el candado tomado, y el motor
no puede protegerse de ello sin coste.

**Qué hacer:** reiniciar el proceso restaura el servicio. **Y luego arregla el
extractor**, que no debe entrar en pánico nunca. Los datos están intactos: el
pánico ocurrió antes de confirmar, así que la base sigue en el commit anterior.

### 3.9 `IndexVersionMismatch { id, stored, provided }`

El registro del catálogo en disco no coincide con el `IndexDef` que estás
pasando. **Se compara el registro COMPLETO** —versión, unicidad, `ns` y
nombre—, no solo la versión: redefinir el mismo `id` como único cuando antes no
lo era, o sobre otro espacio de claves, deja el índice mintiendo en silencio
exactamente igual que un extractor cambiado.

**Qué hacer:** o corriges la llamada, o reconstruyes el índice. **El motor no
lo reconstruye por ti** (el diseño dice lo contrario; está desactualizado).
Reconstruir significa: borrar las entradas del espacio `0x80 | id`, borrar el
registro del catálogo, y reescribir cada fila.

**Lo que esto NO puede detectar:** un `extract` cambiado sin subir la versión.
`extract` es un puntero a función, sin ninguna propiedad observable que
distinga «la misma lógica» de «otra que hoy calcula lo mismo por casualidad».
`version` es y seguirá siendo la única defensa.

### 3.10 `DuplicateKey { id }`

Un índice único ya contiene ese valor indexado, en **otra** fila. **No es
corrupción.** Reescribir la misma fila con el mismo valor indexado no dispara
esto: la comprobación compara la clave primaria almacenada, no solo la
existencia de la entrada.

**Ni el dato ni ningún índice se han tocado**: la comprobación ocurre en la
fase de planificación, antes de mutar nada. Puedes seguir usando la misma
transacción.

### 3.11 `IndexNotDeclared { id, ns }`

El catálogo **en disco** declara el índice `id` sobre el espacio `ns`, y este
`Db` no lo tiene registrado. La escritura se rechaza porque el motor sabe lo
bastante para **negarse** aunque no sepa lo bastante para **mantener** el
índice (le falta el extractor, que no viaja en el fichero).

**Qué hacer:** llama a `define_index` con la definición correcta y repite la
operación. Ver §7.2, que es donde esto se convierte en un incidente si nadie
lo ve.

**Es una buena noticia cuando aparece.** Antes de este error, esa escritura
seguía adelante y dejaba el índice divergiendo en silencio.

### 3.12 `DeleteRangeIndexed { ns }`

`delete_range` sobre un espacio con índices definidos —**decidido contra el
catálogo en disco**, no contra lo que este proceso haya registrado.

**Declarar el índice NO resuelve esto**, a diferencia de
`IndexNotDeclared`: la operación sigue rechazada. El borrado por rango libera
subárboles enteros sin visitar cada entrada, así que no hay forma barata de
saber qué entradas de índice retirar; enrutarlo clave a clave sería correcto
pero destruiría la garantía de coste que justifica la operación.

**Qué hacer:** borra clave a clave con `delete` (que sí mantiene los índices),
declarando antes los índices. Es más caro, y esa es exactamente la disyuntiva
que el error te obliga a tomar de forma explícita.

### 3.13 `KeyTooLarge { len, max }`

La clave pasa de `page_size_lógico / 4`. Con páginas de 512 B sin cifrar son
128 bytes; cifrada, 118.

**No dice si la rechazó la clave primaria o una entrada de índice**, ni cuál —
limitación conocida y documentada. En un índice **no** único la entrada es
`valor_indexado ++ clave_primaria ++ 2`, así que dos mitades individualmente
legales pueden pasarse juntas.

**Ni el dato ni ningún índice se han tocado.** Recuperable: sí, arreglando la
clave. Si necesitas claves más grandes, la única palanca es un `page_size`
mayor, y eso solo se fija al crear la base.

### 3.14 `Full`

Se alcanzaron 2^32 páginas: 2 TB con páginas de 512 B, 16 TB con 4 KB. No queda
espacio direccionable.

**Recuperable:** solo repartiendo los datos en varias bases. Es un límite del
formato.

### 3.15 `Decrypt { page }`

El descifrado falló. Con `page: 0` viene de la clave envuelta de la meta; con
otro número, de esa página concreta.

Tres causas, en orden de probabilidad:

1. **Clave maestra incorrecta.** Con diferencia la más común. Un despliegue con
   la clave de otro entorno, una rotación de secretos a medias.
2. **Abriste una base cifrada sin dar clave.** Da el mismo error a propósito:
   para quien llama es la misma situación de fondo.
3. **La página fue manipulada** o los bytes de otra página se copiaron encima
   (los datos asociados atan cada página a **su** número, así que mover una
   página se detecta).

**Cómo distinguirlas:** si falla con `page: 0`, es la clave o el envoltorio —
prueba con la clave del entorno correcto. Si el envoltorio de la meta **sí**
abre y luego falla una página de datos concreta, la clave es la correcta y esa
página está tocada: ve a §2, rama de manipulación.

**Recuperable:** con la clave correcta, del todo. Sin ella, **no**: la clave de
datos está cifrada con la maestra y no hay puerta trasera.

### 3.16 `NonceReuse { page }`

**Comprobación interna, no un fallo del llamante.** El motor detectó que iba a
sellar una página con un número de escritura ya usado en esta misma
transacción. Con el diseño actual esto es **matemáticamente inalcanzable** si
el resto del motor es correcto.

**Qué hacer:** es un bug. Para el servicio para esa base, preserva el fichero,
escala. La transacción no confirmó, así que el fichero sigue en el commit
anterior — pero la premisa de la que depende toda la confidencialidad del
cifrado acaba de fallar y hay que entender por qué antes de seguir escribiendo.

### 3.17 `NonceExhausted`

El flujo de nonces de esta apertura se agotó. **Solo alcanzable bajo `no_std`
con AES-256-GCM-SIV**: su nonce de 12 bytes deja un campo de contador de 32
bits, así que a las 2^32 escrituras de página de una misma apertura hace falta
un prefijo nuevo, y sin sistema operativo no hay de dónde sortearlo.

**Bajo `std` no ocurre**: el prefijo se renueva de `/dev/urandom`.

**Qué hacer:** reabrir la base con un prefijo nuevo. Fallar aquí es lo
correcto: la alternativa sería repetir un nonce en silencio.

---

## 4. Cada variante de `CorruptKind`

### 4.1 `MetaAuth` — la única que significa manipulación con certeza

Una meta-ranura **completa** (su CRC32 cuadra con sus propios bytes) que **no**
lleva el tag que le corresponde bajo la clave de datos de esta base. Solo
alcanzable en una base cifrada.

**El distingo con `Checksum` es toda la señal.** Una ranura desgarrada falla el
CRC; una que lo cuadra es, por construcción, una ranura entera. Que además no
autentique significa que alguien calculó ese CRC sobre un contenido que la
clave no avala.

**El motor se detiene aquí y NO cae a la otra ranura**, a propósito: caer
convertiría un ataque detectado en una vuelta atrás silenciosa.

**Qué hacer:** §2, rama de manipulación. **No reintentar.** **Recuperable:**
solo desde copia de seguridad.

### 4.2 `Checksum` — casi siempre un desgarro

El CRC32 no cuadra: cabecera, meta o página de datos.

| Dónde | Qué significa | Qué hace el motor |
|---|---|---|
| Cabecera (página 0) | Desgarro de la única reescritura que existe (reubicación de la meta B), o daño en el sector | Cae al espejo (offset 64) y **repara la principal** |
| Una meta-ranura | Corte a media escritura de meta | Descarta esa ranura y monta por la otra |
| Página de datos | Sector dañado, o escritura perdida | **Fatal para esa página**: no hay segunda copia |

**Recuperable:** cabecera y meta, sí y solo. Una **página de datos** con el CRC
roto no tiene redundancia ninguna: lo que hay bajo esa página se pierde. Si es
una hoja, pierdes su rango de claves; si es un nodo interno, pierdes su
subárbol entero.

**Qué hacer con una página de datos rota:** vuelca todo lo que aún se pueda
recorrer (`scan` por rangos, saltando el rango que falla) y reconstruye la base
desde ese volcado más la copia de seguridad. Si el `page` que reporta el error
es la raíz, no hay nada que recorrer: restaura desde copia.

### 4.3 `PageType`

El byte de tipo no es 0..3, o es un tipo que no corresponde: una página de
overflow donde se esperaba un nodo, un nodo donde se esperaba una página de
lista de libres.

**Causa probable:** un número de página que apunta al sitio equivocado — un
puntero corrupto — más que la página en sí. También aparece cuando una cadena
de lista de libres se reasignó como dato (ver §6.3).

**Recuperable:** depende de dónde. En la lista de libres, el motor degrada solo
y la base abre. En el árbol, es como `Checksum` sobre esa página.

### 4.4 `SlotOffset`

Un slot apunta fuera del área de celdas, o los sufijos de la página no están en
orden estrictamente ascendente (**dos claves iguales en una misma página
también son inválidas**).

Es una página cuyo CRC **sí** cuadra, así que: o alguien la escribió a mano, o
hay un bug en la construcción de páginas. Ver §2.

### 4.5 `CellBounds`

La familia más amplia. Una celda no decodifica dentro de la página, dos celdas
se solapan, `free_start` no coincide con lo que implican `n_slots` y
`prefix_len`, o el `count` de una página de lista de libres pasa de lo que cabe
físicamente.

**También lo devuelven las fronteras de números de página**: una entrada de
lista de libres que apunta a la página 0, a la meta A, al destino de la
reubicación de la meta B o más allá del final del fichero; y un hijo de nodo
interno en cualquiera de esas posiciones, o un nodo con dos hijos iguales.

Y `read_overflow` lo usa para «la cadena terminó pero no reunió los `len` bytes
que la celda declaraba».

**Cuando aparece desde la lista de libres con el CRC en orden, es la firma más
clara de manipulación en una base sin cifrar.**

### 4.6 `FreelistLoop`

Un ciclo en los punteros `next` de la cadena de lista de libres: una página que
se apunta a sí misma, o más saltos que páginas tiene el fichero.

**Recuperable:** sí, y el motor lo hace solo. Una cadena ilegible **no impide
abrir**: se degrada a «no hay lista de libres» y la base funciona. El coste es
espacio, no datos — ver §6.3.

### 4.7 `TreeLoop`

El descenso superó `MAX_DEPTH` (128) sin llegar a una hoja: un ciclo de
punteros a hijos, no un árbol válido. También lo devuelven las cotas de trabajo
total contra un DAG corrupto con hijos compartidos, y `audit_pages` ante una
cadena de nodos internos más profunda de lo que un árbol puede ser.

**No lo puede producir ninguna operación de este motor**: todas las funciones
de escritura se niegan a bajar más de 128 niveles. Si lo ves sobre un fichero
que nadie ha tocado, es un bug (§2).

### 4.8 `OverflowLoop`

Un ciclo en una cadena de páginas de overflow, o una cadena que reunió los
`len` bytes declarados **sin llegar a su propio final** — que es la señal que de
verdad detecta el ciclo, porque la cota de saltos sola no puede.

**Recuperable:** el valor de esa clave concreta se pierde; el resto del árbol
está bien. Vuelca todo lo demás.

### 4.9 `MetaMismatch`

Tres situaciones distintas bajo el mismo nombre:

1. **Ninguna de las dos ranuras es legible.** La base no abre. Ver §6.1.
2. **La meta declara más páginas de las que el fichero tiene.** Un fichero no
   encoge por su cuenta: solo puede venir de una manipulación (el CRC lo cubre,
   así que la podredumbre de bits se detiene antes) o de un medio que miente.
   Es el campo más peligroso del formato: sin esta comprobación, el primer
   `put` escribía a cientos de gigabytes del dato real y `audit_pages`
   reservaba hasta 4,29 GB de golpe.
3. **La cola por reconciliar pasa de 2^20 páginas** (512 MB con páginas de
   512 B). Una transacción interrumpida legítima puede dejar cola, pero no
   tanta: por encima de ahí, la desproporción deja de ser plausible.
   Referencia: el banco más grande que este proyecto se mide a sí mismo (un
   millón de registros) ocupa unas 66 000 páginas, quince veces por debajo.

**Recuperable:** el caso 1, casi nunca (§6.1). Los casos 2 y 3 son manipulación
o un medio roto: §2.

---

## 5. `Db::audit_pages()`: qué prueba y qué NO prueba

**Lo que hace:** recorre TODO el fichero —prefijo reservado, árbol de datos
completo (todos los espacios de claves, incluidos catálogo e índices), cada
cadena de overflow, y la cadena de lista de libres con las páginas que
enumera— y comprueba que **cada página de `[0, n_pages)` tiene exactamente un
dueño**.

- `Ok(true)`: cada página tiene un dueño y solo uno.
- `Ok(false)`: una página aparece en dos categorías (**doble asignación**) o en
  ninguna (**fuga**). Son el mismo defecto de fondo en direcciones opuestas.
- `Err(...)`: corrupción de verdad — una página que no decodifica, un tipo
  inesperado.

Coste O(n_pages). No la llama ningún camino caliente, y **`Db::open` no la
llama** a propósito: recorrer el árbol entero contradiría que abrir cuesta un
número constante de lecturas, y negar la apertura por un problema de
contabilidad convertiría espacio desperdiciado en una base inaccesible.

### Lo que NO prueba, con dos casos medidos

**`audit_pages` comprueba propiedad de páginas y NADA MÁS.** Devolvió `true`
en los dos incidentes más caros que este proyecto ha tenido:

1. **Mientras el fichero crecía de forma cuadrática.** Con la lista de libres
   sin fusionar y el punto durable retrasado, 2 000 commits sobre 200 claves
   producían **216 016 páginas — un fichero de 110 MB para 24 páginas de datos
   reales**. Cada página tenía exactamente un dueño en todo momento; la
   contabilidad estaba perfecta y el fichero era basura.
2. **Mientras una base perdía claves en silencio.** Con índices mantenidos sin
   declarar, `scan_index` devolvía claves primarias de filas ya borradas y
   omitía filas recién insertadas. Medido sobre una carga de retención de 14
   días: **30 000 entradas de índice para 1 400 filas vivas, 95,3 % de basura**,
   con la base creciendo sin cota. Y `audit_pages` decía `true` **con razón**:
   la propiedad de las páginas estaba intacta; lo que estaba muerto era el
   **significado** de las entradas.

**No comprueba:** que el árbol esté ordenado, que las claves sean las que
escribiste, que los índices coincidan con los datos, que el fichero tenga un
tamaño razonable, ni que las respuestas de `get`/`scan` sean correctas.

**Un `Ok(true)` no es un certificado de salud. Un `Ok(false)` sí es una señal
real, y siempre merece investigación.**

---

## 6. Procedimientos de recuperación

### 6.1 La base no abre por ninguna de las dos metas (`MetaMismatch`)

Es el peor caso y el más raro: exige que las dos ranuras estén rotas a la vez,
lo que el diseño de dos ranuras existe justo para evitar.

1. Verifica que estás usando el **binario correcto** y la **clave correcta**:
   `VersionTooNew`/`VersionTooOld`/`Decrypt` se descartan antes que nada.
2. Lee la cabecera a mano (los 64 primeros bytes, ver `formato-en-disco.md`
   §2). Si el CRC no cuadra, prueba el espejo en el offset 64.
3. Con la geometría en la mano, localiza las dos ranuras (`meta_a_page` = 1,
   `meta_b_page` de la cabecera) y decodifícalas a mano. Comprueba cuál de las
   dos comprobaciones falla: CRC, o `page_size_log2` contra la cabecera.
4. Si una ranura decodifica pero fue rechazada por contradecir la geometría,
   **estás leyendo con el tamaño de página equivocado** — vuelve al paso 2.
5. Si ninguna sirve, restaura desde copia de seguridad. El árbol puede seguir
   intacto, pero sin una meta válida no hay raíz desde la que empezar. Una
   reconstrucción por fuerza bruta (buscar páginas de tipo hoja y volcar sus
   celdas) es posible con el formato documentado, pero **no existe herramienta
   y el orden de las claves no se puede reconstruir con garantías**.

### 6.2 La cabecera está rota

El motor lo resuelve solo: cae al espejo y repara la principal. Si **las dos**
copias están rotas, la geometría se puede reconstruir a mano: `page_size` sale
del `page_size_log2` que llevan **las propias meta-ranuras** (byte 28), y
`meta_a_page` es siempre 1. Prueba `meta_b_page` = 2 y luego
`max(2, 4096/page_size)`.

### 6.3 La base abre pero ha perdido espacio (`FreelistLoop` / `PageType` en la cadena)

Cuando la cadena de lista de libres no decodifica, el motor **degrada con
gracia**: abre igual, pone `freelist_head`/`freelist_tail` a cero y sigue. Los
datos están intactos; lo que se pierde es la contabilidad del espacio libre.

**No es poco.** Un caso medido dejó **27 de 56 páginas (48 % del fichero)**
huérfanas para siempre: esas páginas siguen por debajo de `n_pages`, así que la
reconciliación de apertura —que solo barre más allá de `n_pages`— no las
alcanza, y `reclaim_tail` tampoco (no están en la cola).

**Cómo lo notas:** `audit_pages()` devuelve `false`, y el fichero es mucho más
grande de lo que sus datos justifican.

**Cómo se arregla:** volcando y recargando. `scan` sobre cada espacio de claves,
crear una base nueva, reinsertar. No hay compactación en línea.

### 6.4 Sospecha de manipulación

1. **No reintentes la apertura.** Un reintento puede escribir (la reparación de
   cabecera es una escritura).
2. Preserva el fichero y ponlo fuera del alcance de escritura.
3. Restaura desde copia de seguridad. Ten en cuenta que **la autenticación no
   detecta una vuelta atrás**: si el atacante pudo escribir el fichero, también
   pudo restaurar un estado antiguo auténtico, y eso valida perfectamente.
4. Si la base **no** está cifrada, no hay ninguna detección de manipulación más
   allá de la implausibilidad. Trátalo como comprometido.

---

## 7. Lo que el motor NO hace por ti

### 7.1 Exclusión entre procesos — **el riesgo operativo número uno**

**No existe, y no existirá.** El registro de ficheros abiertos cubre **este
proceso** y nada más. `flock(2)` no es alcanzable sin `unsafe` (prohibido en
todo el *crate*) ni sin una dependencia de ejecución.

**Dos procesos con la misma base abierta para escritura corrompen el fichero.**
El copy-on-write de dos escritores concurrentes es corrupción; no hay ninguna
detección, ningún error, ninguna señal.

**Qué debes garantizar tú:**

- Un solo proceso por fichero. En un despliegue con reinicios sin corte
  («blue-green», recargas), asegúrate de que el proceso viejo **ha cerrado el
  fichero** antes de que el nuevo lo abra. Un solapamiento de unos segundos
  basta.
- Cuidado con los sistemas de ficheros en red: dos nodos montando el mismo
  volumen es exactamente este caso.
- Los procesos auxiliares cuentan: el podador de retención, el trabajo de
  copias de seguridad, cualquier herramienta de inspección.

Bueno saberlo: **ya no es además un fallo de confidencialidad**. Cada apertura
sortea su propio prefijo de nonce de 16 bytes, así que dos procesos no pueden
compartir un nonce ni aunque el guardián no existiera. Lo que queda —la
corrupción del árbol— sigue siendo motivo de sobra.

### 7.2 Declarar los índices antes de escribir un espacio indexado

**Todo proceso que escriba un espacio de claves con índices debe llamar a
`define_index` en cada apertura**, con la definición exacta. Los índices
registrados **no se releen del fichero**: el extractor es código del llamante y
no puede vivir en el disco.

El motor te protege — `IndexNotDeclared` y `DeleteRangeIndexed` se deciden
contra el **catálogo en disco**, no contra tu lista — pero esa protección es
una **negativa**, no una reparación: tus escrituras fallarán hasta que declares
los índices.

**El caso que más duele es el menos obvio:** un podador de retención no tiene
ningún motivo para declarar índices —no tiene el extractor— y es justo el que
borra a diario. Si tu podador no declara, todos sus borrados fallarán con
`DeleteRangeIndexed`, que es lo correcto y lo que hay que arreglar en el
podador, no rodear.

**Y `define_index` no rellena hacia atrás:** las filas escritas antes de la
primera llamada se quedan sin indexar **para siempre**, en silencio, y reabrir
con la misma definición no lo detecta ni lo avisa. Levantar un índice sobre
datos preexistentes exige reescribir esas filas a mano.

### 7.3 Copias de seguridad

**Restaurar una copia completa hoy es seguro.** Cada apertura sortea un prefijo
de nonce nuevo, así que la línea temporal restaurada vive en un espacio de
nonces distinto del original.

**No lo era antes del formato 2**, y el fallo era total: el techo del contador
de nonce se persistía en la meta, junto a la clave envuelta, así que **los dos
retrocedían juntos**. Medido sobre aquel código: **296 de 296 nonces
compartidos** entre las dos líneas temporales, 164 con texto plano distinto y
hasta un **96,52 % de bytes cero en el XOR** de los textos cifrados —
recuperación total del texto plano a partir de un procedimiento de operación
corriente, **sin ningún atacante de por medio**. Si tienes copias de bases del
formato 1, trátalas como material comprometido y rota la clave.

**Lo que sigue siendo responsabilidad tuya:**

- **La copia tiene que ser coherente.** No hay mecanismo de instantánea. Copiar
  el fichero mientras un escritor está activo puede dar una mezcla de dos
  estados: el fichero resultante puede montar por una meta cuyas páginas no se
  copiaron. Copia con la base cerrada, o desde una instantánea del sistema de
  ficheros.
- **Guarda la clave maestra aparte del fichero.** La clave de datos está
  cifrada con la maestra dentro de la propia meta: sin la maestra la copia no
  vale nada, y no hay puerta trasera.
- **Una copia restaurada es indistinguible de la actual para el motor.** La
  autenticación detecta falsificación, no retroceso.

### 7.4 Elegir la política de `Sync` a sabiendas

| Modo | `fsync` por commit | Pérdida máxima en un corte |
|---|---|---|
| `Commit` | dos | El commit en vuelo |
| `Interval(d)` | como mucho uno cada `d` | Los commits de la última ventana |
| `Never` | ninguno | Todo lo confirmado desde el último `fsync` que el motor emitió por su cuenta |

Los tres comparten la garantía que el motor **sí** puede dar: **lo que
sobreviva es un snapshot entero, nunca uno con agujeros**.

**Y ningún modo relajado promete que el último commit sobreviva.** Sin `fsync`
entre las páginas y su meta, nada impide que el sistema operativo escriba la
meta antes que las páginas que referencia; si el corte cae ahí, la base monta
por una meta cuyas páginas nunca llegaron. Eso no lo puede evitar el motor:
ordenar las dos cosas es exactamente lo que hace el primer `fsync` de
`Sync::Commit`.

**`Never` no significa cero `fsync`.** El motor emite uno cuando el punto
durable se retrasa más de 16 transacciones, para poder reciclar espacio: sin
él, el fichero crecería sin cota justo donde el disco es más escaso. Coste
medido (2 000 commits sobre 200 claves, páginas de 512 B): **84 páginas frente
a las 24 de `Sync::Commit`** —un margen constante, no proporcional al trabajo—
con un 23 % más de escrituras físicas y **31 veces menos `fsync`**.

### 7.5 `Db::reclaim_tail()`: qué hace y qué NO hace

**Lo que hace:** devuelve al sistema de ficheros el **sufijo de páginas libres
que hay al final** del fichero, y responde cuántos bytes devolvió (`0` si no
había nada). Repite pasadas hasta que una deja de ganar.

**Lo que NO hace: compactar.** No mueve páginas vivas hacia abajo — eso sería
reescribir el árbol, con un coste completamente distinto — así que **una sola
página viva alta limita lo que se recupera**. En la práctica no suele
ocurrir, porque la operación reordena la lista de libres de menor a mayor antes
de reescribir la cadena, y la cadena de libres es lo único que suele quedar
arriba cuando el árbol se ha vaciado. Sin ese reordenamiento, medido: las tres
páginas de cadena caían en la 12, la 44 y la 108 de 139, y el recorte se
quedaba en un **22 %**.

**Nunca es automática, y es deliberado.** `commit` no la llama: una base que
borra por la mañana y vuelve a escribir por la tarde recortaría y volvería a
extender el fichero todos los días, pagando `fsync` y fragmentación a cambio de
nada. Quien sabe que el pico no va a volver es el llamante.

**Cuándo llamarla:** después de una poda que sabes que no se va a revertir —
por ejemplo, el trabajo que baja a un cliente de un plan de retención de 5 días
a uno de 2.

**Coste:** un `fsync` para poner al día el punto durable, más dos por cada
pasada que recorte de verdad. El trabajo es proporcional al número de páginas
**libres**, no al tamaño del árbol: no recorre ningún dato.

**Errores:** `WriterBusy` si hay otra transacción de escritura viva. **Los
lectores abiertos no la bloquean, pero sí limitan lo que puede recortar**: una
página que un snapshot vivo todavía podría necesitar no se toca. Un lector de
larga duración es la explicación más común de un `reclaim_tail` que devuelve 0
cuando esperabas espacio.

**Lo que no arregla:** las páginas huérfanas por debajo de `n_pages` (§6.3). El
recorte solo se lleva la cola.

**En un ciclo de retención en régimen permanente devuelve prácticamente cero, y
eso es lo normal, no un síntoma.** Medido sobre la carga de referencia — crudo
de 6 horas podado cada hora, agregados con el perfil por defecto,
`tests/retention_size.rs::what_blocks_reclaim_tail_in_the_steady_state`:

| | micro | starter |
|---|---|---|
| Fichero en régimen | 964 KB | 1.904 KB |
| `reclaim_tail` | **4 KB** | **4 KB** |
| Y después de borrar **todo el crudo** | 16 KB | 16 KB |
| Y después de borrar **también los agregados** | **932 KB** | **1.872 KB** |

Borrar el log entero devuelve 16 KB; borrar además los agregados devuelve el
fichero completo. **Lo que está arriba son los agregados**, y la razón es
estructural: sobreviven al crudo y crecen de forma monótona durante 90 días, así
que sus páginas se asignan tarde —números altos— mientras las del crudo se
liberan y se vuelven a pedir por abajo sin parar. Como `reclaim_tail` solo se
lleva el **sufijo** libre, una capa de páginas vivas de agregado en lo alto lo
bloquea entero.

Consecuencia operativa: **`reclaim_tail` sirve para un cambio de plan, no para
la poda diaria.** Llamarla cada día en régimen permanente cuesta tres `fsync` y
devuelve cuatro kilobytes. Donde sí paga es cuando el pico no vuelve — un
inquilino que baja de plan, o uno cuyos agregados se acortan de 90 días a 30.

---

### 7.6 No escribir en los espacios de claves reservados — hueco vivo, sin arreglar

**`put`, `delete` y `delete_range` NO validan el `ns`.** Y las defensas de
índice no llegan aquí, por construcción: `define_index` rechaza `ns == 0x00` y
`ns >= 0x80`, así que **ningún índice puede estar declarado sobre un espacio
reservado**, y por tanto ni `refuse_undeclared` ni el rechazo
`DeleteRangeIndexed` se disparan nunca sobre ellos.

Lo que eso deja abierto:

| Llamada | Efecto |
|---|---|
| `delete_range(0x80 \| id, ..)` | **Barre las entradas de un índice entero dejando todas las filas vivas.** Sin error, sin señal |
| `delete_range(0x00, ..)` | Borra el **catálogo de índices** |
| `put(0x00, ..)` / `put(0x80 \| id, ..)` | Escribe bytes arbitrarios en el catálogo o en un índice |

Nada de esto es corrupción del árbol —las páginas siguen bien contabilizadas y
`audit_pages` seguirá diciendo `true`— pero deja el índice mintiendo o el
catálogo ilegible. El motor tolera la basura al leer (un registro de catálogo
de menos de 6 bytes se ignora; una entrada de índice mal formada da
`BadFormat` en vez de panicar), pero no la impide.

**Qué debes garantizar tú:** que tu aplicación use únicamente `ns` de `0x01` a
`0x7F`. Trátalo como parte del contrato, porque el motor no lo comprueba.

### 7.7 Dos trampas de uso que parecen fallos del motor

**Reintentar sobre un `Cursor` que devolvió `Err` es un bucle infinito.** Todo
error envenena el cursor de forma permanente — es lo que impide devolver datos
equivocados tras un fallo transitorio — así que cada `next()` posterior
devuelve el mismo error para siempre. **Lo único que lo limpia es volver a
llamar a `seek`**, aceptando perder la posición. Un bucle
`while let Err(_) = cursor.next() { /* reintentar */ }` no termina nunca.

**`mem::forget` sobre un `ReadTxn` bloquea el reciclado de páginas para
siempre.** El lector se da de baja en su `Drop`; sin él, su `txn_id` se queda
como el lector vivo más antiguo durante toda la vida del proceso, y ninguna
página liberada desde entonces se puede reciclar ni recortar. El fichero crece
sin cota. Un pánico **sí** ejecuta `Drop` con la configuración actual
(`panic = unwind`), así que solo el olvido explícito lo provoca — pero si ves
un fichero que crece y `reclaim_tail` devuelve 0, este es el segundo sitio
donde mirar, después de un lector legítimamente longevo.

---

## 8. Cifras de referencia (medidas)

Para saber si un número que estás mirando es normal:

| | |
|---|---|
| Bytes por entrada, un millón de registros, páginas de 4 KB | **34,14** (SQLite, misma carga y misma corrida: 56,06 — 1,64× más) |
| `get` puntual | **6,12 µs** |
| Recorrido completo, 300 000 entradas | **0,064 s** |
| Lecturas de `Db::open` | **4, sea cual sea el tamaño de la base** — cabecera, dos metas y la cabeza de la cadena de libres. La prueba fija `<= 4` y exige el mismo número con 500 y con 200 000 entradas |
| RSS por asa abierta y ociosa | ~2 KB — **SIN VERIFICAR aquí** (ver abajo) |
| RSS por asa tras usarse | ~10 KB — **SIN VERIFICAR aquí** (ver abajo) |
| Base recién creada | < **2 KB** (3 páginas de 512 B) |
| Sobrecoste de `Sync::Never` frente a `Commit` | 84 páginas frente a 24; 23 % más escrituras; **31× menos `fsync`** |

Si el fichero de un cliente es mucho más grande de lo que estas cifras
justifican, sospecha, en este orden: un lector de larga duración que bloquea el
reciclado (o uno olvidado con `mem::forget`, §7.7), índices mantenidos sin
declarar (§7.2), o una lista de libres perdida (§6.3).

### Dos cifras que NO están verificadas en este repositorio

Se citan de todos modos porque son las que circulan, pero **no las uses como
línea base de una alerta hasta medirlas**:

- **RSS por asa abierta** (~2 KB ociosa, ~10 KB tras usarse). No existe ninguna
  medición aislada de la RAM por base abierta: el único banco que toca RSS mide
  el **proceso entero**, con los dos motores de la comparativa corriendo uno
  después del otro, y el propio documento de diseño lo marca como «sin medir»
  por motor. Medirlo de verdad exigiría un proceso por motor.
*(Los 56,06 B/fila de SQLite figuraban aquí como no verificados. Ya no lo son:
la comparativa se reejecutó entera después del cambio a 34,14 y los dos lados
salen de la misma corrida. Ver `formato-en-disco.md`, §12.)*
