# Arquitectura de `inro` — mapa

Corto a propósito: quien lea esto debería poder retenerlo entero en la cabeza.
Para los bytes, ver `formato-en-disco.md`; para las reglas, `invariantes.md`;
para qué hacer cuando algo falla, `runbook.md`.

`inro` es un motor de clave-valor empotrado con B+tree de **copia al escribir**,
**un solo escritor** y **lectores sin bloqueos**. Cero dependencias de ejecución
(salvo las dos de criptografía, opcionales y tras *feature*), `unsafe`
prohibido en todo el *crate*, sin hilos de fondo, sin compactación, sin
mantenimiento periódico.

---

## Las capas, de abajo arriba

```
        API pública:  Db · WriteTxn · ReadTxn · Cursor · IndexDef
                             │
   tx.rs  ─────────  transacciones, commit, lectores, catálogo, auditoría
      │  │  │
      │  │  └── index.rs ──  catálogo y codificación de claves de índice
      │  └───── tree.rs ───  B+tree: descenso, división, borrado, overflow
      │                             cursor de rango
      └──────── freelist.rs ─  cola de páginas libres y su cadena en disco
                             │
   pager.rs ────────  caché de páginas ya validadas, cifra/descifra
                             │
   storage.rs ──────  medio: fichero, memoria, inyección de fallos
```

Y, cruzando todas ellas, el **formato de fichero puro** — sin `std`, sin
`sync`, sin `fs`: `header.rs`, `meta.rs`, `page.rs`, más las utilidades
`crc32.rs`, `varint.rs` y `crypto.rs`.

---

## Qué posee cada módulo

| Módulo | Es dueño de | Notas |
|---|---|---|
| `error.rs` | `Error`, `IoError`, `CorruptKind` | Todo `Copy`: ni `String` ni `Box<dyn Error>`. En IoT cuestan memoria y tamaño de binario |
| `crc32.rs` | CRC-32 IEEE a mano | Slice-by-8 (8 KB de tabla) bajo `std`; byte a byte (1 KB) sin `std`. El reparto está medido, no supuesto |
| `varint.rs` | LEB128 sin signo | La codificación más usada del motor |
| `header.rs` | `Geometry`: identidad y geometría del fichero, y su espejo | Se escribe una vez; solo la reubicación de la meta B la reescribe |
| `meta.rs` | `Meta`, `MetaSlot`, `MetaSeal`; selección de ranura | Todo el procedimiento de recuperación que existe: sin WAL, sin recorrido de cola, coste constante |
| `page.rs` | `PageRef::parse` (**la** frontera de validación), `PageBuilder`, `ValidPage` | Ver la invariante 1 |
| `crypto.rs` | `seal`/`open` de página, `wrap_key`/`unwrap_key`, `seal_meta`/`verify_meta`, `NonceStream` | Único sitio con dependencias externas, y solo tras *feature* |
| `storage.rs` | El trait `Storage` y tres implementaciones: `FileStorage`, `MemStorage`, `FaultStorage` | También el registro de rutas abiertas por este proceso |
| `pager.rs` | Caché de tamaño fijo de páginas **ya validadas**; cifrado/descifrado; `truncate` | El presupuesto es en páginas y no crece nunca: es la garantía de RAM constante |
| `freelist.rs` | La cola de páginas libres, su carga perezosa y su serialización | En memoria solo viven los grupos de los extremos |
| `tree.rs` | El B+tree crudo: `get`/`put`/`delete`/`delete_range`, overflow, `Cursor` | No sabe nada de índices ni de espacios de claves con significado |
| `index.rs` | `IndexDef`, codificación del registro de catálogo y de las claves de índice | Puras funciones sin estado; el cableado vive en `tx.rs` |
| `tx.rs` | `Db`, `WriteTxn`, `ReadTxn`, `Options`, `Sync`, `audit_pages`, `reclaim_tail` | La política entera: qué se sincroniza, qué se recicla, quién puede escribir |

**Superficie pública real**: `Db`, `WriteTxn`, `ReadTxn`, `Cursor`, `IndexDef`,
`Storage`, `Error`/`CorruptKind`/`IoError`, `MIN_PAGE_SIZE`/`MAX_PAGE_SIZE`, y
—solo bajo la *feature* `encryption`— `Encryption`/`Algorithm`/`NonceStream` y
`seal_page`/`open_page` para quien integre su propio almacenamiento sin `std`.
`tree`, `tx`, `pager` y `freelist` son `pub(crate)` **por corrección, no por
estética**: con `WriteTxn::write_page` y `set_root` públicos, cualquiera podía
construir una página a mano y apuntar la raíz a ella sin que ningún índice se
enterara.

### Espacios de claves

Toda clave que ve el árbol es `[ns] ++ clave_del_usuario`: un byte de espacio
por delante. Hay un único árbol para todo.

| `ns` | Uso |
|---|---|
| `0x00` | Catálogo de índices. Clave = `[id]`, valor = registro de `IndexDef` |
| `0x01`..`0x7F` | Datos del usuario |
| `0x80 \| id` | Entradas del índice `id` |

---

## `get`, de punta a punta

```
Db::begin_read()
  └─ copia la meta confirmada · se apunta en la tabla de lectores por txn_id
ReadTxn::get(ns, clave)
  └─ scoped(ns, clave) = [ns] ++ clave
     tree::get(src, meta.root, clave_completa)
       └─ descend(...)                        ← acotado por MAX_DEPTH (128)
            └─ por cada nivel: PageSource::read_page(n)
                 └─ Pager::read(n)
                      ├─ acierto de caché → ValidPage clonada (no revalida)
                      └─ fallo → storage.read_at → crypto::open (si cifra)
                                → ValidPage::parse (CRC + estructura)
                                → entra en la caché
            └─ interna: search_key sobre los sufijos → hijo · hoja: se devuelve
       └─ search_key en la hoja que descend ya validó (no se relee)
            ├─ LeafValue::Inline(v)          → copia
            └─ LeafValue::Overflow{len,first}→ read_overflow: recorre la cadena,
                                                acotada por len Y por las páginas
                                                que el fichero tiene de verdad
```

La hoja no se vuelve a leer ni a parsear después del descenso: `descend`
devuelve la página ya validada. Y la caché guarda páginas **validadas**, no
bytes, así que un acierto no vuelve a pagar el CRC de la página entera.

Medido: `get` puntual **6,12 µs**; recorrido completo de 300 000 entradas
**0,064 s**.

## `put`, de punta a punta

```
Db::begin_write()
  ├─ try_lock del candado de escritor  → WriterBusy / WriterPoisoned si no
  ├─ meta = copia de la confirmada, txn_id + 1
  └─ meta.n_pages = max(meta.n_pages, suelo del fichero real)
WriteTxn::put(ns, clave, valor)
  ├─ indexes_for(ns) — índices REGISTRADOS en este proceso
  ├─ refuse_undeclared: lee el CATÁLOGO en disco (una vez por apertura, perezoso)
  │    └─ si el catálogo declara un índice sobre ns que este proceso no registró
  │       → Err(IndexNotDeclared).  Ver la invariante 9
  ├─ sin índices → put_raw
  └─ con índices: PLANIFICAR (solo lecturas: tamaños, unicidad, entradas viejas
       y nuevas) y solo después APLICAR (borrados de índice, altas de índice,
       y por último el dato). Nada muta hasta que todo ha validado
tree::put(tx, root, clave_completa, valor)
  ├─ clave > page_size_lógico/4 → Err(KeyTooLarge), antes de tocar nada
  ├─ valor > page_size_lógico/4 → write_overflow: cadena de páginas nuevas
  └─ insert_rec(...)                              ← acotado por MAX_DEPTH
       └─ desciende; en la hoja reconstruye la lista de entradas y llama a emit
            └─ PageBuilder::build (prefijo común, slots, celdas desde el final)
               tx.alloc()      ← own_free · lista de libres · extender fichero
               tx.write_page() ← sella con un nonce nuevo si la base cifra
               tx.free(vieja)  ← copia al escribir: la página vieja se libera
       └─ si la hoja se parte, el padre se reconstruye igual, y así hasta la raíz
```

Nada de esto ha tocado el disco de forma visible: las páginas nuevas están
escritas, pero **ninguna meta las referencia todavía**.

## `commit`, de punta a punta

El orden es lo único que hace atómico un commit. De arriba abajo:

```
WriteTxn::commit()
 1. si el fichero pasó de 4 KB → relocate_meta_b (a lo sumo una vez en la vida):
      copia de la meta CONFIRMADA en la posición nueva · sync
      espejo de la cabecera · sync
      cabecera principal · sync
      libera la página vieja de la meta B
 2. own_free → lista de libres persistente, etiquetadas con este txn_id
 3. si el punto durable se ha quedado a más de 16 transacciones → UN fsync
 4. Freelist::flush: absorbe el tramo pendiente y la cadena del flush anterior,
    fusiona los grupos en ≤2, saca contenedores de la propia lista antes que
    extender el fichero, y escribe la cadena de la COLA hacia la CABEZA
 5. meta.freelist_head/tail y meta.n_pages ← lo que dejó flush
 6. ── SYNC DE PÁGINAS ──   (maybe_sync, según la política)
 7. escribe la meta en la ranura INACTIVA (la que no está en uso), sellada
 8. ── SYNC DE META ──      (maybe_sync)
 9. publica (meta, ranura) como la confirmada
```

Los pasos 4→6→7→8 son **la** secuencia: páginas, sincronizar, ranura inactiva,
sincronizar. Escribir la meta antes de que sus páginas estén en el medio es
exactamente lo que un corte convierte en una base que monta un árbol con
agujeros.

Si la transacción se descarta sin `commit`, su `Drop` restaura la lista de
libres tal como estaba: ninguna página liberada por una transacción muerta
queda marcada libre, y ninguna reciclada se pierde. Lo que **no** deshace son
las páginas ya escritas en el medio — nadie las referencia, y la reconciliación
de la próxima apertura las recupera.

Medido: abrir cuesta **4 lecturas del medio, sea cual sea el tamaño de la
base** — cabecera, las dos metas y, si hay cadena de libres, su cabeza (la
prueba fija `<= 4` y compara 500 contra 200 000 entradas exigiendo el mismo
número). Una base recién creada ocupa menos de 2 KB.

Se citan además unos 2 KB de RSS por asa abierta y ociosa y unos 10 KB tras
usarse. **Sin verificar en este repositorio**: la RAM por base abierta no tiene
ninguna medición aislada aquí, y el único banco que toca RSS mide el proceso
entero, no un asa (ver §17.1 del documento de diseño, que lo dice con esas
palabras). Trátalos como órdenes de magnitud, no como cifras medidas.

---

## Los tres estados que hay que no confundir

Casi todos los defectos caros de este motor han salido de mezclar dos de estos:

| Estado | Qué es | Dónde vive |
|---|---|---|
| **En vuelo** | Lo que la transacción de escritura abierta ha construido | `WriteTxn::meta`, en memoria |
| **Confirmado** | La última meta **escrita** en el fichero | `Db::committed` — fiel byte a byte a lo que hay en disco |
| **Durable** | El último `txn_id` cuya meta se ha **demostrado** en disco con un `fsync` que devolvió `Ok` | `Db::durable` |

Bajo `Sync::Commit` el confirmado y el durable van al día. Bajo
`Sync::Interval`/`Never` **no**, y esa diferencia es la que gobierna el
reciclado de páginas: el suelo de reutilización es el **durable**, porque el
durable es la meta que montaría tras un corte. Ver la invariante 4, que es la
que costó 82 claves confirmadas en una prueba medida.
