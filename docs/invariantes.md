# Invariantes de `inro` — referencia

Estas son las reglas que el motor mantiene. **Casi ninguna es una elección de
estilo: la mayoría se aprendió porque algo salió mal.** Cada una lleva qué se
rompe si se viola, qué la hace cumplir en el código, y qué prueba la atrapa.

Quien vaya a cambiar este motor debería leer esto antes que el código. Quien lo
esté depurando a las tres de la mañana, `runbook.md`.

Verificado contra `src/` en el formato 3.

---

## 1. `PageRef::parse` es la única frontera de validación de una página

**La regla.** Toda página que entra al sistema pasa por `PageRef::parse` una
vez, que comprueba el CRC32 y **toda** la estructura: tipo conocido,
`free_start` coherente con `n_slots` y `prefix_len`, `cell_start` dentro de la
página y por encima de los slots, cada slot apuntando al área de celdas, cada
celda decodificando entera dentro de la página, los sufijos en orden
**estrictamente ascendente** y las celdas sin solaparse. A partir de ahí los
accesores (`cell`, `suffix`, `leaf_value`, `child`) no vuelven a validar y usan
`.expect("validado en parse")`.

**Qué se rompe.** Cualquier página que llegue a un accesor sin haber pasado por
`parse` convierte esos `expect` de triviales en pánicos en producción, y el
`slice` fuera de rango de una celda mal formada aborta el proceso desde
`Db::get` — el camino de solo lectura.

**Qué lo hace cumplir.**
- `Pager::read` es el único productor de páginas y llama a `ValidPage::parse`
  **antes de cachear**. Una página corrupta ni se cachea ni se sirve.
- `ValidPage` guarda juntos los bytes (`Arc<[u8]>`, inmutable por
  construcción — el *crate* no usa `Arc::get_mut` ni `make_mut` en ninguna
  parte) y la disposición que `parse` produjo, así que el par no se puede
  desparejar. `PageRef::from_validated`, que los recompone, es **privado al
  módulo**: su único llamador posible es `ValidPage::page`.
- `PageRef::value` (valor en línea sin comprobar si la celda es de overflow) es
  `#[cfg(test)]` **y privado**, no solo documentado: sobre una celda de
  overflow tomaría un *slice* de `u64::MAX` bytes y entraría en pánico.

**Lo que `parse` NO modela**, y por tanto necesita su propia frontera:
- El `count` y las entradas de una página de lista de libres →
  `freelist::decode_freelist_page` + `PageDomain`.
- La `len` de una celda de overflow → `tree::read_overflow`.
- Los campos de una meta → `Db::check_meta_against_file`.

**Pruebas.** `rejects_a_page_with_a_bad_checksum`,
`rejects_an_unknown_page_type`, `rejects_a_slot_pointing_outside_the_page`,
`get_on_a_page_with_permuted_slots_returns_corrupt_not_a_wrong_answer`,
`get_on_a_page_with_overlapping_cells_returns_corrupt`,
`put_on_a_page_with_permuted_slots_returns_corrupt_instead_of_panicking`,
`a_corrupt_page_is_rejected_and_never_cached`.

---

## 2. Una entrada corrupta produce `Err`. Nunca un pánico, nunca un cuelgue, nunca una respuesta equivocada

**La regla.** Los tres desenlaces prohibidos son igual de inaceptables, y el
orden en que se ordenan por gravedad no es el que parece: **una respuesta
equivocada silenciosa es peor que un `Err`, y un pánico es peor todavía**,
porque además aborta el proceso de quien nos integra.

**Qué se rompe.** Casos reales que este motor ha tenido:
- Una `len` de overflow de 64 MiB declarada en una celda con CRC válido hacía
  136 403 lecturas sobre un fichero de **seis** páginas (628 ms); con
  `u64::MAX`, el `Vec` de salida crecía hasta agotar la memoria y el proceso
  moría con SIGABRT — desde `Db::get`.
- Un `count` de lista de libres sin acotar indexaba hasta 262 140 bytes más
  allá de la página.
- Un `n_pages` manipulado en **un solo byte** hacía que `audit_pages` reservara
  `vec![false; u32::MAX]`: 4,29 GB de golpe para auditar un fichero de 4 KB.
- Una cadena de nodos internos encadenados por `extra`, cada uno una página
  perfectamente válida con su CRC correcto, desbordaba la pila de
  `audit_walk_tree` y abortaba el proceso con 10 000 páginas.

**Qué lo hace cumplir.** `Error` es un enum `Copy` sin asignación; toda función
que toque datos de disco devuelve `Result`. Ni un `unwrap` sobre datos
externos, `checked_*` en toda aritmética que mezcle un número de disco
(`checked_add` en `alloc`, `checked_sub` en `index::primary_of`,
`saturating_sub` en `pages_in_use`), y `Pager::file_pages` **satura** en
`u32::MAX` en vez de truncar — con `as u32` a secas, un fichero de 3 TB con
páginas de 512 B se presentaba como 1,7×10⁹ páginas, un número *pequeño*, y por
tanto una frontera que dejaba pasar justo lo que tenía que rechazar.

**Consecuencia de diseño, no negociable:** `ReadTxn::scan` devuelve `Result`
aunque el *brief* pedía un `Cursor` a secas con un `.expect("el descenso
inicial no falla en un árbol válido")`. Ese `expect` convertiría cualquier
corrupción del descenso en un pánico de la API pública.

**Pruebas.** `read_overflow_rejects_a_cycle_instead_of_returning_wrong_data`,
`rejects_an_oversized_count_instead_of_panicking`,
`a_key_alone_too_big_for_a_page_returns_an_error_instead_of_panicking`,
`scan_index_reports_bad_format_instead_of_panicking_on_a_garbage_entry`,
`a_transient_read_error_poisons_the_cursor_instead_of_returning_wrong_data`,
`a_freelist_count_larger_than_the_file_does_not_underflow_pages_in_use`,
`audit_pages_rejects_a_chain_of_internal_nodes_deeper_than_a_tree_can_be`.

---

## 3. Todo recorrido que siga un número de página leído del disco va acotado

**La regla.** No hay ni una excepción. Y hay que acotar **dos cosas distintas**:
el **trabajo total** y la **profundidad de la pila**. Confundirlas cuesta el
proceso entero: «acotado por `n_pages`» son hasta 2^32 marcos de pila.

| Recorrido | Cota | Error |
|---|---|---|
| `descend`, `insert_rec`, `delete_rec`, `free_subtree`, `delete_range_rec`, `Cursor::seek_from`, `Cursor::advance_to_next_leaf`, `audit_walk_tree` | `MAX_DEPTH` = 128 | `TreeLoop` |
| `Cursor::next` (trabajo de un solo avance) | `MAX_NEXT_WORK` = 8·128 = 1024 | `TreeLoop` |
| `free_subtree` / `delete_range_rec` (trabajo total) | `RangeBudget`, acotado por `n_pages` | `TreeLoop` |
| `read_overflow` / `free_overflow` | `min(ceil(len/capacidad), páginas del fichero)` | `OverflowLoop` |
| Cadena de lista de libres (`fill_from_disk`, `absorb`, `walk_chain`) | páginas del fichero | `FreelistLoop` |
| Reconciliación de cola al abrir | `MAX_RECOVERABLE_TAIL` = 2^20 páginas | `MetaMismatch` |

**Por qué `MAX_DEPTH` es 128 y no 32.** El argumento «cada nodo interno rama en
al menos dos, luego con páginas de 32 bits la profundidad no pasa de 32» asume
un árbol equilibrado en altura, y `delete_rec` rompe esa suposición a
propósito: colapsa nodos internos de un solo hijo pero **no funde páginas
infrautilizadas con sus hermanas**. Medido, el *churn* sostenido da una
profundidad de ≈ `1,65·log₂(n) − 4,5`; extrapolado a 2^32 páginas da ≈ 50, con
un margen de solo ~1,3× sobre 64. 128 duplica el margen real medido y solo
cuesta que detectar un ciclo genuino tarde 128 lecturas en vez de 64.

**Por qué una cota de profundidad no basta sola.** Un DAG corrupto **acíclico**
donde cada nodo apunta dos veces al mismo hijo respeta `MAX_DEPTH` en cada
camino individual y tiene 2^k caminos: la cota de profundidad no se dispara
nunca y el recorrido explota exponencialmente. De ahí `RangeBudget` y
`MAX_NEXT_WORK`.

**Por qué la cota de saltos no basta para overflow.** Con capacidad uniforme
por página, cada vuelta de un ciclo aporta los mismos bytes que una página
nueva, así que un ciclo alcanza `len` bytes en exactamente el mismo número de
saltos que una cadena legítima. Lo que de verdad lo cierra es comprobar,
**después** del bucle, que la cadena llegó a su propio final (`extra == 0`).

**Pruebas.** Toda la familia `*_returns_an_error_instead_of_looping_forever_on_a_cycle`
(`descend`, `insert_rec`, `delete_rec`, `free_subtree`, `delete_range`,
`seek_from`, `advance_to_next_leaf`),
`*_rejects_a_corrupt_dag_quickly_instead_of_exploring_exponentially_many_paths`,
`a_file_far_longer_than_its_meta_declares_is_rejected_instead_of_reconciled_page_by_page`.

---

## 4. El reciclado de páginas y el recorte se apoyan en la meta DURABLE, nunca en la meramente escrita

**La regla.** Una página liberada en la transacción N sigue viva para cualquier
lector cuyo *snapshot* sea anterior a N. Entre esos lectores hay uno implícito
y es el más importante: **la meta que montaría tras un corte de corriente**. Y
esa no es la última meta *escrita*, sino la última *sincronizada*.

**Qué se rompe.** Bajo `Sync::Interval`/`Never` una escritura de meta puede
pasar mucho tiempo sin sincronizarse, así que confirmada y durable divergen.
Con la confirmada como suelo, `alloc` repartía páginas que el árbol durable
seguía referenciando, el escritor las sobrescribía, y tras el corte la meta
superviviente describía **un árbol con agujeros**: claves confirmadas y
reconocidas al llamante decenas de commits antes devueltas como `None`, y
claves de commits muy posteriores devueltas como si fueran suyas.

**Medido, bajo `Sync::Interval`:** el *snapshot* superviviente (transacción 83)
devolvía `Ok(None)` para **las 82 claves que había confirmado**, y entregaba
**41 claves escritas unas 120 transacciones DESPUÉS**. Sin un solo `Err`. No es
pérdida de datos: es **respuesta equivocada en las dos direcciones**, que es
peor.

**Y por qué nadie lo vio antes**, que es la lección que merece quedarse: los
dos ingredientes para atraparlo ya vivían en el repositorio, **nunca juntos**.
Una prueba usaba el modelo de corte correcto pero no releía ninguna clave; otra
sí releía, pero bajo un modelo de fallo donde las escrituras paran de forma
monótona y el defecto es imposible.

Y en la lista de libres, la misma raíz: `Freelist::flush` recicla como
contenedor la cadena física que el `flush` anterior escribió, y con la meta
escrita como suelo podía reasignar la cadena que la meta durable todavía
declaraba suya. Un caso medido dejó **27 de 56 páginas (48 % del fichero)**
huérfanas para siempre tras degradar la apertura.

**Qué lo hace cumplir.** `Db::durable` (un `AtomicU64`) solo lo mueve
`Db::sync_upto`, **después** de que `pager.sync()` haya devuelto `Ok` — nunca
antes, nunca si falla. `Db::reuse_floor()` toma
`min(committed, durable, lector_real_más_antiguo)` y es el suelo que reciben
`Freelist::pop`, `Freelist::flush` y `Freelist::free_suffix_start`.

**El `fsync` que ningún modo relajado evita.** Un punto durable retrasado
retendría páginas libres para siempre bajo `Sync::Never`, y el fichero crecería
sin cota justo donde el disco es más escaso. Por eso el motor no deja que el
durable se retrase más de `MAX_DURABLE_LAG` = **16** transacciones: pasado ese
punto paga **un** `fsync` y desbloquea de golpe todo lo liberado hasta ahí. Se
comprueba en `WriteTxn::recycle` **y** en `commit` — solo en `recycle` no
bastaba: `Freelist::flush` pide contenedores con un `alloc` propio que se salta
el presupuesto, y medido, 2 000 commits sobre 200 claves pasaban de 24 a **2 088
páginas** y de 8 000 a 65 000 escrituras físicas. Con la comprobación en los dos
sitios: **84 páginas frente a las 24 de `Sync::Commit`** — un margen constante,
no proporcional al trabajo — un 23 % más de escrituras y **31 veces menos
`fsync`**.

**Pruebas.**
`a_power_cut_that_keeps_data_pages_but_loses_the_last_metas_leaves_a_whole_snapshot`,
`a_power_cut_that_loses_an_arbitrary_subset_of_the_unsynced_writes_leaves_a_whole_snapshot`,
`relaxed_sync_loses_commits_but_never_corrupts`,
`relaxed_sync_costs_bounded_space_and_far_fewer_fsyncs` (todas en
`tests/faults.rs`), `a_page_freed_by_txn_n_is_not_reusable_while_an_older_reader_lives`.

---

## 5. El orden del commit: páginas, sincronizar, ranura de meta INACTIVA, sincronizar

**La regla.** En ese orden y sin excepciones. La meta solo apunta a páginas que
ya están en el medio, y se escribe **siempre en la ranura que no está en uso**,
para que la que sí lo está siga intacta hasta el final.

**Qué se rompe.** Escribir la meta antes de que sus páginas estén en el medio
deja, tras un corte, una meta que monta un árbol cuyas páginas nunca llegaron a
existir. Escribir sobre la ranura activa deja el fichero sin ninguna meta
completa durante la escritura.

**El límite honesto que ningún modo relajado supera.** Con
`Sync::Interval`/`Never`, entre las páginas de un commit y su meta puede no
haber ningún `fsync`, así que nada impide que el sistema operativo escriba la
meta **antes** que las páginas que referencia. Si el corte cae ahí, la base
monta por una meta cuyas páginas nunca llegaron. **Eso el motor no lo puede
evitar**: ordenar las dos cosas es precisamente lo que hace el primer `fsync`
de `Sync::Commit`. Dicho al derecho: *el modo relajado no promete que el último
commit sobreviva entero; promete que lo que sobreviva no lo habrá estropeado
una transacción posterior.*

**El recorte añade dos pasos, y no son intercambiables** (`reclaim_tail`):
la meta con el `n_pages` reducido se escribe y se sincroniza, luego la **otra**
ranura recibe esa misma meta y se sincroniza, **y solo entonces** se recorta el
fichero. Recortar antes deja una meta superviviente que declara páginas que ya
no existen — su raíz, sus nodos internos y su cadena de libres pueden apuntar
más allá del final, y de ahí no hay recuperación. En el orden correcto, un
corte deja lo contrario: `n_pages` pequeño sobre un fichero todavía grande, que
es exactamente lo que `Db::open` ya sabe reconciliar. Escribir las **dos**
ranuras es lo que impide que la meta anterior —con el `n_pages` grande— se
elija por ser la única legible y falle al leer su cadena más allá del final
(`UnexpectedEof` **es fatal**, no degrada con gracia como un `Corrupt`).

Invariante resultante, simple de comprobar sobre cualquier fichero: **ninguna
meta legible referencia jamás una página más allá del final.**

**Pruebas.** `aborting_at_any_write_of_a_transaction_leaves_the_previous_commit_intact`
y `tearing_any_write_of_a_transaction_at_two_depths_never_leaks_partial_effects`
(barren *todas* las escrituras de una transacción, una por una),
`a_torn_write_of_the_meta_page_falls_back_to_the_other_slot`,
`aborting_at_any_operation_of_a_reclaim_leaves_the_database_readable`,
`a_power_cut_that_keeps_only_the_truncate_leaves_a_whole_snapshot`,
`assert_no_meta_points_past_the_end`.

---

## 6. Unicidad del nonce: prefijo aleatorio por apertura, contador dentro de ella

**La regla.**

```
nonce = prefijo aleatorio (16 B, sorteado UNA vez por apertura)
        || contador (8 B, monótono dentro de esa apertura)
```

El contador **no rebobina jamás**: ni al abortar una transacción, ni cuando el
prefijo se renueva por agotamiento del campo de contador de AES.

**Qué se rompe.** Reutilizar un nonce bajo la misma clave es pérdida total de
la confidencialidad, y con Poly1305 es **peor**: dos mensajes distintos bajo el
mismo nonce dejan recuperar la clave de un solo uso y falsificar tags a
voluntad.

**Por qué se cambió el diseño anterior** (`página || contador`, con el techo del
contador persistido en la meta): al vivir el contador y la clave envuelta los
dos en la meta, **retrocedían juntos**. Restaurar una copia de seguridad
reutilizaba todos los contadores bajo la misma clave de datos — medido sobre el
código anterior, **296 de 296 nonces compartidos** entre las dos líneas
temporales, 164 con texto plano distinto y hasta un **96,52 % de bytes cero en
el XOR** de los textos cifrados: recuperación total del texto plano a partir de
un procedimiento de operación corriente, **sin ningún atacante de por medio**.

**Por qué NO se sortea entropía en cada escritura.** Dos razones, las dos
verificadas: `read_random` abre `/dev/urandom` en **cada** llamada, así que un
nonce aleatorio por página serían un `open` y un `read` por página en un motor
cuya premisa entera es el mínimo consumo de CPU; y bajo `no_std` no hay ninguna
fuente de entropía portable. Un sorteo por **apertura** cuesta una lectura por
sesión, no por escritura.

**Por qué no se deriva de `txn_id`** (fue un hallazgo BLOQUEANTE): `txn_id` es
el mismo para toda la transacción, y `alloc` recicla `own_free`, así que la
**misma** página se reescribe muchas veces dentro de una sola transacción —
medido, **121 veces sobre 200 `put`**.

**Qué lo hace cumplir.**
- `NonceStream` no se puede construir sin 16 bytes de prefijo. No hay ningún
  camino que selle con un prefijo por defecto, a cero o sin inicializar.
- Vive en `WriterState` (estado de la **base**), no en `WriteTxn`, precisamente
  para sobrevivir a un aborto sin rebobinar. `WriteTxn::Drop` restaura la lista
  de libres y **nunca** toca el flujo de nonces.
- `seal` toma `&mut NonceStream`, no un nonce ni un contador sueltos.
- `WriteTxn::write_page` comprueba **antes de sellar** que el número de
  escritura no se haya usado ya en esta transacción (`Error::NonceReuse`).
  Matemáticamente inalcanzable si el resto es correcto: convierte una
  suposición no comprobada en algo que el motor verifica en cada escritura.
- `Freelist::flush` recibe el **mismo** flujo, no uno propio: dos flujos con el
  mismo prefijo repartirían exactamente los mismos nonces.
- Con AES-256-GCM-SIV el campo de contador es de 32 bits: al desbordar, se
  sortea un prefijo nuevo (bajo `std`) o se falla con `NonceExhausted` (sin
  `std`, donde no hay de dónde sortear). Nunca un nonce repetido en silencio.

**Pruebas.** `the_nonce_stream_is_injective_within_an_open`,
`no_nonce_is_ever_reused_across_many_small_transactions`,
`a_rollback_then_a_commit_reuses_no_nonce`,
`a_torn_commit_meta_write_reuses_no_nonce`,
`a_restored_backup_shares_no_nonce_with_the_timeline_it_was_copied_from`,
`two_opens_of_the_same_file_draw_different_prefixes`,
`sync_never_or_long_interval_survives_simulated_power_loss_without_reusing_a_nonce`,
`the_nonce_counter_restarts_at_zero_on_every_open`,
`exhausting_the_aes_counter_field_renews_the_prefix_instead_of_repeating`.

---

## 7. Regla de reutilización de la lista de libres, y las dos bolsas de páginas libres

**La regla.** Un grupo de páginas libres lleva el `txn_id` **más alto** de las
transacciones que lo liberaron, y **se reutiliza entero o ninguna de sus
páginas**. Una página no se sirve mientras el suelo de reutilización sea
anterior a ese `txn_id`.

Y hay **dos bolsas distintas**, no una:

| Bolsa | Qué contiene | Cuándo se puede reutilizar |
|---|---|---|
| `own_free` | Páginas que **esta misma** transacción asignó y ya liberó | De inmediato. Nunca formaron parte del árbol confirmado, así que ninguna meta las referencia |
| Lista de libres persistente | Páginas que venían de antes de esta transacción | Solo cuando el suelo (§4) lo permita |

**Qué se rompe si se confunden.** Sin `own_free`, el camino de inserción por
copia al escribir —que libera el camino raíz→hoja en **cada** `put`— haría
crecer el fichero unos 16 MB por lote de mil registros con páginas de 4 KB, en
un motor cuyo objetivo es el mínimo consumo de disco. Al revés, tratar como
propia una página del árbol confirmado la sobrescribe mientras la meta anterior
la sigue señalando.

**Y todo lo que quede en `own_free` al llegar al commit hay que volcarlo** a la
lista persistente antes de serializarla: si no, esas páginas no quedan
referenciadas por nada — ni por el árbol nuevo, ni por la lista de libres, ni
por la meta vieja. Fuga silenciosa.

**Qué lo hace cumplir.** `self_allocated` (un `BTreeSet`, no un escaneo lineal:
un lote asigna y libera miles de páginas y una comprobación O(n) por página
haría la carga cuadrática) decide a qué bolsa va cada `free`.

**Pruebas.** `a_page_freed_while_a_reader_is_live_is_not_recycled`,
`freeing_a_committed_page_is_not_reused_within_the_same_uncommitted_transaction`,
`no_page_is_lost_when_a_reused_container_goes_unused`,
`repeated_updates_to_one_key_do_not_leak_pages_within_one_transaction` y su
gemela `_once_committed`, y la propiedad
`pages_are_never_lost_or_double_allocated` (`tests/props.rs`) contra un oráculo
`BTreeMap`.

---

## 8. Una meta que falla su tag PARA; una meta incompleta CAE a la otra

**La regla.** Los dos fallos merecen desenlaces opuestos, y el reparto no es
estilo: es lo que separa «sobrevivir a un corte de corriente» de «tragarse un
ataque en silencio».

| Estado de la ranura | Diagnóstico | Qué hace el motor |
|---|---|---|
| CRC32 no cuadra | **Incompleta**: mitad de una meta y mitad de otra. Eso es lo que deja un corte a media escritura | Se descarta en silencio y se monta por la otra ranura |
| CRC32 cuadra, tag no valida | **Entera**: nadie la partió. Alguien calculó ese CRC sobre un contenido que la clave no avala | **Se para.** `Corrupt { kind: MetaAuth }`. No se prueba con la otra |

**Qué se rompe si se cae a la otra ranura ante un fallo de tag.** Se convierte
un ataque **detectado** en una vuelta atrás **silenciosa**: el llamante recibe
`Ok` y una base un commit más vieja, sin ninguna señal de que alguien le tocó
el fichero.

**Y no se pierde nada legítimo por ello:** lo que se comprueba es el envoltorio
de la clave (idéntico en las dos ranuras de cualquier fichero sano — se sella
una vez en `Db::create` y se copia) y el tag. En un fichero sano, si la ranura
nueva no pasa, la vieja tampoco iba a pasar.

**El precio, explícito:** una ranura desgarrada cuyo CRC cuadre **por
casualidad** (2^-32) deja la base sin abrir en vez de caer a la otra. Es el
mismo riesgo que el motor ya acepta en cada página del árbol, que no tiene
segunda copia ninguna.

**Pruebas.** `load_falls_back_when_the_newest_slot_is_torn`,
`a_torn_write_of_the_meta_page_falls_back_to_the_other_slot`,
`a_meta_forged_at_every_field_is_rejected_on_open`,
`a_meta_from_another_database_is_rejected`,
`swapping_the_two_meta_slots_is_rejected`,
`a_forged_page_size_is_discarded_by_the_geometry_check_not_by_the_tag`,
`without_encryption_there_is_no_key_and_therefore_no_authentication`.

---

## 9. El CATÁLOGO en disco, no la lista de índices registrados, decide si una escritura puede seguir

**La regla.** `Db::indexes` arranca **vacío en cada apertura** y solo lo puebla
`define_index`, que exige un `extract` —un puntero a función, código del
llamante— que el fichero no puede guardar. Por tanto, «mi lista está vacía»
**no** significa «esta base no tiene índices». Antes de toda escritura, el
motor lee el catálogo del fichero y **se niega** si declara sobre ese espacio
de claves algún índice que esta apertura no haya registrado.

**Qué se rompe.** Nada, en el momento. `put` guardaba la fila sin entrada de
índice, `delete` borraba la fila y dejaba la suya huérfana, y `delete_range`
huerfanaba el rango entero de una vez. La divergencia aparecía **en otra
apertura**, la que sí declara sus índices, como una respuesta **equivocada** de
`scan_index` en las dos direcciones: claves primarias de filas ya borradas, y
ausencia de filas ya insertadas. Y `audit_pages` decía `true` todo el rato, con
razón: la propiedad de las páginas estaba intacta; **lo que estaba muerto era
el significado de las entradas.**

El caso donde más duele es el que este motor prioriza: **un podador de
retención no tiene ningún motivo para declarar índices** —no tiene el
extractor— y es justo el que borra a diario. Medido sobre la carga de retención
de 14 días: con el índice registrado, la base se estabiliza en **328 páginas**
del día 30 al 59; sin registrarlo, crece **sin cota** (+4,43 páginas/día, 1 557
al día 299) con **30 000 entradas de índice para 1 400 filas vivas — 95,3 % de
basura**.

**Qué lo hace cumplir.** `Db::catalog_indexes` guarda los pares `(id, ns)` que
el catálogo declara, leídos **del fichero**, como mucho una vez por apertura.
`WriteTxn::refuse_undeclared` compara **por id, no por espacio de claves**: dos
índices sobre el mismo `ns` y un llamante que solo registra uno mantendría el
suyo y dejaría el otro divergiendo, con la lista no vacía y por tanto sin
sospecha ninguna.

**Perezoso a propósito, no por comodidad.** Leerlo en `Db::open` costaría un
descenso hasta la hoja más a la izquierda, y ese descenso crece con la
profundidad del árbol — es decir, con el tamaño de la base — que es exactamente
lo que el criterio de coste de apertura prohíbe. Quien solo lee no lo paga
nunca; quien escribe lo paga una vez por apertura.

**Pruebas.** `an_opener_that_did_not_declare_the_index_cannot_write_that_namespace`,
`a_row_written_without_declaring_the_index_never_lands_unindexed`,
`declaring_only_one_of_two_indexes_on_a_namespace_is_refused`,
`delete_range_is_refused_on_an_indexed_namespace`,
`a_namespace_the_catalog_does_not_index_still_writes_after_an_undeclared_reopen`,
`opening_a_database_never_reads_the_catalog`,
`the_catalog_is_read_once_per_handle_not_once_per_write`.

---

## 10. `Db::committed` es fiel byte a byte a lo que hay en el fichero

**La regla.** El campo `Db::committed` es exactamente lo que devolvería un
`Meta::load` ahora mismo. **Nunca** un estado «mejorado» en memoria.

**Qué se rompe.** `Db::open` subía `n_pages` hasta la extensión real del
fichero (las páginas recuperadas de una transacción interrumpida) y lo guardaba
aquí, mientras esas páginas vivían solo en la lista de libres **en memoria**:
una extensión seguida de un aborto dejaba en disco un `n_pages` alto con una
lista de libres que no poseía la diferencia. **Doce ciclos abrir-extender-
abortar: `n_pages` de 10 a 22, doce páginas fugadas, sin cota.**

**Qué lo hace cumplir.** La extensión recuperada vive en
`WriterState::n_pages_floor`, que es donde pertenece — es el punto de partida
de la **próxima** transacción, no algo que ya esté confirmado — y
`begin_write` toma el máximo de los dos. Solo un commit real, que vuelca la
lista de libres a la vez, llega a grabarlo.

**Pruebas.** `open_write_abort_cycles_leak_no_pages`,
`reopening_recovers_pages_leaked_by_an_interrupted_transaction`,
`an_aborted_transaction_leaves_no_trace`,
`writing_after_a_reclaim_starts_from_the_new_extent`.

---

## 11. Todo número de página que sale del disco se contrasta contra el fichero real

**La regla.** Tres puntos de entrada, tres fronteras, ninguna opcional:

| Entra por | Frontera | Rechaza |
|---|---|---|
| La meta | `Db::check_meta_against_file` | `n_pages > páginas reales`; cola por reconciliar > 2^20; `root`/`catalog_root` distinto de 0 y fuera de `(1, páginas reales)` |
| La lista de libres | `freelist::PageDomain` | `<= 1`, el destino de reubicación de la meta B, `>= páginas reales` |
| Un hijo de nodo interno | `tree::validate_child` | `<= 1`, la meta B **actual**, el destino de reubicación, `>= n_pages` |

**Qué se rompe.** Sustituir **una** entrada de lista de libres por `0` y
recalcular el CRC bastaba para que `alloc` repartiera la página 0 —la cabecera—
y el siguiente `put` la sobrescribiera con una hoja: `commit` devolvía `Ok(())`
y la base entera quedaba irrecuperable (con el espejo de cabecera perdido en la
misma escritura, porque vive en esa misma página). Con `1`, lo mismo contra la
meta A. Con **un solo byte alto cambiado** (2,67×10⁹), `Pager::write` escribía a
1,37 TB: sobre un fichero real eso no falla, crea un fichero disperso y el
commit tiene éxito; el daño aparece al reabrir, cuando la reconciliación
intenta recuperar 2,7×10⁹ páginas — del orden de 10 GB de `VecDeque` para un
fichero con 15 páginas reales. El proceso moría **en el `Db::open`**, así que
la base quedaba inservible para siempre: ninguna herramienta del motor,
`audit_pages` incluida, llegaba a ejecutarse, porque `open` es la puerta.

`freelist_head`/`freelist_tail` **no** se validan en la meta a propósito: los
valida `Freelist::load`, para que un puntero imposible salga por la degradación
con gracia (abrir y perder la lista) en vez de negarle la entrada a un fichero
cuyo árbol está sano.

**Un nodo interno no puede tener dos hijos iguales.** `validate_child` valida
cada hijo por separado, y dos hijos pueden ser cada uno perfectamente
plausibles y a la vez el **mismo** número: eso libera la misma página dos veces
dentro de una sola llamada, y tras el siguiente `alloc` hay dos dueños. De ahí
`validate_no_duplicate_children`, llamada en **las dos** ramas de
`free_subtree`.

**Pruebas.** `a_meta_that_declares_more_pages_than_the_file_has_is_rejected_at_open`,
`a_freelist_entry_of_zero_never_becomes_a_page_that_put_overwrites`,
`a_freelist_entry_past_the_end_of_the_file_never_becomes_a_write_at_that_offset`,
`free_subtree_rejects_a_child_*` (cinco variantes),
`free_subtree_rejects_duplicate_child_pointers_on_the_bulk_path` y
`_on_the_recursive_path`, `delete_range_rejects_duplicate_child_pointers`.

---

## 12. La página destino de la reubicación de la meta B no se reparte JAMÁS

**La regla.** `max(2, 4096/page_size)` se retira del espacio de numeración
desde la primera vez que una extensión de fichero podría entregarla, tanto si
la reubicación ya ocurrió como si no.

**Qué se rompe.** Sin esto, **una reubicación exitosa —sin ningún corte de
corriente— corrompe datos en vivo**: con páginas de 512 B, la página 8 es una
página de datos como cualquier otra mientras el fichero es pequeño, así que si
el árbol o la lista de libres la reciben y la referencian en el estado
confirmado, y **después** el fichero crece más allá de 4 KB, la reubicación
escribe bytes de meta encima sin saber que había algo ahí.

**Qué lo hace cumplir.** `skip_meta_b_target`, aplicada en **los dos** sitios
que extienden el fichero — el `else` de `alloc` **y** el cierre de `commit` que
serializa la lista de libres. Una página de lista de libres viva es tan real
como cualquier nodo del árbol, y nada comparte el salto entre los dos caminos
si no se repite. Y en **un tercero**: la reconciliación de `Db::open`, porque
la escritura de la reubicación extiende el fichero hasta esa página antes de
que la cabecera cambie, y un corte justo ahí la dejaba dentro del rango a
reconciliar.

**Pruebas.** `allocation_never_hands_out_the_meta_b_relocation_target`,
`freelist_serialization_never_hands_out_the_meta_b_relocation_target_either`,
`reopening_after_a_crash_during_relocation_never_recovers_the_relocation_target_into_the_freelist`,
`free_subtree_rejects_a_child_at_the_relocation_target_before_any_relocation`,
`audit_pages_stays_clean_across_a_real_relocation`.

---

## 13. La reubicación de la meta B escribe respaldo primero, principal después, y sincroniza entre medias

**La regla.** El orden es: copia de la meta **confirmada** en la posición nueva
+ `sync`; **espejo** de la cabecera + `sync`; cabecera **principal** + `sync`.
Y la copia que se escribe es la meta **confirmada**, nunca la de la transacción
en curso.

**Qué se rompe.** La cabecera se escribía una sola vez, sin respaldo. La nueva
solo difiere de la vieja en `meta_b_page` (bytes 44..48) y el CRC (60..64), así
que **cualquier corte entre el byte 45 y el 63** deja un `meta_b_page`
actualizado con un CRC que no le corresponde, y `Geometry::decode` falla con
`Checksum` **para siempre**: la base no se puede volver a abrir nunca más
aunque las dos metas y el árbol entero sigan intactos. Justo la inmunidad que
tenía la cabecera de escritura única, y que esta operación le quita al
convertirla en reescribible.

Y escribir la meta *de la transacción en curso* publicaría un commit a medio
hacer como si estuviera confirmado.

**Qué lo hace cumplir.** El espejo (§3 del formato) más la caída automática de
`Geometry::read`, y la reparación oportunista de la principal en la apertura
siguiente. Con las dos copias sincronizadas por separado, un corte a medio
escribir **cualquiera** de las dos deja a la otra —ya sincronizada, con el
contenido completo de una de las dos versiones— como fuente fiable.

**Pruebas.** `a_torn_header_rewrite_does_not_permanently_brick_the_database`
(siete prefijos de corte dentro de la región que cambia),
`the_database_survives_a_crash_during_relocation`,
`a_crash_after_the_header_write_does_not_roll_back_a_commit`,
`reopening_after_a_torn_primary_repairs_it_from_the_mirror`,
`relocation_survives_a_torn_write_at_every_cut_point_under_every_sync_policy`,
`relocation_reclaims_the_old_meta_b_page_without_leaking_it`.

---

## 14. Una transacción abortada deshace la lista de libres, y NADA más

**La regla.** `WriteTxn::Drop`, si no hubo commit, restaura la lista de libres
persistente desde la copia que `begin_write` guardó. **No** rebobina el flujo
de nonces, **no** borra páginas ya escritas en el medio, **no** toca la meta.

**Qué se rompe.** Sin la restauración, una página liberada por una transacción
que nunca confirma queda marcada libre para siempre mientras la meta confirmada
la sigue señalando como viva — dos dueños a la vez — o una página reciclada por
esa transacción se pierde para siempre, porque ni la recuperación al abrir (que
solo mira más allá de `n_pages`) ni nada más vuelve a ofrecerla. Y al revés:
rebobinar el contador de nonces devolvería a circulación nonces que una
transacción muerta ya usó para sellar páginas que **sí** llegaron al medio.

Las páginas escritas y no confirmadas no son un problema: nadie las referencia,
ningún lector puede verlas, y la reconciliación de la próxima apertura las
recupera como reutilizables de inmediato.

**Contrato del llamante, que el motor no puede imponer:** si `put` o `delete`
devuelven `Err`, **abandona la transacción** — déjala caer sin `commit` — en
vez de reintentar sobre el mismo `WriteTxn`. Los casos previsibles (clave
demasiado grande, duplicado en índice único) se comprueban **enteros antes de
mutar ninguna página**; el contrato cubre el resto: un `Corrupt` o un `Full` a
mitad de aplicar mutaciones ya planeadas.

**Pruebas.** `an_aborted_transaction_leaves_no_trace`,
`freeing_a_page_in_an_aborted_transaction_does_not_persist`,
`an_alloc_from_the_freelist_in_an_aborted_transaction_is_not_lost`,
`a_rollback_then_a_commit_reuses_no_nonce`,
`a_rejected_duplicate_leaves_neither_data_nor_index_changed`,
`an_oversized_primary_key_is_rejected_before_any_index_mutation`.

---

## 15. Ninguna clave ni ningún valor en línea pasa de un cuarto de página lógica

**La regla.** `put` rechaza una clave mayor que `page_size_lógico / 4` **antes
de tocar ninguna página**. Un valor por encima del mismo umbral no se guarda en
línea: va a una cadena de overflow.

**Qué se rompe.** Una división de nodo interno promueve un separador y reparte
el resto entre dos mitades; para que ambas conserven al menos un separador
propio hacen falta tres entradas. Sin este límite, las claves grandes degeneran
casi toda división interna en un nodo de un solo hijo: **profundidad sin
ramificar, hasta reventar `MAX_DEPTH` en un árbol perfectamente válido y dejar
sus claves ilegibles**. Medido antes del arreglo, con claves de 250 bytes:
profundidad **34 con 3 000 claves** y profundidad **65 con 95 512** — por
encima del `MAX_DEPTH` de entonces, con el árbol entero ilegible.

**Es `logical_page_size`, no `page_size`.** En una base cifrada son 40 bytes
menos. Comprobarlo contra el tamaño físico haría que el motor aceptara aquí una
clave que el constructor de páginas rechazaría después, ya con la entrada vieja
de índice borrada.

**Y la clave de un índice no único es `indexado ++ primaria ++ 2`**: las dos
mitades pueden ser individualmente legales y superar el límite juntas. Por eso
`WriteTxn::put` valida el tamaño de **cada entrada de índice** en su fase de
planificación, con el `+1` del byte de espacio de claves que `scoped` antepone.

**Pruebas.** `put_rejects_a_key_larger_than_a_quarter_page`,
`put_accepts_a_key_exactly_at_a_quarter_page`,
`keys_near_the_limit_keep_the_tree_shallow`,
`an_index_entry_one_byte_over_the_cap_is_rejected_cleanly`,
`an_oversized_concatenated_index_key_is_rejected_cleanly`,
`a_value_too_large_for_a_single_page_now_succeeds_via_overflow`.

---

## 16. La caché sirve páginas validadas, y se invalida al escribir — nunca se actualiza

**La regla.** `Pager::write` **borra** la entrada de la caché justo después de
escribir; no la actualiza. `Pager::truncate` descarta toda entrada por encima
del corte **antes** de recortar.

**Qué se rompe.** Una página reescrita puede además haber cambiado de dueño
tras pasar por la lista de libres, y servir contenido antiguo bajo el mismo
número sería corrupción silenciosa. En el recorte, si el `truncate` falla a
mitad y el llamante reintenta, o si la página vuelve a existir tras una
extensión posterior, se serviría el contenido viejo.

**Lo que esta capa NO garantiza**, y hay que saberlo: que nadie sostenga una
página que el escritor va a reescribir. Eso lo garantiza la capa de
transacciones (lista de libres + tabla de lectores), no el `Pager`. Y quien ya
sostiene una `ValidPage` sigue viéndola después de que otro la reescriba —
exactamente igual que cuando lo que sostenía eran bytes clonados.

**Ninguna meta se lee jamás por `Pager::read`.** La vista de un lector sale del
estado ya confirmado en el momento de abrir su transacción. Las metas quedan a
salvo por ese argumento distinto, y **se rompe si algún código futuro empieza a
leer una meta-página a través del `Pager`.**

**Pruebas.** `a_rewritten_page_is_not_served_stale_from_cache`,
`a_page_overwritten_with_garbage_is_not_served_from_the_validated_entry`,
`a_corrupt_page_is_rejected_and_never_cached`,
`cache_never_grows_past_its_budget`.

---

## 17. La lista de libres se serializa fusionada, reciclando su propia cadena anterior

**La regla.** Antes de escribir, `flush` absorbe todo lo que la carga perezosa
dejó en disco, recicla la cadena física que **su propio `flush` anterior**
escribió, fusiona los grupos en **como mucho dos** (los servibles y los que
no), y saca contenedores de la propia lista antes de extender el fichero.

**Qué se rompe, y cada pieza tiene su medición.**

- **Sin reciclar la cadena anterior:** cada `flush` extendía el fichero con
  páginas nuevas y nada volvía a marcar como libre la cadena del `flush`
  previo. Medido: **+1-2 páginas por commit, sin cota**; con páginas de 512 B,
  treinta `commit` de un solo `put` hacían crecer el fichero **de 4 a 59
  páginas**.
- **Sin fusionar los grupos:** cada transacción deja su propio grupo y se
  reserva al menos una página física por grupo aunque tenga una sola entrada.
  Con la reutilización bloqueada por el retraso del punto durable, eso crece de
  forma **cuadrática**. Medido con 2 000 commits sobre 200 claves y
  `Sync::Never`: **4 308 páginas** con un retraso de 64 transacciones, 108 con
  un retraso de 8, y **216 016 páginas —un fichero de 110 MB para 24 páginas de
  datos reales—** con un retraso de 128.
- **Sin sacar contenedores de la propia lista:** cada contenedor que un commit
  necesita es una página física nueva para siempre, y el reciclado convierte el
  contenedor de hoy en una entrada libre más para el commit de mañana, que a su
  vez necesita otro contenedor. Medido: **300 páginas físicas tras 30 commits
  de un solo `put`; 374 418 tras 500.**

Fusionar es seguro porque cada grupo fusionado se etiqueta con el `max_txn`
**más alto** de los que absorbe: subir la etiqueta solo puede **retrasar** la
reutilización de una página, jamás adelantarla.

**Y el contenido lógico nunca se duplica**: al reciclar la cadena anterior solo
se recorren sus **números de página** vía `next`; las entradas que listaba
siguen viviendo en memoria, y reincorporarlas sería un doble reparto
silencioso.

**Pruebas.** `freelist_growth_stays_bounded_with_a_single_repeated_key`,
`freelist_growth_stays_bounded_with_many_distinct_keys`,
`no_page_is_lost_when_a_reused_container_goes_unused`,
`pages_are_never_lost_or_double_allocated` (`tests/props.rs`),
`survives_a_flush_and_load_roundtrip`.

---

## 18. Antes de recortar el fichero, la lista de libres se purga de todo lo que dejará de existir

**La regla.** `truncate_at(cut)` saca de la lista **toda** página `>= cut`, de
los grupos servibles **y de los que no** (ahí viven los contenedores recién
reciclados), y deja el resto ordenado de menor a mayor en un solo grupo.

**Qué se rompe.** Una entrada de lista de libres por encima del final del
fichero es una página que `alloc` repartiría tan tranquilamente como cualquier
otra, y el primer `write_page` que la recibiera escribiría más allá del final:
extendiendo el fichero otra vez y dejando por debajo un hueco de páginas sin
inicializar.

**Y ordenar no es cosmética.** Los contenedores que `flush` necesita salen del
**frente** de la lista, que sin ordenar es el orden FIFO de liberación: páginas
repartidas por todo el fichero, y **basta un contenedor alto para clavar la cola
entera**. Medido sobre 2 000 registros borrados: sin ordenar, las tres páginas
de cadena caían en la 12, la 44 y la 108 de 139, así que el sufijo libre
empezaba en la 109 y el recorte se quedaba en un **22 %**. Ordenando, se
empaquetan abajo del todo.

**Recortar y reutilizar son preguntas distintas y ocurren en momentos
distintos.** Un contenedor que la meta durable todavía declara suyo **no se
puede reutilizar** (escribirle encima durante el commit, con esa meta aún
vigente, es el defecto de §4) pero **sí se puede recortar**, porque el recorte
ocurre después de que la meta nueva —que ya no lo menciona— esté sincronizada
en las **dos** ranuras. Sin esa asimetría, el recorte se queda casi siempre en
nada: medido sobre 800 registros borrados enteros, **cero páginas devueltas**
sin contarlos, y el fichero baja a su suelo contándolos.

**Pruebas.** `deleting_everything_and_reclaiming_gives_the_file_back`,
`pruning_to_a_shorter_retention_window_returns_the_surplus`,
`a_live_reader_keeps_the_tail_until_it_goes_away`,
`it_never_truncates_into_the_reserved_prefix`,
`it_returns_the_tail_under_every_sync_policy`,
`reclaiming_the_tail_never_changes_what_the_tree_answers` (`tests/props.rs`).

---

## 19. Un solo escritor por proceso, y una sola asa por fichero

**La regla.** `Db::begin_write` toma un `Mutex` con `try_lock`. Y
`FileStorage::open` mantiene un registro **en memoria de este proceso** de rutas
**canonicalizadas** abiertas: una segunda apertura del mismo fichero mientras la
primera siga viva falla con `Error::AlreadyOpen`.

**Qué se rompe.** Dos asas independientes significan dos candados de escritor
distintos: el escritor único deja de serlo, y el copy-on-write de dos
escritores concurrentes es corrupción, con cifrado o sin él.

**Ya no es además un fallo de confidencialidad.** Lo era, y era el peor de los
dos daños: las dos asas arrancaban su contador desde el mismo `write_counter`
de la meta, así que repartían **los mismos** nonces bajo la misma clave. Hoy
cada apertura sortea su propio prefijo, así que dos asas no pueden colisionar
aunque este rechazo no existiera — y por eso esa propiedad vale también para
dos **procesos**, donde no hay guardián posible.

**Dos errores distintos, y el distingo importa:** `WriterBusy` es un escritor
legítimo en curso, reintentar tiene sentido. `WriterPoisoned` significa que una
transacción anterior entró en pánico con el candado tomado (el sitio más
probable: un extractor de índice) y **el candado no se libera nunca más**:
reintentar no funcionará jamás. Colapsarlos en uno convertía ese
envenenamiento en un ladrillo silencioso con un mensaje que invita a esperar.

**LO QUE ESTO NO CUBRE — el límite más importante del motor.** Un **segundo
proceso**. `flock(2)` no es alcanzable: `std` no lo expone, `libc`/`rustix`
exigen `unsafe` (prohibido en todo el *crate*) y `fs4`/`fs2` serían una
dependencia de ejecución; un fichero `.lock` al lado sí sería posible, pero
renuncia justo a la ventaja sobre LMDB que el diseño reclama. **Quien reparta
un fichero entre varios procesos tiene que excluirlos por su cuenta, y no
hacerlo corrompe la base.**

**Pruebas.** `a_second_writer_is_rejected_while_one_is_open`,
`opening_the_same_file_twice_in_one_process_is_refused`,
`an_encrypted_database_refuses_the_second_handle_too`,
`a_panicking_extractor_poisons_the_writer_lock_with_a_distinct_error`,
`it_refuses_while_another_writer_is_live`.

---

## 20. Las entradas de una página van en orden estrictamente ascendente, sin duplicados

**La regla.** `PageBuilder::build` exige entradas ya ordenadas por clave y sin
duplicados (precondición **no verificada en *release***, con `debug_assert` en
depuración), y `PageRef::parse` rechaza cualquier página cuyos sufijos no estén
en orden estrictamente ascendente — **claves iguales en una misma página también
son inválidas**.

**Qué se rompe.** Si las entradas no vienen ordenadas, `&key[prefix_len..]`
puede entrar en pánico con un *slice* fuera de rango: `prefix_len` se deriva
solo de la primera y la última clave, y una clave intermedia puede ser más
corta que ese prefijo.

**La dirección del solape importa y es contraintuitiva.** Las celdas crecen
desde el **final** de la página hacia el hueco libre, así que la entrada 0 (la
clave más pequeña) queda pegada al final y cada siguiente ocupa un offset
**menor**. En una página válida, `slot(i) < slot(i-1)`: los offsets bajan según
sube la clave. Dos celdas vecinas no se solapan si la celda `i` termina antes
de donde empieza la `i-1`, y la igualdad se da exactamente (celdas contiguas,
sin hueco) — de ahí que la comprobación sea `<=` y no `<`.

**Pruebas.** `build_panics_on_unsorted_entries_in_debug`,
`manual_suffix_order_matches_the_slice_operator` (compara la comparación
escrita a mano contra el operador de la biblioteca sobre todos los pares de un
conjunto que incluye el vacío, prefijos, iguales y el byte alto con el bit de
signo puesto), `get_on_a_page_with_permuted_slots_returns_corrupt_not_a_wrong_answer`.

---

## 21. La liberación en bloque de un subárbol solo se salta la lectura de los hijos si el bit lo garantiza

**La regla.** `free_subtree` vuelca los hijos a la lista de libres sin abrirlos
**solo** si el bit `CHILDREN_PLAIN` de la página lo afirma. `false` no afirma
lo contrario: significa «no hay garantía, compruébalo», y entonces se recurre
de verdad.

**Qué se rompe.** La versión original asumía el árbol equilibrado (bastaba
abrir el hijo `0` para saber si todos eran hojas) y, si lo eran, los liberaba
sin comprobar overflow. Las dos suposiciones son falsas:
- `delete_rec` colapsa nodos de un solo hijo sin fundirlos con sus hermanos, así
  que un nodo interno puede acabar con una hoja en una posición y un nodo
  interno en otra. Verificado por *fuzzing*: **8 semillas × 150 pasos
  produjeron 4 pasos con fuga, 15 páginas perdidas**; el caso mínimo pierde las
  hojas 122 y 125 en un árbol con profundidades de hoja {3, 4, 5}. Esos
  hermanos internos se liberaban como si fueran hojas y sus subárboles enteros
  quedaban huérfanos **para siempre**.
- Una hoja liberada sin abrir nunca comprueba si tiene valores de overflow.
  Reproducido: 3 000 claves con 15 valores de 2 000 bytes, `delete_range` sobre
  un tercio → **15 páginas huérfanas**, exactas 3 cadenas × 5 páginas.

**El coste de perder el bit, medido**, porque es monótono por nodo: un valor
grande escrito **una vez** bajo un nodo, aunque se borre después, le cuesta a
ese nodo su camino rápido **para siempre**.

| Árbol (20 000 entradas) | Páginas leídas, tercio medio | Poda completa |
|---|---|---|
| Recién sembrado | 50 | 80 |
| 4 000 ciclos de borrar-y-reinsertar, sin overflow | 50 | — |
| **Una** hoja que alguna vez tuvo un valor de overflow, ya borrado | 71 | — |
| **Todas** las hojas lo tuvieron alguna vez, ya borrados | 230 | 651 |

El *churn* puro no envenena el árbol; un valor grande sí, y hasta 4,6× más
lecturas en el tercio medio y más de 8× en la poda completa. **Una base que
alguna vez ha guardado valores grandes deja de tener la garantía de coste de la
poda diaria** para los nodos que llegaron a tocarlos.

**Pruebas.** `overflow_inside_a_bulk_freed_subtree_leaves_no_orphan_pages`,
`churn_then_range_delete_on_a_low_fanout_tree_leaves_no_orphan_pages`,
`an_overflow_value_ever_written_costs_its_node_the_fast_path_permanently`,
`children_plain_flag_roundtrips_and_defaults_to_false`,
`overflow_values_at_a_range_boundary_leaf_are_freed_too`.

---

## 22. Un índice y su dato viven o mueren con el mismo commit

**La regla.** El motor invoca `IndexDef::extract` en cada `put`/`delete` de su
espacio de claves origen y mantiene las entradas de índice **dentro de la misma
transacción** que los datos. Eso compra atomicidad: el índice y el dato no
pueden divergir, ni siquiera ante un corte a mitad de escritura.

`put` lo hace en **dos fases**: planificar (solo lecturas — tamaños, unicidad,
qué entradas viejas borrar y cuáles nuevas insertar) y solo después aplicar. Si
algo va a fallar, falla limpio, sin haber tocado el dato ni ningún índice.

La comprobación de unicidad compara la clave primaria **almacenada**, no solo
si la entrada existe: así una fila que se reescribe con el mismo valor indexado
que ya tenía no se confunde consigo misma. Comparar solo existencia obligaría a
borrar la entrada vieja antes de comprobar duplicados — mutación prematura.

**Límites conocidos, sin arreglo, documentados:**
- **`define_index` no rellena hacia atrás.** Las filas escritas en `ns` **antes**
  de la llamada se quedan sin indexar **para siempre**, y reabrir con la misma
  definición no lo detecta ni lo avisa: el índice está incompleto desde el
  principio, en silencio. Levantar un índice sobre datos preexistentes exige
  hoy reescribir esas filas a mano.
- **`version` es la única defensa contra un extractor cambiado**, y no hay otra
  posible: `extract` es un puntero a función, sin ninguna propiedad observable
  que distinga «la misma lógica» de «otra que hoy calcula lo mismo por
  casualidad».
- **El modismo `scan_index(id, v, v ++ [0xff])`** para «todo lo que vale
  exactamente `v`» **tiene un hueco** en un índice no único: la entrada completa
  es `v ++ primaria ++ longitud`, así que ese límite superior es *menor* que
  cualquier entrada cuya clave primaria empiece por `0xff`, y esas filas no se
  devuelven. Hay que construir `to` con suficientes bytes `0xff` como para
  exceder cualquier clave primaria real.
- **`KeyTooLarge` no distingue** si lo rechazó la clave primaria o una entrada
  de índice, ni cuál.

**Pruebas.** `a_unique_index_rejects_a_duplicate`,
`updating_a_non_indexed_part_of_the_value_is_not_a_self_duplicate`,
`a_rejected_duplicate_leaves_neither_data_nor_index_changed`,
`an_extractor_returning_several_keys_per_row_leaves_no_orphan`,
`two_rows_sharing_an_indexed_value_leave_no_orphan`,
`insert_then_reinsert_after_delete_leaves_no_orphan`,
`reopening_with_a_stale_extractor_version_is_rejected`,
`redefining_with_the_same_version_but_a_different_ns_is_rejected`,
`the_secondary_index_matches_a_recomputed_index_after_every_op` (`tests/props.rs`).

---

## 23. Lo que el motor NO promete

Ponerlo por escrito es parte de las invariantes: creerse lo contrario es de
donde salen los incidentes.

| No promete | Detalle |
|---|---|
| **Exclusión entre procesos** | No existe y no existirá. Ver §19 |
| **Frescura frente a una vuelta atrás** | La autenticación de la meta detecta **falsificación**, no **retroceso**. Una copia de seguridad íntegra de ayer valida perfectamente |
| **Confidencialidad de la meta** | El sellado es un MAC: `root`, `txn_id` y `n_pages` viajan en claro incluso en una base cifrada |
| **Que el papel de una página esté autenticado** | Los datos asociados ligan cada página con su **número**, no con su **papel** en el árbol. Quien pueda escribir el fichero puede reapuntar `root` a otra página cifrada del mismo fichero, y esa página **se descifrará limpia** |
| **Que el último commit sobreviva bajo `Sync` relajado** | Solo promete que lo que sobreviva será un *snapshot* entero. Ver §5 |
| **Compactación** | `reclaim_tail` recorta la **cola**; no mueve páginas vivas hacia abajo. Ver `runbook.md` |
| **Fusión de páginas infrautilizadas** | `delete` colapsa nodos de un solo hijo, pero no funde. De ahí la deriva de profundidad de §3 |
| **`audit_pages` como comprobación de corrección** | Solo comprueba propiedad única de página. Ver `runbook.md` |
| **Que un `commit` que devolvió `Err` no haya tenido efecto** | Puede haber quedado **duradero**: un desgarro que deposite 152 bytes o más deja la ranura completa. Ver `runbook.md` §2 |
| **Validación del espacio de claves en `put`/`delete`/`delete_range`** | **No existe.** Nada impide escribir o barrer los espacios reservados (`0x00`, `0x80\|id`). Ver `runbook.md` §7.6 |
| **Horas de producción** | Cero. El motor tiene días de vida |

---

## 24. Trampas para quien venga a mantener esto

Cosas que parecen mejoras y destruyen datos. Ninguna es hipotética: las cuatro
están hoy en el código, esperando a alguien con buenas intenciones.

### `cargo clippy --fix` DESTRUYE TODAS LAS BASES DE LA FLOTA

`FileStorage::open` usa `.read(true).write(true).create(true)`. Clippy lo marca
con `suspicious_open_options` y **su sugerencia es aplicable a máquina**:

```
462 |                 .create(true)
    |                  ^^^^^^^^^^^^- help: add: `.truncate(true)`
```

El propio resumen de clippy invita a ello: *«run `cargo clippy --fix --lib -p
inro` to apply 1 suggestion»*.

**`.truncate(true)` haría que ABRIR una base la vaciase a cero bytes.** Todas
las bases, en cada apertura, sin ningún error. Pérdida total, aplicada por una
herramienta automática, en un motor donde hay un fichero por cliente.

La corrección buena, si algún día se quiere silenciar el aviso, es
`.truncate(false)` **explícito** — que es lo que el código ya hace de forma
implícita. Nunca `--fix` a ciegas sobre este aviso. Es uno de los cuatro
hallazgos de clippy adjudicados y conscientemente no suprimidos con `#[allow]`.

### Los `.expect("validado en parse")` no son descuido

Cada uno está respaldado por la pasada de `PageRef::parse` (§1). Añadir un
camino que produzca un `PageRef` sin pasar por `parse` los convierte en pánicos
de producción. Si alguna vez hace falta, el sitio a mirar es `ValidPage`, y el
constructor `from_validated` debe seguir siendo **privado al módulo**.

### El bit `children_plain` no se puede poner a `true` «por optimizar»

Es una afirmación de certeza, no una pista (§21). Ponerlo sin haber comprobado
de verdad los hijos hace que `free_subtree` libere subárboles enteros sin
abrirlos: fuga permanente de páginas y de cadenas de overflow. La lectura
conservadora por defecto es `false`.

### Leer una meta a través de `Pager::read` rompe el argumento de la caché

Hoy ninguna meta pasa por ahí, y esa es la única razón por la que las
meta-páginas quedan a salvo de servirse obsoletas (§16). El argumento que
protege a las páginas de datos —que el escritor nunca reescribe una página que
un lector vivo pueda estar leyendo— **no cubre las metas**, que se reescriben en
cada commit.
