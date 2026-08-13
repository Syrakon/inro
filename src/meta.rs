use alloc::vec;
use alloc::vec::Vec;
use crate::header::Geometry;
use crate::{crc32, CorruptKind, Error, PageNo, Result, Storage, TxnId};

/// Fin de la región AUTENTICADA de una meta-ranura, y a la vez el tamaño
/// que tenía la parte con contenido antes del formato 3: bytes `0..108`.
///
/// Todo lo que el motor lee de una meta vive aquí dentro — `txn_id`, `root`,
/// `catalog_root`, `freelist_head`, `freelist_tail`, `n_pages`,
/// `page_size_log2`, `flags`, `format_major`, la clave de datos envuelta y
/// los dos huecos reservados a cero. Es exactamente el bloque que el tag de
/// `MetaSeal` cubre, byte a byte y tal como está en el plato. Ver
/// `crypto::verify_meta` para qué queda FUERA y por qué no puede entrar.
pub const META_AUTH_END: usize = 108;

/// Nonce del sellado de la ranura, bytes `108..132`. Cero en una base sin
/// cifrar, donde no hay ninguna clave con la que sellar.
pub const META_NONCE_OFF: usize = META_AUTH_END;

/// Tag de autenticación de la ranura, bytes `132..148`. Cero sin cifrado.
pub const META_TAG_OFF: usize = META_NONCE_OFF + crate::crypto::STORED_NONCE_LEN;

/// Bytes útiles de una meta-ranura. El resto de la página queda a cero.
/// Se dimensiona con hueco para la clave de datos envuelta (tarea 17) y,
/// desde el formato 3, para el nonce y el tag de `MetaSeal`: la meta ocupa
/// una página entera de todos modos (512 B como mínimo), así que reservar
/// no cuesta.
///
/// Disposición completa, desde el formato 3:
///
/// ```text
///   0..8    txn_id
///   8..12   root
///  12..16   catalog_root
///  16..20   freelist_head
///  20..24   freelist_tail
///  24..28   n_pages
///     28    page_size_log2
///     29    flags
///  30..32   format_major
///  32..40   reservado (cero)
///  40..100  clave de datos envuelta (crypto::WRAPPED_KEY_LEN = 60)
/// 100..108  reservado (cero) — aquí vivía `write_counter`
/// --------- META_AUTH_END: fin de lo que el tag autentica ---------
/// 108..132  nonce del sellado (crypto::STORED_NONCE_LEN = 24)
/// 132..148  tag del sellado (crypto::TAG_LEN = 16)
/// 148..152  CRC32 sobre 0..148
/// ```
///
/// **El CRC sigue siendo el último campo y sigue cubriéndolo todo, tag
/// incluido, también en una base cifrada.** No es redundancia ociosa ni un
/// resto del formato anterior: es la única comprobación de integridad que
/// no necesita clave. Una base SIN cifrar no tiene otra cosa, y una base
/// cifrada la usa para descartar una ranura DESGARRADA sin haber
/// desenvuelto nada — que es lo que deja distinguir "un corte de corriente
/// partió esta escritura" (`CorruptKind::Checksum`, se cae a la otra
/// ranura) de "alguien escribió una ranura entera que la clave no avala"
/// (`CorruptKind::MetaAuth`, se para la apertura). Ver `load_verified`.
pub const META_SIZE: usize = META_TAG_OFF + crate::crypto::TAG_LEN + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaSlot {
    A,
    B,
}

impl MetaSlot {
    /// La ranura que toca escribir a continuación: siempre la que no está en uso.
    pub fn other(self) -> Self {
        match self {
            MetaSlot::A => MetaSlot::B,
            MetaSlot::B => MetaSlot::A,
        }
    }

    /// Identidad de la ranura tal como entra en los datos asociados del
    /// sellado (`crypto::meta_associated_data`).
    ///
    /// **La LETRA, no el número de página**, y la diferencia es
    /// deliberada: `WriteTxn::relocate_meta_b` mueve la ranura B de la
    /// página 2 a su posición definitiva sin que su contenido cambie de
    /// significado, así que atar el tag al número de página obligaría a
    /// resellar en la reubicación y dejaría sin validar la copia que quedó
    /// en la posición vieja durante la ventana del corte. La letra es lo
    /// que de verdad hay que atar: es lo que impide intercambiar las dos
    /// ranuras y con ello dirigir qué `txn_id` gana en `load_verified`.
    pub fn index(self) -> u8 {
        match self {
            MetaSlot::A => 0,
            MetaSlot::B => 1,
        }
    }

    pub fn page(self, g: &Geometry) -> PageNo {
        match self {
            MetaSlot::A => g.meta_a_page,
            MetaSlot::B => g.meta_b_page,
        }
    }
}

/// Estado de commit. A diferencia de la cabecera, se reescribe en cada
/// transacción, alternando entre las dos ranuras.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub txn_id: TxnId,
    pub root: PageNo,
    pub catalog_root: PageNo,
    pub freelist_head: PageNo,
    pub freelist_tail: PageNo,
    /// Páginas que esta transacción consideraba asignadas. Si el fichero es
    /// mayor, las páginas sobrantes son fugas de una transacción interrumpida
    /// y se recuperan al abrir.
    pub n_pages: u32,
    // Copia de la geometría, para poder reconstruir una cabecera dañada.
    pub page_size_log2: u8,
    pub format_major: u16,
    pub flags: u8,
    /// Clave de datos envuelta con la maestra (tarea 17), bytes 40..100:
    /// nonce de 12, texto cifrado de 32 y tag de 16 (`crypto::WRAPPED_KEY_LEN`
    /// = 60). `Some` si y solo si `flags & header::FLAG_ENCRYPTED != 0` — es
    /// `decode` quien impone esa correspondencia (ver más abajo), no un
    /// invariante que este `struct` pueda hacer cumplir por construcción.
    pub wrapped_key: Option<[u8; crate::crypto::WRAPPED_KEY_LEN]>,
}

/// Sellado de una meta-ranura: el nonce con el que se calculó su tag y el
/// tag en sí, bytes `108..148`. `None` en una base sin cifrar.
///
/// Vive en `meta.rs` y no en `crypto.rs` porque es FORMATO DE FICHERO —
/// esos 40 bytes existen en toda meta-ranura, se compile o no la feature
/// `encryption`, igual que la clave envuelta de los bytes 40..100. Quien
/// sabe producirlo y comprobarlo es `crypto::seal_meta`/`verify_meta`, que
/// sí están gateados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaSeal {
    pub nonce: [u8; crate::crypto::STORED_NONCE_LEN],
    pub tag: [u8; crate::crypto::TAG_LEN],
}

/// El paso de aceptación de `Meta::load_verified`: recibe la ranura
/// ganadora ya decodificada, sus bytes CRUDOS tal como están en el plato
/// (que es sobre lo que hay que autenticar, ver
/// `crypto::meta_associated_data`) y su letra.
///
/// Un alias y no la firma escrita a mano en el parámetro: `cargo clippy`
/// (`type_complexity`) lo pide, y de paso da un sitio donde documentar qué
/// significan los tres argumentos sin repetirlo en cada llamante.
pub type MetaAccept<'a> = dyn FnMut(&Meta, &[u8], MetaSlot) -> Result<()> + 'a;

// Los bytes 100..108 de cada ranura llevaban `write_counter`, el techo del
// contador de nonce de página reservado de forma duradera. **Eliminado con
// el cambio a nonces aleatorios** (formato 2): el nonce ya no es
// `página || contador` con un contador que tenga que sobrevivir a las
// caídas, sino `prefijo aleatorio por apertura || contador dentro de la
// apertura`, así que reiniciar el contador en cero al abrir es seguro por
// construcción y no queda nada que persistir. Con el campo se fueron su
// protocolo de extensión (`Db::extend_counter_ceiling`, dos escrituras de
// meta con dos sincronizaciones incondicionales), `COUNTER_RESERVE`,
// `WriterState::counter_ceiling` y el desempate por contador que `load`
// necesitaba (ver más abajo).
//
// La región vuelve a quedar reservada a cero, como antes de la tarea 17.
// **Y sigue reservada tras el formato 3**, que es donde uno esperaría que
// se reaprovechara: entre esos 8 bytes y los 8 de 32..40 hay exactamente
// los 16 que mide un tag, y aun así el sellado no se metió ahí. Partir un
// tag en dos trozos no contiguos para ahorrar 40 bytes de una página de
// 512 que ya iba a estar medio vacía habría cambiado un formato legible por
// uno que hay que reensamblar para leer, y el nonce de 24 bytes no cabía de
// ninguna forma. `META_SIZE` crece de 112 a 152 y la región autenticada se
// queda exactamente donde estaba: 0..108, los mismos bytes que el CRC cubría
// antes.

impl Meta {
    /// Los bytes `0..META_AUTH_END` de esta meta: la región que el tag
    /// autentica. Se calcula aparte de `encode` porque el sellado necesita
    /// verlos ANTES de que la ranura esté completa — el tag es parte de la
    /// ranura, así que no puede calcularse sobre ella entera.
    pub fn payload(&self) -> [u8; META_AUTH_END] {
        let mut b = [0u8; META_AUTH_END];
        b[0..8].copy_from_slice(&self.txn_id.to_le_bytes());
        b[8..12].copy_from_slice(&self.root.to_le_bytes());
        b[12..16].copy_from_slice(&self.catalog_root.to_le_bytes());
        b[16..20].copy_from_slice(&self.freelist_head.to_le_bytes());
        b[20..24].copy_from_slice(&self.freelist_tail.to_le_bytes());
        b[24..28].copy_from_slice(&self.n_pages.to_le_bytes());
        b[28] = self.page_size_log2;
        b[29] = self.flags;
        b[30..32].copy_from_slice(&self.format_major.to_le_bytes());
        // 32..40 reservado a cero. 40..100 clave de datos envuelta (tarea
        // 17): nonce de 12, texto cifrado de 32 y tag de 16. 100..108
        // reservado (ver el comentario tras la struct: ahí vivía
        // `write_counter`, ya eliminado).
        if let Some(wrapped) = &self.wrapped_key {
            b[40..40 + crate::crypto::WRAPPED_KEY_LEN].copy_from_slice(wrapped);
        }
        b
    }

    /// La ranura entera, lista para escribir. `seal` es `Some` si y solo si
    /// la base está cifrada; con `None`, el nonce y el tag quedan a cero
    /// —una base sin cifrar no tiene ninguna clave con la que sellar, y eso
    /// no es un hueco que disculpar sino lo que el formato sin cifrado
    /// garantiza: integridad frente a corrupción accidental (el CRC32) y
    /// nada frente a quien pueda escribir el fichero.
    ///
    /// El CRC va el ÚLTIMO y cubre también el sellado: ver `META_SIZE`.
    pub fn encode(&self, page_size: u32, seal: Option<&MetaSeal>) -> Vec<u8> {
        let mut b = vec![0u8; page_size as usize];
        b[..META_AUTH_END].copy_from_slice(&self.payload());
        if let Some(s) = seal {
            b[META_NONCE_OFF..META_TAG_OFF].copy_from_slice(&s.nonce);
            b[META_TAG_OFF..META_TAG_OFF + crate::crypto::TAG_LEN].copy_from_slice(&s.tag);
        }
        let crc = crc32::checksum(&b[..META_SIZE - 4]);
        b[META_SIZE - 4..META_SIZE].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// El sellado que lleva una ranura ya leída del medio. No comprueba
    /// nada — eso es `crypto::verify_meta` — solo recorta los dos campos.
    ///
    /// Devolverlo SIEMPRE, también en una base sin cifrar (donde son 40
    /// bytes a cero), en vez de un `Option`: quien decide si hay algo que
    /// verificar es quien sabe si hay clave, no este recorte.
    pub fn seal_of(b: &[u8]) -> MetaSeal {
        debug_assert!(b.len() >= META_SIZE);
        let mut seal =
            MetaSeal { nonce: [0u8; crate::crypto::STORED_NONCE_LEN], tag: [0u8; crate::crypto::TAG_LEN] };
        seal.nonce.copy_from_slice(&b[META_NONCE_OFF..META_TAG_OFF]);
        seal.tag.copy_from_slice(&b[META_TAG_OFF..META_TAG_OFF + crate::crypto::TAG_LEN]);
        seal
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < META_SIZE {
            return Err(Error::Corrupt { page: 0, kind: CorruptKind::MetaMismatch });
        }
        let stored = u32::from_le_bytes(b[META_SIZE - 4..META_SIZE].try_into().unwrap());
        if stored != crc32::checksum(&b[..META_SIZE - 4]) {
            return Err(Error::Corrupt { page: 0, kind: CorruptKind::Checksum });
        }
        let flags = b[29];
        // `wrapped_key` se lee condicionado a `FLAG_ENCRYPTED`, no a si la
        // región 40..100 es distinta de cero: una base sin cifrar nunca
        // escribe ahí (`encode`, arriba, solo copia `wrapped_key` cuando es
        // `Some`), así que en la práctica ambos criterios coinciden, pero
        // basarse en el flag es exacto — "todo ceros" también sería, en
        // teoría, un envoltorio válido (nonce, texto cifrado y tag a cero),
        // por astronómicamente improbable que sea en la práctica.
        let wrapped_key = if flags & crate::header::FLAG_ENCRYPTED != 0 {
            let mut w = [0u8; crate::crypto::WRAPPED_KEY_LEN];
            w.copy_from_slice(&b[40..40 + crate::crypto::WRAPPED_KEY_LEN]);
            Some(w)
        } else {
            None
        };
        Ok(Self {
            txn_id: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            root: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            catalog_root: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            freelist_head: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            freelist_tail: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            n_pages: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            page_size_log2: b[28],
            flags,
            format_major: u16::from_le_bytes(b[30..32].try_into().unwrap()),
            wrapped_key,
        })
    }

    pub fn store(
        &self,
        storage: &dyn Storage,
        g: &Geometry,
        slot: MetaSlot,
        seal: Option<&MetaSeal>,
    ) -> Result<()> {
        let offset = slot.page(g) as u64 * g.page_size as u64;
        storage.write_at(offset, &self.encode(g.page_size, seal))
    }

    /// Escribe a través del `Pager` en lugar de directamente al medio, para
    /// que la caché se invalide.
    #[cfg(feature = "std")]
    pub fn store_via(
        &self,
        pager: &crate::pager::Pager,
        g: &Geometry,
        slot: MetaSlot,
        seal: Option<&MetaSeal>,
    ) -> Result<()> {
        pager.write(slot.page(g), &self.encode(g.page_size, seal))
    }

    /// Lee ambas ranuras, descarta las que no validen y devuelve la de mayor
    /// `txn_id`. Es todo el procedimiento de recuperación que existe: sin WAL,
    /// sin recorrido de cola, coste constante.
    ///
    /// **Sin desempate a igualdad de `txn_id`, y ya no hace falta ninguno**
    /// (cambio de diseño a nonces aleatorios). Lo hubo: mientras existió
    /// `write_counter`, `Db::extend_counter_ceiling` escribía las dos
    /// ranuras con el MISMO `txn_id` y distinto contador, una detrás de
    /// otra, a mitad de una transacción — una ventana en la que las dos
    /// ranuras empataban en `txn_id`, y en la que quedarse con la primera
    /// podía perder el techo recién reservado. Ese protocolo desapareció
    /// con el campo, y con él la única forma de que dos ranuras compartan
    /// `txn_id` con contenido distinto: hoy la única escritura de meta que
    /// no viene de un commit es la de `Db::create`, que deja las dos
    /// ranuras byte a byte idénticas. `>` estricto vuelve a bastar.
    pub fn load(storage: &dyn Storage, g: &Geometry) -> Result<(Meta, MetaSlot)> {
        Self::load_verified(storage, g, &mut |_, _, _| Ok(()))
    }

    /// `load` con un paso de aceptación por medio: `accept` recibe cada
    /// candidata en orden de `txn_id` DESCENDENTE junto con los bytes
    /// CRUDOS de su ranura, y la primera que devuelva `Ok` es la que monta.
    ///
    /// # El orden, y por qué la clave envuelta no es un círculo vicioso
    ///
    /// La clave de datos con la que se autentica una ranura viaja DENTRO de
    /// esa misma ranura (bytes 40..100), envuelta con la clave maestra del
    /// llamante. Parece circular y no lo es, porque las dos capas usan
    /// claves distintas:
    ///
    /// 1. Se lee la ranura y se comprueba su CRC32. Sin clave, sin
    ///    confiar en nada: solo descarta lo que está roto o a medio
    ///    escribir.
    /// 2. `accept` toma los bytes 40..100 y los abre con la clave MAESTRA.
    ///    Eso es un AEAD: un envoltorio que no produjera quien tiene la
    ///    maestra falla aquí. Leerlo antes de verificar nada no es confiar
    ///    en él — es abrirlo, que es precisamente lo que lo autentica.
    /// 3. Con la clave de DATOS que sale de ahí se comprueba el tag sobre
    ///    los bytes 0..`META_AUTH_END` — los 60 de la clave envuelta
    ///    incluidos, así que quedan cubiertos dos veces y por dos claves
    ///    distintas — más `db_id` y la letra de la ranura
    ///    (`crypto::verify_meta`).
    ///
    /// Un atacante que trasplante el envoltorio de OTRA base cifrada con la
    /// misma maestra pasa el paso 2 con una clave de datos que no es la de
    /// este fichero, y se estrella en el 3: no puede fabricar un tag bajo
    /// una clave que no conoce, y el `db_id` de la cabecera de ESTE fichero
    /// entra en los datos asociados.
    ///
    /// # Una ranura INCOMPLETA se descarta; una COMPLETA que no se acepta, no
    ///
    /// Son fallos distintos y merecen desenlaces distintos, y el reparto no
    /// es una elección de estilo: es lo que separa "sobrevivir a un corte de
    /// corriente" de "tragarse un ataque en silencio".
    ///
    /// Una ranura que no supera el paso 1 está INCOMPLETA: los bytes del
    /// plato son mitad de una meta y mitad de otra, que es lo que deja un
    /// corte a media escritura. El diseño de dos ranuras existe exactamente
    /// para eso — se descarta sin más y se monta por la otra — y por eso el
    /// CRC32 sigue en el formato aunque haya un tag: descarta lo desgarrado
    /// SIN clave y sin haber desenvuelto nada.
    ///
    /// Una ranura que supera el paso 1 está COMPLETA: su CRC cuadra con sus
    /// propios bytes, así que nadie la partió. Si aun así `accept` la
    /// rechaza, esta función NO prueba con la otra: devuelve el error.
    /// Caer a la otra ranura ahí convertiría un ataque DETECTADO en una
    /// vuelta atrás silenciosa — el llamante recibiría `Ok` y una base un
    /// commit más vieja, sin ninguna señal de que alguien le tocó el
    /// fichero.
    ///
    /// Y no se pierde nada legítimo por ello: lo que `Db::open` comprueba en
    /// `accept` es el envoltorio de la clave (idéntico en las dos ranuras de
    /// cualquier fichero sano — se sella una vez en `Db::create` y se copia)
    /// y el tag. En un fichero sano, si la ranura nueva no pasa, la vieja
    /// tampoco iba a pasar.
    ///
    /// El precio es que una ranura desgarrada cuyo CRC cuadre POR CASUALIDAD
    /// (2^-32) deja la base sin abrir en vez de caer a la otra. Es el mismo
    /// riesgo que el motor ya acepta en cada página del árbol, que no tiene
    /// segunda copia ninguna.
    pub fn load_verified(
        storage: &dyn Storage,
        g: &Geometry,
        accept: &mut MetaAccept<'_>,
    ) -> Result<(Meta, MetaSlot)> {
        let mut best: Option<(Meta, Vec<u8>, MetaSlot)> = None;
        for slot in [MetaSlot::A, MetaSlot::B] {
            let mut buf = vec![0u8; g.page_size as usize];
            let offset = slot.page(g) as u64 * g.page_size as u64;
            if storage.read_at(offset, &mut buf).is_err() {
                continue;
            }
            let Ok(meta) = Meta::decode(&buf) else { continue };
            // Una meta cuya geometría contradiga la cabecera indica que se está
            // leyendo con el tamaño de página equivocado: es corrupción, no una
            // ranura vieja.
            if meta.page_size_log2 != g.page_size.trailing_zeros() as u8 {
                continue;
            }
            // `>` estricto: A gana los empates por ser la primera del
            // recorrido, igual que antes de que `accept` existiera. Ver
            // `load_is_deterministic_when_both_slots_are_identical`.
            let better = match &best {
                None => true,
                Some((b, _, _)) => meta.txn_id > b.txn_id,
            };
            if better {
                best = Some((meta, buf, slot));
            }
        }
        let Some((meta, raw, slot)) = best else {
            return Err(Error::Corrupt { page: g.meta_a_page, kind: CorruptKind::MetaMismatch });
        };
        accept(&meta, &raw, slot)?;
        Ok((meta, slot))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::header::{Geometry, FORMAT_MAJOR};
    use crate::storage::MemStorage;
    use crate::Storage;

    fn geo() -> Geometry {
        Geometry {
            page_size: 512, format_major: FORMAT_MAJOR, format_minor: 0, flags: 0,
            db_id: [0; 16], created_unix: 0, meta_a_page: 1, meta_b_page: 8,
        }
    }

    fn meta(txn_id: u64) -> Meta {
        Meta {
            txn_id, root: 9, catalog_root: 0, freelist_head: 0, freelist_tail: 0,
            n_pages: 10, page_size_log2: 9, format_major: FORMAT_MAJOR, flags: 0,
            wrapped_key: None,
        }
    }

    /// Los bytes donde vivía `write_counter` tienen que quedar a cero, no
    /// con basura: es lo que hace que un fichero nuevo sea reproducible y
    /// que la región siga disponible si algún día se reaprovecha. Sin esta
    /// prueba, un `encode` que dejara ahí lo que hubiera en el búfer
    /// pasaría inadvertido — el CRC se calcula DESPUÉS, así que cubriría la
    /// basura tan felizmente como los ceros.
    #[test]
    fn the_bytes_that_held_the_nonce_counter_ceiling_are_reserved_zero() {
        let encoded = meta(1).encode(512, None);
        assert_eq!(&encoded[100..108], &[0u8; 8][..]);
    }

    #[test]
    fn wrapped_key_roundtrips_when_the_encrypted_flag_is_set() {
        let mut m = meta(1);
        m.flags = crate::header::FLAG_ENCRYPTED;
        m.wrapped_key = Some([9u8; crate::crypto::WRAPPED_KEY_LEN]);
        let encoded = m.encode(512, None);
        assert_eq!(
            &encoded[40..40 + crate::crypto::WRAPPED_KEY_LEN],
            &[9u8; crate::crypto::WRAPPED_KEY_LEN][..]
        );
        assert_eq!(Meta::decode(&encoded).unwrap(), m);
    }

    /// Regresión adversarial: sin `FLAG_ENCRYPTED`, `decode` debe ignorar la
    /// región 40..100 aunque no esté a cero — p. ej. basura que dejó una
    /// versión anterior del fichero, o una base que nunca se cifró pero
    /// cuya página de meta comparte bytes con una que sí lo estuvo. Si
    /// `decode` derivara `wrapped_key` de "la región no es toda cero" en
    /// vez de mirar el flag, este caso devolvería `Some` con basura en vez
    /// de `None`.
    #[test]
    fn wrapped_key_is_none_without_the_encrypted_flag_even_if_bytes_are_nonzero() {
        let m = meta(1);
        let mut encoded = m.encode(512, None);
        encoded[40] = 0xff;
        let crc = crate::crc32::checksum(&encoded[..META_SIZE - 4]);
        encoded[META_SIZE - 4..META_SIZE].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(Meta::decode(&encoded).unwrap().wrapped_key, None);
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let m = meta(42);
        assert_eq!(Meta::decode(&m.encode(512, None)).unwrap(), m);
    }

    #[test]
    fn load_picks_the_highest_valid_txn_id() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A, None).unwrap();
        meta(2).store(&s, &g, MetaSlot::B, None).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.txn_id, 2);
        assert_eq!(slot, MetaSlot::B);
    }

    /// El único escenario que quedaba con dos ranuras empatadas en
    /// `txn_id` tras eliminar `write_counter` y su protocolo de extensión:
    /// una base recién creada, donde `Db::create` escribe las DOS ranuras
    /// con la misma meta. Empatan porque son idénticas, así que da lo mismo
    /// cuál gane — lo que esta prueba fija es que `load` siga eligiendo una
    /// de forma determinista (la A, la primera del recorrido) en vez de
    /// fallar o de depender del orden en que se escribieron.
    #[test]
    fn load_is_deterministic_when_both_slots_are_identical() {
        let (s, g) = (MemStorage::new(), geo());
        meta(5).store(&s, &g, MetaSlot::A, None).unwrap();
        meta(5).store(&s, &g, MetaSlot::B, None).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.txn_id, 5);
        assert_eq!(slot, MetaSlot::A);

        // Y en el orden inverso de escritura, para confirmar que no es un
        // artefacto de cuál se escribió última.
        let (s2, g2) = (MemStorage::new(), geo());
        meta(7).store(&s2, &g2, MetaSlot::B, None).unwrap();
        meta(7).store(&s2, &g2, MetaSlot::A, None).unwrap();
        assert_eq!(Meta::load(&s2, &g2).unwrap().1, MetaSlot::A);
    }

    #[test]
    fn load_falls_back_when_the_newest_slot_is_torn() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A, None).unwrap();
        meta(2).store(&s, &g, MetaSlot::B, None).unwrap();
        // Simula un corte a mitad de escribir la meta B.
        s.write_at(8 * 512, &[0xff; 16]).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.txn_id, 1, "monta por la meta superviviente");
        assert_eq!(slot, MetaSlot::A);
    }

    #[test]
    fn load_fails_when_both_slots_are_unreadable() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A, None).unwrap();
        meta(2).store(&s, &g, MetaSlot::B, None).unwrap();
        s.write_at(1 * 512, &[0xff; 16]).unwrap();
        s.write_at(8 * 512, &[0xff; 16]).unwrap();
        assert!(matches!(Meta::load(&s, &g), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn decode_rejects_geometry_that_contradicts_the_header() {
        let mut m = meta(1);
        m.page_size_log2 = 12;
        let bytes = m.encode(512, None);
        // El llamante compara contra la geometría real en `load`; aquí se
        // comprueba que el campo viaja intacto para poder compararlo.
        assert_eq!(Meta::decode(&bytes).unwrap().page_size_log2, 12);
    }
}
