use alloc::vec;
use alloc::vec::Vec;
use crate::header::Geometry;
use crate::{crc32, CorruptKind, Error, PageNo, Result, Storage, TxnId};

/// Bytes útiles de una meta-ranura. El resto de la página queda a cero.
/// Se dimensiona ya con hueco para la clave de datos envuelta de la tarea 17:
/// la meta ocupa una página entera de todos modos, así que reservar no cuesta.
pub const META_SIZE: usize = 112;

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
    /// Techo del contador de nonce de página ya reservado de forma duradera
    /// (tarea 17, ronda de revisión posterior a la primera entrega), bytes
    /// 100..108 — el hueco que ya dejaba `encode` como "reservado". NO es
    /// "el último contador usado": es "ningún contador por debajo de este
    /// valor se ofrece jamás a una transacción futura", incluso si el
    /// contador real usado por la última transacción fue mucho menor — ver
    /// `Db::extend_counter_ceiling` en `tx.rs`, que es quien mantiene esa
    /// propiedad. Sin significado en una base sin cifrar (queda en 0, sin
    /// que nada lo lea).
    ///
    /// **Las DOS ranuras lo llevan siempre** (tarea 17, tercera ronda de
    /// revisión): una extensión escribe este campo en ambas, con una
    /// sincronización tras cada una. Si viviera en una sola, el commit
    /// siguiente — que escribe justo esa — dejaría el registro del techo a
    /// merced de una única escritura desgarrada, y la ranura superviviente
    /// devolvería un contador VIEJO que la sesión siguiente volvería a
    /// repartir.
    pub write_counter: u64,
}

impl Meta {
    pub fn encode(&self, page_size: u32) -> Vec<u8> {
        let mut b = vec![0u8; page_size as usize];
        b[0..8].copy_from_slice(&self.txn_id.to_le_bytes());
        b[8..12].copy_from_slice(&self.root.to_le_bytes());
        b[12..16].copy_from_slice(&self.catalog_root.to_le_bytes());
        b[16..20].copy_from_slice(&self.freelist_head.to_le_bytes());
        b[20..24].copy_from_slice(&self.freelist_tail.to_le_bytes());
        b[24..28].copy_from_slice(&self.n_pages.to_le_bytes());
        b[28] = self.page_size_log2;
        b[29] = self.flags;
        b[30..32].copy_from_slice(&self.format_major.to_le_bytes());
        // 40..100 clave de datos envuelta (tarea 17): nonce de 12, texto
        // cifrado de 32 y tag de 16. 100..108 techo del contador de nonce
        // de página (tarea 17, ronda de revisión posterior a la primera
        // entrega — ver el comentario de `write_counter`).
        if let Some(wrapped) = &self.wrapped_key {
            b[40..40 + crate::crypto::WRAPPED_KEY_LEN].copy_from_slice(wrapped);
        }
        b[100..108].copy_from_slice(&self.write_counter.to_le_bytes());
        let crc = crc32::checksum(&b[..META_SIZE - 4]);
        b[META_SIZE - 4..META_SIZE].copy_from_slice(&crc.to_le_bytes());
        b
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
            write_counter: u64::from_le_bytes(b[100..108].try_into().unwrap()),
        })
    }

    pub fn store(&self, storage: &dyn Storage, g: &Geometry, slot: MetaSlot) -> Result<()> {
        let offset = slot.page(g) as u64 * g.page_size as u64;
        storage.write_at(offset, &self.encode(g.page_size))
    }

    /// Escribe a través del `Pager` en lugar de directamente al medio, para
    /// que la caché se invalide.
    #[cfg(feature = "std")]
    pub fn store_via(&self, pager: &crate::pager::Pager, g: &Geometry, slot: MetaSlot) -> Result<()> {
        pager.write(slot.page(g), &self.encode(g.page_size))
    }

    /// Lee ambas ranuras, descarta las que no validen y devuelve la de mayor
    /// `txn_id`. Es todo el procedimiento de recuperación que existe: sin WAL,
    /// sin recorrido de cola, coste constante.
    ///
    /// **Desempate por `write_counter` a igualdad de `txn_id`** (tarea 17,
    /// segunda ronda de revisión posterior a la primera entrega):
    /// `Db::extend_counter_ceiling` deja las dos ranuras con el MISMO
    /// `txn_id` — cada una una copia exacta de la última meta confirmada,
    /// solo con `write_counter` avanzado — y las escribe una detrás de otra
    /// mientras una transacción está en curso (ver su comentario en
    /// `tx.rs`). Entre las dos escrituras hay una ventana en la que las
    /// ranuras comparten `txn_id` y difieren en `write_counter`. Sin este
    /// desempate, `meta.txn_id > b.txn_id` es estrictamente falso a
    /// igualdad y la ranura A (procesada primero) gana siempre — que
    /// podría ser precisamente la que tiene el `write_counter` más VIEJO,
    /// dejando que una futura transacción reparta de nuevo contadores que
    /// la extensión ya había dejado fuera de circulación.
    ///
    /// Es seguro preferir el `write_counter` mayor en este caso, y solo en
    /// este caso, porque a igualdad de `txn_id` las dos ranuras describen
    /// el MISMO estado confirmado: `root`, lista de libres y `n_pages`
    /// coinciden byte a byte, porque las dos salen de copiar la misma meta
    /// confirmada. Y esa premisa es hoy exacta (tarea 17, TERCERA ronda de
    /// revisión): hasta esa ronda, `Db::open` subía el `n_pages` de la meta
    /// que guardaba en memoria hasta la extensión real del fichero, así que
    /// la copia que escribía una extensión podía diferir de la ranura
    /// hermana en un campo que NO era el contador — el único camino vivo
    /// por el que este desempate llegaba a elegir entre dos estados
    /// distintos. Ver el comentario del campo `Db::committed` en `tx.rs`.
    pub fn load(storage: &dyn Storage, g: &Geometry) -> Result<(Meta, MetaSlot)> {
        let mut best: Option<(Meta, MetaSlot)> = None;
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
            let better = match best {
                None => true,
                Some((b, _)) => {
                    meta.txn_id > b.txn_id
                        || (meta.txn_id == b.txn_id && meta.write_counter > b.write_counter)
                }
            };
            if better {
                best = Some((meta, slot));
            }
        }
        best.ok_or(Error::Corrupt { page: g.meta_a_page, kind: CorruptKind::MetaMismatch })
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
            wrapped_key: None, write_counter: 0,
        }
    }

    #[test]
    fn write_counter_roundtrips() {
        let mut m = meta(1);
        m.write_counter = 0x0102_0304_0506_0708;
        assert_eq!(Meta::decode(&m.encode(512)).unwrap().write_counter, m.write_counter);
    }

    #[test]
    fn wrapped_key_roundtrips_when_the_encrypted_flag_is_set() {
        let mut m = meta(1);
        m.flags = crate::header::FLAG_ENCRYPTED;
        m.wrapped_key = Some([9u8; crate::crypto::WRAPPED_KEY_LEN]);
        let encoded = m.encode(512);
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
        let mut encoded = m.encode(512);
        encoded[40] = 0xff;
        let crc = crate::crc32::checksum(&encoded[..META_SIZE - 4]);
        encoded[META_SIZE - 4..META_SIZE].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(Meta::decode(&encoded).unwrap().wrapped_key, None);
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let m = meta(42);
        assert_eq!(Meta::decode(&m.encode(512)).unwrap(), m);
    }

    #[test]
    fn load_picks_the_highest_valid_txn_id() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A).unwrap();
        meta(2).store(&s, &g, MetaSlot::B).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.txn_id, 2);
        assert_eq!(slot, MetaSlot::B);
    }

    /// Tarea 17, segunda ronda de revisión posterior a la primera entrega:
    /// a igualdad de `txn_id` (el escenario que deja
    /// `Db::extend_counter_ceiling` cuando extiende el techo de nonce a
    /// mitad de una transacción, escribiendo una copia de la última meta
    /// confirmada en la ranura inactiva), `load` debe preferir la ranura
    /// con el `write_counter` más alto — es la única forma de que una
    /// extensión sobreviva a una caída justo después: sin este desempate,
    /// la ranura A (procesada primero en el bucle) gana siempre, aunque su
    /// `write_counter` sea el más viejo de las dos.
    #[test]
    fn load_prefers_the_higher_write_counter_when_txn_id_ties() {
        let (s, g) = (MemStorage::new(), geo());
        let mut a = meta(5);
        a.write_counter = 100;
        a.store(&s, &g, MetaSlot::A).unwrap();
        let mut b = meta(5); // mismo txn_id que A
        b.write_counter = 200;
        b.store(&s, &g, MetaSlot::B).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.write_counter, 200, "debe preferir el contador mas alto a igualdad de txn_id");
        assert_eq!(slot, MetaSlot::B);

        // Y en el orden inverso (la ranura A tiene el contador mayor), para
        // confirmar que no es un artefacto del orden de recorrido del bucle.
        let (s2, g2) = (MemStorage::new(), geo());
        let mut a2 = meta(7);
        a2.write_counter = 300;
        a2.store(&s2, &g2, MetaSlot::A).unwrap();
        let mut b2 = meta(7);
        b2.write_counter = 250;
        b2.store(&s2, &g2, MetaSlot::B).unwrap();
        let (m2, slot2) = Meta::load(&s2, &g2).unwrap();
        assert_eq!(m2.write_counter, 300);
        assert_eq!(slot2, MetaSlot::A);
    }

    #[test]
    fn load_falls_back_when_the_newest_slot_is_torn() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A).unwrap();
        meta(2).store(&s, &g, MetaSlot::B).unwrap();
        // Simula un corte a mitad de escribir la meta B.
        s.write_at(8 * 512, &[0xff; 16]).unwrap();
        let (m, slot) = Meta::load(&s, &g).unwrap();
        assert_eq!(m.txn_id, 1, "monta por la meta superviviente");
        assert_eq!(slot, MetaSlot::A);
    }

    #[test]
    fn load_fails_when_both_slots_are_unreadable() {
        let (s, g) = (MemStorage::new(), geo());
        meta(1).store(&s, &g, MetaSlot::A).unwrap();
        meta(2).store(&s, &g, MetaSlot::B).unwrap();
        s.write_at(1 * 512, &[0xff; 16]).unwrap();
        s.write_at(8 * 512, &[0xff; 16]).unwrap();
        assert!(matches!(Meta::load(&s, &g), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn decode_rejects_geometry_that_contradicts_the_header() {
        let mut m = meta(1);
        m.page_size_log2 = 12;
        let bytes = m.encode(512);
        // El llamante compara contra la geometría real en `load`; aquí se
        // comprueba que el campo viaja intacto para poder compararlo.
        assert_eq!(Meta::decode(&bytes).unwrap().page_size_log2, 12);
    }
}
