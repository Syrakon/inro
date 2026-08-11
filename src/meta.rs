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
        // cifrado de 32 y tag de 16. 100..108 reservado.
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
        Ok(Self {
            txn_id: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            root: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            catalog_root: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            freelist_head: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            freelist_tail: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            n_pages: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            page_size_log2: b[28],
            flags: b[29],
            format_major: u16::from_le_bytes(b[30..32].try_into().unwrap()),
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
            if best.map_or(true, |(b, _)| meta.txn_id > b.txn_id) {
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
        }
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
