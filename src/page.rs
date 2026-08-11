use crate::{crc32, varint, CorruptKind, Error, PageNo, Result};

pub const PAGE_HEADER_SIZE: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    Leaf = 0,
    Internal = 1,
    Overflow = 2,
    Freelist = 3,
}

impl PageType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => PageType::Leaf,
            1 => PageType::Internal,
            2 => PageType::Overflow,
            3 => PageType::Freelist,
            _ => return None,
        })
    }
}

/// Vista de solo lectura sobre los bytes de una página ya validada.
/// `parse` comprueba el CRC y toda la estructura una vez; a partir de ahí los
/// accesores no vuelven a validar y no pueden salirse de la página.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRef<'a> {
    bytes: &'a [u8],
    page_type: PageType,
    n_slots: usize,
    prefix_len: usize,
    slots_at: usize,
}

impl<'a> PageRef<'a> {
    pub fn parse(bytes: &'a [u8], page_no: PageNo) -> Result<Self> {
        let corrupt = |kind| Error::Corrupt { page: page_no, kind };

        if bytes.len() < PAGE_HEADER_SIZE {
            return Err(corrupt(CorruptKind::CellBounds));
        }

        // El CRC va primero: sin él, cualquier campo leído a continuación
        // podría ser basura interpretada como estructura válida.
        let stored = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mut h = crc32::Hasher::new();
        h.update(&bytes[..8]);
        h.update(&bytes[12..]);
        if stored != h.finish() {
            return Err(corrupt(CorruptKind::Checksum));
        }

        let page_type = PageType::from_u8(bytes[0]).ok_or_else(|| corrupt(CorruptKind::PageType))?;
        let n_slots = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let free_start = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
        let cell_start = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
        let prefix_len = u16::from_le_bytes(bytes[16..18].try_into().unwrap()) as usize;

        let slots_at = PAGE_HEADER_SIZE + prefix_len;
        let expected_free_start = slots_at + 2 * n_slots;
        // `free_start` es redundante: se deriva de `n_slots` y `prefix_len`.
        // Se almacena precisamente para poder contrastarlo y detectar
        // corrupción que el CRC no vería si afectase a varios campos a la vez.
        if free_start != expected_free_start
            || expected_free_start > bytes.len()
            || cell_start > bytes.len()
            || cell_start < expected_free_start
        {
            return Err(corrupt(CorruptKind::CellBounds));
        }

        let page = Self { bytes, page_type, n_slots, prefix_len, slots_at };

        // Cada slot debe apuntar dentro del área de celdas, y cada celda debe
        // decodificarse entera dentro de la página.
        for i in 0..n_slots {
            let off = page.slot(i);
            if off < cell_start || off >= bytes.len() {
                return Err(corrupt(CorruptKind::SlotOffset));
            }
            page.cell_end(off).ok_or_else(|| corrupt(CorruptKind::CellBounds))?;
        }

        Ok(page)
    }

    fn slot(&self, i: usize) -> usize {
        let at = self.slots_at + 2 * i;
        u16::from_le_bytes(self.bytes[at..at + 2].try_into().unwrap()) as usize
    }

    /// Fin de la celda que empieza en `off`, o `None` si no cabe en la página.
    /// Las celdas de hoja e internas comparten prefijo de formato:
    /// `[len_sufijo varint][sufijo]` seguido de la carga propia del tipo.
    fn cell_end(&self, off: usize) -> Option<usize> {
        let b = self.bytes.get(off..)?;
        let (suffix_len, n1) = varint::read(b)?;
        let after_suffix = off.checked_add(n1)?.checked_add(suffix_len as usize)?;
        match self.page_type {
            PageType::Leaf => {
                let b = self.bytes.get(after_suffix..)?;
                let (value_len, n2) = varint::read(b)?;
                let end = after_suffix.checked_add(n2)?.checked_add(value_len as usize)?;
                (end <= self.bytes.len()).then_some(end)
            }
            PageType::Internal => {
                let end = after_suffix.checked_add(4)?;
                (end <= self.bytes.len()).then_some(end)
            }
            _ => (after_suffix <= self.bytes.len()).then_some(after_suffix),
        }
    }

    pub fn page_type(&self) -> PageType {
        self.page_type
    }

    pub fn n_slots(&self) -> usize {
        self.n_slots
    }

    pub fn prefix(&self) -> &'a [u8] {
        &self.bytes[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + self.prefix_len]
    }

    /// En nodos internos, el hijo más a la derecha. Cero en el resto de tipos.
    pub fn extra(&self) -> u32 {
        u32::from_le_bytes(self.bytes[12..16].try_into().unwrap())
    }

    /// Bytes completos de la celda `i`, tal como se almacenaron.
    pub fn cell(&self, i: usize) -> &'a [u8] {
        let off = self.slot(i);
        let end = self.cell_end(off).expect("validado en parse");
        &self.bytes[off..end]
    }

    /// Sufijo de clave de la celda `i`, sin el prefijo común de la página.
    pub fn suffix(&self, i: usize) -> &'a [u8] {
        let off = self.slot(i);
        let (len, n) = varint::read(&self.bytes[off..]).expect("validado en parse");
        &self.bytes[off + n..off + n + len as usize]
    }

    /// Busca `suffix` entre los sufijos de la página. `Ok(i)` si está en la
    /// posición `i`; `Err(i)` con el punto de inserción si no está.
    ///
    /// El llamante debe haber quitado antes el prefijo de la página a la clave
    /// buscada. Comparar sufijos equivale a comparar claves completas porque
    /// todas comparten exactamente el mismo prefijo.
    pub fn search(&self, suffix: &[u8]) -> core::result::Result<usize, usize> {
        let (mut lo, mut hi) = (0usize, self.n_slots);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.suffix(mid).cmp(suffix) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Ok(mid),
            }
        }
        Err(lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye una página cruda a mano para probar el lector sin depender
    /// todavía de `PageBuilder`.
    fn raw_leaf(prefix: &[u8], cells: &[&[u8]]) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0u8; 512];
        b[0] = PageType::Leaf as u8;
        b[2..4].copy_from_slice(&(cells.len() as u16).to_le_bytes());
        b[16..18].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
        b[20..20 + prefix.len()].copy_from_slice(prefix);
        let slots_at = 20 + prefix.len();
        let free_start = slots_at + 2 * cells.len();
        b[4..6].copy_from_slice(&(free_start as u16).to_le_bytes());
        let mut cursor = 512;
        for (i, cell) in cells.iter().enumerate() {
            cursor -= cell.len();
            b[cursor..cursor + cell.len()].copy_from_slice(cell);
            b[slots_at + 2 * i..slots_at + 2 * i + 2]
                .copy_from_slice(&(cursor as u16).to_le_bytes());
        }
        b[6..8].copy_from_slice(&(cursor as u16).to_le_bytes());
        let crc = {
            let mut h = crate::crc32::Hasher::new();
            h.update(&b[..8]);
            h.update(&b[12..]);
            h.finish()
        };
        b[8..12].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Celda de hoja: [len_sufijo varint][sufijo][len_valor varint][valor]
    fn leaf_cell(suffix: &[u8], value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut c = alloc::vec::Vec::new();
        let mut tmp = [0u8; 10];
        let n = crate::varint::write(&mut tmp, suffix.len() as u64);
        c.extend_from_slice(&tmp[..n]);
        c.extend_from_slice(suffix);
        let n = crate::varint::write(&mut tmp, value.len() as u64);
        c.extend_from_slice(&tmp[..n]);
        c.extend_from_slice(value);
        c
    }

    #[test]
    fn parses_a_well_formed_page() {
        let cells = [leaf_cell(b"aa", b"1"), leaf_cell(b"bb", b"2")];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let raw = raw_leaf(b"pre", &refs);
        let p = PageRef::parse(&raw, 3).unwrap();
        assert_eq!(p.page_type(), PageType::Leaf);
        assert_eq!(p.n_slots(), 2);
        assert_eq!(p.prefix(), b"pre");
        assert_eq!(p.cell(0), cells[0].as_slice());
        assert_eq!(p.cell(1), cells[1].as_slice());
    }

    #[test]
    fn rejects_a_page_with_a_bad_checksum() {
        let mut raw = raw_leaf(b"", &[]);
        raw[30] ^= 0xff;
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::Checksum })
        );
    }

    #[test]
    fn rejects_an_unknown_page_type() {
        let mut raw = raw_leaf(b"", &[]);
        raw[0] = 9;
        fix_crc(&mut raw);
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::PageType })
        );
    }

    #[test]
    fn rejects_a_slot_pointing_outside_the_page() {
        let cells = [leaf_cell(b"aa", b"1")];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let mut raw = raw_leaf(b"", &refs);
        raw[20..22].copy_from_slice(&600u16.to_le_bytes());
        fix_crc(&mut raw);
        assert_eq!(
            PageRef::parse(&raw, 7),
            Err(Error::Corrupt { page: 7, kind: CorruptKind::SlotOffset })
        );
    }

    #[test]
    fn binary_search_finds_present_and_missing_suffixes() {
        let cells = [
            leaf_cell(b"aa", b"1"),
            leaf_cell(b"cc", b"2"),
            leaf_cell(b"ee", b"3"),
        ];
        let refs: alloc::vec::Vec<&[u8]> = cells.iter().map(|c| c.as_slice()).collect();
        let raw = raw_leaf(b"k", &refs);
        let p = PageRef::parse(&raw, 1).unwrap();
        assert_eq!(p.search(b"cc"), Ok(1));
        assert_eq!(p.search(b"aa"), Ok(0));
        assert_eq!(p.search(b"ee"), Ok(2));
        assert_eq!(p.search(b"bb"), Err(1));
        assert_eq!(p.search(b"a"), Err(0));
        assert_eq!(p.search(b"zz"), Err(3));
    }

    fn fix_crc(b: &mut [u8]) {
        let mut h = crate::crc32::Hasher::new();
        h.update(&b[..8]);
        h.update(&b[12..]);
        let crc = h.finish();
        b[8..12].copy_from_slice(&crc.to_le_bytes());
    }
}
