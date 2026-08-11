use crate::{crc32, CorruptKind, Error, Result, Storage};

pub const HEADER_SIZE: usize = 64;
pub const MAGIC: &[u8; 8] = b"INRO\0DB\x01";
pub const FORMAT_MAJOR: u16 = 1;

pub const MIN_PAGE_SIZE: u32 = 512;
pub const MAX_PAGE_SIZE: u32 = 65_536;

/// Cifrado activo. Fijo en la creación: activarlo después exigiría reescribir
/// todas las páginas.
pub const FLAG_ENCRYPTED: u8 = 0b0000_0001;
/// Compresión de prefijo por página activa.
pub const FLAG_PREFIX_COMPRESSION: u8 = 0b0000_0010;

/// Identidad y geometría del fichero. Se escribe una vez al crear y no se
/// reescribe: por eso el puntero a la raíz vive en las meta-páginas y no aquí.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub page_size: u32,
    pub format_major: u16,
    pub format_minor: u16,
    pub flags: u8,
    pub db_id: [u8; 16],
    pub created_unix: u64,
    pub meta_a_page: u32,
    pub meta_b_page: u32,
}

impl Geometry {
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        // `encode` derives log2 from `trailing_zeros`, which only means "log base 2"
        // for a power of two: 1536.trailing_zeros() is 9, so a non-power-of-two would
        // silently encode as 512 and decode back as 512. Both halves are load-bearing.
        debug_assert!(
            self.page_size.is_power_of_two(),
            "page_size {} no es potencia de dos",
            self.page_size
        );
        debug_assert!(
            (9..=16).contains(&self.page_size.trailing_zeros()),
            "page_size {} fuera del rango admitido de 512 B a 64 KB",
            self.page_size
        );
        let mut b = [0u8; HEADER_SIZE];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&self.format_major.to_le_bytes());
        b[10..12].copy_from_slice(&self.format_minor.to_le_bytes());
        b[12] = self.page_size.trailing_zeros() as u8;
        b[13] = self.flags;
        // 14..16 reservado
        b[16..32].copy_from_slice(&self.db_id);
        b[32..40].copy_from_slice(&self.created_unix.to_le_bytes());
        b[40..44].copy_from_slice(&self.meta_a_page.to_le_bytes());
        b[44..48].copy_from_slice(&self.meta_b_page.to_le_bytes());
        // 48..60 reservado
        let crc = crc32::checksum(&b[..HEADER_SIZE - 4]);
        b[HEADER_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; HEADER_SIZE]) -> Result<Self> {
        if &b[0..8] != MAGIC {
            return Err(Error::BadFormat);
        }
        // El CRC se comprueba antes que cualquier otro campo: sin él, una
        // geometría corrupta se interpretaría como válida.
        let stored = u32::from_le_bytes(b[HEADER_SIZE - 4..].try_into().unwrap());
        if stored != crc32::checksum(&b[..HEADER_SIZE - 4]) {
            return Err(Error::Corrupt { page: 0, kind: CorruptKind::Checksum });
        }
        let format_major = u16::from_le_bytes(b[8..10].try_into().unwrap());
        if format_major > FORMAT_MAJOR {
            return Err(Error::VersionTooNew { found: format_major, supported: FORMAT_MAJOR });
        }
        let log2 = b[12] as u32;
        if !(9..=16).contains(&log2) {
            return Err(Error::BadFormat);
        }
        Ok(Self {
            page_size: 1u32 << log2,
            format_major,
            format_minor: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            flags: b[13],
            db_id: b[16..32].try_into().unwrap(),
            created_unix: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            meta_a_page: u32::from_le_bytes(b[40..44].try_into().unwrap()),
            meta_b_page: u32::from_le_bytes(b[44..48].try_into().unwrap()),
        })
    }

    pub fn read(storage: &dyn Storage) -> Result<Self> {
        let mut b = [0u8; HEADER_SIZE];
        storage.read_at(0, &mut b)?;
        Self::decode(&b)
    }

    pub fn write(&self, storage: &dyn Storage) -> Result<()> {
        storage.write_at(0, &self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Geometry {
        Geometry {
            page_size: 512,
            format_major: FORMAT_MAJOR,
            format_minor: 0,
            flags: 0,
            db_id: [7u8; 16],
            created_unix: 1_760_000_000,
            meta_a_page: 1,
            meta_b_page: 8,
        }
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let g = sample();
        assert_eq!(Geometry::decode(&g.encode()).unwrap(), g);
    }

    #[test]
    fn roundtrip_at_max_page_size() {
        let mut g = sample();
        g.page_size = MAX_PAGE_SIZE; // 65_536 (log2 = 16)
        assert_eq!(Geometry::decode(&g.encode()).unwrap(), g);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "no es potencia de dos")]
    fn encode_rejects_a_page_size_that_is_not_a_power_of_two() {
        let mut g = sample();
        g.page_size = 1536;
        let _ = g.encode();
    }

    #[test]
    fn rejects_a_file_that_is_not_inro() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        assert_eq!(Geometry::decode(&bytes), Err(Error::BadFormat));
    }

    #[test]
    fn rejects_a_newer_format() {
        let mut g = sample();
        g.format_major = FORMAT_MAJOR + 1;
        assert_eq!(
            Geometry::decode(&g.encode()),
            Err(Error::VersionTooNew { found: FORMAT_MAJOR + 1, supported: FORMAT_MAJOR })
        );
    }

    #[test]
    fn rejects_a_corrupted_header() {
        let mut bytes = sample().encode();
        bytes[20] ^= 0xff; // dentro de db_id, no del crc
        assert!(matches!(
            Geometry::decode(&bytes),
            Err(Error::Corrupt { page: 0, kind: CorruptKind::Checksum })
        ));
    }

    #[test]
    fn rejects_an_impossible_page_size() {
        for log2 in [0u8, 8, 17] {
            let mut bytes = sample().encode();
            bytes[12] = log2;
            fix_crc(&mut bytes);
            assert_eq!(Geometry::decode(&bytes), Err(Error::BadFormat), "log2={log2}");
        }
    }

    fn fix_crc(bytes: &mut [u8; HEADER_SIZE]) {
        let crc = crate::crc32::checksum(&bytes[..HEADER_SIZE - 4]);
        bytes[HEADER_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    }
}
