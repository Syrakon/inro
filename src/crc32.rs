//! CRC-32 (IEEE 802.3, polinomio reflejado 0xEDB88320). Cuarenta líneas
//! escritas a mano en lugar de una dependencia.

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = make_table();

/// Acumulador incremental. Hace falta porque el CRC de una página cubre
/// tramos no contiguos: todo menos el propio campo de CRC.
#[derive(Clone)]
pub struct Hasher(u32);

impl Hasher {
    pub fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        for &byte in data {
            c = TABLE[((c ^ byte as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    pub fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

/// CRC-32 de `data`.
pub fn checksum(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vectors() {
        assert_eq!(checksum(b""), 0x0000_0000);
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
        assert_eq!(checksum(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut h = Hasher::new();
        h.update(b"1234");
        h.update(b"56789");
        assert_eq!(h.finish(), checksum(b"123456789"));
    }
}
