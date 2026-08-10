//! LEB128 sin signo. Se escribe a mano: es la codificación más usada del motor
//! y no justifica una dependencia.

/// Bytes que ocupa `v` codificado.
pub fn len(v: u64) -> usize {
    let bits = 64 - v.leading_zeros() as usize;
    if bits == 0 { 1 } else { bits.div_ceil(7) }
}

/// Escribe `v` al principio de `buf` y devuelve los bytes usados.
/// Entra en pánico si `buf` es más corto que `len(v)`: el llamante siempre
/// reserva con `len` antes, así que un fallo aquí es un error de programación.
pub fn write(buf: &mut [u8], mut v: u64) -> usize {
    let mut i = 0;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf[i] = byte;
            return i + 1;
        }
        buf[i] = byte | 0x80;
        i += 1;
    }
}

/// Lee un varint del principio de `buf`. Devuelve el valor y los bytes
/// consumidos, o `None` si la entrada está truncada o la codificación excede
/// los 64 bits.
pub fn read(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_covers_boundaries() {
        let mut buf = [0u8; 10];
        for v in [0u64, 1, 127, 128, 16_383, 16_384, u32::MAX as u64, u64::MAX] {
            let n = write(&mut buf, v);
            assert_eq!(n, len(v), "len desacorde para {v}");
            assert_eq!(read(&buf[..n]), Some((v, n)));
        }
    }

    #[test]
    fn read_rejects_truncated_input() {
        assert_eq!(read(&[0x80]), None);
        assert_eq!(read(&[]), None);
    }

    #[test]
    fn read_rejects_overlong_encoding() {
        // Once bytes con el bit de continuación: más de lo que cabe en u64.
        assert_eq!(read(&[0x80; 11]), None);
    }
}
