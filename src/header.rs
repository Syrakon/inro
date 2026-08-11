use crate::{crc32, CorruptKind, Error, Result, Storage};

pub const HEADER_SIZE: usize = 64;
pub const MAGIC: &[u8; 8] = b"INRO\0DB\x01";
pub const FORMAT_MAJOR: u16 = 1;

pub const MIN_PAGE_SIZE: u32 = 512;
/// 32 KB, no 64 KB. El campo `cell_start` de la cabecera de página es `u16` y no
/// puede expresar 65536, así que una página sin celdas a ese tamaño se truncaría a
/// cero y `parse` la rechazaría — lo que dejaría inservibles las páginas de lista de
/// libres y de overflow, que siempre escriben `cell_start = page_size`. Bajar el
/// máximo elimina la clase entera de fallo sin tocar el formato, y no cuesta nada:
/// el motor usa 512 B por defecto y 4 KB en los tiers grandes.
pub const MAX_PAGE_SIZE: u32 = 32_768;

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
            (9..=15).contains(&self.page_size.trailing_zeros()),
            "page_size {} fuera del rango admitido de 512 B a 32 KB",
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
        if !(9..=15).contains(&log2) {
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

    /// Lee la cabecera principal (página `0`, offset `0`); si no decodifica
    /// (CRC roto, magic ausente, cualquier motivo), cae al espejo (tarea
    /// 18, hallazgo HIGH de revisión) antes de rendirse.
    ///
    /// La cabecera se escribe una sola vez en toda la vida del fichero,
    /// salvo por `WriteTxn::relocate_meta_b` — la única reescritura que
    /// existe (tarea 18). Antes de esa tarea, "se escribe una vez y nunca
    /// más" era en sí mismo lo que la protegía de un corte de corriente: no
    /// hay ninguna ESCRITURA que un corte pueda desgarrar salvo la primera,
    /// y si esa se pierde entera, `Db::create` nunca llegó a devolver
    /// `Ok`, así que no hay ningún commit previo que proteger — el
    /// llamante no tiene nada que perder. La reescritura de `relocate_meta_b`
    /// es distinta: corre sobre un fichero que YA tiene commits reales
    /// detrás, y un corte a medio escribir la deja con un CRC que no
    /// corresponde a sus propios bytes — `Geometry::decode` lo rechaza sin
    /// poder distinguir "cabecera vieja intacta" de "cabecera nueva a
    /// medias": las dos fallan el mismo CRC. Sin más protección, `Db::open`
    /// fallaría para siempre — todo lo demás (las dos metas, el árbol
    /// entero) sigue intacto, pero inalcanzable, porque nada llega a leer
    /// más allá de la cabecera.
    pub fn read(storage: &dyn Storage) -> Result<Self> {
        let mut b = [0u8; HEADER_SIZE];
        storage.read_at(0, &mut b)?;
        match Self::decode(&b) {
            Ok(g) => Ok(g),
            Err(primary_err) => {
                let mut mirror = [0u8; HEADER_SIZE];
                match storage.read_at(HEADER_MIRROR_OFFSET, &mut mirror).ok().and_then(|()| Self::decode(&mirror).ok()) {
                    Some(g) => Ok(g),
                    // Sin espejo legible tampoco: el error de la PRINCIPAL,
                    // no el del espejo, es el que quien llama espera — es
                    // el mismo `Err` que devolvía este método antes de que
                    // el espejo existiera (bases creadas antes de la tarea
                    // 18, o un espejo que nunca llegó a escribirse porque la
                    // base nunca reubicó).
                    None => Err(primary_err),
                }
            }
        }
    }

    pub fn write(&self, storage: &dyn Storage) -> Result<()> {
        storage.write_at(0, &self.encode())
    }

    /// Copia de la cabecera en `HEADER_MIRROR_OFFSET` (tarea 18): la escribe
    /// solo `WriteTxn::relocate_meta_b`, ANTES de reescribir la principal —
    /// ver su comentario para el orden completo y por qué protege contra un
    /// corte a medio escribir cualquiera de las dos copias. Cabe siempre:
    /// para cuando `relocate_meta_b` corre, la base ya tiene al menos la
    /// meta A escrita, así que la página `0` ya se extendió hasta
    /// `page_size` (como mínimo `MIN_PAGE_SIZE` = 512 B) — muy por encima de
    /// `HEADER_MIRROR_OFFSET + HEADER_SIZE` = 128.
    pub fn write_mirror(&self, storage: &dyn Storage) -> Result<()> {
        storage.write_at(HEADER_MIRROR_OFFSET, &self.encode())
    }
}

/// Offset del espejo de la cabecera (tarea 18). Vive a un offset de
/// fichero FIJO, no en función de `page_size` — deliberado: para poder
/// leerlo hace falta saber dónde está, y si dependiera de `page_size`
/// eso crearía el mismo problema de huevo-y-gallina que la reubicación
/// vino a evitar (no se puede saber `page_size` sin antes poder leer la
/// cabecera). `HEADER_SIZE` (64), justo después de la principal: la
/// página `0` mide como mínimo `MIN_PAGE_SIZE` (512 B) en cuanto la base
/// tiene una sola página más escrita, así que sobra espacio de sobra sin
/// tocar el formato de página en absoluto — son bytes crudos del fichero,
/// no una página con su propia estructura.
pub const HEADER_MIRROR_OFFSET: u64 = HEADER_SIZE as u64;

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
        g.page_size = MAX_PAGE_SIZE; // 32_768 (log2 = 15)
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
        for log2 in [0u8, 8, 16] {
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

    /// Cobertura unitaria y directa del hallazgo HIGH de revisión (tarea
    /// 18): `Geometry::read` tiene que caer al espejo cuando la principal
    /// no decodifica — las pruebas de más alto nivel (`tx.rs`, `crypto.rs`)
    /// ya lo comprueban de punta a punta a través de `relocate_meta_b`
    /// real, pero esta prueba aísla el mecanismo en sí, sin pasar por
    /// ningún `WriteTxn`.
    #[test]
    #[cfg(feature = "std")]
    fn read_falls_back_to_the_mirror_when_the_primary_does_not_decode() {
        use crate::storage::MemStorage;
        let s = MemStorage::new();
        let g = sample();
        g.write(&s).unwrap();
        g.write_mirror(&s).unwrap();

        // Corrompe solo la principal (un byte dentro de `meta_b_page`, sin
        // arreglar el CRC): el espejo sigue intacto.
        let mut bytes = [0u8; HEADER_SIZE];
        s.read_at(0, &mut bytes).unwrap();
        bytes[45] ^= 0xff;
        s.write_at(0, &bytes).unwrap();

        assert_eq!(Geometry::read(&s).unwrap(), g, "debio caer al espejo, todavia legible");
    }

    /// Sin espejo en absoluto — una base creada antes de que existiera, o
    /// que nunca llegó a reubicar — `read` debe devolver el mismo error que
    /// devolvía antes de esta tarea, no uno distinto sobre el espejo (que
    /// ni siquiera se ha escrito nunca, así que decodificarlo es, como
    /// mucho, `UnexpectedEof` sobre un fichero mas corto).
    #[test]
    #[cfg(feature = "std")]
    fn read_fails_with_the_primary_error_when_there_is_no_mirror_to_fall_back_to() {
        use crate::storage::MemStorage;
        let s = MemStorage::new();
        let g = sample();
        g.write(&s).unwrap();
        // Ningun `write_mirror`: el fichero ni siquiera llega al offset del
        // espejo.

        let mut bytes = [0u8; HEADER_SIZE];
        s.read_at(0, &mut bytes).unwrap();
        bytes[45] ^= 0xff;
        s.write_at(0, &bytes).unwrap();

        assert!(matches!(
            Geometry::read(&s),
            Err(Error::Corrupt { page: 0, kind: CorruptKind::Checksum })
        ));
    }

    /// La principal, cuando decodifica, gana siempre — el espejo ni se
    /// mira. No debería importar en la práctica (las dos copias siempre
    /// deberían coincidir cuando ambas son legibles, porque
    /// `relocate_meta_b` escribe la misma `Geometry` en las dos), pero
    /// confirma que `read` no tiene ninguna lógica de "el espejo manda" por
    /// accidente.
    #[test]
    #[cfg(feature = "std")]
    fn read_prefers_the_primary_over_the_mirror_when_both_decode() {
        use crate::storage::MemStorage;
        let s = MemStorage::new();
        let primary = sample();
        primary.write(&s).unwrap();
        let mut mirror = sample();
        mirror.created_unix += 1;
        mirror.write_mirror(&s).unwrap();

        assert_eq!(Geometry::read(&s).unwrap(), primary);
    }
}
