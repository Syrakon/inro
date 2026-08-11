use crate::Result;

/// Abstracción del medio de almacenamiento. Toma `&self` también en las
/// escrituras porque el escritor es único y los lectores son concurrentes: la
/// exclusión mutua la impone `WriteTxn`, no el tipo. `FileStorage` lo cumple
/// con `pread`/`pwrite`, que no mueven un cursor compartido y por tanto no
/// necesitan `&mut`.
pub trait Storage: Send + Sync {
    /// Llena `buf` desde `offset`. Falla con `UnexpectedEof` si no hay bytes
    /// suficientes: una lectura corta significa fichero truncado, y devolver
    /// un buffer a medio llenar escondería la corrupción.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Escribe `buf` en `offset`, extendiendo el medio si hace falta.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Fuerza a disco lo escrito hasta ahora.
    fn sync(&self) -> Result<()>;

    fn len(&self) -> Result<u64>;
}

#[cfg(feature = "std")]
pub use imp_std::{FileStorage, MemStorage};

#[cfg(feature = "std")]
mod imp_std {
    use super::Storage;
    use crate::{Error, IoError, Result};
    use std::fs::{File, OpenOptions};
    use std::path::Path;
    use std::sync::Mutex;

    fn map_io(e: std::io::Error) -> Error {
        use std::io::ErrorKind as K;
        Error::Io(match e.kind() {
            K::NotFound => IoError::NotFound,
            K::PermissionDenied => IoError::PermissionDenied,
            K::UnexpectedEof => IoError::UnexpectedEof,
            K::WriteZero => IoError::WriteZero,
            _ => IoError::Other(e.raw_os_error().unwrap_or(0)),
        })
    }

    pub struct MemStorage {
        data: Mutex<Vec<u8>>,
        reads: std::sync::atomic::AtomicU64,
    }

    impl MemStorage {
        pub fn new() -> Self {
            Self { data: Mutex::new(Vec::new()), reads: std::sync::atomic::AtomicU64::new(0) }
        }

        /// Copia del contenido completo. Solo para pruebas.
        pub fn snapshot(&self) -> Vec<u8> {
            self.data.lock().unwrap().clone()
        }

        /// Restaura el contenido completo. Solo para pruebas.
        pub fn restore(&self, bytes: Vec<u8>) {
            *self.data.lock().unwrap() = bytes;
        }

        /// Número de llamadas a `read_at` desde la creación o el último
        /// `reset_read_count`. Solo para pruebas: mide el coste de apertura
        /// contando lecturas, no tiempo.
        pub fn read_count(&self) -> u64 {
            self.reads.load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn reset_read_count(&self) {
            self.reads.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl Storage for MemStorage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let data = self.data.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                return Err(Error::Io(IoError::UnexpectedEof));
            }
            buf.copy_from_slice(&data[start..end]);
            Ok(())
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            let mut data = self.data.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&self) -> Result<()> {
            Ok(())
        }

        fn len(&self) -> Result<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }
    }

    pub struct FileStorage {
        file: File,
    }

    impl FileStorage {
        pub fn open(path: &Path) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .map_err(map_io)?;
            Ok(Self { file })
        }
    }

    impl Storage for FileStorage {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            read_exact_at(&self.file, offset, buf)
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            write_all_at(&self.file, offset, buf)
        }

        fn sync(&self) -> Result<()> {
            self.file.sync_all().map_err(map_io)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.file.metadata().map_err(map_io)?.len())
        }
    }

    #[cfg(unix)]
    fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset).map_err(map_io)
    }

    #[cfg(unix)]
    fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset).map_err(map_io)
    }

    #[cfg(windows)]
    fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match file.seek_read(buf, offset).map_err(map_io)? {
                0 => return Err(Error::Io(IoError::UnexpectedEof)),
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn write_all_at(file: &File, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match file.seek_write(buf, offset).map_err(map_io)? {
                0 => return Err(Error::Io(IoError::WriteZero)),
                n => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::{Error, IoError};

    fn exercise<S: Storage>(s: &S) {
        s.write_at(0, b"hola").unwrap();
        s.write_at(4, b"mundo").unwrap();
        let mut buf = [0u8; 9];
        s.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"holamundo");
        assert_eq!(s.len().unwrap(), 9);
    }

    #[test]
    fn mem_storage_reads_back_what_it_wrote() {
        exercise(&MemStorage::new());
    }

    #[test]
    fn writing_past_the_end_grows_the_backing_store() {
        let s = MemStorage::new();
        s.write_at(100, b"x").unwrap();
        assert_eq!(s.len().unwrap(), 101);
        let mut buf = [0xffu8; 1];
        s.read_at(50, &mut buf).unwrap();
        assert_eq!(buf[0], 0, "el hueco se rellena con ceros");
    }

    #[test]
    fn reading_past_the_end_is_an_error() {
        let s = MemStorage::new();
        s.write_at(0, b"ab").unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(s.read_at(0, &mut buf), Err(Error::Io(IoError::UnexpectedEof)));
    }
}
