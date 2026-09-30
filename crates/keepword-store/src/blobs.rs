//! Content-addressed blob store keyed by BLAKE3.
//!
//! Most snapshots of a page are identical, so storing by hash deduplicates
//! them for free. Blobs are verified on read; a corrupted file is reported,
//! never returned.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use keepword_core::Digest;

use crate::StoreError;

pub struct BlobStore {
    dir: PathBuf,
}

impl BlobStore {
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("tmp"))?;
        Ok(BlobStore { dir })
    }

    fn path(&self, d: &Digest) -> PathBuf {
        let h = d.to_hex();
        self.dir.join(&h[..2]).join(&h[2..4]).join(h)
    }

    pub fn has(&self, d: &Digest) -> bool {
        self.path(d).exists()
    }

    pub fn put(&self, data: &[u8]) -> Result<Digest, StoreError> {
        let d = Digest::of(data);
        let path = self.path(&d);
        if path.exists() {
            return Ok(d);
        }
        fs::create_dir_all(path.parent().expect("blob path has parent"))?;
        // Write to a temp file and rename so readers never see partial blobs.
        let tmp = self
            .dir
            .join("tmp")
            .join(format!("{}.{}", d.to_hex(), std::process::id()));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(d)
    }

    pub fn get(&self, d: &Digest) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.path(d)) {
            Ok(data) => {
                if Digest::of(&data) != *d {
                    return Err(StoreError::Corrupt(format!(
                        "blob {d} fails its hash check"
                    )));
                }
                Ok(Some(data))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(&self, d: &Digest) -> Result<bool, StoreError> {
        match fs::remove_file(self.path(d)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dedup_and_corruption() {
        let t = tempfile::tempdir().unwrap();
        let s = BlobStore::open(t.path()).unwrap();
        let d = s.put(b"hello").unwrap();
        assert_eq!(s.put(b"hello").unwrap(), d);
        assert_eq!(s.get(&d).unwrap().unwrap(), b"hello");
        fs::write(s.path(&d), b"tampered").unwrap();
        assert!(s.get(&d).is_err());
        assert!(s.delete(&d).unwrap());
        assert!(s.get(&d).unwrap().is_none());
    }
}
