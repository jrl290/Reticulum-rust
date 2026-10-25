//! The persisted Bluetooth identity: `<storage_dir>/ble_identity`, in the
//! record Prns writes (`wire::encode_identity_record`).
//!
//! Copyright (c) 2026 The Prns Authors
//! Copyright (c) 2026 James LaFarge
//! SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::wire::{self, IDENTITY_LEN};

/// What `load_or_create` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// The record was there and intact.
    Existing([u8; IDENTITY_LEN]),
    /// There was no record, or a damaged one (`damaged` says what was
    /// wrong with it), and a new identity has been written.
    Created { identity: [u8; IDENTITY_LEN], damaged: Option<String> },
}

impl Loaded {
    pub fn identity(&self) -> [u8; IDENTITY_LEN] {
        match self {
            Loaded::Existing(identity) | Loaded::Created { identity, .. } => *identity,
        }
    }
}

/// Loads `<storage_dir>/ble_identity`, creating it on first use. The
/// identity persists by design: RTNode keys the phone's interface by it.
pub fn load_or_create(storage_dir: &Path) -> Result<Loaded, String> {
    let path: PathBuf = storage_dir.join("ble_identity");
    let damaged = match std::fs::read(&path) {
        Ok(record) => match wire::decode_identity_record(&record) {
            Ok(identity) => return Ok(Loaded::Existing(identity)),
            Err(why) => Some(format!("{}: {why}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut identity = [0u8; IDENTITY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut identity);
    std::fs::create_dir_all(storage_dir).map_err(|e| format!("cannot create {}: {e}", storage_dir.display()))?;
    let temp = storage_dir.join("ble_identity.tmp");
    std::fs::write(&temp, wire::encode_identity_record(&identity)).map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, &path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(Loaded::Created { identity, damaged })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_created_once_and_then_read_back() {
        let dir = std::env::temp_dir().join(format!("prns-ble-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = load_or_create(&dir).unwrap();
        assert!(matches!(first, Loaded::Created { damaged: None, .. }));
        assert_eq!(load_or_create(&dir).unwrap(), Loaded::Existing(first.identity()));
        let record = std::fs::read(dir.join("ble_identity")).unwrap();
        assert_eq!(wire::decode_identity_record(&record), Ok(first.identity()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_identity_record_is_replaced() {
        let dir = std::env::temp_dir().join(format!("prns-ble-identity-damaged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ble_identity"), b"not a record").unwrap();
        let loaded = load_or_create(&dir).unwrap();
        assert!(matches!(&loaded, Loaded::Created { damaged: Some(_), .. }));
        assert_eq!(wire::decode_identity_record(&std::fs::read(dir.join("ble_identity")).unwrap()), Ok(loaded.identity()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
