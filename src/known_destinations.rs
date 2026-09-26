//! Known destinations: destination hash → announced public key and app data,
//! persisted in SQLite (`known_destinations.sqlite3` in the storage path).
//!
//! One row per destination, written only when a destination is new, its key
//! or app data changed, or its stored last-seen time is an hour old
//! ([`merge`]), so a repeated announce costs nothing. SQLite in WAL mode
//! commits each row on its own; a process killed at any point leaves the
//! database whole, missing at most the row being written.
//!
//! Until 2026-09-26 the whole map was one msgpack file rewritten in place on
//! every announce: several MB, several times a second on rfed. A stop
//! mid-write left it truncated; the next start could not read it and began
//! empty without a word, and the first new key saved that over it. Every rfed
//! deploy forgot every public key it knew (63,594 in August, 1,378 after the
//! 2026-09-26 restart), and a notify wake to the push bridge failed with
//! "relay identity not known" until the bridge announced again. The
//! reference (Identity.py 1.5.2) writes a temp file and replaces, on its
//! persist job and at exit; the on-disk format is not shared with it (the
//! Rust msgpack layout already differed), so this store departs from the
//! file, not from the behaviour of remember and recall.
//!
//! Nothing here is ever deleted: the legacy file is renamed once imported,
//! and a file that cannot be read is logged and set aside, never overwritten.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde::Deserialize;

pub(crate) const DB_FILE: &str = "known_destinations.sqlite3";
/// The msgpack file every build before 2026-09-26 wrote.
pub(crate) const LEGACY_FILE: &str = "known_destinations";
/// A destination's stored last-seen time is refreshed at most this often.
pub(crate) const LAST_SEEN_REFRESH_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KnownDestination {
    pub public_key: Vec<u8>,
    pub app_data: Option<Vec<u8>>,
    /// Unix seconds this destination was last announced, as stored (so
    /// accurate to [`LAST_SEEN_REFRESH_SECS`]).
    pub last_seen: u64,
}

/// What an announce of `public_key` (with `app_data`, when it carried any)
/// makes of `existing`: the entry to store, or None when storage already
/// holds it. An announce without app data keeps the app data known.
pub(crate) fn merge(
    existing: Option<&KnownDestination>,
    public_key: &[u8],
    app_data: Option<Vec<u8>>,
    now: u64,
) -> Option<KnownDestination> {
    let Some(existing) = existing else {
        return Some(KnownDestination { public_key: public_key.to_vec(), app_data, last_seen: now });
    };
    let key_changed = existing.public_key != public_key;
    let app_data_changed = app_data.is_some() && existing.app_data != app_data;
    let stale = now.saturating_sub(existing.last_seen) >= LAST_SEEN_REFRESH_SECS;
    if !(key_changed || app_data_changed || stale) {
        return None;
    }
    Some(KnownDestination {
        public_key: public_key.to_vec(),
        app_data: if app_data.is_some() { app_data } else { existing.app_data.clone() },
        last_seen: now,
    })
}

pub(crate) struct KnownDestinationStore {
    conn: Connection,
}

impl KnownDestinationStore {
    /// Open (creating) the store in `storage_dir`, importing a legacy msgpack
    /// file if one is there, and return it with everything it holds.
    pub fn open(storage_dir: &Path) -> Result<(Self, HashMap<Vec<u8>, KnownDestination>), String> {
        fs::create_dir_all(storage_dir)
            .map_err(|e| format!("cannot create {}: {e}", storage_dir.display()))?;
        let db_path = storage_dir.join(DB_FILE);

        let store = match Self::open_db(&db_path) {
            Ok(store) => store,
            Err(e) => {
                let aside = set_aside(&db_path, &["-wal", "-shm"]);
                crate::log(
                    format!(
                        "Known destinations database {} could not be opened ({e}); set aside as {}, starting a new one",
                        db_path.display(),
                        aside.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                    ),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
                Self::open_db(&db_path)?
            }
        };

        store.import_legacy(storage_dir);

        let map = store.load_all()?;
        crate::log(format!("Loaded {} known destinations from storage", map.len()), crate::LOG_VERBOSE, false, false);
        Ok((store, map))
    }

    fn open_db(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        conn.busy_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())?;
        // WAL: a commit is one append, and a killed process never leaves the
        // database half-written. NORMAL: no fsync per commit; a power loss
        // can lose the last commits, never the database.
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS known_destinations (
                 destination_hash BLOB PRIMARY KEY NOT NULL,
                 public_key       BLOB NOT NULL,
                 app_data         BLOB,
                 last_seen        INTEGER NOT NULL
             ) WITHOUT ROWID;",
        )
        .map_err(|e| e.to_string())?;
        // A file that is not a database fails here, not on first use.
        conn.query_row("SELECT count(*) FROM known_destinations", [], |_| Ok(()))
            .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    fn load_all(&self) -> Result<HashMap<Vec<u8>, KnownDestination>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT destination_hash, public_key, app_data, last_seen FROM known_destinations")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    KnownDestination {
                        public_key: row.get(1)?,
                        app_data: row.get(2)?,
                        last_seen: row.get::<_, i64>(3)?.max(0) as u64,
                    },
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<HashMap<_, _>, _>>().map_err(|e| e.to_string())
    }

    /// Store one destination (insert or replace).
    pub fn put(&self, destination_hash: &[u8], entry: &KnownDestination) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO known_destinations (destination_hash, public_key, app_data, last_seen)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(destination_hash) DO UPDATE SET
                     public_key = excluded.public_key,
                     app_data   = excluded.app_data,
                     last_seen  = excluded.last_seen",
                params![destination_hash, entry.public_key, entry.app_data, entry.last_seen as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Write a consistent copy of the database to `target` (for a process
    /// that keeps its own storage, such as the iOS notification extension).
    /// Built beside `target` and renamed over it, so a reader never sees a
    /// partial copy.
    pub fn snapshot_to(&self, target: &Path) -> Result<(), String> {
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("invalid snapshot path {}", target.display()))?;
        let tmp = target.with_file_name(format!("{name}.tmp-{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let tmp_str = tmp.to_str().ok_or_else(|| format!("invalid snapshot path {}", tmp.display()))?;
        self.conn.execute("VACUUM INTO ?1", params![tmp_str]).map_err(|e| e.to_string())?;
        // A WAL left by a previous copy would be replayed onto this one.
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", target.display()));
        }
        fs::rename(&tmp, target).map_err(|e| format!("cannot place snapshot at {}: {e}", target.display()))
    }

    /// Import the msgpack file written before 2026-09-26, once. Rows the
    /// database already holds are kept. The file is renamed afterwards, never
    /// deleted; one that cannot be read is set aside and logged.
    fn import_legacy(&self, storage_dir: &Path) {
        let legacy = storage_dir.join(LEGACY_FILE);
        if !legacy.is_file() {
            return;
        }
        match read_legacy(&legacy) {
            Ok(entries) => {
                let now = unix_now_secs();
                match self.insert_missing(&entries, now) {
                    Ok(added) => {
                        let moved = rename_with_stamp(&legacy, "imported");
                        crate::log(
                            format!(
                                "Imported {added} of {} known destinations from {} (kept as {})",
                                entries.len(),
                                legacy.display(),
                                moved.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                            ),
                            crate::LOG_NOTICE,
                            false,
                            false,
                        );
                    }
                    // Left in place: the next start tries again.
                    Err(e) => crate::log(
                        format!("Could not import known destinations from {}: {e}", legacy.display()),
                        crate::LOG_ERROR,
                        false,
                        false,
                    ),
                }
            }
            Err(e) => {
                let moved = rename_with_stamp(&legacy, "unreadable");
                crate::log(
                    format!(
                        "Legacy known destinations file {} could not be read ({e}); set aside as {}",
                        legacy.display(),
                        moved.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                    ),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
            }
        }
    }

    fn insert_missing(&self, entries: &HashMap<Vec<u8>, (Vec<u8>, Option<Vec<u8>>)>, now: u64) -> Result<usize, String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut added = 0;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR IGNORE INTO known_destinations (destination_hash, public_key, app_data, last_seen)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(|e| e.to_string())?;
            for (hash, (public_key, app_data)) in entries {
                added += stmt.execute(params![hash, public_key, app_data, now as i64]).map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(added)
    }
}

/// The legacy entry layout (rmp_serde of the old struct).
#[derive(Deserialize)]
struct LegacyEntry {
    public_key: Vec<u8>,
    app_data: Option<Vec<u8>>,
}

/// Read a legacy msgpack file in either layout it was written in.
pub(crate) fn read_legacy(path: &Path) -> Result<HashMap<Vec<u8>, (Vec<u8>, Option<Vec<u8>>)>, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    if let Ok(map) = rmp_serde::from_slice::<HashMap<Vec<u8>, LegacyEntry>>(&data) {
        return Ok(map.into_iter().map(|(h, e)| (h, (e.public_key, e.app_data))).collect());
    }
    let keys_only = rmp_serde::from_slice::<HashMap<Vec<u8>, Vec<u8>>>(&data).map_err(|e| e.to_string())?;
    Ok(keys_only.into_iter().map(|(h, k)| (h, (k, None))).collect())
}

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Rename `path` to `<path>.<label>-<unix secs>`; None when it could not be moved.
fn rename_with_stamp(path: &Path, label: &str) -> Option<PathBuf> {
    let target = PathBuf::from(format!("{}.{label}-{}", path.display(), unix_now_secs()));
    fs::rename(path, &target).ok().map(|_| target)
}

/// Set a database that cannot be opened aside, with its WAL and shared-memory
/// files, so a new one can be made without destroying it.
fn set_aside(db_path: &Path, companions: &[&str]) -> Option<PathBuf> {
    let moved = rename_with_stamp(db_path, "unreadable");
    if let Some(moved) = &moved {
        for suffix in companions {
            let companion = PathBuf::from(format!("{}{suffix}", db_path.display()));
            if companion.exists() {
                let _ = fs::rename(&companion, format!("{}{suffix}", moved.display()));
            }
        }
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-known-destinations-{name}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(key: u8, app_data: Option<&[u8]>, last_seen: u64) -> KnownDestination {
        KnownDestination { public_key: vec![key; 64], app_data: app_data.map(|a| a.to_vec()), last_seen }
    }

    fn files_starting(dir: &Path, prefix: &str) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with(prefix))
            .collect()
    }

    #[derive(Serialize)]
    struct WrittenLegacyEntry {
        public_key: Vec<u8>,
        app_data: Option<Vec<u8>>,
    }

    fn legacy_bytes(n: u8) -> Vec<u8> {
        let map: HashMap<Vec<u8>, WrittenLegacyEntry> = (0..n)
            .map(|i| (vec![i; 16], WrittenLegacyEntry { public_key: vec![i; 64], app_data: Some(vec![i]) }))
            .collect();
        rmp_serde::to_vec(&map).unwrap()
    }

    #[test]
    fn what_is_stored_survives_a_reopen() {
        let dir = temp_dir("reopen");
        {
            let (store, map) = KnownDestinationStore::open(&dir).unwrap();
            assert!(map.is_empty());
            store.put(&[1; 16], &entry(1, Some(b"a"), 100)).unwrap();
            store.put(&[2; 16], &entry(2, None, 200)).unwrap();
            store.put(&[1; 16], &entry(1, Some(b"b"), 300)).unwrap();
        }
        let (_, map) = KnownDestinationStore::open(&dir).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[&vec![1; 16]], entry(1, Some(b"b"), 300));
        assert_eq!(map[&vec![2; 16]], entry(2, None, 200));
        fs::remove_dir_all(dir).ok();
    }

    /// The upgrade: every key the old file held is kept, and the file is
    /// renamed, not deleted, so it is imported once.
    #[test]
    fn the_legacy_file_is_imported_once_and_kept() {
        let dir = temp_dir("legacy");
        let bytes = legacy_bytes(5);
        fs::write(dir.join(LEGACY_FILE), &bytes).unwrap();

        let (store, map) = KnownDestinationStore::open(&dir).unwrap();
        assert_eq!(map.len(), 5);
        assert_eq!(map[&vec![3; 16]].public_key, vec![3; 64]);
        assert_eq!(map[&vec![3; 16]].app_data, Some(vec![3]));
        assert!(!dir.join(LEGACY_FILE).exists());
        let kept = files_starting(&dir, "known_destinations.imported-");
        assert_eq!(kept.len(), 1);
        assert_eq!(fs::read(&kept[0]).unwrap(), bytes, "kept byte for byte");

        // A newer row is not overwritten by a later legacy file.
        store.put(&[3; 16], &entry(9, None, 1)).unwrap();
        drop(store);
        fs::write(dir.join(LEGACY_FILE), &bytes).unwrap();
        let (_, map) = KnownDestinationStore::open(&dir).unwrap();
        assert_eq!(map[&vec![3; 16]].public_key, vec![9; 64]);
        fs::remove_dir_all(dir).ok();
    }

    /// The failure that emptied rfed's keys on every deploy: a file cut off
    /// mid-write. It is set aside intact and logged, not overwritten.
    #[test]
    fn a_truncated_legacy_file_is_set_aside_not_overwritten() {
        let dir = temp_dir("truncated");
        let bytes = legacy_bytes(40);
        let truncated = &bytes[..bytes.len() / 2];
        fs::write(dir.join(LEGACY_FILE), truncated).unwrap();

        let (store, map) = KnownDestinationStore::open(&dir).unwrap();
        assert!(map.is_empty());
        store.put(&[7; 16], &entry(7, None, 1)).unwrap();
        let aside = files_starting(&dir, "known_destinations.unreadable-");
        assert_eq!(aside.len(), 1);
        assert_eq!(fs::read(&aside[0]).unwrap(), truncated, "kept byte for byte");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_database_that_cannot_be_read_is_set_aside() {
        let dir = temp_dir("baddb");
        fs::write(dir.join(DB_FILE), b"this is not a database, it is sixteen bytes and more").unwrap();

        let (store, map) = KnownDestinationStore::open(&dir).unwrap();
        assert!(map.is_empty());
        store.put(&[1; 16], &entry(1, None, 1)).unwrap();
        let aside = files_starting(&dir, "known_destinations.sqlite3.unreadable-");
        assert_eq!(aside.len(), 1);
        assert!(fs::read(&aside[0]).unwrap().starts_with(b"this is not a database"));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_snapshot_is_a_complete_database() {
        let dir = temp_dir("snapshot");
        let other = temp_dir("snapshot-target");
        let (store, _) = KnownDestinationStore::open(&dir).unwrap();
        for i in 0..50u8 {
            store.put(&[i; 16], &entry(i, Some(&[i]), i as u64)).unwrap();
        }
        store.snapshot_to(&other.join(DB_FILE)).unwrap();
        // Twice: the second replaces the first.
        store.put(&[99; 16], &entry(99, None, 1)).unwrap();
        store.snapshot_to(&other.join(DB_FILE)).unwrap();

        let (_, copied) = KnownDestinationStore::open(&other).unwrap();
        assert_eq!(copied.len(), 51);
        assert_eq!(copied[&vec![42; 16]], entry(42, Some(&[42]), 42));
        assert!(files_starting(&other, "known_destinations.sqlite3.tmp-").is_empty());
        fs::remove_dir_all(dir).ok();
        fs::remove_dir_all(other).ok();
    }

    #[test]
    fn a_repeated_announce_writes_nothing() {
        let known = entry(1, Some(b"x"), 1_000);
        assert_eq!(merge(None, &[1; 64], None, 5), Some(entry(1, None, 5)), "new: stored");
        assert_eq!(merge(Some(&known), &[1; 64], None, 1_010), None, "same key, no app data");
        assert_eq!(merge(Some(&known), &[1; 64], Some(b"x".to_vec()), 1_010), None, "same app data");
        assert_eq!(
            merge(Some(&known), &[1; 64], Some(b"y".to_vec()), 1_010),
            Some(entry(1, Some(b"y"), 1_010)),
            "app data changed"
        );
        assert_eq!(merge(Some(&known), &[2; 64], None, 1_010), Some(entry(2, Some(b"x"), 1_010)), "key changed; app data kept");
        assert_eq!(
            merge(Some(&known), &[1; 64], None, 1_000 + LAST_SEEN_REFRESH_SECS),
            Some(entry(1, Some(b"x"), 1_000 + LAST_SEEN_REFRESH_SECS)),
            "last seen an hour old"
        );
    }
}
