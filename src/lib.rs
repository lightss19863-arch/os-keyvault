//! # os-keyvault
//!
//! Cross-platform wrapper around OS-native credential stores for desktop apps
//! that need to hold encryption keys without ever writing them to disk.
//!
//! I built this because I have a Tauri desktop app that encrypts its local
//! SQLite database with SQLCipher. The encryption key has to live *somewhere*,
//! and writing it to a config file next to the database is basically security
//! theater. So the key goes into Windows Credential Manager / macOS Keychain /
//! Linux Secret Service, and this crate handles the plumbing for that.
//!
//! The module also manages "workspace identity" — each workspace directory gets
//! a UUID v4 persisted as a JSON manifest, and the encryption key is stored
//! under that UUID. This way, moving the workspace folder to a different path
//! doesn't orphan the key (which happened to me during testing and was really
//! not fun to debug).
//!
//! ## Basic usage
//!
//! ```rust,no_run
//! use os_keyvault::{store_secret, get_secret, new_random_key};
//!
//! let key = new_random_key();
//! store_secret("my-app", "db-encryption-key", &key).unwrap();
//!
//! let retrieved = get_secret("my-app", "db-encryption-key").unwrap();
//! assert_eq!(retrieved, Some(key));
//! ```

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

const MANIFEST_FILENAME: &str = ".workspace-identity.json";
const MANIFEST_VERSION: u32 = 1;

// ─── OS Credential Store ─────────────────────────────────────────────────

/// Store a hex-encoded secret in the OS credential store.
///
/// After writing, we immediately read it back and compare. I do this because
/// I've seen `keyring-rs` silently succeed on Windows when Credential Manager
/// was in a weird state after a domain policy change, only for `get_password`
/// to return gibberish later. The read-after-write catches that.
pub fn store_secret(service: &str, key_id: &str, secret: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(service, key_id)
        .map_err(|e| format!("unable to access OS credential store: {e}"))?;
    entry
        .set_password(secret)
        .map_err(|e| format!("unable to store secret: {e}"))?;
    let readback = entry
        .get_password()
        .map_err(|e| format!("unable to verify stored secret: {e}"))?;
    if readback != secret {
        return Err("OS credential store failed read-after-write verification".into());
    }
    Ok(())
}

/// Retrieve a hex-encoded secret from the OS credential store.
///
/// Returns `Ok(None)` if the key doesn't exist yet (first launch),
/// and `Err` if the stored value is corrupted or not valid hex.
pub fn get_secret(service: &str, key_id: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(service, key_id)
        .map_err(|e| format!("unable to access OS credential store: {e}"))?;
    match entry.get_password() {
        Ok(value) if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(Some(value))
        }
        Ok(_) => Err("stored secret is not a valid 256-bit hex key".into()),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("unable to retrieve secret: {e}")),
    }
}

/// Generate a cryptographically random 256-bit key, hex-encoded.
pub fn new_random_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ─── Workspace Identity ──────────────────────────────────────────────────

/// A workspace identity manifest. Gets written as JSON to the workspace root.
///
/// The UUID ties the workspace directory to its encryption key in the OS
/// credential store. Without this, renaming or moving the folder would
/// orphan the key.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceManifest {
    pub schema_version: u32,
    pub workspace_uuid: String,
}

/// Generate a new UUID v4 using OS-level randomness.
///
/// I could use the `uuid` crate for this but it felt silly to pull in a whole
/// dependency for 8 lines of hex formatting. The bit-twiddling sets the version
/// nibble to 4 and the variant bits to 10xx per RFC 4122.
pub fn new_workspace_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
    let h = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Validate a UUID v4 string.
///
/// Checks length, hyphen positions, version nibble = 4, variant nibble ∈ {8,9,a,b}.
/// Only lowercase hex is accepted because that's what `new_workspace_uuid` produces
/// and I didn't want to deal with case-insensitive comparison edge cases.
pub fn valid_workspace_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Compute a deterministic key ID from a workspace path.
/// Used as a fallback for workspaces that predate the UUID manifest system.
pub fn legacy_key_id(workspace: &Path) -> String {
    let digest = Sha256::digest(workspace.to_string_lossy().as_bytes());
    format!("workspace-db-{}", &hex::encode(digest)[..32])
}

/// Compute a key ID from a workspace UUID. This is the preferred method.
pub fn key_id_for_uuid(workspace_uuid: &str) -> String {
    format!("workspace-db-{workspace_uuid}")
}

/// Read the workspace identity manifest from a directory, if it exists.
pub fn read_manifest(workspace: &Path) -> Result<Option<WorkspaceManifest>, String> {
    let path = workspace.join(MANIFEST_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    let meta =
        fs::metadata(&path).map_err(|e| format!("unable to inspect workspace manifest: {e}"))?;
    if !meta.is_file() || meta.len() > 1024 {
        return Err("workspace manifest is invalid".into());
    }
    let bytes = fs::read(&path).map_err(|e| format!("unable to read workspace manifest: {e}"))?;
    let manifest: WorkspaceManifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("workspace manifest is invalid: {e}"))?;
    if manifest.schema_version != MANIFEST_VERSION
        || !valid_workspace_uuid(&manifest.workspace_uuid)
    {
        return Err("workspace manifest has unsupported version or invalid UUID".into());
    }
    Ok(Some(manifest))
}

/// Create a workspace identity manifest, crash-safely.
///
/// Uses the write-to-temp-then-rename pattern so we never end up with a
/// half-written manifest if the process gets killed mid-write. This was a
/// real bug during development — kill the app at the wrong moment and you'd
/// get a corrupt 0-byte manifest that would then fail to parse on next launch,
/// permanently locking the user out of their workspace. Not great.
pub fn activate_manifest(workspace: &Path, uuid: &str) -> Result<(), String> {
    if !valid_workspace_uuid(uuid) {
        return Err("workspace UUID is invalid".into());
    }
    if let Some(existing) = read_manifest(workspace)? {
        return if existing.workspace_uuid == uuid {
            Ok(())
        } else {
            Err("workspace identity conflict — different UUID already exists".into())
        };
    }

    let path = workspace.join(MANIFEST_FILENAME);
    let temp = workspace.join(format!(
        ".workspace-identity.{}.{}.tmp",
        std::process::id(),
        rand::rngs::OsRng.next_u64()
    ));

    let manifest = WorkspaceManifest {
        schema_version: MANIFEST_VERSION,
        workspace_uuid: uuid.to_string(),
    };
    let serialized =
        serde_json::to_vec_pretty(&manifest).map_err(|e| format!("serialization failed: {e}"))?;

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|e| format!("unable to create temp manifest: {e}"))?;
    file.write_all(&serialized)
        .map_err(|e| format!("unable to write temp manifest: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("unable to flush temp manifest: {e}"))?;
    drop(file);

    // Check again — another process may have raced us
    if let Some(existing) = read_manifest(workspace)? {
        let _ = fs::remove_file(&temp);
        return if existing.workspace_uuid == uuid {
            Ok(())
        } else {
            Err("workspace identity conflict during activation".into())
        };
    }

    if let Err(e) = fs::rename(&temp, &path) {
        let _ = fs::remove_file(&temp);
        return Err(format!("unable to activate workspace manifest: {e}"));
    }

    // On Unix, fsync the directory to make sure the rename is durable.
    // Windows doesn't need this — NTFS metadata updates are synchronous.
    #[cfg(unix)]
    {
        fs::File::open(workspace)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("unable to fsync workspace directory: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_generation_is_valid() {
        for _ in 0..100 {
            let id = new_workspace_uuid();
            assert!(
                valid_workspace_uuid(&id),
                "generated UUID failed validation: {id}"
            );
        }
    }

    #[test]
    fn uuid_validation_rejects_garbage() {
        assert!(!valid_workspace_uuid(""));
        assert!(!valid_workspace_uuid("not-a-uuid-at-all"));
        assert!(!valid_workspace_uuid(
            "00000000-0000-0000-0000-000000000000"
        )); // version 0
        assert!(!valid_workspace_uuid(
            "00000000-0000-4000-0000-000000000000"
        )); // variant 0
        assert!(!valid_workspace_uuid(
            "00000000-0000-4000-C000-000000000000"
        )); // uppercase
    }

    #[test]
    fn uuid_validation_accepts_valid() {
        assert!(valid_workspace_uuid("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"));
        assert!(valid_workspace_uuid("00000000-0000-4000-8000-000000000000"));
        assert!(valid_workspace_uuid("ffffffff-ffff-4fff-bfff-ffffffffffff"));
    }

    #[test]
    fn manifest_roundtrip() {
        let dir = std::env::temp_dir().join(format!("keyvault-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let uuid = new_workspace_uuid();
        activate_manifest(&dir, &uuid).unwrap();

        let manifest = read_manifest(&dir).unwrap().expect("manifest should exist");
        assert_eq!(manifest.workspace_uuid, uuid);

        // idempotent — calling again with same UUID is fine
        activate_manifest(&dir, &uuid).unwrap();

        // conflict — different UUID should fail
        let other = new_workspace_uuid();
        assert!(activate_manifest(&dir, &other).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_key_id_is_deterministic() {
        let a = legacy_key_id(Path::new("/home/user/workspace"));
        let b = legacy_key_id(Path::new("/home/user/workspace"));
        assert_eq!(a, b);
        assert!(a.starts_with("workspace-db-"));
    }

    #[test]
    fn random_key_is_256_bit_hex() {
        let key = new_random_key();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
