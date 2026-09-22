# os-keyvault

Cross-platform wrapper for storing encryption keys in the OS credential store instead of on disk.

## Why this exists

I have a desktop app that encrypts its local SQLite database with SQLCipher. The 256-bit encryption key needs to live somewhere, and writing it to a `.env` file or a config JSON next to the database is basically pointless if someone has access to the file system, they have access to both the key and the database.

So the key goes into Windows Credential Manager / macOS Keychain / Linux Secret Service via `keyring-rs`. This crate wraps that with a few things I needed:

- **Read-after-write verification.** I've seen the Windows credential store silently succeed on write but return garbage on read after a domain policy change. So every `store_secret` immediately reads the value back and compares. Paranoid? Maybe. But it's caught real issues.

- **Workspace identity manifests.** Each workspace directory gets a UUID v4 written as a `.workspace-identity.json` file, and the encryption key is stored under that UUID. This way you can move or rename the workspace folder without orphaning the key. (I learned this the hard way when a user moved their workspace and got permanently locked out.)

- **Crash-safe manifest creation.** Uses write-to-temp-then-rename so a killed process can't leave a corrupt 0-byte manifest that bricks the workspace on next launch. Also happened during testing. Also not fun.

## Usage

```rust,no_run
use os_keyvault::{store_secret, get_secret, new_random_key};

// Generate and store a key
let key = new_random_key(); // 256-bit, hex-encoded
store_secret("my-app", "db-key", &key).unwrap();

// Later, retrieve it
let retrieved = get_secret("my-app", "db-key").unwrap();
assert_eq!(retrieved, Some(key));
```

### Workspace identity

```rust,no_run
use os_keyvault::{new_workspace_uuid, activate_manifest, read_manifest};
use std::path::Path;

let workspace = Path::new("/path/to/workspace");
let uuid = new_workspace_uuid();
activate_manifest(workspace, &uuid).unwrap();

// On next launch:
let manifest = read_manifest(workspace).unwrap().unwrap();
let key_id = os_keyvault::key_id_for_uuid(&manifest.workspace_uuid);
let key = get_secret("my-app", &key_id).unwrap();
```

## Platform support

| Platform | Backend |
|---|---|
| Windows | Credential Manager |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet) |

## Limitations

- Keys are stored as hex strings, not raw bytes. The OS credential stores are designed for passwords (text), and I didn't want to deal with encoding ambiguity.
- No key rotation built in you handle that at the application level.
- The manifest system assumes one workspace per directory. If you need multiple encrypted databases in one folder, you'll need to extend it.

## License

MIT
