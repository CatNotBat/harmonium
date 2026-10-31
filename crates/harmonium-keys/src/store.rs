//! On-disk persistence for the local identity and known peers.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::KeysError;
use crate::identity::{Bundle, Identity, pq_pk_hash};
use crate::peer::PeerEntry;

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    wg_private: String,
    age_identity: String,
}

impl Drop for IdentityFile {
    fn drop(&mut self) {
        self.wg_private.zeroize();
        self.age_identity.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct PeerRecord {
    bundle: String,
    verified: bool,
}

type PeerFile = BTreeMap<String, PeerRecord>;

/// Filesystem-backed store for the local identity and peer keys.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Returns a store rooted at `dir` without touching the filesystem.
    pub fn open(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// The default store directory: `<config_dir>/harmonium`, falling back to
    /// `./harmonium` when no config directory is available.
    pub fn default_dir() -> PathBuf {
        dirs::config_dir()
            .map(|d| d.join("harmonium"))
            .unwrap_or_else(|| PathBuf::from("harmonium"))
    }

    /// Persists `identity` to `identity.toml`, refusing to overwrite an
    /// existing identity unless `force` is set.
    pub fn save_identity(&self, identity: &Identity, force: bool) -> Result<(), KeysError> {
        fs::create_dir_all(&self.dir)?;
        let path = self.dir.join("identity.toml");
        if path.exists() && !force {
            return Err(KeysError::IdentityExists);
        }

        let file = IdentityFile {
            wg_private: STANDARD.encode(identity.wg_private),
            age_identity: identity.age.to_string().expose_secret().to_string(),
        };
        let contents =
            Zeroizing::new(toml::to_string(&file).map_err(|e| KeysError::Parse(e.to_string()))?);
        atomic_write(&path, contents.as_bytes())
    }

    /// Loads the identity from `identity.toml`.
    pub fn load_identity(&self) -> Result<Identity, KeysError> {
        let path = self.dir.join("identity.toml");
        let contents = Zeroizing::new(fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => KeysError::NotFound,
            _ => KeysError::Io(e),
        })?);

        let file: IdentityFile =
            toml::from_str(&contents).map_err(|e| KeysError::Parse(e.to_string()))?;

        let decoded = Zeroizing::new(
            STANDARD
                .decode(&file.wg_private)
                .map_err(|e| KeysError::Parse(format!("invalid WireGuard private key: {e}")))?,
        );
        let wg_private: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeysError::Parse("WireGuard private key must be 32 bytes".into()))?;

        let age = file
            .age_identity
            .parse::<age::x25519::Identity>()
            .map_err(|e| KeysError::Parse(format!("invalid age identity: {e}")))?;

        Ok(Identity::from_parts(wg_private, age))
    }

    /// Adds (or re-confirms) a peer's bundle under `name`.
    ///
    /// Re-adding the same bundle is a no-op; a different bundle under an
    /// existing name is rejected (key pinning).
    pub fn add_peer(&self, name: &str, bundle: &Bundle) -> Result<(), KeysError> {
        validate_name(name)?;

        let mut peers = self.load_peers()?;
        let new_bundle = bundle.to_string();
        match peers.get(name) {
            Some(existing) if existing.bundle == new_bundle => return Ok(()),
            Some(_) => {
                return Err(KeysError::PeerKeyChanged {
                    name: name.to_string(),
                });
            }
            None => {}
        }

        peers.insert(
            name.to_string(),
            PeerRecord {
                bundle: new_bundle,
                verified: false,
            },
        );
        self.write_peers(&peers)
    }

    /// Marks the peer named `name` as verified.
    pub fn mark_verified(&self, name: &str) -> Result<(), KeysError> {
        let mut peers = self.load_peers()?;
        let record = peers.get_mut(name).ok_or(KeysError::NotFound)?;
        record.verified = true;
        self.write_peers(&peers)
    }

    /// Returns the peer named `name`, or `None` on any read/parse error or a
    /// missing name.
    pub fn peer(&self, name: &str) -> Option<PeerEntry> {
        let Ok(Some(peers)) = self.read_peers_optional() else {
            return None;
        };
        let record = peers.get(name)?;
        let bundle: Bundle = record.bundle.parse().ok()?;
        Some(PeerEntry {
            bundle,
            verified: record.verified,
        })
    }

    /// Returns all peers sorted by name, skipping unparseable bundles and
    /// returning an empty vec on read errors.
    pub fn peers(&self) -> Vec<(String, PeerEntry)> {
        let Ok(Some(peers)) = self.read_peers_optional() else {
            return Vec::new();
        };
        peers
            .into_iter()
            .filter_map(|(name, record)| {
                let bundle: Bundle = record.bundle.parse().ok()?;
                Some((
                    name,
                    PeerEntry {
                        bundle,
                        verified: record.verified,
                    },
                ))
            })
            .collect()
    }

    /// Removes the peer named `name` (absent is a no-op).
    pub fn remove_peer(&self, name: &str) -> Result<(), KeysError> {
        let mut peers = self.load_peers()?;
        peers.remove(name);
        self.write_peers(&peers)
    }

    /// Persists the local PQ secret and public keys as raw bytes, refusing to
    /// overwrite an existing keypair unless `force` is set.
    pub fn save_pq_keys(&self, sk: &[u8], pk: &[u8], force: bool) -> Result<(), KeysError> {
        fs::create_dir_all(&self.dir)?;
        let sk_path = self.dir.join("pq.sk");
        let pk_path = self.dir.join("pq.pk");
        if !force && (sk_path.exists() || pk_path.exists()) {
            return Err(KeysError::PqKeysExist);
        }
        atomic_write(&sk_path, sk)?;
        atomic_write(&pk_path, pk)
    }

    /// Loads the local PQ keypair; `None` if either file is absent. The secret key is wiped
    /// from memory when dropped.
    #[allow(clippy::type_complexity)]
    pub fn load_pq_keys(&self) -> Result<Option<(Zeroizing<Vec<u8>>, Vec<u8>)>, KeysError> {
        let Some(sk) = read_optional(&self.dir.join("pq.sk"))? else {
            return Ok(None);
        };
        let Some(pk) = read_optional(&self.dir.join("pq.pk"))? else {
            return Ok(None);
        };
        Ok(Some((Zeroizing::new(sk), pk)))
    }

    /// Loads only the local PQ public key, without reading the secret key; `None` if absent.
    pub fn load_pq_public(&self) -> Result<Option<Vec<u8>>, KeysError> {
        read_optional(&self.dir.join("pq.pk"))
    }

    /// Persists a peer's PQ public key, verifying it against the hash in the
    /// peer's bundle.
    pub fn save_peer_pq_pk(&self, name: &str, pk: &[u8]) -> Result<(), KeysError> {
        validate_name(name)?;
        let entry = self.peer(name).ok_or(KeysError::NotFound)?;
        let hash = entry.bundle.pq.ok_or(KeysError::PeerPqMissing {
            name: name.to_string(),
        })?;
        if pq_pk_hash(pk) != hash {
            return Err(KeysError::PeerPqMismatch {
                name: name.to_string(),
            });
        }
        fs::create_dir_all(self.dir.join("pq-peers"))?;
        atomic_write(&self.dir.join("pq-peers").join(format!("{name}.pk")), pk)
    }

    /// Returns the peer's stored PQ public key, or `None` on any read error or when it no
    /// longer matches the hash in the peer's current bundle (e.g. the peer was re-added).
    pub fn peer_pq_pk(&self, name: &str) -> Option<Vec<u8>> {
        validate_name(name).ok()?;
        let hash = self.peer(name)?.bundle.pq?;
        let pk = fs::read(self.dir.join("pq-peers").join(format!("{name}.pk"))).ok()?;
        (pq_pk_hash(&pk) == hash).then_some(pk)
    }

    /// Loads the peer table, treating a missing file as empty.
    fn load_peers(&self) -> Result<PeerFile, KeysError> {
        Ok(self.read_peers_optional()?.unwrap_or_default())
    }

    /// Reads and parses the peer table; a missing file yields `Ok(None)`.
    fn read_peers_optional(&self) -> Result<Option<PeerFile>, KeysError> {
        let path = self.dir.join("peers.toml");
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(KeysError::Io(e)),
        };
        let peers: PeerFile =
            toml::from_str(&contents).map_err(|e| KeysError::Parse(e.to_string()))?;
        Ok(Some(peers))
    }

    fn write_peers(&self, peers: &PeerFile) -> Result<(), KeysError> {
        let contents = toml::to_string(peers).map_err(|e| KeysError::Parse(e.to_string()))?;
        atomic_write(&self.dir.join("peers.toml"), contents.as_bytes())
    }
}

/// Reads a whole file; a missing file yields `Ok(None)`.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, KeysError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KeysError::Io(e)),
    }
}

fn validate_name(name: &str) -> Result<(), KeysError> {
    if name.is_empty() || name.len() > 32 {
        return Err(KeysError::InvalidName);
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(KeysError::InvalidName);
    }
    Ok(())
}

/// Writes `contents` to `path` atomically via a same-directory temp file and
/// `rename`.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), KeysError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp_path = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));

    {
        let mut f = create_private_file(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::create(path)
}
