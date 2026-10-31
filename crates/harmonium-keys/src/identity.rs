//! The local identity and its public [`Bundle`].

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use zeroize::Zeroize as _;

use crate::error::KeysError;

/// A local identity: a WireGuard private key (for the modem/link layer) and an
/// `age` identity (for text encryption).
pub struct Identity {
    pub(crate) wg_private: [u8; 32],
    pub(crate) age: age::x25519::Identity,
}

impl Identity {
    /// Generates a fresh identity with random keys.
    ///
    /// The WireGuard private key is not clamped here; x25519 clamps internally
    /// when deriving the public key.
    pub fn generate() -> Self {
        Self {
            wg_private: rand::random::<[u8; 32]>(),
            age: age::x25519::Identity::generate(),
        }
    }

    pub(crate) fn from_parts(wg_private: [u8; 32], age: age::x25519::Identity) -> Self {
        Self { wg_private, age }
    }
}

// The age key zeroizes itself on drop; the WireGuard key is a plain array.
impl Drop for Identity {
    fn drop(&mut self) {
        self.wg_private.zeroize();
    }
}

impl Identity {
    /// The WireGuard public key derived from the private key.
    pub fn wg_public(&self) -> [u8; 32] {
        let secret = gotatun::x25519::StaticSecret::from(self.wg_private);
        gotatun::x25519::PublicKey::from(&secret).to_bytes()
    }

    /// The `age1...` recipient string for this identity's age key.
    /// The WireGuard static private key, for building a link. Handle with care.
    pub fn wg_private(&self) -> [u8; 32] {
        self.wg_private
    }

    /// The age identity, for decrypting text messages.
    pub fn age_identity(&self) -> &age::x25519::Identity {
        &self.age
    }

    pub fn age_recipient(&self) -> String {
        self.age.to_public().to_string()
    }

    /// The public [`Bundle`] identifying this identity to peers.
    pub fn bundle(&self) -> Bundle {
        Bundle {
            wg_public: self.wg_public(),
            age_recipient: self.age_recipient(),
            pq: None,
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show only public material; never the WireGuard private bytes or the
        // `AGE-SECRET-KEY-...` string.
        f.debug_struct("Identity")
            .field("wg_public", &STANDARD.encode(self.wg_public()))
            .field("age_recipient", &self.age_recipient())
            .finish()
    }
}

/// The public identity material shared with a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub wg_public: [u8; 32],
    pub age_recipient: String,
    /// SHA-256 hash of the peer's Rosenpass public key; `None` means no PQ layer.
    pub pq: Option<[u8; 32]>,
}

impl fmt::Display for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pq {
            Some(hash) => write!(
                f,
                "harmonium2:{}:{}:{}",
                STANDARD.encode(self.wg_public),
                self.age_recipient,
                STANDARD.encode(hash)
            ),
            None => write!(
                f,
                "harmonium1:{}:{}",
                STANDARD.encode(self.wg_public),
                self.age_recipient
            ),
        }
    }
}

impl FromStr for Bundle {
    type Err = KeysError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, has_pq) = match (s.strip_prefix("harmonium1:"), s.strip_prefix("harmonium2:")) {
            (Some(rest), None) => (rest, false),
            (None, Some(rest)) => (rest, true),
            _ => {
                return Err(KeysError::Parse(
                    "bundle must start with \"harmonium1:\" or \"harmonium2:\"".into(),
                ));
            }
        };

        let mut parts = rest.split(':');
        let wg_b64 = parts
            .next()
            .ok_or_else(|| KeysError::Parse("missing WireGuard public key".into()))?;
        let age_recipient = parts
            .next()
            .ok_or_else(|| KeysError::Parse("missing age recipient".into()))?;
        let hash_b64 = parts.next();
        if parts.next().is_some() {
            return Err(KeysError::Parse("bundle has extra fields".into()));
        }
        if wg_b64.is_empty() {
            return Err(KeysError::Parse("empty WireGuard public key".into()));
        }
        if age_recipient.is_empty() {
            return Err(KeysError::Parse("empty age recipient".into()));
        }

        let wg_bytes = STANDARD
            .decode(wg_b64)
            .map_err(|e| KeysError::Parse(format!("invalid WireGuard public key: {e}")))?;
        let wg_public: [u8; 32] = wg_bytes
            .try_into()
            .map_err(|_| KeysError::Parse("WireGuard public key must be 32 bytes".into()))?;

        let recipient = age_recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|e| KeysError::Parse(format!("invalid age recipient: {e}")))?;

        let pq = if has_pq {
            let hash_b64 = hash_b64.ok_or_else(|| KeysError::Parse("missing pq hash".into()))?;
            let hash_bytes = STANDARD
                .decode(hash_b64)
                .map_err(|e| KeysError::Parse(format!("invalid pq hash: {e}")))?;
            let hash: [u8; 32] = hash_bytes
                .try_into()
                .map_err(|_| KeysError::Parse("pq hash must be 32 bytes".into()))?;
            Some(hash)
        } else {
            if hash_b64.is_some() {
                return Err(KeysError::Parse("bundle has extra fields".into()));
            }
            None
        };

        Ok(Bundle {
            wg_public,
            age_recipient: recipient.to_string(),
            pq,
        })
    }
}

/// SHA-256(b"harmonium-pq-pk-v1\0" || pk).
pub fn pq_pk_hash(pk: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"harmonium-pq-pk-v1\0");
    hasher.update(pk);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_private_material() {
        let wg_private = [0xAB; 32];
        let identity = Identity {
            wg_private,
            age: age::x25519::Identity::generate(),
        };

        let debug = format!("{identity:?}");
        assert!(!debug.contains(&STANDARD.encode(wg_private)));
        assert!(!debug.contains("AGE-SECRET-KEY"));
        assert!(debug.contains("age1"));
    }
}
