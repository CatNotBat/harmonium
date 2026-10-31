//! Identity and peer management commands.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
#[cfg(feature = "pq")]
use anyhow::{anyhow, bail};
use harmonium_keys::{
    Bundle, Identity, KeysError, PeerEntry, Store, fingerprint, pq_pk_hash, qr_unicode,
};

use crate::cli::PeerCmd;
#[cfg(feature = "pq")]
use crate::cli::PqCmd;
#[cfg(feature = "pq")]
use harmonium_pq::PqKeypair;

/// Everything `keygen` / `id` print about an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDisplay {
    pub bundle: String,
    pub fingerprint: String,
    pub qr: String,
}

impl IdentityDisplay {
    /// Render for the terminal: bundle, fingerprint, then the QR code.
    pub fn render(&self) -> String {
        format!(
            "bundle:      {}\nfingerprint: {}\n{}",
            self.bundle, self.fingerprint, self.qr
        )
    }
}

fn display(store: &Store, identity: &Identity) -> IdentityDisplay {
    let mut bundle = identity.bundle();
    if let Ok(Some(pk)) = store.load_pq_public() {
        bundle.pq = Some(pq_pk_hash(&pk));
    }
    let bundle_string = bundle.to_string();
    IdentityDisplay {
        fingerprint: fingerprint(&bundle),
        qr: qr_unicode(&bundle_string),
        bundle: bundle_string,
    }
}

/// Generate a new identity and save it. Fails with [`KeysError::IdentityExists`]
/// unless `force` is set.
pub fn keygen(store: &Store, force: bool) -> Result<IdentityDisplay, KeysError> {
    let identity = Identity::generate();
    store.save_identity(&identity, force)?;
    Ok(display(store, &identity))
}

/// Load and display the saved identity.
pub fn show_identity(store: &Store) -> Result<IdentityDisplay, KeysError> {
    let identity = store.load_identity()?;
    Ok(display(store, &identity))
}

/// Parse a bundle string and add it under `name`.
pub fn add_peer(store: &Store, name: &str, bundle: &str) -> Result<(), KeysError> {
    let bundle: Bundle = bundle.parse()?;
    store.add_peer(name, &bundle)
}

/// Return every peer, sorted by name.
pub fn all_peers(store: &Store) -> Vec<(String, PeerEntry)> {
    store.peers()
}

/// Mark a peer as verified.
pub fn verify_peer(store: &Store, name: &str) -> Result<(), KeysError> {
    store.mark_verified(name)
}

/// Remove a peer by name.
pub fn remove_peer(store: &Store, name: &str) -> Result<(), KeysError> {
    store.remove_peer(name)
}

/// Render one peer as a `name: bundle  verified=...  fingerprint=...` line.
pub fn format_peer(name: &str, peer: &PeerEntry) -> String {
    format!(
        "{name}: {}  verified={}  fingerprint={}",
        peer.bundle,
        if peer.verified { "yes" } else { "no" },
        fingerprint(&peer.bundle)
    )
}

/// `harmonium keygen`. Returns the process exit code.
pub fn run_keygen(store: &Store, dir: &Path, force: bool) -> Result<u8> {
    match keygen(store, force) {
        Ok(out) => {
            println!("{}", out.render());
            Ok(0)
        }
        Err(KeysError::IdentityExists) => {
            eprintln!(
                "An identity already exists at {}. Re-run with --force to overwrite it.",
                dir.display()
            );
            Ok(1)
        }
        Err(err) => Err(err.into()),
    }
}

/// `harmonium id`.
pub fn run_id(store: &Store) -> Result<u8> {
    let out = show_identity(store)?;
    println!("{}", out.render());
    Ok(0)
}

/// Load the local PQ keypair, the peer's PQ public key, and who initiates the
/// exchange (the lower WireGuard public key).
#[cfg(feature = "pq")]
pub fn load_pq_context(
    store: &Store,
    peer_name: &str,
    identity: &Identity,
) -> Result<(PqKeypair, Vec<u8>, bool)> {
    let Some((sk, pk)) = store.load_pq_keys()? else {
        bail!("no post-quantum keys; run `harmonium pq keygen` first");
    };
    let own = PqKeypair::from_bytes(sk, pk)?;
    let Some(peer_pk) = store.peer_pq_pk(peer_name) else {
        bail!(
            "no post-quantum public key for peer {peer_name:?}; import it with `harmonium peer pq-import {peer_name} <FILE>`"
        );
    };
    let peer = store
        .peer(peer_name)
        .ok_or_else(|| anyhow!("peer {peer_name:?} not found"))?;
    let initiator = identity.wg_public() < peer.bundle.wg_public;
    Ok((own, peer_pk, initiator))
}

/// `harmonium pq ...`.
#[cfg(feature = "pq")]
pub fn run_pq(store: &Store, cmd: &PqCmd) -> Result<u8> {
    match cmd {
        PqCmd::Keygen { force } => {
            let kp = PqKeypair::generate()?;
            match store.save_pq_keys(kp.secret_bytes(), kp.public(), *force) {
                Ok(()) => {
                    println!("generated post-quantum keypair");
                    Ok(0)
                }
                Err(KeysError::PqKeysExist) => {
                    eprintln!(
                        "post-quantum keys already exist; re-run with --force to overwrite them"
                    );
                    Ok(1)
                }
                Err(e) => Err(e.into()),
            }
        }
        PqCmd::Export { file } => {
            let pk = store
                .load_pq_public()?
                .ok_or_else(|| anyhow!("no post-quantum keys; run `harmonium pq keygen` first"))?;
            std::fs::write(file, &pk)
                .with_context(|| format!("failed to write {}", file.display()))?;
            println!("exported post-quantum public key to {}", file.display());
            Ok(0)
        }
    }
}

/// `harmonium peer ...`.
pub fn run_peer(store: &Store, cmd: &PeerCmd) -> Result<u8> {
    match cmd {
        PeerCmd::Add { name, bundle } => match add_peer(store, name, bundle) {
            Ok(()) => {
                println!("added peer {name}");
                Ok(0)
            }
            Err(KeysError::PeerKeyChanged { name }) => {
                eprintln!(
                    "WARNING: the stored key for peer {name:?} does not match the bundle just provided."
                );
                eprintln!(
                    "This usually means the peer's identity changed. Do not overwrite it blindly:"
                );
                eprintln!(
                    "remove the old key, re-add the peer out-of-band, then verify the new fingerprint:"
                );
                eprintln!("    harmonium peer remove {name}");
                eprintln!("    harmonium peer add {name} <NEW-BUNDLE>");
                eprintln!("    harmonium peer verify {name}");
                Ok(1)
            }
            Err(err) => Err(err.into()),
        },

        PeerCmd::Show { name } => {
            match name {
                Some(name) => {
                    let peer = store
                        .peer(name)
                        .with_context(|| format!("peer {name:?} not found"))?;
                    println!("{}", format_peer(name, &peer));
                }
                None => {
                    let peers = all_peers(store);
                    if peers.is_empty() {
                        println!("no peers");
                    }
                    for (name, peer) in &peers {
                        println!("{}", format_peer(name, peer));
                    }
                }
            }
            Ok(0)
        }

        PeerCmd::Verify { name } => {
            let peer = store
                .peer(name)
                .with_context(|| format!("peer {name:?} not found"))?;
            let identity = store.load_identity()?;
            // The same bundle `harmonium id` shows, PQ key hash included, so verifying covers it.
            println!(
                "your fingerprint:     {}",
                display(store, &identity).fingerprint
            );
            println!("{name}'s fingerprint: {}", fingerprint(&peer.bundle));
            print!("Do the fingerprints match what {name} reads to you? [y/N] ");
            io::stdout().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if answer.trim().to_ascii_lowercase().starts_with('y') {
                verify_peer(store, name)?;
                println!("marked {name} verified");
            } else {
                println!("{name} left unverified");
            }
            Ok(0)
        }

        PeerCmd::Remove { name } => {
            remove_peer(store, name)?;
            println!("removed peer {name}");
            Ok(0)
        }

        #[cfg(feature = "pq")]
        PeerCmd::PqImport { name, file } => {
            let pk = std::fs::read(file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            store.save_peer_pq_pk(name, &pk)?;
            println!("imported post-quantum public key for {name}");
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path());
        (dir, store)
    }

    #[test]
    fn keygen_id_peer_flow() {
        let (_dir, store) = store();

        let identity = keygen(&store, false).unwrap();
        assert!(identity.bundle.starts_with("harmonium1:"));
        assert!(!identity.fingerprint.is_empty());
        assert!(!identity.qr.is_empty());

        // A second identity becomes the peer's bundle.
        let peer_identity = Identity::generate();
        let peer_bundle = peer_identity.bundle().to_string();

        add_peer(&store, "bob", &peer_bundle).unwrap();
        let entry = store.peer("bob").unwrap();
        assert!(!entry.verified);
        assert_eq!(entry.bundle.to_string(), peer_bundle);

        verify_peer(&store, "bob").unwrap();
        assert!(store.peer("bob").unwrap().verified);

        let all = all_peers(&store);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "bob");

        remove_peer(&store, "bob").unwrap();
        assert!(all_peers(&store).is_empty());
    }

    #[test]
    fn keygen_refuses_to_overwrite_without_force() {
        let (_dir, store) = store();
        keygen(&store, false).unwrap();
        let err = keygen(&store, false).unwrap_err();
        assert!(matches!(err, KeysError::IdentityExists));
        // With force it succeeds.
        keygen(&store, true).unwrap();
    }

    #[test]
    fn re_add_same_bundle_is_idempotent_but_change_is_rejected() {
        let (_dir, store) = store();
        let a = Identity::generate();
        let b = Identity::generate();
        let a_bundle = a.bundle().to_string();
        let b_bundle = b.bundle().to_string();

        add_peer(&store, "eve", &a_bundle).unwrap();
        add_peer(&store, "eve", &a_bundle).unwrap(); // no-op
        let err = add_peer(&store, "eve", &b_bundle).unwrap_err();
        assert!(matches!(err, KeysError::PeerKeyChanged { .. }));
    }
}
