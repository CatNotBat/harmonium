//! Text encrypt/decrypt commands.

use std::io::Read;

use anyhow::{Context, Result, bail};
use harmonium_keys::{Identity, PeerEntry, Store};
use harmonium_text::{clipboard_decrypt, clipboard_encrypt, decrypt, encrypt, fits_discord};

use crate::cli::TextCmd;

/// Read all of stdin into a UTF-8 string.
pub fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read stdin")?;
    Ok(buf)
}

/// Resolve a peer and refuse unverified peers unless allowed.
pub fn load_verified_peer(store: &Store, name: &str, allow_unverified: bool) -> Result<PeerEntry> {
    let peer = store
        .peer(name)
        .with_context(|| format!("peer {name:?} not found; add it with `harmonium peer add`"))?;
    if !peer.verified && !allow_unverified {
        bail!(
            "peer {name:?} is not verified; verify it with `harmonium peer verify {name}` \
             or pass --allow-unverified"
        );
    }
    Ok(peer)
}

/// Encrypt `plaintext` to `peer`, returning the armored ciphertext.
pub fn encrypt_to(peer: &PeerEntry, plaintext: &str) -> Result<String> {
    Ok(encrypt(&peer.bundle.age_recipient, plaintext)?)
}

/// Decrypt an armor block with our own age identity.
pub fn decrypt_with(identity: &Identity, text: &str) -> Result<String> {
    Ok(decrypt(identity.age_identity(), text)?)
}

/// Full `text encrypt` command. Returns the armored ciphertext.
pub fn run_encrypt(
    store: &Store,
    peer_name: &str,
    message: Option<&str>,
    no_clipboard: bool,
    allow_unverified: bool,
) -> Result<String> {
    let peer = load_verified_peer(store, peer_name, allow_unverified)?;
    let armored = match message {
        Some(message) => encrypt_to(&peer, message)?,
        None if no_clipboard => {
            let stdin_text = read_stdin()?;
            let text = stdin_text.trim_end_matches('\n');
            encrypt_to(&peer, text)?
        }
        None => clipboard_encrypt(&peer.bundle.age_recipient)?,
    };
    Ok(armored)
}

/// Full `text decrypt` command. Returns the plaintext.
pub fn run_decrypt(store: &Store, no_clipboard: bool) -> Result<String> {
    let identity = store.load_identity()?;
    if no_clipboard {
        let stdin_text = read_stdin()?;
        decrypt_with(&identity, &stdin_text)
    } else {
        Ok(clipboard_decrypt(identity.age_identity())?)
    }
}

/// Warn if an armored block will not fit in a Discord message.
pub fn discord_fit(armored: &str) -> Option<String> {
    if fits_discord(armored) {
        None
    } else {
        Some(format!(
            "warning: armored message is {} characters; Discord caps messages at 2000",
            armored.chars().count()
        ))
    }
}

/// `harmonium text ...`. Returns the process exit code.
pub fn run(store: &Store, cmd: &TextCmd) -> Result<u8> {
    match cmd {
        TextCmd::Encrypt {
            peer,
            message,
            no_clipboard,
            allow_unverified,
        } => {
            let armored = run_encrypt(
                store,
                peer,
                message.as_deref(),
                *no_clipboard,
                *allow_unverified,
            )?;
            println!("{armored}");
            if let Some(warning) = discord_fit(&armored) {
                eprintln!("{warning}");
            }
        }
        TextCmd::Decrypt { no_clipboard } => {
            let plaintext = run_decrypt(store, *no_clipboard)?;
            print!("{plaintext}");
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let identity = Identity::generate();
        let peer = PeerEntry {
            bundle: identity.bundle(),
            verified: true,
        };
        let armored = encrypt_to(&peer, "hello secret").unwrap();
        assert!(fits_discord(&armored));
        let plaintext = decrypt_with(&identity, &armored).unwrap();
        assert_eq!(plaintext, "hello secret");
    }

    #[test]
    fn decrypt_finds_armor_inside_prose() {
        let identity = Identity::generate();
        let armored = encrypt_to(
            &PeerEntry {
                bundle: identity.bundle(),
                verified: true,
            },
            "hi",
        )
        .unwrap();
        let wrapped = format!("here you go:\n```\n{armored}\n```\nthanks!");
        assert_eq!(decrypt_with(&identity, &wrapped).unwrap(), "hi");
    }

    #[test]
    fn unverified_peer_is_refused_but_allowable() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path());
        let identity = Identity::generate();
        store.add_peer("bob", &identity.bundle()).unwrap();

        let err = load_verified_peer(&store, "bob", false).unwrap_err();
        assert!(err.to_string().contains("not verified"));

        let ok = load_verified_peer(&store, "bob", true).unwrap();
        assert!(!ok.verified);
    }
}
