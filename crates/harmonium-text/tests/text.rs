//! Integration tests for harmonium-text.

use harmonium_text::{decrypt, encrypt, fits_discord};

#[test]
fn encrypt_decrypt_round_trip() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let plaintext = "hello, harmonium \u{1F44B}";
    let armored = encrypt(&recipient, plaintext).unwrap();
    assert_eq!(decrypt(&identity, &armored).unwrap(), plaintext);
}

#[test]
fn short_message_fits_discord() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let armored = encrypt(&recipient, "short message").unwrap();
    assert!(fits_discord(&armored));
    assert!(armored.chars().count() <= 2000);
}

#[test]
fn decrypt_finds_embedded_block() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let plaintext = "secret text";
    let armored = encrypt(&recipient, plaintext).unwrap();
    let embedded = format!("hello ```\n{armored}\n``` bye");
    assert_eq!(decrypt(&identity, &embedded).unwrap(), plaintext);
}

#[test]
fn wrong_identity_fails() {
    let identity = age::x25519::Identity::generate();
    let other = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let armored = encrypt(&recipient, "for your eyes only").unwrap();
    assert!(decrypt(&other, &armored).is_err());
}

#[test]
fn tampered_block_fails() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let armored = encrypt(&recipient, "integrity matters").unwrap();

    const BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
    const END: &str = "-----END AGE ENCRYPTED FILE-----";
    let body_start = armored.find(BEGIN).unwrap() + BEGIN.len();
    let body_end = armored.find(END).unwrap();

    let mut bytes = armored.as_bytes().to_vec();
    let body = &mut bytes[body_start..body_end];
    let pos = body
        .iter()
        .position(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        .expect("expected a base64 character in the body");
    body[pos] = if body[pos] == b'A' { b'B' } else { b'A' };

    let tampered = String::from_utf8(bytes).unwrap();
    assert!(decrypt(&identity, &tampered).is_err());
}

// Note: there is deliberately no test for a non-UTF-8 plaintext result, since
// `encrypt` takes `&str` (so the plaintext is UTF-8 by construction) and the
// `age` decrypt path can only ever return bytes for a valid block. The
// `TextError::NonUtf8` arm is defensive for future binary-plaintext support.
