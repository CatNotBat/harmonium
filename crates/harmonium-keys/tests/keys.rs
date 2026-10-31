//! Integration tests for harmonium-keys.

use harmonium_keys::{Bundle, Identity, KeysError, Store, fingerprint};

/// The public key of age's upstream test secret key
/// `AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33`.
const TEST_RECIPIENT: &str = "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";

/// Standard base64 of 32 zero bytes.
const ZERO32_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// Standard base64 of 31 zero bytes (one byte short of a public key).
const ZERO31_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

#[test]
fn generate_save_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path());
    let identity = Identity::generate();
    store.save_identity(&identity, false).unwrap();

    let loaded = store.load_identity().unwrap();
    assert_eq!(identity.wg_public(), loaded.wg_public());
    assert_eq!(identity.age_recipient(), loaded.age_recipient());
}

#[cfg(unix)]
#[test]
fn identity_file_mode_is_0600() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path());
    let identity = Identity::generate();
    store.save_identity(&identity, false).unwrap();

    let meta = std::fs::metadata(dir.path().join("identity.toml")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
}

#[test]
fn refuse_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path());
    let first = Identity::generate();
    store.save_identity(&first, false).unwrap();

    let second = Identity::generate();
    assert!(matches!(
        store.save_identity(&second, false),
        Err(KeysError::IdentityExists)
    ));

    store.save_identity(&second, true).unwrap();
    let loaded = store.load_identity().unwrap();
    assert_eq!(loaded.wg_public(), second.wg_public());
}

#[test]
fn bundle_display_from_str_round_trip() {
    let bundle = Bundle {
        wg_public: [7u8; 32],
        age_recipient: TEST_RECIPIENT.to_string(),
    };

    let text = bundle.to_string();
    assert!(text.starts_with("harmonium1:"));
    assert_eq!(text.parse::<Bundle>().unwrap(), bundle);
}

#[test]
fn bundle_from_str_rejects_bad_inputs() {
    // Bad prefix.
    assert!(matches!(
        "nope:aaa:bbb".parse::<Bundle>(),
        Err(KeysError::Parse(_))
    ));

    // 31-byte (not 32-byte) WireGuard public key.
    let short = format!("harmonium1:{ZERO31_B64}:{TEST_RECIPIENT}");
    assert!(matches!(short.parse::<Bundle>(), Err(KeysError::Parse(_))));

    // Bad age recipient.
    let bad_recipient = format!("harmonium1:{ZERO32_B64}:not-a-recipient");
    assert!(matches!(
        bad_recipient.parse::<Bundle>(),
        Err(KeysError::Parse(_))
    ));

    // Extra field (a third ':'-separated part).
    let extra = format!("harmonium1:{ZERO32_B64}:{TEST_RECIPIENT}:extra");
    assert!(matches!(extra.parse::<Bundle>(), Err(KeysError::Parse(_))));
}

#[test]
fn fingerprint_is_deterministic_and_shaped() {
    let bundle = Bundle {
        wg_public: [1u8; 32],
        age_recipient: TEST_RECIPIENT.to_string(),
    };

    let a = fingerprint(&bundle);
    let b = fingerprint(&bundle);
    assert_eq!(a, b);

    let groups: Vec<&str> = a.split(' ').collect();
    assert_eq!(groups.len(), 6);
    for group in groups {
        assert_eq!(group.len(), 5);
        assert!(group.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn fingerprint_varies_with_inputs() {
    let b1 = Bundle {
        wg_public: [0u8; 32],
        age_recipient: TEST_RECIPIENT.to_string(),
    };
    let b2 = Bundle {
        wg_public: [1u8; 32],
        age_recipient: TEST_RECIPIENT.to_string(),
    };
    assert_ne!(fingerprint(&b1), fingerprint(&b2));

    let other_recipient = Identity::generate().age_recipient();
    let b3 = Bundle {
        wg_public: [0u8; 32],
        age_recipient: other_recipient,
    };
    assert_ne!(fingerprint(&b1), fingerprint(&b3));
}

#[test]
fn fingerprint_known_answer() {
    // `TEST_RECIPIENT` is the public key of age's upstream test secret key
    // `AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33`;
    // the expected string was computed independently (one-off Python
    // hashlib.sha256) over `b"harmonium-fingerprint-v1\0" + 32 zero bytes +
    // recipient bytes`, first 30 bytes -> six big-endian 5-byte chunks mod
    // 100000.
    let bundle = Bundle {
        wg_public: [0u8; 32],
        age_recipient: TEST_RECIPIENT.to_string(),
    };
    assert_eq!(fingerprint(&bundle), "50362 18073 48296 21045 75515 78009");
}

#[test]
fn peer_pinning_and_verification() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path());
    let b1 = Identity::generate().bundle();
    let b2 = Identity::generate().bundle();

    store.add_peer("alice", &b1).unwrap();
    // Re-adding the same bundle is a no-op.
    store.add_peer("alice", &b1).unwrap();
    // A different bundle under the same name is rejected (key pinning).
    assert!(matches!(
        store.add_peer("alice", &b2),
        Err(KeysError::PeerKeyChanged { .. })
    ));

    store.mark_verified("alice").unwrap();
    let entry = store.peer("alice").unwrap();
    assert!(entry.verified);
    assert_eq!(entry.bundle, b1);

    store.add_peer("charlie", &b2).unwrap();
    store.add_peer("bob", &b1).unwrap();
    let names: Vec<String> = store.peers().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["alice", "bob", "charlie"]);
}

#[test]
fn invalid_names_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path());
    let bundle = Identity::generate().bundle();

    for name in [
        "",
        "way-too-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "bad name!",
    ] {
        assert!(
            matches!(store.add_peer(name, &bundle), Err(KeysError::InvalidName)),
            "name {name:?} should be rejected"
        );
    }
}

#[test]
fn identity_debug_does_not_leak_secret() {
    let identity = Identity::generate();
    let debug = format!("{identity:?}");

    assert!(!debug.contains("AGE-SECRET-KEY"));
    assert!(debug.contains("age1"));
}
