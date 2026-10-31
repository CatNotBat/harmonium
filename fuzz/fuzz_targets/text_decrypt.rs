#![no_main]
use std::sync::OnceLock;

use harmonium_text::decrypt;
use libfuzzer_sys::fuzz_target;

fn identity() -> &'static age::x25519::Identity {
    static ID: OnceLock<age::x25519::Identity> = OnceLock::new();
    ID.get_or_init(age::x25519::Identity::generate)
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = decrypt(identity(), s);
});
