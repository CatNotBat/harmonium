//! Human-readable fingerprint and QR rendering of a [`Bundle`].

use sha2::{Digest, Sha256};

use crate::identity::Bundle;

/// Domain separator hashed before the public material of a PQ-less bundle.
const FINGERPRINT_PREFIX: &[u8] = b"harmonium-fingerprint-v1\0";

/// Domain separator hashed before the public material of a bundle with a PQ key.
const FINGERPRINT_PREFIX_V2: &[u8] = b"harmonium-fingerprint-v2\0";

/// Returns a stable, human-comparable fingerprint for a [`Bundle`].
///
/// The fingerprint is the first 30 bytes of a SHA-256 digest, split into six
/// 5-byte big-endian chunks, each reduced modulo 100 000 and zero-padded to
/// five decimal digits. For a PQ-less bundle the digest covers
/// `b"harmonium-fingerprint-v1\0" || wg_public || age_recipient`; for a bundle
/// with a PQ key it covers
/// `b"harmonium-fingerprint-v2\0" || wg_public || age_recipient || pq`.
pub fn fingerprint(bundle: &Bundle) -> String {
    let digest = match bundle.pq {
        Some(hash) => {
            let mut hasher = Sha256::new();
            hasher.update(FINGERPRINT_PREFIX_V2);
            hasher.update(bundle.wg_public);
            hasher.update(bundle.age_recipient.as_bytes());
            hasher.update(hash);
            hasher.finalize()
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(FINGERPRINT_PREFIX);
            hasher.update(bundle.wg_public);
            hasher.update(bundle.age_recipient.as_bytes());
            hasher.finalize()
        }
    };

    format_digits(&digest)
}

/// Renders the first 30 bytes of `digest` as six 5-byte big-endian chunks,
/// each reduced modulo 100 000 and zero-padded to five decimal digits.
fn format_digits(digest: &[u8]) -> String {
    let mut out = String::with_capacity(35);
    for i in 0..6 {
        let chunk = &digest[i * 5..(i + 1) * 5];
        let mut value: u64 = 0;
        for &byte in chunk {
            value = (value << 8) | u64::from(byte);
        }
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:05}", value % 100_000));
    }
    out
}

/// Renders `s` as a Unicode QR code (dense 1×2 blocks, no quiet zone).
pub fn qr_unicode(s: &str) -> String {
    qrcode::QrCode::new(s)
        .expect("bundle fits in a QR code")
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(false)
        .build()
}
