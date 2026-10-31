#![no_main]
use std::collections::VecDeque;

use gotatun::x25519;
use harmonium_link::{Channel, Link, LinkKeys};
use harmonium_voice::VoicePacket;
use libfuzzer_sys::fuzz_target;

/// Derive the x25519 public key for a fixed private key, exactly as the link
/// integration tests do.
fn public_key(private: [u8; 32]) -> [u8; 32] {
    let secret = x25519::StaticSecret::from(private);
    *x25519::PublicKey::from(&secret).as_bytes()
}

/// Drive the two links through an in-memory pipe until both sides are up.
fn bring_up(a: &mut Link, b: &mut Link) -> bool {
    let mut a2b: VecDeque<Vec<u8>> = VecDeque::new();
    let mut b2a: VecDeque<Vec<u8>> = VecDeque::new();
    for _ in 0..50 {
        a2b.extend(a.tick());
        b2a.extend(b.tick());
        loop {
            let mut moved = false;
            while let Some(w) = a2b.pop_front() {
                moved = true;
                let (resp, _) = b.receive(&w);
                b2a.extend(resp);
            }
            while let Some(w) = b2a.pop_front() {
                moved = true;
                let (resp, _) = a.receive(&w);
                a2b.extend(resp);
            }
            if !moved {
                break;
            }
        }
        if a.is_up() && b.is_up() {
            return true;
        }
    }
    a.is_up() && b.is_up()
}

fuzz_target!(|data: &[u8]| {
    let a_priv = [0x11u8; 32];
    let b_priv = [0x22u8; 32];
    let a_pub = public_key(a_priv);
    let b_pub = public_key(b_priv);

    let mut a = Link::new(&LinkKeys {
        private: a_priv,
        peer_public: b_pub,
        psk: None,
    });
    let mut b = Link::new(&LinkKeys {
        private: b_priv,
        peer_public: a_pub,
        psk: None,
    });

    // Phase A: the unauthenticated path — any wire bytes straight into `b`.
    let _ = b.receive(data);

    // Phase B: complete a real handshake, send a datagram, and exercise the
    // VoicePacket parser on every Voice-channel delivery.
    if !data.is_empty() && bring_up(&mut a, &mut b) {
        let channel = match data[0] % 3 {
            0 => Channel::Voice,
            1 => Channel::Control,
            _ => Channel::Text,
        };
        for wire in a.send(channel, &data[1..]) {
            let (_, delivered) = b.receive(&wire);
            for d in delivered {
                if d.channel == Channel::Voice {
                    let _ = VoicePacket::from_bytes(&d.payload);
                }
            }
        }
    }
});
