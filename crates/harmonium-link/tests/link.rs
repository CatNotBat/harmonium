//! End-to-end tests for `harmonium-link`: two links driven through an in-memory pipe with
//! configurable random loss. No network, no files.

use std::collections::VecDeque;
use std::time::Duration;

use gotatun::x25519;
use harmonium_link::{Channel, Delivered, Link, LinkKeys};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

const SEED: u64 = 0x9e37_79b9_7f4a_7c15;

/// Generate an x25519 key pair from random bytes (the private key is clamped inside x25519).
fn keypair(rng: &mut StdRng) -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    rng.fill_bytes(&mut private);
    let secret = x25519::StaticSecret::from(private);
    let public = x25519::PublicKey::from(&secret);
    (private, *public.as_bytes())
}

fn channel_for(seq: u64) -> Channel {
    match seq % 3 {
        0 => Channel::Voice,
        1 => Channel::Control,
        _ => Channel::Text,
    }
}

/// A lossy in-memory pipe between two links.
struct Pipe {
    a: Link,
    b: Link,
    rng: StdRng,
    loss: f64,
    a2b: VecDeque<Vec<u8>>,
    b2a: VecDeque<Vec<u8>>,
}

impl Pipe {
    fn new(loss: f64, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let (a_private, a_public) = keypair(&mut rng);
        let (b_private, b_public) = keypair(&mut rng);
        let a = Link::new(&LinkKeys {
            private: a_private,
            peer_public: b_public,
            psk: None,
        });
        let b = Link::new(&LinkKeys {
            private: b_private,
            peer_public: a_public,
            psk: None,
        });
        Pipe {
            a,
            b,
            rng,
            loss,
            a2b: VecDeque::new(),
            b2a: VecDeque::new(),
        }
    }

    fn drop_packet(&mut self) -> bool {
        self.loss > 0.0 && self.rng.random_bool(self.loss)
    }

    fn push_a2b(&mut self, wire: Vec<Vec<u8>>) {
        for w in wire {
            if !self.drop_packet() {
                self.a2b.push_back(w);
            }
        }
    }

    fn push_b2a(&mut self, wire: Vec<Vec<u8>>) {
        for w in wire {
            if !self.drop_packet() {
                self.b2a.push_back(w);
            }
        }
    }

    /// Move every queued packet, and every response it provokes, until both directions are
    /// empty. Returns the datagrams delivered, as `(a → b, b → a)`.
    fn drain(&mut self) -> (Vec<Delivered>, Vec<Delivered>) {
        let mut from_a = Vec::new();
        let mut from_b = Vec::new();
        loop {
            let mut moved = false;
            while let Some(w) = self.a2b.pop_front() {
                moved = true;
                let (resp, delivered) = self.b.receive(&w);
                from_a.extend(delivered);
                self.push_b2a(resp);
            }
            while let Some(w) = self.b2a.pop_front() {
                moved = true;
                let (resp, delivered) = self.a.receive(&w);
                from_b.extend(delivered);
                self.push_a2b(resp);
            }
            if !moved {
                break;
            }
        }
        (from_a, from_b)
    }

    fn tick(&mut self) {
        let a = self.a.tick();
        let b = self.b.tick();
        self.push_a2b(a);
        self.push_b2a(b);
    }

    fn step(&mut self) {
        self.tick();
        self.drain();
    }

    fn bring_up(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            if self.a.is_up() && self.b.is_up() {
                return;
            }
            self.step();
        }
        assert!(self.a.is_up() && self.b.is_up(), "links never came up");
    }
}

/// Drive two links: tick each (if enabled), then move every queued packet until quiescent.
/// Returns true once both sides are up (checked at the end of each step).
fn drive(a: &mut Link, b: &mut Link, tick_a: bool, tick_b: bool, max_steps: usize) -> bool {
    let mut a2b = VecDeque::new();
    let mut b2a = VecDeque::new();
    for _ in 0..max_steps {
        if tick_a {
            a2b.extend(a.tick());
        }
        if tick_b {
            b2a.extend(b.tick());
        }
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

#[test]
fn handshake_completes_from_cold_start() {
    let mut pipe = Pipe::new(0.0, SEED + 1);
    pipe.bring_up(50);
    assert!(pipe.a.is_up());
    assert!(pipe.b.is_up());
    assert!(pipe.a.stats().handshakes_completed >= 1);
    assert!(pipe.b.stats().handshakes_completed >= 1);
}

#[test]
fn send_fails_closed_before_handshake() {
    let mut pipe = Pipe::new(0.0, SEED + 2);
    let before = pipe.a.stats().dropped_no_session;
    let wire = pipe.a.send(Channel::Voice, b"hello");
    assert_eq!(pipe.a.stats().dropped_no_session, before + 1);
    assert_eq!(pipe.a.stats().sent, 0);
    // Only a handshake initiation may come back, never a data packet.
    assert!(!wire.is_empty());
    for w in &wire {
        assert_ne!(
            w.first(),
            Some(&4),
            "must never send a data packet in the clear"
        );
    }
}

#[test]
fn data_roundtrip_with_loss() {
    let mut pipe = Pipe::new(0.0, SEED + 3);
    pipe.bring_up(50);
    pipe.loss = 0.05;

    let mut sent_a: Vec<(Channel, Vec<u8>)> = Vec::with_capacity(1000);
    let mut sent_b: Vec<(Channel, Vec<u8>)> = Vec::with_capacity(1000);
    let mut delivered_a: Vec<Delivered> = Vec::new();
    let mut delivered_b: Vec<Delivered> = Vec::new();
    let mut lost_a = 0u64;
    let mut lost_b = 0u64;

    for seq in 0..1000u64 {
        // a -> b
        let ch = channel_for(seq);
        let mut payload = Vec::with_capacity(208);
        payload.extend_from_slice(&seq.to_le_bytes());
        let tail = pipe.rng.random_range(1..=200usize);
        for _ in 0..tail {
            payload.push(pipe.rng.random::<u8>());
        }
        sent_a.push((ch, payload.clone()));
        let wire = pipe.a.send(ch, &payload);
        assert_eq!(
            wire.len(),
            1,
            "established session sends exactly one data packet"
        );
        if pipe.drop_packet() {
            lost_a += 1;
        } else {
            pipe.a2b.push_back(wire.into_iter().next().unwrap());
        }

        // b -> a
        let ch = channel_for(seq + 1);
        let mut payload = Vec::with_capacity(208);
        payload.extend_from_slice(&seq.to_le_bytes());
        let tail = pipe.rng.random_range(1..=200usize);
        for _ in 0..tail {
            payload.push(pipe.rng.random::<u8>());
        }
        sent_b.push((ch, payload.clone()));
        let wire = pipe.b.send(ch, &payload);
        assert_eq!(wire.len(), 1);
        if pipe.drop_packet() {
            lost_b += 1;
        } else {
            pipe.b2a.push_back(wire.into_iter().next().unwrap());
        }

        let (da, db) = pipe.drain();
        delivered_a.extend(da);
        delivered_b.extend(db);
    }

    assert_eq!(delivered_a.len() as u64, 1000 - lost_a);
    assert_eq!(delivered_b.len() as u64, 1000 - lost_b);

    for d in &delivered_a {
        let seq = u64::from_le_bytes(d.payload[..8].try_into().unwrap()) as usize;
        assert_eq!(
            d.channel, sent_a[seq].0,
            "channel must be preserved (a -> b)"
        );
        assert_eq!(
            &d.payload, &sent_a[seq].1,
            "payload must match what was sent"
        );
    }
    for d in &delivered_b {
        let seq = u64::from_le_bytes(d.payload[..8].try_into().unwrap()) as usize;
        assert_eq!(
            d.channel, sent_b[seq].0,
            "channel must be preserved (b -> a)"
        );
        assert_eq!(
            &d.payload, &sent_b[seq].1,
            "payload must match what was sent"
        );
    }
}

#[test]
fn tampering_rejected_and_later_still_delivers() {
    let mut pipe = Pipe::new(0.0, SEED + 4);
    pipe.bring_up(50);

    let wire = pipe.a.send(Channel::Control, b"tamper target");
    assert_eq!(wire.len(), 1);
    let mut tampered = wire[0].clone();
    *tampered.last_mut().unwrap() ^= 0x01; // flip a bit in the AEAD tag

    let (resp, delivered) = pipe.b.receive(&tampered);
    assert!(
        delivered.is_empty(),
        "tampered packet must not be delivered"
    );
    assert!(
        resp.is_empty(),
        "tampered packet must not produce a response"
    );
    assert_eq!(pipe.b.stats().rejected, 1);

    let wire = pipe.a.send(Channel::Control, b"later");
    let (_, delivered) = pipe.b.receive(&wire[0]);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].channel, Channel::Control);
    assert_eq!(delivered[0].payload, b"later");
}

#[test]
fn garbage_inputs_never_panic() {
    let mut pipe = Pipe::new(0.0, SEED + 5);
    pipe.bring_up(50);

    let before = pipe.b.stats().rejected;
    let garbage: [Vec<u8>; 6] = [
        Vec::new(),      // too short
        vec![0x04],      // one byte, data type but far too short
        vec![42u8; 148], // handshake length but unknown type byte
        vec![7u8; 5000], // long, unknown type byte
        vec![1u8; 148],  // handshake-init shaped but garbage AEAD
        vec![4u8; 5000], // data shaped, no matching session
    ];
    for g in &garbage {
        let (resp, delivered) = pipe.b.receive(g);
        assert!(delivered.is_empty(), "garbage must never deliver");
        assert!(resp.is_empty(), "garbage must never produce a response");
    }
    assert_eq!(pipe.b.stats().rejected, before + garbage.len() as u64);
}

#[test]
fn replay_delivers_once() {
    let mut pipe = Pipe::new(0.0, SEED + 6);
    pipe.bring_up(50);

    let wire = pipe.a.send(Channel::Voice, b"replay me");
    assert_eq!(wire.len(), 1);
    let packet = wire[0].clone();

    let (_, first) = pipe.b.receive(&packet);
    assert_eq!(first.len(), 1);
    let (_, second) = pipe.b.receive(&packet);
    assert!(
        second.is_empty(),
        "replayed packet must not be delivered twice"
    );
}

#[test]
fn rekey_no_datagram_loss() {
    let mut pipe = Pipe::new(0.0, SEED + 7);
    pipe.a.set_timer_params_for_tests(Duration::from_secs(1));
    pipe.b.set_timer_params_for_tests(Duration::from_secs(1));
    pipe.bring_up(50);
    assert!(pipe.a.is_up() && pipe.b.is_up());

    let base_a = pipe.a.stats().handshakes_completed;
    let base_b = pipe.b.stats().handshakes_completed;

    // Exchange one datagram each direction every 50 ms for ~4 s of wall-clock time.
    let mut delivered_a = 0u64;
    let mut delivered_b = 0u64;
    for _ in 0..80 {
        let wire = pipe.a.send(Channel::Voice, b"ping-a");
        assert_eq!(wire.len(), 1);
        pipe.a2b.extend(wire);

        let wire = pipe.b.send(Channel::Voice, b"ping-b");
        assert_eq!(wire.len(), 1);
        pipe.b2a.extend(wire);

        let (da, db) = pipe.drain();
        delivered_a += da.len() as u64;
        delivered_b += db.len() as u64;

        pipe.tick();
        let (da, db) = pipe.drain();
        delivered_a += da.len() as u64;
        delivered_b += db.len() as u64;

        std::thread::sleep(Duration::from_millis(50));
    }

    // Loss 0: every datagram after the first handshake must arrive.
    assert_eq!(delivered_a, 80);
    assert_eq!(delivered_b, 80);
    // At least one side must have completed a rekey (more handshakes than the initial one).
    assert!(
        pipe.a.stats().handshakes_completed > base_a
            || pipe.b.stats().handshakes_completed > base_b
    );
    assert!(pipe.a.stats().handshakes_completed >= 2 || pipe.b.stats().handshakes_completed >= 2);
}

#[test]
fn wrong_key_never_comes_up() {
    let mut rng = StdRng::seed_from_u64(SEED + 8);
    let (a_private, a_public) = keypair(&mut rng);
    let (c_private, _c_public) = keypair(&mut rng);
    let (_d_private, d_public) = keypair(&mut rng); // a third key neither side actually holds

    // A expects peer `d`, but C (whose own static is `c`) tries to talk to A.
    let mut a = Link::new(&LinkKeys {
        private: a_private,
        peer_public: d_public,
        psk: None,
    });
    let mut c = Link::new(&LinkKeys {
        private: c_private,
        peer_public: a_public,
        psk: None,
    });

    assert!(!drive(&mut a, &mut c, true, true, 20));
    assert!(!a.is_up() && !c.is_up());
    assert_eq!(a.stats().delivered, 0);
    assert_eq!(c.stats().delivered, 0);

    // Fail closed: C has no session, so sending drops the datagram and never emits data.
    let before = c.stats().dropped_no_session;
    let wire = c.send(Channel::Voice, b"x");
    assert_eq!(c.stats().dropped_no_session, before + 1);
    assert!(wire.iter().all(|w| w.first() != Some(&4)));
}

#[test]
fn psk_matching_and_mismatched() {
    let mut rng = StdRng::seed_from_u64(SEED + 9);
    let (a_private, a_public) = keypair(&mut rng);
    let (b_private, b_public) = keypair(&mut rng);

    // Matching PSK: handshake completes and a datagram round-trips.
    let mut a = Link::new(&LinkKeys {
        private: a_private,
        peer_public: b_public,
        psk: Some([7; 32]),
    });
    let mut b = Link::new(&LinkKeys {
        private: b_private,
        peer_public: a_public,
        psk: Some([7; 32]),
    });
    assert!(drive(&mut a, &mut b, true, true, 50));
    assert!(a.is_up() && b.is_up());
    let wire = a.send(Channel::Text, b"psk ok");
    assert_eq!(wire.len(), 1);
    let (_, delivered) = b.receive(&wire[0]);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].payload, b"psk ok");

    // Mismatched PSK: the initiating side never establishes, and nothing is ever delivered.
    let mut a = Link::new(&LinkKeys {
        private: a_private,
        peer_public: b_public,
        psk: Some([7; 32]),
    });
    let mut b = Link::new(&LinkKeys {
        private: b_private,
        peer_public: a_public,
        psk: Some([9; 32]),
    });
    assert!(!drive(&mut a, &mut b, true, false, 20));
    assert!(
        !a.is_up(),
        "initiator must not establish a session with a mismatched PSK"
    );
    assert_eq!(a.stats().delivered, 0);
    // The responder answered, but no packet from the initiator ever confirmed its session.
    assert!(
        !b.is_up(),
        "responder must not report up before key confirmation"
    );
    assert_eq!(b.stats().handshakes_completed, 0);
    // The responder may hold a dead session; prove it cannot deliver to the initiator either.
    for packet in b.send(Channel::Voice, b"x") {
        let (_, delivered) = a.receive(&packet);
        assert!(delivered.is_empty());
    }
    assert_eq!(a.stats().delivered, 0);
}

#[test]
fn debug_never_prints_secrets() {
    let keys = harmonium_link::LinkKeys {
        private: [0xAB; 32],
        peer_public: [1; 32],
        psk: Some([0xCD; 32]),
    };
    let s = format!("{keys:?}");
    assert!(!s.contains("171") && !s.contains("205"), "{s}");
}

#[test]
fn pq_channel_round_trips() {
    let mut pipe = Pipe::new(0.0, SEED + 10);
    pipe.bring_up(50);

    let wire = pipe.a.send(Channel::Pq, b"pq msg");
    assert_eq!(wire.len(), 1);
    let (_, delivered) = pipe.b.receive(&wire[0]);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].channel, Channel::Pq);
    assert_eq!(delivered[0].payload, b"pq msg");
}

#[test]
fn force_handshake_after_set_psk_comes_back_up() {
    let mut pipe = Pipe::new(0.0, SEED + 11);
    pipe.bring_up(50);

    let hs_a = pipe.a.stats().handshakes_completed;
    let hs_b = pipe.b.stats().handshakes_completed;

    pipe.a.set_psk(Some([0x42; 32]));
    pipe.b.set_psk(Some([0x42; 32]));

    let wire = pipe.a.force_handshake();
    assert!(!wire.is_empty());
    pipe.a2b.extend(wire);
    pipe.drain();

    assert!(pipe.a.is_up() && pipe.b.is_up());
    assert!(pipe.a.stats().handshakes_completed > hs_a);
    assert!(pipe.b.stats().handshakes_completed > hs_b);
}
