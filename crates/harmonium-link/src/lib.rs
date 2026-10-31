//! Glue between application datagrams and WireGuard wire packets for Harmonium.
//!
//! A [`Link`] carries a real WireGuard session (GotaTun's [`Tunn`]) over a lossy modem link.
//! Application datagrams are a one-byte [`Channel`] tag followed by an arbitrary payload, and
//! travel inside WireGuard data packets. This crate contains no cryptography of its own: every
//! AEAD/KDF/DH operation is performed inside GotaTun.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use gotatun::noise::errors::WireGuardError;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{TimerParams, Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::x25519;
use zeroize::Zeroize as _;

/// Static keys for one link endpoint. The private key is ours; `peer_public` is the other
/// endpoint's long-term static public key; `psk` is an optional preshared key (Rosenpass feeds
/// this in later). `Debug` redacts the secrets.
#[derive(Clone)]
pub struct LinkKeys {
    pub private: [u8; 32],
    pub peer_public: [u8; 32],
    pub psk: Option<[u8; 32]>,
}

impl std::fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkKeys")
            .field("private", &"<redacted>")
            .field("peer_public", &self.peer_public)
            .field("psk", &self.psk.map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for LinkKeys {
    fn drop(&mut self) {
        self.private.zeroize();
        self.psk.zeroize();
    }
}

/// Application channel, carried as the first plaintext byte inside a WireGuard data packet.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Voice = 1,
    Control = 2,
    Text = 3,
    Pq = 4,
}

impl Channel {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Channel::Voice),
            2 => Some(Channel::Control),
            3 => Some(Channel::Text),
            4 => Some(Channel::Pq),
            _ => None,
        }
    }
}

/// A decrypted application datagram delivered by [`Link::receive`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub channel: Channel,
    pub payload: Vec<u8>,
}

/// Counters kept by a [`Link`].
#[derive(Default, Debug, Clone)]
pub struct LinkStats {
    /// Datagrams encrypted and handed to the modem.
    pub sent: u64,
    /// Datagrams dropped because no session existed (fail closed, never queued).
    pub dropped_no_session: u64,
    /// Datagrams decrypted and delivered to the application.
    pub delivered: u64,
    /// Garbage wire packets, AEAD failures, and unknown-channel plaintexts.
    pub rejected: u64,
    /// Sessions established, on either role. A responder counts a session only once a packet
    /// from the initiator decrypts under it (key confirmation).
    pub handshakes_completed: u64,
    /// Time since the most recent completed handshake, if any.
    pub last_handshake: Option<Duration>,
}

/// Handshakes allowed per rate-limit window. See GotaTun's [`RateLimiter`].
const HANDSHAKE_RATE_LIMIT: u64 = 10;

/// WireGuard persistent-keepalive interval, in seconds.
const PERSISTENT_KEEPALIVE: u16 = 10;

/// One end of a Harmonium link: application datagrams ⇄ WireGuard wire packets.
pub struct Link {
    tunn: Tunn,
    stats: LinkStats,
    unconfirmed: Option<Unconfirmed>,
}

/// A session we created as responder that no packet from the initiator has confirmed yet.
///
/// The responder cannot check the initiator's PSK: it only learns the keys match when a data
/// packet decrypts under the new session. GotaTun makes a responder session current only then,
/// except when it lands in the slot already marked current (the very first handshake, or after
/// a reset); `blocks_up` marks that case, where no older live session stands behind it.
#[derive(Clone, Copy)]
struct Unconfirmed {
    receiving_idx: u32,
    blocks_up: bool,
}

impl Link {
    /// Create a link endpoint with `persistent_keepalive = Some(10)`.
    pub fn new(keys: &LinkKeys) -> Self {
        let static_private = x25519::StaticSecret::from(keys.private);
        let static_public = x25519::PublicKey::from(&static_private);
        let peer_public = x25519::PublicKey::from(keys.peer_public);

        let rate_limiter = Arc::new(RateLimiter::new(&static_public, HANDSHAKE_RATE_LIMIT));
        let tunn = Tunn::new(
            static_private,
            peer_public,
            keys.psk,
            Some(PERSISTENT_KEEPALIVE),
            IndexTable::from_os_rng(),
            rate_limiter,
        );

        Link {
            tunn,
            stats: LinkStats::default(),
            unconfirmed: None,
        }
    }

    /// Encrypt one datagram into wire packets for the modem.
    ///
    /// Fails closed: if there is no session that can encrypt, the datagram is dropped (never
    /// queued, never sent in the clear) and `dropped_no_session` is incremented; a handshake
    /// initiation is returned instead if one is due. Note that "no session" here means GotaTun
    /// has no current session to encrypt with ([`Tunn::encapsulate_with_session`] returned the
    /// packet back) — this is deliberately looser than [`Link::is_up`], so an aging session keeps
    /// carrying datagrams until its replacement handshake actually completes.
    pub fn send(&mut self, channel: Channel, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut plaintext = BytesMut::with_capacity(1 + payload.len());
        plaintext.extend_from_slice(&[channel as u8]);
        plaintext.extend_from_slice(payload);
        let packet = Packet::from_bytes(plaintext);

        match self.tunn.encapsulate_with_session(packet) {
            Ok(data) => {
                self.stats.sent += 1;
                vec![wire_packet(WgKind::Data(data))]
            }
            Err(_) => {
                self.stats.dropped_no_session += 1;
                self.tunn
                    .format_handshake_initiation(false)
                    .map(|p| wire_packet(p.into()))
                    .into_iter()
                    .collect()
            }
        }
    }

    /// Process one wire packet from the modem.
    ///
    /// Returns wire packets to send back (handshake responses, keepalives) and any datagrams
    /// delivered. Any input is safe: parse failures, AEAD failures, and unknown channel bytes
    /// increment `rejected` and are otherwise ignored.
    pub fn receive(&mut self, wire: &[u8]) -> (Vec<Vec<u8>>, Vec<Delivered>) {
        let parsed = match Packet::from_bytes(BytesMut::from(wire)).try_into_wg() {
            Ok(kind) => kind,
            Err(_) => {
                self.stats.rejected += 1;
                return (Vec::new(), Vec::new());
            }
        };

        let data_idx = match &parsed {
            WgKind::Data(data) => Some(data.header.receiver_idx.get()),
            _ => None,
        };
        let was_up = self.is_up();

        match self.tunn.handle_incoming_packet(parsed) {
            TunnResult::WriteToNetwork(kind) => {
                match &kind {
                    // We answered an initiation (responder role). The session is not established
                    // until the initiator proves it holds the same keys; see `Unconfirmed`.
                    WgKind::HandshakeResp(resp) => {
                        self.unconfirmed = Some(Unconfirmed {
                            receiving_idx: resp.sender_idx.get(),
                            blocks_up: !was_up,
                        });
                    }
                    // A `Data` keepalive written from the receive path is the confirmation the
                    // initiator emits after decrypting a handshake response, which proves the
                    // responder used the same keys (initiator role). The new session is current.
                    WgKind::Data(data) if data.is_keepalive() => {
                        self.stats.handshakes_completed += 1;
                        self.unconfirmed = None;
                    }
                    _ => {}
                }
                (vec![wire_packet(kind)], Vec::new())
            }
            TunnResult::WriteToTunnel(packet) => {
                if let Some(u) = self.unconfirmed
                    && data_idx == Some(u.receiving_idx)
                {
                    self.stats.handshakes_completed += 1;
                    self.unconfirmed = None;
                }
                let plaintext = packet.as_ref();
                if plaintext.is_empty() {
                    // Keepalive decrypts to an empty packet: nothing to deliver.
                    return (Vec::new(), Vec::new());
                }
                match Channel::from_byte(plaintext[0]) {
                    Some(channel) => {
                        self.stats.delivered += 1;
                        (
                            Vec::new(),
                            vec![Delivered {
                                channel,
                                payload: plaintext[1..].to_vec(),
                            }],
                        )
                    }
                    None => {
                        self.stats.rejected += 1;
                        (Vec::new(), Vec::new())
                    }
                }
            }
            TunnResult::Err(_) => {
                self.stats.rejected += 1;
                (Vec::new(), Vec::new())
            }
            TunnResult::Done => (Vec::new(), Vec::new()),
        }
    }

    /// Advance timers. Call every 250 ms of wall-clock time.
    ///
    /// Returns wire packets to send. If there is no session and none is being established, a
    /// handshake is started (either peer may initiate). A `ConnectionExpired` resets the tunnel
    /// state and keeps going.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        match self.tunn.update_timers() {
            Ok(Some(kind)) => vec![wire_packet(kind)],
            Ok(None) => {
                // `format_handshake_initiation(false)` returns `None` while one is already in
                // flight, so this is safe to call whenever the session is stale or missing.
                if !self.tunn.has_active_session() {
                    self.tunn
                        .format_handshake_initiation(false)
                        .map(|p| wire_packet(p.into()))
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            }
            Err(WireGuardError::ConnectionExpired) => {
                self.tunn.reset();
                self.unconfirmed = None;
                Vec::new()
            }
            Err(_) => Vec::new(),
        }
    }

    /// Whether the current session exists, is confirmed, and is not yet due for rekeying.
    pub fn is_up(&self) -> bool {
        self.tunn.has_active_session() && !self.unconfirmed.is_some_and(|u| u.blocks_up)
    }

    /// Replace the preshared key used by subsequent handshakes. Takes effect at the next
    /// handshake; the current session is unaffected.
    pub fn set_psk(&mut self, psk: Option<[u8; 32]>) {
        self.tunn.set_preshared_key(psk);
    }

    /// Start a new WireGuard handshake immediately (forcing one even if a handshake is
    /// already in flight). Returns wire packets like `send`.
    pub fn force_handshake(&mut self) -> Vec<Vec<u8>> {
        self.tunn
            .format_handshake_initiation(true)
            .map(|p| wire_packet(p.into()))
            .into_iter()
            .collect()
    }

    /// Snapshot the link's counters plus the time since the last handshake.
    pub fn stats(&self) -> LinkStats {
        let mut stats = self.stats.clone();
        stats.last_handshake = self.tunn.stats().0;
        stats
    }

    /// Shorten the WireGuard rekey timers. **Tests only**: this makes the tunnel deviate from
    /// the WireGuard spec (it wraps GotaTun's `dangerously_set_timer_params`).
    pub fn set_timer_params_for_tests(&mut self, rekey_after: Duration) {
        self.tunn.dangerously_set_timer_params(TimerParams {
            rekey_after_time: rekey_after..=rekey_after,
            ..TimerParams::default()
        });
    }
}

/// Serialize a WireGuard packet kind into wire bytes for the modem.
fn wire_packet(kind: WgKind) -> Vec<u8> {
    let packet: Packet = kind.into();
    packet.as_ref().to_vec()
}
