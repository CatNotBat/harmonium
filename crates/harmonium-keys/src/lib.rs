//! Key and identity management for Harmonium.
//!
//! This crate handles the local identity (a WireGuard private key plus an
//! `age` identity), on-disk persistence, peer key pinning, and the
//! human-readable fingerprint shared out-of-band.

pub mod error;
pub mod fingerprint;
pub mod identity;
pub mod peer;
pub mod store;

pub use error::KeysError;
pub use fingerprint::{fingerprint, qr_unicode};
pub use identity::{Bundle, Identity, pq_pk_hash};
pub use peer::PeerEntry;
pub use store::Store;
