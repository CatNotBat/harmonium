//! A known peer and its verification status.

use crate::identity::Bundle;

/// A peer's public key bundle and whether it has been verified out-of-band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    pub bundle: Bundle,
    pub verified: bool,
}
