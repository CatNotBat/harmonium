//! Error type for the harmonium-keys crate.

/// Errors produced by identity and peer store operations.
#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Parse(String),

    #[error("peer key changed for {name}")]
    PeerKeyChanged { name: String },

    #[error("identity already exists")]
    IdentityExists,

    #[error("invalid peer name")]
    InvalidName,

    #[error("not found")]
    NotFound,

    #[error("pq keys already exist")]
    PqKeysExist,

    #[error("peer {name} has no pq public key hash in its bundle")]
    PeerPqMissing { name: String },

    #[error("pq public key does not match peer {name}'s bundle hash")]
    PeerPqMismatch { name: String },
}
