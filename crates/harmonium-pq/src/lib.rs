//! Post-quantum key exchange for Harmonium.
//!
//! Harmonium tunnels WireGuard through a modem. This crate wraps the
//! `rosenpass` crate to run a post-quantum key exchange and emit a 32-byte
//! pre-shared key for WireGuard's PSK slot. It contains no cryptography of
//! its own; everything is delegated to rosenpass.

use rosenpass::pqkem::{KEM, StaticKEM};
use rosenpass::protocol::{CryptoServer, MsgBuf, PeerPtr, PollResult, SPk, SSk};
use zeroize::Zeroizing;

/// Length in bytes of a Classic McEliece 460896 public key.
pub const PK_LEN: usize = StaticKEM::PK_LEN;

/// Length in bytes of a Classic McEliece 460896 secret key.
pub const SK_LEN: usize = StaticKEM::SK_LEN;

/// Errors produced by the post-quantum key exchange.
#[derive(Debug, thiserror::Error)]
pub enum PqError {
    #[error("secret key must be {expected} bytes, got {actual}")]
    SecretKeyLength { actual: usize, expected: usize },

    #[error("public key must be {expected} bytes, got {actual}")]
    PublicKeyLength { actual: usize, expected: usize },

    #[error("rosenpass: {0}")]
    Rosenpass(#[from] anyhow::Error),
}

/// A static Classic McEliece keypair. The secret key is wiped from memory when dropped.
pub struct PqKeypair {
    sk: Zeroizing<Vec<u8>>,
    pk: Vec<u8>,
}

impl PqKeypair {
    /// Generates a fresh keypair.
    pub fn generate() -> Result<Self, PqError> {
        rosenpass::sodium::sodium_init()?;
        let mut sk = Zeroizing::new(vec![0u8; SK_LEN]);
        let mut pk = vec![0u8; PK_LEN];
        StaticKEM::keygen(&mut sk, &mut pk).map_err(anyhow::Error::from)?;
        Ok(Self { sk, pk })
    }

    /// Builds a keypair from raw key bytes, checking their lengths.
    pub fn from_bytes(sk: Zeroizing<Vec<u8>>, pk: Vec<u8>) -> Result<Self, PqError> {
        if sk.len() != SK_LEN {
            return Err(PqError::SecretKeyLength {
                actual: sk.len(),
                expected: SK_LEN,
            });
        }
        if pk.len() != PK_LEN {
            return Err(PqError::PublicKeyLength {
                actual: pk.len(),
                expected: PK_LEN,
            });
        }
        Ok(Self { sk, pk })
    }

    /// The public key bytes.
    pub fn public(&self) -> &[u8] {
        &self.pk
    }

    /// The secret key bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.sk
    }
}

impl std::fmt::Debug for PqKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeypair")
            .field("pk_len", &self.pk.len())
            .finish()
    }
}

/// The result of advancing a [`PqSession`].
pub struct PqOutput {
    /// Messages to send to the peer.
    pub send: Vec<Vec<u8>>,
    /// A freshly established pre-shared key, if the exchange just completed. Wiped from
    /// memory when dropped.
    pub new_psk: Option<Zeroizing<[u8; 32]>>,
    /// Whether the established key expired and must be re-established.
    pub expired: bool,
}

/// A single post-quantum key exchange with one peer.
pub struct PqSession {
    server: CryptoServer,
    peer: PeerPtr,
    initiator: bool,
    tx_buf: MsgBuf,
    pending_psk: Option<Zeroizing<[u8; 32]>>,
    exchanges: u64,
    rejected: u64,
}

impl PqSession {
    /// Creates a session that exchanges with `peer_pk` using `own`'s keypair.
    ///
    /// `initiator` selects the handshake role; only the initiator sends the
    /// opening and retransmission messages.
    pub fn new(own: &PqKeypair, peer_pk: &[u8], initiator: bool) -> Result<Self, PqError> {
        rosenpass::sodium::sodium_init()?;
        if peer_pk.len() != PK_LEN {
            return Err(PqError::PublicKeyLength {
                actual: peer_pk.len(),
                expected: PK_LEN,
            });
        }
        let sk = SSk::from_slice(own.secret_bytes());
        let pk = SPk::from_slice(own.public());
        let mut server = CryptoServer::new(sk, pk);
        let peer = server.add_peer(None, SPk::from_slice(peer_pk))?;
        Ok(Self {
            server,
            peer,
            initiator,
            tx_buf: MsgBuf::zero(),
            pending_psk: None,
            exchanges: 0,
            rejected: 0,
        })
    }

    /// Advances the session, collecting any messages to send.
    ///
    /// Never emits a PSK; that only happens in [`Self::receive`].
    pub fn poll(&mut self) -> PqOutput {
        let mut send = Vec::new();
        let mut expired = false;
        loop {
            match self.server.poll() {
                Ok(PollResult::Sleep(_)) => break,
                Ok(PollResult::SendInitiation(_)) => {
                    if self.initiator
                        && let Ok(len) =
                            self.server.initiate_handshake(self.peer, &mut *self.tx_buf)
                    {
                        send.push(self.tx_buf[..len].to_vec());
                    }
                }
                Ok(PollResult::SendRetransmission(_)) => {
                    if self.initiator
                        && let Ok(len) = self
                            .server
                            .retransmit_handshake(self.peer, &mut *self.tx_buf)
                    {
                        send.push(self.tx_buf[..len].to_vec());
                    }
                }
                Ok(PollResult::DeleteKey(_)) => {
                    expired = true;
                    self.pending_psk = None;
                }
                Err(_) => break,
            }
        }
        PqOutput {
            send,
            new_psk: None,
            expired,
        }
    }

    /// Feeds an incoming message to the session, returning any response and,
    /// once the handshake completes, the pre-shared key.
    pub fn receive(&mut self, msg: &[u8]) -> PqOutput {
        let is_empty_data = !msg.is_empty() && msg[0] == rosenpass::msgs::MsgType::EmptyData as u8;
        let mut send = Vec::new();
        let mut new_psk = None;
        match self.server.handle_msg(msg, &mut *self.tx_buf) {
            Err(_) => self.rejected += 1,
            Ok(res) => {
                if let Some(len) = res.resp {
                    send.push(self.tx_buf[..len].to_vec());
                }
                if let Some(peer) = res.exchanged_with {
                    if let Ok(key) = self.server.osk(peer) {
                        if self.initiator {
                            self.pending_psk = Some(Zeroizing::new(*key.secret()));
                        } else {
                            new_psk = Some(Zeroizing::new(*key.secret()));
                            self.exchanges += 1;
                        }
                    }
                } else if self.initiator
                    && is_empty_data
                    && let Some(psk) = self.pending_psk.take()
                {
                    new_psk = Some(psk);
                    self.exchanges += 1;
                }
            }
        }
        PqOutput {
            send,
            new_psk,
            expired: false,
        }
    }

    /// The number of successful key exchanges completed so far.
    pub fn exchanges(&self) -> u64 {
        self.exchanges
    }

    /// The number of bad or unauthenticated messages dropped so far.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    // McEliece keygen is slow and stack-hungry: generate each keypair exactly
    // once, on a thread with a larger stack than the default test thread.
    fn keypair_a() -> &'static PqKeypair {
        static A: OnceLock<PqKeypair> = OnceLock::new();
        A.get_or_init(|| keygen_in_thread("A"))
    }

    fn keypair_b() -> &'static PqKeypair {
        static B: OnceLock<PqKeypair> = OnceLock::new();
        B.get_or_init(|| keygen_in_thread("B"))
    }

    fn keypair_c() -> &'static PqKeypair {
        static C: OnceLock<PqKeypair> = OnceLock::new();
        C.get_or_init(|| keygen_in_thread("C"))
    }

    fn keygen_in_thread(label: &str) -> PqKeypair {
        let label = label.to_string();
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn({
                let label = label.clone();
                move || PqKeypair::generate().unwrap_or_else(|e| panic!("keygen {label}: {e}"))
            })
            .expect("spawn keygen thread")
            .join()
            .unwrap_or_else(|_| panic!("keygen {label} thread panicked"))
    }

    #[test]
    fn full_exchange_yields_same_psk() {
        let mut init = PqSession::new(keypair_a(), keypair_b().public(), true).unwrap();
        let mut resp = PqSession::new(keypair_b(), keypair_a().public(), false).unwrap();

        // Initiator opens with InitHello, then has nothing else to send.
        let hello = init.poll().send;
        assert_eq!(hello.len(), 1);
        let again = init.poll();
        assert!(again.send.is_empty());
        assert_eq!(init.exchanges(), 0);

        // Responder ignores its own initiation request.
        assert!(resp.poll().send.is_empty());

        // Responder answers with RespHello, without yet emitting a PSK.
        let r1 = resp.receive(&hello[0]);
        assert_eq!(r1.send.len(), 1);
        assert!(r1.new_psk.is_none());

        // Initiator answers with InitConf, storing the pending PSK but not
        // emitting it.
        let i1 = init.receive(&r1.send[0]);
        assert_eq!(i1.send.len(), 1);
        assert!(i1.new_psk.is_none());

        // Responder emits the PSK and answers with EmptyData.
        let r2 = resp.receive(&i1.send[0]);
        assert_eq!(r2.send.len(), 1);
        let resp_psk = r2.new_psk;
        assert!(resp_psk.is_some());

        // Initiator emits only now, upon the responder's EmptyData.
        let i2 = init.receive(&r2.send[0]);
        assert!(i2.send.is_empty());
        let init_psk = i2.new_psk;
        assert!(init_psk.is_some());

        assert_eq!(init_psk.unwrap(), resp_psk.unwrap());
        assert_eq!(init.exchanges(), 1);
        assert_eq!(resp.exchanges(), 1);
    }

    #[test]
    fn wrong_peer_never_emits_psk() {
        // Initiator talks to C, but the responder only knows A: the handshake
        // message cannot be authenticated and is dropped.
        let mut init = PqSession::new(keypair_a(), keypair_c().public(), true).unwrap();
        let mut resp = PqSession::new(keypair_b(), keypair_a().public(), false).unwrap();

        let hello = init.poll().send;
        assert_eq!(hello.len(), 1);

        let r = resp.receive(&hello[0]);
        assert!(r.send.is_empty());
        assert!(r.new_psk.is_none());
        assert_eq!(resp.exchanges(), 0);
        assert!(resp.rejected() >= 1);
    }

    #[test]
    fn garbage_message_increments_rejected() {
        let mut s = PqSession::new(keypair_a(), keypair_b().public(), true).unwrap();

        let out = s.receive(&[0x00, 0x01, 0x02]);
        assert!(out.send.is_empty());
        assert!(out.new_psk.is_none());
        assert!(!out.expired);
        assert_eq!(s.rejected(), 1);

        s.receive(&[]);
        assert_eq!(s.rejected(), 2);
    }

    #[test]
    fn keypair_debug_hides_secret() {
        let kp = PqKeypair::from_bytes(vec![0xAB; SK_LEN].into(), vec![0xCD; PK_LEN]).unwrap();
        let d = format!("{kp:?}");
        assert!(d.contains("pk_len"));
        assert!(!d.contains("ab"));
        assert!(!d.contains("cd"));
        assert!(!d.contains("sk"));
    }

    #[test]
    fn message_sizes_match_wire() {
        use rosenpass::msgs::{EmptyData, Envelope, InitConf, InitHello, LenseView, RespHello};

        let init_hello = <Envelope<(), InitHello<()>> as LenseView>::LEN;
        let resp_hello = <Envelope<(), RespHello<()>> as LenseView>::LEN;
        let init_conf = <Envelope<(), InitConf<()>> as LenseView>::LEN;
        let empty_data = <Envelope<(), EmptyData<()>> as LenseView>::LEN;

        assert_eq!(init_hello, 1092);
        assert_eq!(resp_hello, 1132);
        assert_eq!(init_conf, 176);
        assert_eq!(empty_data, 64);
        assert_eq!(init_hello + resp_hello + init_conf + empty_data, 2464);
    }
}
