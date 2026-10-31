//! Command-line interface definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use harmonium_modem::{FecParams, MfskParams, ModemConfig, OfdmParams, PhyKind};

use crate::call::CallOpts;
use crate::selftest::SelftestOpts;

/// Encrypted voice and text over a Discord call.
#[derive(Parser, Debug)]
#[command(name = "harmonium", version, about)]
pub struct Cli {
    /// Directory that holds the identity and peer store (defaults to the
    /// platform config dir).
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Verbose logging (debug level on stderr).
    #[arg(short = 'v', global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a new identity (WireGuard + age).
    Keygen {
        /// Overwrite an existing identity.
        #[arg(long)]
        force: bool,
    },

    /// Print your own identity bundle, fingerprint and QR code.
    Id,

    /// Manage peers (add, show, verify, remove).
    Peer {
        #[command(subcommand)]
        cmd: PeerCmd,
    },

    /// Set up / tear down / inspect the virtual audio devices.
    Devices {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },

    /// Encrypt or decrypt a text message (clipboard or stdin).
    Text {
        #[command(subcommand)]
        cmd: TextCmd,
    },

    /// Offline end-to-end voice loop (file in, file out, no audio devices).
    Selftest(SelftestOpts),

    /// Run a live encrypted call.
    Call(CallOpts),

    #[cfg(feature = "pq")]
    /// Manage the post-quantum (Rosenpass) keypair.
    Pq {
        #[command(subcommand)]
        cmd: PqCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeerCmd {
    /// Add a peer's bundle under a name.
    Add {
        /// Short name for this peer (alphanumeric, `_`, `-`).
        name: String,
        /// The peer's `harmonium1:...` bundle string.
        bundle: String,
    },

    /// Show one peer, or a table of all peers when no name is given.
    Show { name: Option<String> },

    /// Compare fingerprints out-of-band and mark the peer verified.
    Verify { name: String },

    /// Remove a peer (absent is a no-op).
    Remove { name: String },

    #[cfg(feature = "pq")]
    /// Import a peer's post-quantum public key from a file.
    PqImport { name: String, file: PathBuf },
}

#[cfg(feature = "pq")]
#[derive(Subcommand, Debug)]
pub enum PqCmd {
    /// Generate a new post-quantum keypair.
    Keygen {
        #[arg(long)]
        force: bool,
    },

    /// Write this identity's post-quantum public key to a file (send it to the peer).
    Export { file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// Create the virtual devices and keep them alive until Ctrl-C.
    Setup,

    /// Explain that devices die with the process on Linux (no-op).
    Teardown,

    /// List audio devices and report whether the virtual devices exist.
    Check,
}

#[derive(Subcommand, Debug)]
pub enum TextCmd {
    /// Encrypt a message to a peer (clipboard, argument, or stdin).
    Encrypt {
        /// Peer name the message is encrypted to.
        peer: String,
        /// The message; when absent, use the clipboard (or stdin).
        message: Option<String>,
        /// Read the plaintext from stdin instead of the clipboard.
        #[arg(long)]
        no_clipboard: bool,
        /// Allow encrypting to a peer that has not been verified.
        #[arg(long)]
        allow_unverified: bool,
    },

    /// Decrypt the clipboard (or stdin) with your own age identity.
    Decrypt {
        /// Read the ciphertext from stdin instead of the clipboard.
        #[arg(long)]
        no_clipboard: bool,
    },
}

/// Which modem PHY to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PhyArg {
    /// OFDM-DQPSK: the high-rate candidate.
    Ofdm,
    /// MFSK: the robust baseline.
    Mfsk,
}

impl std::fmt::Display for PhyArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl PhyArg {
    pub fn name(self) -> &'static str {
        match self {
            PhyArg::Ofdm => "ofdm",
            PhyArg::Mfsk => "mfsk",
        }
    }

    /// Build the [`ModemConfig`] for this PHY, using the modem crate's defaults.
    pub fn modem_config(self) -> ModemConfig {
        match self {
            PhyArg::Ofdm => ModemConfig {
                phy: PhyKind::Ofdm(OfdmParams::default()),
                fec: FecParams::default(),
            },
            PhyArg::Mfsk => ModemConfig {
                phy: PhyKind::Mfsk(MfskParams::default()),
                fec: FecParams::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_keygen_and_global_home() {
        let cli =
            Cli::try_parse_from(["harmonium", "--home", "/tmp/x", "keygen", "--force"]).unwrap();
        assert_eq!(cli.home.as_deref(), Some(std::path::Path::new("/tmp/x")));
        assert!(matches!(cli.command, Command::Keygen { force: true }));
    }

    #[test]
    fn parse_id() {
        let cli = Cli::try_parse_from(["harmonium", "id"]).unwrap();
        assert!(matches!(cli.command, Command::Id));
    }

    #[test]
    fn parse_peer_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "add", "bob", "harmonium1:abc:age1x"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::Add { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "show"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::Show { name: None }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "show", "bob"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::Show { name: Some(_) }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "verify", "bob"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::Verify { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "remove", "bob"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::Remove { .. }
            }
        ));
    }

    #[test]
    fn parse_devices() {
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "devices", "setup"])
                .unwrap()
                .command,
            Command::Devices {
                cmd: DeviceCmd::Setup
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "devices", "teardown"])
                .unwrap()
                .command,
            Command::Devices {
                cmd: DeviceCmd::Teardown
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "devices", "check"])
                .unwrap()
                .command,
            Command::Devices {
                cmd: DeviceCmd::Check
            }
        ));
    }

    #[test]
    fn parse_text() {
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "text", "encrypt", "bob", "hi"])
                .unwrap()
                .command,
            Command::Text {
                cmd: TextCmd::Encrypt { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "text", "decrypt"])
                .unwrap()
                .command,
            Command::Text {
                cmd: TextCmd::Decrypt { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "text", "decrypt", "--no-clipboard"])
                .unwrap()
                .command,
            Command::Text {
                cmd: TextCmd::Decrypt { .. }
            }
        ));
    }

    #[test]
    fn parse_selftest() {
        let cli = Cli::try_parse_from([
            "harmonium",
            "selftest",
            "--seconds",
            "7",
            "--opus",
            "--loss",
            "0.02",
            "--phy",
            "mfsk",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Selftest(opts) => {
                assert_eq!(opts.seconds, 7.0);
                assert!(opts.opus);
                assert_eq!(opts.loss, 0.02);
                assert_eq!(opts.phy, PhyArg::Mfsk);
                assert!(opts.json);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn parse_call() {
        let cli = Cli::try_parse_from([
            "harmonium",
            "call",
            "bob",
            "--mic",
            "Mic",
            "--speaker",
            "Speakers",
            "--phy",
            "ofdm",
            "--allow-unverified",
        ])
        .unwrap();
        match cli.command {
            Command::Call(opts) => {
                assert_eq!(opts.peer, "bob");
                assert_eq!(opts.mic.as_deref(), Some("Mic"));
                assert_eq!(opts.speaker.as_deref(), Some("Speakers"));
                assert_eq!(opts.phy, PhyArg::Ofdm);
                assert!(opts.allow_unverified);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[cfg(feature = "pq")]
    #[test]
    fn parse_pq() {
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "pq", "keygen"])
                .unwrap()
                .command,
            Command::Pq {
                cmd: PqCmd::Keygen { force: false }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "pq", "keygen", "--force"])
                .unwrap()
                .command,
            Command::Pq {
                cmd: PqCmd::Keygen { force: true }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "pq", "export", "f.pk"])
                .unwrap()
                .command,
            Command::Pq {
                cmd: PqCmd::Export { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["harmonium", "peer", "pq-import", "bob", "bob.pk"])
                .unwrap()
                .command,
            Command::Peer {
                cmd: PeerCmd::PqImport { .. }
            }
        ));

        match Cli::try_parse_from(["harmonium", "call", "bob", "--pq"])
            .unwrap()
            .command
        {
            Command::Call(opts) => assert!(opts.pq),
            other => panic!("unexpected command {other:?}"),
        }
        match Cli::try_parse_from(["harmonium", "selftest", "--pq"])
            .unwrap()
            .command
        {
            Command::Selftest(opts) => assert!(opts.pq),
            other => panic!("unexpected command {other:?}"),
        }
    }
}
