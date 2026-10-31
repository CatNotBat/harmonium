//! Offline reproduction of Discord's audio path: 48 kHz mono `f32` audio through
//! libopus at a fixed bitrate, with optional packet loss and additive noise.
//!
//! Discord re-encodes everything with Opus at 48 kHz, so a modem must survive
//! libopus. This crate encodes input audio into 20 ms Opus packets, optionally drops
//! them with a Gilbert-Elliott loss process, and decodes the survivors back to audio
//! (`decode_float(&[], ..)` = packet-loss concealment for dropped packets).

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use harmonium_modem::{FecParams, MfskParams, ModemConfig, OfdmParams, PhyKind};

/// Samples in one Opus packet at 48 kHz (20 ms).
pub const FRAME: usize = 960;
/// Sample rate the channel (and the modem) run at.
pub const SAMPLE_RATE: u32 = 48_000;
/// Output buffer for `opus_encode_float`; far above any legal 20 ms mono packet.
const MAX_PACKET: usize = 4096;

/// Which Opus application profile to use, matching Discord's two relevant modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusApp {
    /// `OPUS_APPLICATION_VOIP` — what Discord uses for voice calls.
    Voip,
    /// `OPUS_APPLICATION_AUDIO` — broadcast/high-fidelity profile.
    Audio,
}

impl OpusApp {
    fn to_opus(self) -> opus::Application {
        match self {
            OpusApp::Voip => opus::Application::Voip,
            OpusApp::Audio => opus::Application::Audio,
        }
    }
}

/// Channel configuration.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Opus encoder bitrate in bits/second.
    pub bitrate: i32,
    /// Opus application profile.
    pub app: OpusApp,
    /// Per-20 ms-packet loss probability (stationary rate).
    pub loss: f64,
    /// Gilbert-Elliott burstiness: probability the next packet is lost given this one was.
    /// `0` = independent loss.
    pub burst: f64,
    /// `ChaCha8Rng` seed.
    pub seed: u64,
    /// Add white noise at this SNR (dB, relative to each 20 ms block's RMS) after decode.
    pub noise_db: Option<f64>,
    /// Linear gain applied before encode (Discord volume); output clamped to [-1, 1].
    pub gain: f32,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            bitrate: 64_000,
            app: OpusApp::Voip,
            loss: 0.0,
            burst: 0.0,
            seed: 1,
            noise_db: None,
            gain: 1.0,
        }
    }
}

/// Gilbert-Elliott packet-loss process. Kept public so tests (and the channel) can
/// drive the same generator and verify its stationary rate and burst statistics.
pub struct LossModel {
    loss: f64,
    burst: f64,
    rng: ChaCha8Rng,
    prev_lost: bool,
}

impl LossModel {
    /// Create a loss process. `loss` is the stationary loss rate; `burst` is the
    /// probability the next packet is lost given the previous one was lost
    /// (`0` = independent Bernoulli loss).
    pub fn new(loss: f64, burst: f64, seed: u64) -> Self {
        Self {
            loss,
            burst,
            rng: ChaCha8Rng::seed_from_u64(seed),
            prev_lost: false,
        }
    }

    /// Decide whether the next packet is lost.
    pub fn decide(&mut self) -> bool {
        if self.loss <= 0.0 {
            self.prev_lost = false;
            return false;
        }
        if self.loss >= 1.0 {
            self.prev_lost = true;
            return true;
        }
        // When burst > 0, choose the entry probability so the stationary rate equals
        // `loss`: p_enter = loss * (1 - burst) / (1 - loss).
        let p = if self.burst > 0.0 {
            if self.prev_lost {
                self.burst
            } else {
                (self.loss * (1.0 - self.burst) / (1.0 - self.loss)).clamp(0.0, 1.0)
            }
        } else {
            self.loss
        };
        let lost = self.rng.random_bool(p);
        self.prev_lost = lost;
        lost
    }
}

/// Channel statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelStats {
    /// Opus packets processed.
    pub packets: u64,
    /// Opus packets dropped (decoded with packet-loss concealment).
    pub lost: u64,
    /// Total Opus payload bytes produced.
    pub bytes: u64,
}

/// Errors the channel can raise.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// An Opus encoder/decoder call failed.
    #[error("opus error: {0}")]
    Opus(String),
}

fn opus_err(e: opus::Error) -> ChannelError {
    ChannelError::Opus(e.to_string())
}

/// The channel: Opus encode → (optional loss) → Opus decode, with optional noise.
pub struct Channel {
    enc: opus::Encoder,
    dec: opus::Decoder,
    loss: LossModel,
    noise_db: Option<f64>,
    noise_rng: ChaCha8Rng,
    gain: f32,
    buf: Vec<f32>,
    stats: ChannelStats,
}

impl Channel {
    /// Create a channel from `cfg`.
    pub fn new(cfg: ChannelConfig) -> Result<Self, ChannelError> {
        let mut enc = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, cfg.app.to_opus())
            .map_err(opus_err)?;
        enc.set_bitrate(opus::Bitrate::Bits(cfg.bitrate))
            .map_err(opus_err)?;
        let dec = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).map_err(opus_err)?;
        Ok(Self {
            enc,
            dec,
            loss: LossModel::new(cfg.loss, cfg.burst, cfg.seed),
            noise_db: cfg.noise_db,
            // A derived seed keeps noise draws independent of loss draws while staying
            // deterministic from the single user-facing seed.
            noise_rng: ChaCha8Rng::seed_from_u64(cfg.seed.wrapping_add(0x9E37_79B9_7F4A_7C15)),
            gain: cfg.gain,
            buf: Vec::new(),
            stats: ChannelStats::default(),
        })
    }

    /// Feed any number of samples; returns the samples that came out (whole 20 ms
    /// = 960-sample frames only; the remainder stays buffered for the next call).
    pub fn process(&mut self, input: &[f32]) -> Vec<f32> {
        for &s in input {
            self.buf.push((s * self.gain).clamp(-1.0, 1.0));
        }

        let n_frames = self.buf.len() / FRAME;
        let mut out = Vec::with_capacity(n_frames * FRAME);
        let mut packet = vec![0u8; MAX_PACKET];
        let mut decoded = vec![0.0f32; FRAME];

        for _ in 0..n_frames {
            let n = self
                .enc
                .encode_float(&self.buf[..FRAME], &mut packet)
                .expect("opus encode buffer is large enough for a 20 ms frame");
            self.buf.drain(..FRAME);
            self.stats.packets += 1;
            self.stats.bytes += n as u64;

            if self.loss.decide() {
                self.stats.lost += 1;
                // Empty input slice = packet-loss concealment.
                self.dec
                    .decode_float(&[], &mut decoded, false)
                    .expect("opus PLC decode");
            } else {
                self.dec
                    .decode_float(&packet[..n], &mut decoded, false)
                    .expect("opus decode");
            }

            if let Some(snr) = self.noise_db {
                self.add_noise(&mut decoded, snr);
            }
            out.extend_from_slice(&decoded);
        }
        out
    }

    /// Channel statistics.
    pub fn stats(&self) -> ChannelStats {
        self.stats
    }

    fn add_noise(&mut self, block: &mut [f32], snr: f64) {
        let mean_sq =
            block.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>() / block.len() as f64;
        let rms = mean_sq.sqrt();
        if rms <= 0.0 {
            return;
        }
        // Uniform white noise whose RMS sits `snr` dB below the block RMS:
        // uniform in [-a, a] has RMS a/sqrt(3).
        let amp = (rms * 10f64.powf(-snr / 20.0) * 3f64.sqrt()) as f32;
        if amp.is_finite() && amp > 0.0 {
            for s in block {
                *s += self.noise_rng.random_range(-amp..amp);
            }
        }
    }
}

/// Which modem PHY a bake-off run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyChoice {
    /// OFDM-DQPSK: the high-rate candidate.
    Ofdm,
    /// MFSK: the robust baseline.
    Mfsk,
}

impl PhyChoice {
    fn name(self) -> &'static str {
        match self {
            PhyChoice::Ofdm => "ofdm",
            PhyChoice::Mfsk => "mfsk",
        }
    }
}

/// Build the [`ModemConfig`] for a bake-off PHY (defaults from the modem crate).
pub fn modem_config(phy: PhyChoice) -> ModemConfig {
    match phy {
        PhyChoice::Ofdm => ModemConfig {
            phy: PhyKind::Ofdm(OfdmParams::default()),
            fec: FecParams::default(),
        },
        PhyChoice::Mfsk => ModemConfig {
            phy: PhyKind::Mfsk(MfskParams::default()),
            fec: FecParams::default(),
        },
    }
}

/// Parameters for a modem bake-off run.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Channel to push the modem audio through.
    pub channel: ChannelConfig,
    /// Modem PHY under test.
    pub phy: PhyChoice,
    /// Simulated seconds of audio.
    pub seconds: f64,
    /// Packet payload size in bytes (first 4 bytes carry a big-endian sequence number).
    pub packet_bytes: usize,
    /// Offered load in packets/second; `None` = fill ~90% of `net_bitrate`.
    pub pps: Option<f64>,
    /// Override the Reed-Solomon ECC bytes per codeword (default: the modem's default).
    pub ecc_len: Option<usize>,
    /// Override the OFDM layout `(first_bin, n_carriers, bits_per_carrier)`.
    pub ofdm_layout: Option<(usize, usize, usize)>,
}

/// Result of a bake-off run; serialized as the final JSON line by the binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchReport {
    pub phy: &'static str,
    pub net_bitrate: f64,
    pub offered_bps: f64,
    pub delivered_bps: f64,
    pub frames_ok: u64,
    pub frames_failed: u64,
    pub frame_error_rate: f64,
    pub pre_fec_ber: f64,
    pub packets_sent: u64,
    pub packets_delivered: u64,
    pub packets_corrupt: u64,
    pub opus_packets: u64,
    pub opus_lost: u64,
}

/// Run the bake-off: modem → channel → modem, counting delivered packets.
pub fn run_bench(cfg: &BenchConfig) -> Result<BenchReport, ChannelError> {
    assert!(
        cfg.packet_bytes >= 4,
        "packet_bytes must be >= 4 to carry a sequence number"
    );

    let mut modem = modem_config(cfg.phy);
    if let Some(ecc) = cfg.ecc_len {
        modem.fec.ecc_len = ecc;
    }
    if let (Some((first_bin, n_carriers, bits)), PhyKind::Ofdm(p)) =
        (cfg.ofdm_layout, &mut modem.phy)
    {
        p.first_bin = first_bin;
        p.n_carriers = n_carriers;
        p.bits_per_carrier = bits;
    }
    let net = harmonium_modem::net_bitrate(&modem);
    let pps = cfg.pps.unwrap_or_else(|| {
        // Enough to fill ~90% of the net link rate, counting COBS framing overhead
        // (~4 bytes/packet: COBS + CRC-16) against the payload size.
        (0.9 * net / (8.0 * (cfg.packet_bytes as f64 + 2.0)))
            .floor()
            .max(1.0)
    });
    let total_samples = (cfg.seconds * SAMPLE_RATE as f64) as usize;
    let n_packets = (pps * cfg.seconds).floor() as usize;

    // Generate the offered packets up front; the first 4 bytes are the sequence number.
    let mut rng = ChaCha8Rng::seed_from_u64(cfg.channel.seed);
    let mut sent = Vec::with_capacity(n_packets);
    for i in 0..n_packets {
        let mut p = vec![0u8; cfg.packet_bytes];
        p[..4].copy_from_slice(&(i as u32).to_be_bytes());
        rng.fill(&mut p[4..]);
        sent.push(p);
    }

    let mut tx = harmonium_modem::Transmitter::new(modem.clone());
    let mut rx = harmonium_modem::Receiver::new(modem);
    let mut channel = Channel::new(cfg.channel.clone())?;

    let mut packets_sent = 0u64;
    let mut received = Vec::new();
    let mut generated = 0usize;

    // Generate modem frames until `seconds` of audio have been produced and every
    // queued packet has been emitted. Packet `i` is queued once sim time reaches `i/pps`.
    while generated < total_samples || tx.pending_bytes() > 0 {
        let t = generated as f64 / SAMPLE_RATE as f64;
        while packets_sent < n_packets as u64 && packets_sent as f64 / pps <= t + 1e-9 {
            tx.send(&sent[packets_sent as usize]);
            packets_sent += 1;
        }

        let frame = tx.next_frame();
        generated += frame.len();
        let mut out = Vec::new();
        for chunk in frame.chunks(FRAME) {
            out.extend(channel.process(chunk));
        }
        received.extend(rx.push(&out));
    }

    // Flush the channel's buffered remainder so the final modem frame is fully decoded.
    let rem = generated % FRAME;
    if rem != 0 {
        let pad = vec![0.0f32; FRAME - rem];
        let out = channel.process(&pad);
        received.extend(rx.push(&out));
    }

    let (delivered, corrupt) = tally(&sent, &received);
    let rx_stats = rx.stats();
    let channel_stats = channel.stats();

    let frames_total = rx_stats.frames_ok + rx_stats.frames_failed;
    let frame_error_rate = if frames_total == 0 {
        0.0
    } else {
        rx_stats.frames_failed as f64 / frames_total as f64
    };

    Ok(BenchReport {
        phy: cfg.phy.name(),
        net_bitrate: net,
        offered_bps: pps * 8.0 * cfg.packet_bytes as f64,
        delivered_bps: delivered as f64 * 8.0 * cfg.packet_bytes as f64 / cfg.seconds,
        frames_ok: rx_stats.frames_ok,
        frames_failed: rx_stats.frames_failed,
        frame_error_rate,
        pre_fec_ber: rx_stats.pre_fec_ber(),
        packets_sent,
        packets_delivered: delivered,
        packets_corrupt: corrupt,
        opus_packets: channel_stats.packets,
        opus_lost: channel_stats.lost,
    })
}

/// Compare received packets against the sent ones (by the 4-byte sequence number).
/// Returns (delivered, corrupt): a received packet that matches `sent[seq]` byte-for-byte
/// is delivered, anything else is a post-FEC error.
fn tally(sent: &[Vec<u8>], received: &[Vec<u8>]) -> (u64, u64) {
    let mut delivered = 0u64;
    let mut corrupt = 0u64;
    for p in received {
        if p.len() < 4 {
            corrupt += 1;
            continue;
        }
        let seq = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        if seq < sent.len() && p == &sent[seq] {
            delivered += 1;
        } else {
            corrupt += 1;
        }
    }
    (delivered, corrupt)
}
