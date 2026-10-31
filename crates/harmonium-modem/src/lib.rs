//! The Harmonium modem: turns link packets into 48 kHz mono audio that survives
//! Discord's Opus path, and back.

pub mod fec;
pub mod framer;
pub mod mfsk;
pub mod ofdm;
pub mod sync;

pub use fec::{FecParams, FecResult};
pub use mfsk::MfskParams;
pub use ofdm::OfdmParams;

use std::collections::VecDeque;

/// Extra samples handed to [`Phy::demodulate`] past the nominal frame end, so a frame that
/// Discord stretched (repeated audio) still has its last symbol in the slice. Matches the OFDM
/// per-symbol slip search range.
const FRAME_SLACK: usize = ofdm::MAX_SLIP as usize;

/// A modulation PHY that turns coded bytes into audio frames and back.
pub trait Phy: Send {
    /// Short human-readable name of this PHY.
    fn name(&self) -> &'static str;
    /// Append the audio samples for one frame carrying exactly `coded.len()` bytes.
    fn modulate(&self, coded: &[u8], out: &mut Vec<f32>);
    /// Demodulate one frame whose chirp starts at `frame[0]`, returning the hard-decided coded bytes.
    /// `frame` may run past [`Phy::frame_len`] by up to `FRAME_SLACK` samples.
    fn demodulate(&self, frame: &[f32], coded_len: usize) -> Vec<u8>;
    /// Total samples in one frame (chirp + gap + symbols) for `coded_len` bytes.
    fn frame_len(&self, coded_len: usize) -> usize;
}

/// The two modulation PHYs.
#[derive(Debug, Clone, Copy)]
pub enum PhyKind {
    /// OFDM-DQPSK: the high-rate candidate.
    Ofdm(OfdmParams),
    /// MFSK: the robust baseline.
    Mfsk(MfskParams),
}

impl PhyKind {
    fn build(&self) -> Box<dyn Phy> {
        match self {
            PhyKind::Ofdm(p) => Box::new(ofdm::Ofdm::new(*p)),
            PhyKind::Mfsk(p) => Box::new(mfsk::Mfsk::new(*p)),
        }
    }
}

/// Full modem configuration: a PHY plus FEC parameters.
#[derive(Debug, Clone)]
pub struct ModemConfig {
    /// Modulation PHY.
    pub phy: PhyKind,
    /// Forward error correction parameters.
    pub fec: FecParams,
}

impl Default for ModemConfig {
    fn default() -> Self {
        Self {
            phy: PhyKind::Ofdm(OfdmParams::default()),
            fec: FecParams::default(),
        }
    }
}

/// Net payload bitrate of a configuration, in bits per second.
pub fn net_bitrate(cfg: &ModemConfig) -> f64 {
    let coded_len = cfg.fec.coded_len();
    let frame_len = cfg.phy.build().frame_len(coded_len);
    cfg.fec.payload_len() as f64 * 8.0 / (frame_len as f64 / 48_000.0)
}

/// Transmits packets as a stream of audio frames.
pub struct Transmitter {
    phy: Box<dyn Phy>,
    fec: FecParams,
    framer: framer::Framer,
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
}

impl Transmitter {
    /// Create a transmitter from a configuration.
    pub fn new(cfg: ModemConfig) -> Self {
        let payload_len = cfg.fec.payload_len();
        Self {
            phy: cfg.phy.build(),
            fec: cfg.fec,
            framer: framer::Framer::new(payload_len),
            queue: VecDeque::new(),
            queued_bytes: 0,
        }
    }

    /// Queue a packet (1..=1500 bytes) for transmission.
    pub fn send(&mut self, packet: &[u8]) {
        self.queued_bytes += packet.len();
        self.queue.push_back(packet.to_vec());
    }

    /// Produce the next audio frame. Always returns a full frame; when nothing is queued the
    /// frame carries only padding (an idle frame).
    pub fn next_frame(&mut self) -> Vec<f32> {
        let payload_len = self.fec.payload_len();
        while self.framer.pending() < payload_len {
            match self.queue.pop_front() {
                Some(p) => {
                    self.queued_bytes -= p.len();
                    self.framer.push(&p);
                }
                None => break,
            }
        }
        let payload = self.framer.next_chunk();
        let coded = self.fec.encode(&payload);
        let mut out = Vec::new();
        self.phy.modulate(&coded, &mut out);
        out
    }

    /// Number of queued packet bytes plus encoded stream bytes not yet emitted.
    pub fn pending_bytes(&self) -> usize {
        self.queued_bytes + self.framer.pending()
    }
}

/// Receives audio and yields complete packets.
pub struct Receiver {
    phy: Box<dyn Phy>,
    fec: FecParams,
    deframer: framer::Deframer,
    detector: sync::SyncDetector,
    buf: Vec<f32>,
    buf_start: usize,
    next_global: usize,
    next_search_t: usize,
    frame_len: usize,
    coded_len: usize,
    pending_dets: VecDeque<usize>,
    stats: RxStats,
}

impl Receiver {
    /// Create a receiver from a configuration.
    pub fn new(cfg: ModemConfig) -> Self {
        let coded_len = cfg.fec.coded_len();
        let phy = cfg.phy.build();
        let frame_len = phy.frame_len(coded_len);
        Self {
            phy,
            fec: cfg.fec,
            deframer: framer::Deframer::new(),
            detector: sync::SyncDetector::new(),
            buf: Vec::new(),
            buf_start: 0,
            next_global: 0,
            next_search_t: 0,
            frame_len,
            coded_len,
            pending_dets: VecDeque::new(),
            stats: RxStats::default(),
        }
    }

    /// Feed audio samples; returns any complete packets decoded from them.
    pub fn push(&mut self, samples: &[f32]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(samples);
        self.next_global += samples.len();
        for d in self.detector.push(samples) {
            self.pending_dets.push_back(d);
        }

        let mut packets = Vec::new();
        while let Some(&t) = self.pending_dets.front() {
            if t < self.next_search_t {
                self.pending_dets.pop_front();
                continue;
            }
            if self.next_global < t + self.frame_len + FRAME_SLACK {
                break; // wait for the rest of the frame, plus room for a stretched one
            }
            self.pending_dets.pop_front();
            self.demodulate_at(t, &mut packets);
            // Resume one symbol early: Discord can drop audio mid-frame, so the next chirp may
            // arrive before the nominal frame end.
            self.next_search_t = t + self.frame_len - FRAME_SLACK * 2;
            self.drop_before(self.next_search_t);
        }
        if self.pending_dets.is_empty() {
            // No frame in flight: forget audio the detector has already scanned, so silence
            // or a dead carrier does not grow memory without bound. The detector's scan point
            // trails the newest sample by at most ~BLOCK + CHIRP_LEN, so this keeps a margin.
            let horizon = self
                .next_global
                .saturating_sub(2 * sync::BLOCK + sync::CHIRP_LEN);
            self.drop_before(horizon.max(self.next_search_t));
        }
        packets
    }

    /// Receiver statistics.
    pub fn stats(&self) -> RxStats {
        self.stats
    }

    fn demodulate_at(&mut self, t: usize, packets: &mut Vec<Vec<u8>>) {
        let rel = t - self.buf_start;
        let frame = &self.buf[rel..rel + self.frame_len + FRAME_SLACK];
        let coded = self.phy.demodulate(frame, self.coded_len);
        let res = self.fec.decode(&coded);
        match res.payload {
            Some(payload) => {
                self.stats.coded_bits += (self.coded_len * 8) as u64;
                self.stats.frames_ok += 1;
                self.stats.corrected_bytes += res.corrected_bytes as u64;
                self.stats.bit_errors += res.bit_errors as u64;
                let pkts = self.deframer.push(&payload);
                self.stats.packets += pkts.len() as u64;
                packets.extend(pkts);
            }
            None => {
                self.stats.frames_failed += 1;
                self.deframer.lost();
            }
        }
    }

    #[cfg(test)]
    fn detector_backlog(&self) -> usize {
        self.detector.backlog()
    }

    fn drop_before(&mut self, g: usize) {
        if g > self.buf_start && g <= self.next_global {
            let drop_n = (g - self.buf_start).min(self.buf.len());
            self.buf.drain(..drop_n);
            self.buf_start = g;
        }
        self.detector.drop_before(g);
    }
}

/// Receiver statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RxStats {
    /// Frames decoded successfully.
    pub frames_ok: u64,
    /// Frames whose FEC decode failed.
    pub frames_failed: u64,
    /// Bytes corrected by FEC across successful frames.
    pub corrected_bytes: u64,
    /// Pre-FEC bit errors across successful frames.
    pub bit_errors: u64,
    /// Coded bits received across successful frames.
    pub coded_bits: u64,
    /// Complete packets emitted.
    pub packets: u64,
}

impl RxStats {
    /// Pre-FEC bit-error rate over successfully decoded frames.
    pub fn pre_fec_ber(&self) -> f64 {
        if self.coded_bits == 0 {
            0.0
        } else {
            self.bit_errors as f64 / self.coded_bits as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn phy_cases() -> Vec<PhyKind> {
        vec![
            PhyKind::Ofdm(OfdmParams::default()),
            PhyKind::Mfsk(MfskParams::default()),
        ]
    }

    #[test]
    fn phy_clean_bit_exact_and_peak() {
        for kind in phy_cases() {
            let phy = kind.build();
            let fec = FecParams::default();
            let mut rng = ChaCha8Rng::seed_from_u64(20);
            let mut coded = vec![0u8; fec.coded_len()];
            rng.fill(&mut coded[..]);

            let mut audio = Vec::new();
            phy.modulate(&coded, &mut audio);
            let peak = audio.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
            assert!(peak <= 0.5, "{}: peak {peak}", phy.name());

            let decoded = phy.demodulate(&audio, fec.coded_len());
            assert_eq!(decoded, coded, "{}", phy.name());
        }
    }

    #[test]
    fn phy_noise_20db_fec_exact() {
        for kind in phy_cases() {
            let cfg = ModemConfig {
                phy: kind,
                fec: FecParams::default(),
            };
            let phy = cfg.phy.build();
            let mut rng = ChaCha8Rng::seed_from_u64(21);
            let mut payload = vec![0u8; cfg.fec.payload_len()];
            rng.fill(&mut payload[..]);
            let coded = cfg.fec.encode(&payload);

            let mut audio = Vec::new();
            phy.modulate(&coded, &mut audio);
            let sig_rms = (audio.iter().map(|&s| s * s).sum::<f32>() / audio.len() as f32).sqrt();
            let noise_amp = sig_rms / 10.0 * 3.0f32.sqrt(); // uniform noise at 20 dB SNR
            for s in &mut audio {
                *s += rng.random_range(-noise_amp..noise_amp);
            }

            let decoded = phy.demodulate(&audio, cfg.fec.coded_len());
            let res = cfg.fec.decode(&decoded);
            assert_eq!(
                res.payload.as_deref(),
                Some(payload.as_slice()),
                "{}",
                phy.name()
            );
        }
    }

    #[test]
    fn receiver_with_leading_offset() {
        for kind in phy_cases() {
            let name = kind.build().name();
            let cfg = ModemConfig {
                phy: kind,
                fec: FecParams::default(),
            };
            let mut tx = Transmitter::new(cfg.clone());
            let packet: Vec<u8> = (0..100u8).collect();
            tx.send(&packet);

            let mut audio = Vec::new();
            while tx.pending_bytes() > 0 {
                audio.extend(tx.next_frame());
            }
            audio.extend(tx.next_frame()); // idle flush

            let mut signal = vec![0.0f32; 1234];
            signal.extend(audio);

            let mut rx = Receiver::new(cfg);
            let mut got = Vec::new();
            for chunk in signal.chunks(997) {
                got.extend(rx.push(chunk));
            }
            assert_eq!(got, vec![packet], "{name}");
        }
    }

    /// Live Discord audio loses or repeats a few ms mid-frame (NetEQ-style time-scaling). The
    /// OFDM receiver must re-find symbol timing after the slip, and its chirp search must still
    /// catch the next frame when a dropped chunk pulls it early.
    #[test]
    fn ofdm_survives_mid_frame_sample_slips() {
        let cfg = ModemConfig::default();
        let frame_len = cfg.phy.build().frame_len(cfg.fec.coded_len());
        let mut tx = Transmitter::new(cfg.clone());
        let packets: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 100]).collect();
        for p in &packets {
            tx.send(p);
        }
        let mut frames: Vec<Vec<f32>> = (0..4).map(|_| tx.next_frame()).collect();

        // Frame 0: 200 samples dropped at a symbol boundary in the middle.
        let at = 1008 + 20 * 576;
        frames[0].drain(at..at + 200);
        // Frame 1: 150 samples repeated a few symbols in.
        let at = 1008 + 8 * 576;
        let dup: Vec<f32> = frames[1][at - 150..at].to_vec();
        frames[1].splice(at..at, dup);
        assert_eq!(frames[0].len(), frame_len - 200);

        let mut rx = Receiver::new(cfg);
        let mut got = Vec::new();
        for chunk in frames.concat().chunks(960) {
            got.extend(rx.push(chunk));
        }
        assert_eq!(rx.stats().frames_failed, 0);
        assert_eq!(got[..packets.len()], packets[..]);
    }

    #[test]
    fn net_bitrate_in_range() {
        let cfg = ModemConfig::default();
        let rate = net_bitrate(&cfg);
        assert!(
            (3000.0..5000.0).contains(&rate),
            "default net bitrate out of range: {rate}"
        );
        println!("OFDM net_bitrate = {:.1} bps", rate);

        let mfsk = ModemConfig {
            phy: PhyKind::Mfsk(MfskParams::default()),
            fec: FecParams::default(),
        };
        println!("MFSK net_bitrate = {:.1} bps", net_bitrate(&mfsk));
    }

    #[test]
    fn silence_keeps_memory_bounded_and_still_syncs() {
        let cfg = ModemConfig::default();
        let mut rx = Receiver::new(cfg.clone());
        let mut tx = Transmitter::new(cfg);
        let silence = vec![0.0f32; 960];
        for _ in 0..3000 {
            // 60 s of silence
            assert!(rx.push(&silence).is_empty());
        }
        assert!(
            rx.buf.len() < 3 * sync::BLOCK + sync::CHIRP_LEN,
            "buf {}",
            rx.buf.len()
        );
        assert!(rx.detector_backlog() < 3 * sync::BLOCK + sync::CHIRP_LEN);

        tx.send(b"after the silence");
        let mut audio = tx.next_frame();
        audio.extend(tx.next_frame());
        let mut got = Vec::new();
        for chunk in audio.chunks(960) {
            got.extend(rx.push(chunk));
        }
        assert_eq!(got, vec![b"after the silence".to_vec()]);
    }
}
