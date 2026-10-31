//! The offline end-to-end voice loop.
//!
//! Pure and device-free: two in-process endpoints talk WireGuard over a modem
//! through an in-memory (or Opus) channel. File in, file out.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(feature = "pq")]
use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use clap::Args;

use channel_sim::{Channel, ChannelConfig, OpusApp};
use harmonium_keys::Identity;
use harmonium_link::{LinkKeys, LinkStats};
#[cfg(feature = "pq")]
use harmonium_pq::{PqKeypair, PqSession};

use crate::call::{CallEngine, STEP_SAMPLES};
use crate::cli::PhyArg;

/// Sample rate the modem assumes.
const SAMPLE_RATE: usize = 48_000;
/// Silence fed to A's mic before the input so the handshake completes.
const WARMUP_SECS: f64 = 3.0;
/// Silence fed after the input so queued packets drain.
const TAIL_SECS: f64 = 3.0;
/// WireGuard timer advance interval.
const TICK_INTERVAL: f64 = 0.250;
/// Correlation lag search window, in milliseconds.
const MAX_LAG_MS: usize = 3000;

/// Options for `harmonium selftest`.
#[derive(Args, Debug, Clone)]
pub struct SelftestOpts {
    /// Input WAV (48 kHz mono, i16 or f32); default is a generated test signal.
    #[arg(long, value_name = "IN.wav")]
    pub input: Option<PathBuf>,

    /// Output WAV for the decoded audio (f32, 48 kHz mono).
    #[arg(long, value_name = "OUT.wav")]
    pub output: Option<PathBuf>,

    /// Output WAV for the A→B modem audio as B receives it (after the Opus channel with
    /// `--opus`): what Discord carries (f32, 48 kHz mono).
    #[arg(long, value_name = "OUT.wav")]
    pub modem_output: Option<PathBuf>,

    /// Length of the generated test signal, in seconds.
    #[arg(long, default_value_t = 10.0)]
    pub seconds: f64,

    /// Route the modem audio through a 64 kbps Opus channel (Discord's path).
    #[arg(long)]
    pub opus: bool,

    /// Opus packet loss probability.
    #[arg(long, default_value_t = 0.0)]
    pub loss: f64,

    /// Opus loss burstiness (0 = independent loss).
    #[arg(long, default_value_t = 0.0)]
    pub burst: f64,

    /// Opus loss-model seed (the B→A channel uses seed+1).
    #[arg(long, default_value_t = 1)]
    pub seed: u64,

    /// Modem PHY.
    #[arg(long, value_enum, default_value_t = PhyArg::Ofdm)]
    pub phy: PhyArg,

    /// Emit one JSON object instead of human-readable lines.
    #[arg(long)]
    pub json: bool,

    /// Enable the post-quantum (Rosenpass) key exchange.
    #[cfg(feature = "pq")]
    #[arg(long)]
    pub pq: bool,
}

impl Default for SelftestOpts {
    fn default() -> Self {
        Self {
            input: None,
            output: None,
            modem_output: None,
            seconds: 10.0,
            opus: false,
            loss: 0.0,
            burst: 0.0,
            seed: 1,
            phy: PhyArg::Ofdm,
            json: false,
            #[cfg(feature = "pq")]
            pq: false,
        }
    }
}

/// Aggregate latency of the delivered voice packets.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencyStats {
    pub mean: f64,
    pub min: f64,
    pub max: f64,
}

/// Modem receive statistics for one direction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModemRx {
    pub frames_ok: u64,
    pub frames_failed: u64,
    pub pre_fec_ber: f64,
}

/// Link statistics for one side.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkStat {
    pub sent: u64,
    pub dropped_no_session: u64,
    pub delivered: u64,
    pub rejected: u64,
    pub handshakes: u64,
}

impl From<&LinkStats> for LinkStat {
    fn from(s: &LinkStats) -> Self {
        Self {
            sent: s.sent,
            dropped_no_session: s.dropped_no_session,
            delivered: s.delivered,
            rejected: s.rejected,
            handshakes: s.handshakes_completed,
        }
    }
}

/// The result of an offline voice loop.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelftestReport {
    /// Simulated time (ms) at which both links were up, if that happened.
    pub handshake_ms: Option<f64>,
    pub voice_packets_sent: u64,
    pub voice_packets_delivered: u64,
    pub voice_packets_bad: u64,
    /// `1 - delivered / sent`, clamped to `[0, 1]`.
    pub packet_loss: f64,
    pub latency_ms: LatencyStats,
    pub audio_lag_ms: f64,
    pub audio_corr: f64,
    pub modem_a_to_b: ModemRx,
    pub modem_b_to_a: ModemRx,
    pub link_a: LinkStat,
    pub link_b: LinkStat,
    pub seconds: f64,
    pub phy: &'static str,
    pub opus: bool,
    /// Whether the PQ layer was enabled for this run.
    pub pq: bool,
    pub pq_status_a: &'static str,
    pub pq_status_b: &'static str,
    pub pq_exchanges_a: u64,
    pub pq_exchanges_b: u64,
    /// Simulated time (ms) each side became PQ-secure, if it did.
    pub pq_secure_ms_a: Option<f64>,
    pub pq_secure_ms_b: Option<f64>,
    /// Simulated time (ms) of the first voice packet actually sent.
    pub voice_first_send_ms: Option<f64>,
}

impl SelftestReport {
    /// The acceptance criterion: handshake completed and ≥ 90% of voice delivered.
    pub fn passed(&self) -> bool {
        self.handshake_ms.is_some()
            && self.voice_packets_sent > 0
            && self.voice_packets_delivered as f64 / self.voice_packets_sent as f64 >= 0.90
    }

    /// Human-readable reason the run did not pass.
    pub fn failure_reason(&self) -> Option<String> {
        if self.pq && (self.pq_secure_ms_a.is_none() || self.pq_secure_ms_b.is_none()) {
            return Some("the post-quantum layer never became secure on both sides".to_string());
        }
        if self.passed() {
            return None;
        }
        let reason = if self.handshake_ms.is_none() {
            "the WireGuard handshake never completed".to_string()
        } else if self.voice_packets_sent == 0 {
            "no voice packets were sent after the handshake".to_string()
        } else {
            format!(
                "only {}/{} voice packets were delivered ({:.1}%)",
                self.voice_packets_delivered,
                self.voice_packets_sent,
                100.0 * self.voice_packets_delivered as f64 / self.voice_packets_sent as f64
            )
        };
        Some(reason)
    }
}

impl fmt::Display for SelftestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handshake = self
            .handshake_ms
            .map(|ms| format!("{ms:.1} ms"))
            .unwrap_or_else(|| "never".to_string());
        writeln!(f, "phy:                  {}", self.phy)?;
        writeln!(
            f,
            "channel:              {}",
            if self.opus {
                "opus 64 kbps voip"
            } else {
                "identity"
            }
        )?;
        writeln!(f, "input:                {:.2} s", self.seconds)?;
        writeln!(f, "handshake:            {handshake}")?;
        writeln!(
            f,
            "voice:                sent={} delivered={} loss={:.2}% bad={}",
            self.voice_packets_sent,
            self.voice_packets_delivered,
            100.0 * self.packet_loss,
            self.voice_packets_bad
        )?;
        writeln!(
            f,
            "latency:              mean={:.1} ms min={:.1} ms max={:.1} ms",
            self.latency_ms.mean, self.latency_ms.min, self.latency_ms.max
        )?;
        writeln!(
            f,
            "audio:                lag={:.1} ms corr={:.3}",
            self.audio_lag_ms, self.audio_corr
        )?;
        writeln!(
            f,
            "modem A->B:           frames_ok={} frames_failed={} pre_fec_ber={:.6}",
            self.modem_a_to_b.frames_ok,
            self.modem_a_to_b.frames_failed,
            self.modem_a_to_b.pre_fec_ber
        )?;
        writeln!(
            f,
            "modem B->A:           frames_ok={} frames_failed={} pre_fec_ber={:.6}",
            self.modem_b_to_a.frames_ok,
            self.modem_b_to_a.frames_failed,
            self.modem_b_to_a.pre_fec_ber
        )?;
        writeln!(
            f,
            "pq:                   a={} ({} ms, {} exchange(s))  b={} ({} ms, {} exchange(s))",
            self.pq_status_a,
            self.pq_secure_ms_a
                .map(|ms| format!("{ms:.1}"))
                .unwrap_or_else(|| "never".to_string()),
            self.pq_exchanges_a,
            self.pq_status_b,
            self.pq_secure_ms_b
                .map(|ms| format!("{ms:.1}"))
                .unwrap_or_else(|| "never".to_string()),
            self.pq_exchanges_b
        )?;
        writeln!(
            f,
            "link A:               sent={} dropped={} delivered={} rejected={} handshakes={}",
            self.link_a.sent,
            self.link_a.dropped_no_session,
            self.link_a.delivered,
            self.link_a.rejected,
            self.link_a.handshakes
        )?;
        write!(
            f,
            "link B:               sent={} dropped={} delivered={} rejected={} handshakes={}",
            self.link_b.sent,
            self.link_b.dropped_no_session,
            self.link_b.delivered,
            self.link_b.rejected,
            self.link_b.handshakes
        )
    }
}

/// Run the offline voice loop and return the measurements.
#[cfg_attr(not(feature = "pq"), allow(unused_mut))]
pub fn run_selftest(opts: &SelftestOpts) -> Result<SelftestReport> {
    if opts.seconds <= 0.0 {
        bail!("--seconds must be positive");
    }

    let input = match &opts.input {
        Some(path) => read_wav_mono_48k(path)?,
        None => test_signal(opts.seconds),
    };
    if input.is_empty() {
        bail!("input is empty");
    }

    let cfg = opts.phy.modem_config();
    let a_identity = Identity::generate();
    let b_identity = Identity::generate();

    let mut a = CallEngine::new(
        &LinkKeys {
            private: a_identity.wg_private(),
            peer_public: b_identity.bundle().wg_public,
            psk: None,
        },
        cfg.clone(),
    );
    let mut b = CallEngine::new(
        &LinkKeys {
            private: b_identity.wg_private(),
            peer_public: a_identity.bundle().wg_public,
            psk: None,
        },
        cfg,
    );

    #[cfg(feature = "pq")]
    if opts.pq {
        let a_pq = generate_pq_keypair()?;
        let b_pq = generate_pq_keypair()?;
        let a_initiator = a_identity.wg_public() < b_identity.wg_public();
        a.set_pq_session(
            PqSession::new(&a_pq, b_pq.public(), a_initiator)?,
            a_initiator,
        );
        b.set_pq_session(
            PqSession::new(&b_pq, a_pq.public(), !a_initiator)?,
            !a_initiator,
        );
    }

    let a_to_b = if opts.opus {
        Some(Channel::new(channel_cfg(opts.loss, opts.burst, opts.seed))?)
    } else {
        None
    };
    let b_to_a = if opts.opus {
        Some(Channel::new(channel_cfg(
            opts.loss,
            opts.burst,
            opts.seed.wrapping_add(1),
        ))?)
    } else {
        None
    };
    let mut wire = SimWire::new(a_to_b, b_to_a);

    // `speaker_out` accumulates B's decoded voice; declared before the PQ
    // warm-up so any output produced there is recorded.
    let mut speaker_out: Vec<f32> = Vec::new();

    let mut now = 0.0f64;
    let mut next_tick = TICK_INTERVAL;
    let mut handshake_ms: Option<f64> = None;
    let mut pq_secure_ms_a: Option<f64> = None;
    let mut pq_secure_ms_b: Option<f64> = None;

    let mut warmup_samples = (WARMUP_SECS * SAMPLE_RATE as f64) as usize;
    let mut input_start_samples = warmup_samples;

    #[cfg(feature = "pq")]
    if opts.pq {
        warmup_samples = pq_warmup(
            &mut a,
            &mut b,
            &mut wire,
            &mut speaker_out,
            &mut now,
            &mut next_tick,
            &mut handshake_ms,
            &mut pq_secure_ms_a,
            &mut pq_secure_ms_b,
        );
        input_start_samples = 0;
    }

    let tail_samples = (TAIL_SECS * SAMPLE_RATE as f64) as usize;
    let total_samples = warmup_samples + input.len() + tail_samples;
    let steps = total_samples.div_ceil(STEP_SAMPLES);
    speaker_out.reserve(steps * STEP_SAMPLES);

    for step in 0..steps {
        if now >= next_tick - 1e-9 {
            a.tick();
            b.tick();
            next_tick += TICK_INTERVAL;
        }

        let mic = mic_chunk(step, &input, input_start_samples);
        wire.step(&mut a, &mut b, &mic, &mut speaker_out);

        if handshake_ms.is_none() && a.is_up() && b.is_up() {
            handshake_ms = Some(now * 1000.0);
        }
        now += STEP_SAMPLES as f64 / SAMPLE_RATE as f64;
    }

    // Drain phase: feed A no mic so no new voice packets appear, and keep
    // stepping until both transmitters are empty and one full modem frame has
    // flushed through the receiver. This lets the last tail-silence packets
    // reach B instead of being cut off at the simulation's end.
    let frame_steps = a.frame_len().div_ceil(STEP_SAMPLES);
    let mut empty_streak = 0usize;
    let max_drain_steps = (60.0 * SAMPLE_RATE as f64 / STEP_SAMPLES as f64) as usize;
    for _ in 0..max_drain_steps {
        wire.step(&mut a, &mut b, &[], &mut speaker_out);
        if a.pending_bytes() == 0 && b.pending_bytes() == 0 {
            empty_streak += 1;
            if empty_streak >= frame_steps + 2 {
                break;
            }
        } else {
            empty_streak = 0;
        }
    }

    // Latency: join A's send times with B's receive times on the voice sequence number.
    let recv_map: HashMap<u16, f64> = b.recv_times().iter().copied().collect();
    let mut latencies: Vec<f64> = Vec::with_capacity(a.send_times().len());
    for &(seq, send_t) in a.send_times() {
        if let Some(&recv_t) = recv_map.get(&seq) {
            latencies.push((recv_t - send_t) * 1000.0);
        }
    }
    let latency_ms = if latencies.is_empty() {
        LatencyStats {
            mean: 0.0,
            min: 0.0,
            max: 0.0,
        }
    } else {
        let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        LatencyStats { mean, min, max }
    };

    // Align the input to the simulation timeline (warm-up + input + tail) so the
    // correlation lag is the mouth-to-ear latency rather than that latency plus
    // the 3 s warm-up offset.
    let mut input_timeline = vec![0.0f32; warmup_samples];
    input_timeline.extend_from_slice(&input);
    input_timeline.extend(std::iter::repeat_n(0.0f32, tail_samples));
    let (audio_lag_ms, audio_corr) = audio_lag(&input_timeline, &speaker_out);

    let voice_packets_sent = a.voice_sent();
    let voice_packets_delivered = b.voice_delivered();
    let packet_loss = if voice_packets_sent > 0 {
        (1.0 - voice_packets_delivered as f64 / voice_packets_sent as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let a_link = a.link_stats();
    let b_link = b.link_stats();
    let a_rx = a.rx_stats();
    let b_rx = b.rx_stats();

    let report = SelftestReport {
        handshake_ms,
        voice_packets_sent,
        voice_packets_delivered,
        voice_packets_bad: b.bad_voice(),
        packet_loss,
        latency_ms,
        audio_lag_ms,
        audio_corr,
        modem_a_to_b: ModemRx {
            frames_ok: b_rx.frames_ok,
            frames_failed: b_rx.frames_failed,
            pre_fec_ber: b_rx.pre_fec_ber(),
        },
        modem_b_to_a: ModemRx {
            frames_ok: a_rx.frames_ok,
            frames_failed: a_rx.frames_failed,
            pre_fec_ber: a_rx.pre_fec_ber(),
        },
        link_a: LinkStat::from(&a_link),
        link_b: LinkStat::from(&b_link),
        seconds: input.len() as f64 / SAMPLE_RATE as f64,
        phy: opts.phy.name(),
        opus: opts.opus,
        pq: {
            #[cfg(feature = "pq")]
            {
                opts.pq
            }
            #[cfg(not(feature = "pq"))]
            {
                false
            }
        },
        pq_status_a: a.pq_status(),
        pq_status_b: b.pq_status(),
        pq_exchanges_a: a.pq_exchanges(),
        pq_exchanges_b: b.pq_exchanges(),
        pq_secure_ms_a,
        pq_secure_ms_b,
        voice_first_send_ms: a.send_times().first().map(|&(_, t)| t * 1000.0),
    };

    if let Some(path) = &opts.output {
        write_wav_f32(path, &speaker_out)?;
    }
    if let Some(path) = &opts.modem_output {
        write_wav_f32(path, &wire.a_to_b_audio)?;
    }

    Ok(report)
}

/// Generate a Classic McEliece keypair on a thread with a large stack. McEliece
/// keygen overflows the default test-thread stack; the real command and the
/// offline test both need the extra room.
#[cfg(feature = "pq")]
fn generate_pq_keypair() -> Result<PqKeypair> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| PqKeypair::generate().map_err(anyhow::Error::from))
        .context("failed to spawn post-quantum keygen thread")?
        .join()
        .map_err(|_| anyhow!("post-quantum keygen thread panicked"))?
}

/// PQ warm-up: feed silence, ticking, until both endpoints are PQ-secure or 60 s
/// of simulated time passes. Returns the number of samples fed; records the
/// simulated ms at which each side became secure in the two Option refs.
#[cfg(feature = "pq")]
#[allow(clippy::too_many_arguments)]
fn pq_warmup(
    a: &mut CallEngine,
    b: &mut CallEngine,
    wire: &mut SimWire,
    speaker_out: &mut Vec<f32>,
    now: &mut f64,
    next_tick: &mut f64,
    handshake_ms: &mut Option<f64>,
    pq_secure_ms_a: &mut Option<f64>,
    pq_secure_ms_b: &mut Option<f64>,
) -> usize {
    let max_samples = (60.0 * SAMPLE_RATE as f64) as usize;
    let mut fed = 0usize;
    while fed < max_samples {
        if *now >= *next_tick - 1e-9 {
            a.tick();
            b.tick();
            *next_tick += TICK_INTERVAL;
        }
        wire.step(a, b, &[], speaker_out);
        fed += STEP_SAMPLES;
        *now += STEP_SAMPLES as f64 / SAMPLE_RATE as f64;
        if handshake_ms.is_none() && a.is_up() && b.is_up() {
            *handshake_ms = Some(*now * 1000.0);
        }
        if pq_secure_ms_a.is_none() && a.pq_secure() {
            *pq_secure_ms_a = Some(*now * 1000.0);
        }
        if pq_secure_ms_b.is_none() && b.pq_secure() {
            *pq_secure_ms_b = Some(*now * 1000.0);
        }
        if pq_secure_ms_a.is_some() && pq_secure_ms_b.is_some() {
            break;
        }
    }
    fed
}

/// Print the report as human-readable lines or one JSON object.
pub fn print_report(report: &SelftestReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{report}");
    }
    Ok(())
}

/// `harmonium selftest`. Returns the process exit code (0 pass, 2 fail).
pub fn run(opts: &SelftestOpts) -> Result<u8> {
    let report = run_selftest(opts)?;
    print_report(&report, opts.json)?;
    match report.failure_reason() {
        None => Ok(0),
        Some(reason) => {
            eprintln!("selftest failed: {reason}");
            Ok(2)
        }
    }
}

fn channel_cfg(loss: f64, burst: f64, seed: u64) -> ChannelConfig {
    ChannelConfig {
        bitrate: 64_000,
        app: OpusApp::Voip,
        loss,
        burst,
        seed,
        noise_db: None,
        gain: 1.0,
    }
}

/// Identity channel (`None`) or Opus (`Some`).
fn through(channel: &mut Option<Channel>, samples: &[f32]) -> Vec<f32> {
    match channel {
        Some(ch) => ch.process(samples),
        None => samples.to_vec(),
    }
}

/// The two one-way channels and the previous step's modem audio for each.
struct SimWire {
    a_to_b: Option<Channel>,
    b_to_a: Option<Channel>,
    a_prev_out: Vec<f32>,
    b_prev_out: Vec<f32>,
    /// Everything B received from A, for `--modem-output`.
    a_to_b_audio: Vec<f32>,
}

impl SimWire {
    fn new(a_to_b: Option<Channel>, b_to_a: Option<Channel>) -> Self {
        Self {
            a_to_b,
            b_to_a,
            a_prev_out: Vec::new(),
            b_prev_out: Vec::new(),
            a_to_b_audio: Vec::new(),
        }
    }

    /// One simulation step: A speaks `mic`, B stays silent, and each side's last
    /// modem audio flows through its channel into the other side.
    fn step(
        &mut self,
        a: &mut CallEngine,
        b: &mut CallEngine,
        mic: &[f32],
        speaker_out: &mut Vec<f32>,
    ) {
        // B's last output flows B→A into A; A's last output flows A→B into B.
        let from_b = through(&mut self.b_to_a, &std::mem::take(&mut self.b_prev_out));
        let from_a = through(&mut self.a_to_b, &std::mem::take(&mut self.a_prev_out));
        let out_a = a.step(mic, &from_b);
        self.a_to_b_audio.extend_from_slice(&from_a);
        let out_b = b.step(&[], &from_a);
        self.a_prev_out = out_a.to_discord;
        self.b_prev_out = out_b.to_discord;
        speaker_out.extend_from_slice(&out_b.speaker);
    }
}

/// The speech-like test signal: 200/700/1500 Hz summed at amplitudes 1/0.3/0.09
/// under a 4 Hz amplitude envelope, normalized to a peak of 0.5.
fn test_signal(seconds: f64) -> Vec<f32> {
    let n = (seconds * SAMPLE_RATE as f64) as usize;
    let mut signal = Vec::with_capacity(n);
    for i in 0..n {
        let t = i as f32 / SAMPLE_RATE as f32;
        let envelope = 0.5 + 0.5 * (2.0 * std::f32::consts::PI * 4.0 * t).sin();
        let s = (2.0 * std::f32::consts::PI * 200.0 * t).sin()
            + 0.3 * (2.0 * std::f32::consts::PI * 700.0 * t).sin()
            + 0.09 * (2.0 * std::f32::consts::PI * 1500.0 * t).sin();
        signal.push(envelope * s);
    }
    let peak = signal.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
    if peak > 0.0 {
        for s in &mut signal {
            *s *= 0.5 / peak;
        }
    }
    signal
}

/// The 960-sample mic chunk for a step, slicing the input between the warm-up
/// and tail silences.
fn mic_chunk(step: usize, input: &[f32], warmup_samples: usize) -> Vec<f32> {
    let start = step * STEP_SAMPLES;
    let end = start + STEP_SAMPLES;
    let mut chunk = vec![0.0f32; STEP_SAMPLES];

    let input_start = warmup_samples;
    let input_end = warmup_samples + input.len();
    let overlap_start = start.max(input_start);
    let overlap_end = end.min(input_end);
    if overlap_start < overlap_end {
        let src_off = overlap_start - input_start;
        let dst_off = overlap_start - start;
        let n = overlap_end - overlap_start;
        chunk[dst_off..dst_off + n].copy_from_slice(&input[src_off..src_off + n]);
    }
    chunk
}

/// Cross-correlate the input with the output on 1 ms-RMS envelopes, searching
/// lags `0..=MAX_LAG_MS` ms. Returns `(lag_ms, best normalized correlation)`.
fn audio_lag(input: &[f32], output: &[f32]) -> (f64, f64) {
    let env_in = rms_envelope(input, SAMPLE_RATE / 1000);
    let env_out = rms_envelope(output, SAMPLE_RATE / 1000);
    if env_in.is_empty() || env_out.is_empty() {
        return (0.0, 0.0);
    }
    let in_norm2: f64 = env_in.iter().map(|v| v * v).sum();
    if in_norm2 <= 0.0 {
        return (0.0, 0.0);
    }

    let max_lag = MAX_LAG_MS.min(env_out.len().saturating_sub(1));
    let mut best_lag = 0usize;
    let mut best_corr = 0.0f64;

    for lag in 0..=max_lag {
        let n = env_in.len().min(env_out.len() - lag);
        if n < 100 {
            continue;
        }
        let mut dot = 0.0f64;
        let mut out_norm2 = 0.0f64;
        for i in 0..n {
            dot += env_in[i] * env_out[i + lag];
            out_norm2 += env_out[i + lag] * env_out[i + lag];
        }
        if out_norm2 <= 0.0 {
            continue;
        }
        let corr = dot / (in_norm2.sqrt() * out_norm2.sqrt());
        if corr.is_finite() && corr > best_corr {
            best_corr = corr;
            best_lag = lag;
        }
    }

    (best_lag as f64, best_corr)
}

/// One RMS value per `window` samples.
fn rms_envelope(samples: &[f32], window: usize) -> Vec<f64> {
    samples
        .chunks(window.max(1))
        .map(|chunk| {
            let sum: f64 = chunk.iter().map(|&s| (s as f64) * (s as f64)).sum();
            (sum / chunk.len() as f64).sqrt()
        })
        .collect()
}

/// Read a 48 kHz mono WAV (i16/i32/i24 via hound's `i32`, or f32). Other rates
/// and channel counts are rejected — no resampling is done.
pub(crate) fn read_wav_mono_48k(path: &Path) -> Result<Vec<f32>> {
    let mut reader = hound::WavReader::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let spec = reader.spec();
    if spec.sample_rate != SAMPLE_RATE as u32 {
        bail!(
            "{}: unsupported sample rate {} Hz (only 48000 Hz is supported; resampling is not done)",
            path.display(),
            spec.sample_rate
        );
    }
    if spec.channels != 1 {
        bail!(
            "{}: expected mono input, got {} channels",
            path.display(),
            spec.channels
        );
    }

    match spec.sample_format {
        hound::SampleFormat::Float => reader
            .samples::<f32>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to read WAV samples"),
        hound::SampleFormat::Int => {
            let scale = 2f32.powi(spec.bits_per_sample.saturating_sub(1) as i32);
            reader
                .samples::<i32>()
                .map(|s| s.map(|v| v as f32 / scale))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to read WAV samples")
        }
    }
}

/// Write a 48 kHz mono f32 WAV.
pub(crate) fn write_wav_f32(path: &Path, samples: &[f32]) -> Result<()> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE as u32,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let mut writer = hound::WavWriter::create(path, spec)
        .with_context(|| format!("failed to create {}", path.display()))?;
    for &sample in samples {
        writer.write_sample(sample)?;
    }
    writer.finalize()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_has_requested_length_and_peak() {
        let signal = test_signal(1.0);
        assert_eq!(signal.len(), SAMPLE_RATE);
        let peak = signal.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        assert!((peak - 0.5).abs() < 1e-6, "peak {peak}");
    }

    #[test]
    fn wav_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.wav");
        let signal = test_signal(0.1);
        write_wav_f32(&path, &signal).unwrap();
        let back = read_wav_mono_48k(&path).unwrap();
        assert_eq!(back.len(), signal.len());
        for (a, b) in signal.iter().zip(back.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn wav_i16_is_read_and_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i16.wav");
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: SAMPLE_RATE as u32,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(&path, spec).unwrap();
        for &sample in &[0.0f32, 0.5, -0.5, 0.25] {
            writer.write_sample((sample * 32767.0) as i16).unwrap();
        }
        writer.finalize().unwrap();

        let back = read_wav_mono_48k(&path).unwrap();
        assert_eq!(back.len(), 4);
        for (expected, actual) in [0.0f32, 0.5, -0.5, 0.25].iter().zip(back.iter()) {
            assert!((expected - actual).abs() < 0.001, "{expected} vs {actual}");
        }
    }

    #[test]
    fn correlation_finds_known_lag() {
        // A clean delayed copy should correlate best at exactly that lag.
        let signal = test_signal(2.0);
        let lag_samples = 500 * 48; // 500 ms
        let mut output = vec![0.0f32; lag_samples];
        output.extend_from_slice(&signal);
        output.extend(std::iter::repeat_n(0.0f32, 48_000));
        let (lag, corr) = audio_lag(&signal, &output);
        assert_eq!(lag, 500.0);
        assert!(corr > 0.99, "corr {corr}");
    }

    #[test]
    fn selftest_defaults_pass() {
        let report = run_selftest(&SelftestOpts {
            seconds: 5.0,
            ..Default::default()
        })
        .unwrap();
        assert!(report.passed(), "{}", report.failure_reason().unwrap());
        assert!(
            report.voice_packets_delivered as f64 / report.voice_packets_sent as f64 >= 0.95,
            "delivery ratio {:.3}",
            report.voice_packets_delivered as f64 / report.voice_packets_sent as f64
        );
        assert!(report.audio_corr > 0.5, "audio_corr {}", report.audio_corr);
        assert!(
            report.latency_ms.mean < 2000.0,
            "latency {}",
            report.latency_ms.mean
        );
        assert!(report.handshake_ms.is_some());
    }

    #[test]
    fn selftest_opus_passes() {
        let report = run_selftest(&SelftestOpts {
            seconds: 5.0,
            opus: true,
            ..Default::default()
        })
        .unwrap();
        println!("opus selftest: {report}");
        assert!(report.passed(), "{}", report.failure_reason().unwrap());
        assert!(
            report.voice_packets_delivered as f64 / report.voice_packets_sent as f64 >= 0.90,
            "delivery ratio {:.3}",
            report.voice_packets_delivered as f64 / report.voice_packets_sent as f64
        );
    }

    #[cfg(feature = "pq")]
    #[test]
    fn selftest_pq_is_secure_and_delivers() {
        let report = run_selftest(&SelftestOpts {
            seconds: 10.0,
            pq: true,
            ..Default::default()
        })
        .unwrap();
        assert!(report.pq);
        assert_eq!(report.pq_status_a, "secure");
        assert_eq!(report.pq_status_b, "secure");
        assert!(report.pq_secure_ms_a.is_some() && report.pq_secure_ms_b.is_some());
        assert!(report.pq_exchanges_a >= 1 && report.pq_exchanges_b >= 1);
        assert!(
            report.voice_packets_sent > 0,
            "voice must flow after PQ is secure"
        );
        assert_eq!(
            report.voice_packets_delivered, report.voice_packets_sent,
            "loss 0: all voice delivered"
        );
        // Zero voice packets sent before PQ-secure:
        let a_secure_ms = report.pq_secure_ms_a.unwrap();
        let first_ms = report.voice_first_send_ms.unwrap();
        assert!(
            first_ms + 1e-9 >= a_secure_ms,
            "voice sent before PQ-secure: first={first_ms} secure={a_secure_ms}"
        );
    }
}
