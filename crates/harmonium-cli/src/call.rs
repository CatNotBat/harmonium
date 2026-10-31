//! Live call command and the reusable per-step [`CallEngine`].

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;

use harmonium_audio::{AudioConfig, AudioIo, VirtualDevices};
use harmonium_keys::Store;
use harmonium_link::{Channel, Link, LinkKeys, LinkStats};
use harmonium_modem::{ModemConfig, Receiver, RxStats, Transmitter};
use harmonium_voice::{VoiceDecoder, VoiceEncoder, VoiceMode, VoicePacket};

use crate::cli::PhyArg;
use crate::selftest::{read_wav_mono_48k, write_wav_f32};
use crate::text::load_verified_peer;

/// Samples in one 20 ms audio step at 48 kHz.
pub const STEP_SAMPLES: usize = 960;

/// How often the main loop checks whether the virtual mic needs another step.
const POLL_PERIOD: Duration = Duration::from_millis(5);

/// Mic samples allowed to queue before the oldest are dropped (100 ms).
const MIC_MAX_BACKLOG: usize = 5 * STEP_SAMPLES;

/// Steps of modem audio kept queued ahead of the virtual mic (240 ms). This only absorbs
/// scheduling jitter: the engine always has the rest of the current frame buffered, so it
/// must not scale with the frame length (two frames would exceed the one-second ring and
/// add a second of latency).
const PRIME_STEPS: usize = 12;

/// How often to advance the WireGuard timers.
const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Command-line options for `harmonium call`.
#[derive(Args, Debug)]
pub struct CallOpts {
    /// Peer name to call.
    pub peer: String,

    /// Name of the microphone to read (default: system default).
    #[arg(long)]
    pub mic: Option<String>,

    /// Name of the speaker to play into (default: system default).
    #[arg(long)]
    pub speaker: Option<String>,

    /// Device we play modem audio into (default: the app-side virtual device).
    #[arg(long)]
    pub to_discord: Option<String>,

    /// Device we record Discord's audio from (default: the app-side virtual device).
    #[arg(long)]
    pub from_discord: Option<String>,

    /// Modem PHY.
    #[arg(long, value_enum, default_value_t = PhyArg::Ofdm)]
    pub phy: PhyArg,

    /// Allow calling a peer that has not been verified.
    #[arg(long)]
    pub allow_unverified: bool,

    /// Speak this WAV (48 kHz mono, looped) instead of the microphone. For tests.
    #[arg(long, value_name = "IN.wav")]
    pub mic_wav: Option<PathBuf>,

    /// Also write the decoded peer audio to this WAV (f32, 48 kHz mono).
    #[arg(long, value_name = "OUT.wav")]
    pub record: Option<PathBuf>,

    /// Also write the raw audio received from Discord (before demodulation) to this WAV.
    #[arg(long, value_name = "RX.wav")]
    pub record_rx: Option<PathBuf>,

    /// End the call after this many seconds (default: run until Ctrl-C).
    #[arg(long)]
    pub duration: Option<f64>,

    /// Write a JSON call report (stats plus per-packet send/receive times) here.
    #[arg(long, value_name = "REPORT.json")]
    pub report: Option<PathBuf>,
}

/// What `--report` writes: enough to compute loss and latency across two machines.
#[derive(Debug, serde::Serialize)]
pub struct CallReport {
    /// Unix time (seconds) of engine time zero; engine times are offsets from it.
    pub start_unix: f64,
    /// Engine time covered by the call, in seconds (paced on the device clock).
    pub seconds: f64,
    /// Engine time at which the link first came up.
    pub link_up_at: Option<f64>,
    pub handshakes: u64,
    pub voice_sent: u64,
    pub voice_delivered: u64,
    pub bad_voice: u64,
    pub modem_frames_ok: u64,
    pub modem_frames_failed: u64,
    pub pre_fec_ber: f64,
    pub link_rejected: u64,
    pub audio_underruns: u64,
    pub audio_overruns: u64,
    /// (sequence number, engine time) of every voice packet sent.
    pub send_times: Vec<(u16, f64)>,
    /// (sequence number, engine time) of every voice packet decoded.
    pub recv_times: Vec<(u16, f64)>,
}

/// What one engine step produces.
pub struct StepOut {
    /// Modem audio to write toward Discord (always modem frames).
    pub to_discord: Vec<f32>,
    /// Decoded audio to play on the speaker (may be silence).
    pub speaker: Vec<f32>,
}

/// Per-step logic shared by the live call and the offline selftest.
///
/// Fail-closed by construction: `to_discord` is produced only by
/// [`Transmitter::next_frame`], so the bytes headed for Discord are always modem
/// frames. The only path from microphone samples to that output runs through
/// [`VoiceEncoder`] → [`Link::send`] → [`Transmitter`]; when the link is down,
/// [`Link::send`] drops the datagram and the modem keeps sending idle frames.
pub struct CallEngine {
    link: Link,
    tx: Transmitter,
    rx: Receiver,
    encoder: VoiceEncoder,
    decoder: VoiceDecoder,
    /// Modem audio generated but not yet handed out.
    out_buf: Vec<f32>,
    /// Simulated time in seconds, advanced once per step.
    now: f64,
    /// Whether at least one voice packet has been decoded (speaker is silence before).
    has_voice: bool,
    /// Voice packets actually encrypted (session up) and their send times.
    voice_sent: u64,
    send_times: Vec<(u16, f64)>,
    /// Voice packets decoded and their receive times.
    voice_delivered: u64,
    recv_times: Vec<(u16, f64)>,
    bad_voice: u64,
    /// Samples in one modem frame, from a one-shot probe.
    frame_len: usize,
}

impl CallEngine {
    /// Build one endpoint: a Codec 2 M1300 320 ms voice path over `keys` through `cfg`.
    pub fn new(keys: &LinkKeys, cfg: ModemConfig) -> Self {
        let frame_len = Transmitter::new(cfg.clone()).next_frame().len();
        Self {
            link: Link::new(keys),
            tx: Transmitter::new(cfg.clone()),
            rx: Receiver::new(cfg),
            encoder: VoiceEncoder::new(VoiceMode::M1300, 320),
            decoder: VoiceDecoder::new(),
            out_buf: Vec::new(),
            now: 0.0,
            has_voice: false,
            voice_sent: 0,
            send_times: Vec::new(),
            voice_delivered: 0,
            recv_times: Vec::new(),
            bad_voice: 0,
            frame_len,
        }
    }

    /// Advance one 20 ms step.
    ///
    /// `mic` is the microphone samples captured this step (the caller pads
    /// short reads; an empty slice means "no input", which produces no new
    /// voice packets). `from_discord` is whatever modem audio Discord played
    /// back this step.
    pub fn step(&mut self, mic: &[f32], from_discord: &[f32]) -> StepOut {
        // Mic → Codec 2 → WireGuard → modem queue.
        for packet in self.encoder.push_48k(mic) {
            let bytes = packet.to_bytes();
            let sent_before = self.link.stats().sent;
            for wire in self.link.send(Channel::Voice, &bytes) {
                self.tx.send(&wire);
            }
            if self.link.stats().sent > sent_before {
                self.voice_sent += 1;
                self.send_times.push((packet.seq, self.now));
            }
        }

        // Modem audio in → packets → WireGuard → replies + decoded voice.
        for packet in self.rx.push(from_discord) {
            let (replies, delivered) = self.link.receive(&packet);
            for wire in replies {
                self.tx.send(&wire);
            }
            for datagram in delivered {
                if datagram.channel == Channel::Voice {
                    match VoicePacket::from_bytes(&datagram.payload) {
                        Ok(voice) => {
                            self.decoder.push_packet(&voice);
                            self.has_voice = true;
                            self.voice_delivered += 1;
                            self.recv_times.push((voice.seq, self.now));
                        }
                        Err(_) => self.bad_voice += 1,
                    }
                }
            }
        }

        // Emit the next 960 samples of modem audio (topping up with whole frames).
        while self.out_buf.len() < STEP_SAMPLES {
            self.out_buf.extend(self.tx.next_frame());
        }
        let to_discord: Vec<f32> = self.out_buf.drain(..STEP_SAMPLES).collect();

        // Speaker: silence until the first voice packet arrives.
        let speaker = if self.has_voice {
            self.decoder.pull_48k(STEP_SAMPLES)
        } else {
            vec![0.0f32; STEP_SAMPLES]
        };

        self.now += STEP_SAMPLES as f64 / 48_000.0;
        StepOut {
            to_discord,
            speaker,
        }
    }

    /// Advance the WireGuard timers (call every 250 ms of real time).
    pub fn tick(&mut self) {
        for wire in self.link.tick() {
            self.tx.send(&wire);
        }
    }

    pub fn is_up(&self) -> bool {
        self.link.is_up()
    }

    pub fn link_stats(&self) -> LinkStats {
        self.link.stats()
    }

    pub fn rx_stats(&self) -> RxStats {
        self.rx.stats()
    }

    pub fn voice_sent(&self) -> u64 {
        self.voice_sent
    }

    pub fn voice_delivered(&self) -> u64 {
        self.voice_delivered
    }

    pub fn bad_voice(&self) -> u64 {
        self.bad_voice
    }

    pub fn send_times(&self) -> &[(u16, f64)] {
        &self.send_times
    }

    pub fn recv_times(&self) -> &[(u16, f64)] {
        &self.recv_times
    }

    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// Bytes queued in the transmitter plus encoded stream bytes not yet emitted.
    pub fn pending_bytes(&self) -> usize {
        self.tx.pending_bytes()
    }
}

/// Run a live call. Opened and wired here; only compiles and unit-tests in CI.
pub fn run_call(store: &Store, opts: &CallOpts) -> Result<()> {
    let identity = store.load_identity()?;
    let peer = load_verified_peer(store, &opts.peer, opts.allow_unverified)?;

    // Open the virtual devices first so the app-side device names exist.
    let virtual_devices = VirtualDevices::create().context("failed to create virtual devices")?;

    let to_discord = opts
        .to_discord
        .clone()
        .unwrap_or_else(|| VirtualDevices::app_output_name().to_string());
    let from_discord = opts
        .from_discord
        .clone()
        .unwrap_or_else(|| VirtualDevices::app_input_name().to_string());

    let config = AudioConfig {
        mic: opts.mic.clone(),
        speaker: opts.speaker.clone(),
        to_discord,
        from_discord,
    };
    let mut audio = AudioIo::open(&config).context("failed to open audio devices")?;
    let mic_wav = opts.mic_wav.as_deref().map(read_wav_mono_48k).transpose()?;
    if mic_wav.as_ref().is_some_and(|w| w.is_empty()) {
        anyhow::bail!("--mic-wav file is empty");
    }
    let mut mic_wav_pos = 0usize;
    let mut recorded = Vec::new();
    let mut recorded_rx = Vec::new();

    let keys = LinkKeys {
        private: identity.wg_private(),
        peer_public: peer.bundle.wg_public,
        psk: None,
    };
    let mut engine = CallEngine::new(&keys, opts.phy.modem_config());

    // Prime the to_discord ring so the first callbacks do not underrun.
    for _ in 0..PRIME_STEPS {
        let out = engine.step(&[], &[]);
        let _ = audio.write_to_discord(&out.to_discord);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .context("failed to install Ctrl-C handler")?;

    // Pace on the virtual mic's device clock, not the wall clock: run a step whenever the
    // device has consumed a step's worth below the primed fill. A wall-clock loop drifts
    // against the device (at 100 ppm the prime drains or overflows within about two hours),
    // and either way breaks modem frames mid-transmission. Discord's side is drained in full
    // every step and the mic backlog is capped, so their clocks cannot back up either. The
    // speaker's drift is bounded by its one-second ring (a rare dropped or padded block).
    let target_fill = PRIME_STEPS * STEP_SAMPLES;
    let mut mic_buf = vec![0.0f32; STEP_SAMPLES];
    let mut from_buf = vec![0.0f32; 4 * STEP_SAMPLES];
    let mut next_tick = Instant::now() + TICK_INTERVAL;
    let mut next_status = Instant::now() + Duration::from_secs(1);
    let start_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let max_steps = opts
        .duration
        .map(|s| (s * 48_000.0 / STEP_SAMPLES as f64).ceil() as u64);
    let mut steps = 0u64;
    let mut link_up_at = None;

    while !shutdown.load(Ordering::SeqCst) && max_steps.is_none_or(|m| steps < m) {
        while audio.to_discord_queued() + STEP_SAMPLES <= target_fill {
            audio.trim_mic_backlog(MIC_MAX_BACKLOG);
            let got = audio.read_mic(&mut mic_buf);
            for sample in &mut mic_buf[got..] {
                *sample = 0.0;
            }
            if let Some(wav) = &mic_wav {
                for sample in &mut mic_buf {
                    *sample = wav[mic_wav_pos];
                    mic_wav_pos = (mic_wav_pos + 1) % wav.len();
                }
            }
            let from = audio.read_from_discord(&mut from_buf);
            if opts.record_rx.is_some() {
                recorded_rx.extend_from_slice(&from_buf[..from]);
            }

            let out = engine.step(&mic_buf, &from_buf[..from]);
            let written = audio.write_to_discord(&out.to_discord);
            let _ = audio.write_speaker(&out.speaker);
            if opts.record.is_some() {
                recorded.extend_from_slice(&out.speaker);
            }
            if link_up_at.is_none() && engine.is_up() {
                link_up_at = Some(steps as f64 * STEP_SAMPLES as f64 / 48_000.0);
            }
            steps += 1;
            if written < out.to_discord.len() {
                // Ring full (the device stalled): wait for it rather than spin.
                break;
            }
        }

        if Instant::now() >= next_tick {
            engine.tick();
            next_tick += TICK_INTERVAL;
        }
        if Instant::now() >= next_status {
            eprintln!("{}", status_line(&engine, audio.stats()));
            next_status += Duration::from_secs(1);
        }

        std::thread::sleep(POLL_PERIOD);
    }

    println!("call ended");
    println!("{}", status_line(&engine, audio.stats()));
    if let Some(path) = &opts.record {
        write_wav_f32(path, &recorded)?;
    }
    if let Some(path) = &opts.record_rx {
        write_wav_f32(path, &recorded_rx)?;
    }
    if let Some(path) = &opts.report {
        let link = engine.link_stats();
        let rx = engine.rx_stats();
        let io = audio.stats();
        let report = CallReport {
            start_unix,
            seconds: steps as f64 * STEP_SAMPLES as f64 / 48_000.0,
            link_up_at,
            handshakes: link.handshakes_completed,
            voice_sent: engine.voice_sent(),
            voice_delivered: engine.voice_delivered(),
            bad_voice: engine.bad_voice(),
            modem_frames_ok: rx.frames_ok,
            modem_frames_failed: rx.frames_failed,
            pre_fec_ber: rx.pre_fec_ber(),
            link_rejected: link.rejected,
            audio_underruns: io.underruns,
            audio_overruns: io.overruns,
            send_times: engine.send_times().to_vec(),
            recv_times: engine.recv_times().to_vec(),
        };
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    drop(audio);
    drop(virtual_devices);
    Ok(())
}

fn status_line(engine: &CallEngine, io: harmonium_audio::IoStats) -> String {
    let link = engine.link_stats();
    let rx = engine.rx_stats();
    format!(
        "link={} handshakes={} voice_sent={} voice_delivered={} bad={} \
         modem_ok={} modem_failed={} pre_fec_ber={:.6} audio_underruns={} audio_overruns={}",
        if engine.is_up() { "up" } else { "down" },
        link.handshakes_completed,
        engine.voice_sent(),
        engine.voice_delivered(),
        engine.bad_voice(),
        rx.frames_ok,
        rx.frames_failed,
        rx.pre_fec_ber(),
        io.underruns,
        io.overruns,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmonium_keys::Identity;
    use harmonium_modem::{FecParams, OfdmParams, PhyKind};

    fn pair() -> (CallEngine, CallEngine) {
        let a_id = Identity::generate();
        let b_id = Identity::generate();
        let cfg = ModemConfig {
            phy: PhyKind::Ofdm(OfdmParams::default()),
            fec: FecParams::default(),
        };
        let a = CallEngine::new(
            &LinkKeys {
                private: a_id.wg_private(),
                peer_public: b_id.bundle().wg_public,
                psk: None,
            },
            cfg.clone(),
        );
        let b = CallEngine::new(
            &LinkKeys {
                private: b_id.wg_private(),
                peer_public: a_id.bundle().wg_public,
                psk: None,
            },
            cfg,
        );
        (a, b)
    }

    /// Drive two engines wired A→B through an identity channel, no devices.
    #[test]
    fn two_engines_handshake_and_deliver_voice() {
        let (mut a, mut b) = pair();
        let mut a_out_prev = Vec::new();
        let mut b_out_prev = Vec::new();

        let warmup_steps = (3.0 * 48_000.0 / STEP_SAMPLES as f64) as usize;
        let signal_steps = (1.0 * 48_000.0 / STEP_SAMPLES as f64) as usize;
        let mut next_tick = 0.25;
        let mut now = 0.0;
        let mut up_at = None;

        let mut handshaken_by_3s = false;

        for step in 0..(warmup_steps + signal_steps + warmup_steps) {
            if now >= next_tick - 1e-9 {
                a.tick();
                b.tick();
                next_tick += 0.25;
            }
            // A speaks (a 440 Hz tone); B stays silent.
            let mic = if (warmup_steps..warmup_steps + signal_steps).contains(&step) {
                (0..STEP_SAMPLES)
                    .map(|i| {
                        let t = ((step - warmup_steps) * STEP_SAMPLES + i) as f32 / 48_000.0;
                        0.1 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
                    })
                    .collect()
            } else {
                vec![0.0f32; STEP_SAMPLES]
            };

            let from_b = std::mem::take(&mut b_out_prev);
            let from_a = std::mem::take(&mut a_out_prev);
            let out_a = a.step(&mic, &from_b);
            let out_b = b.step(&[], &from_a);
            a_out_prev = out_a.to_discord;
            b_out_prev = out_b.to_discord;

            if a.is_up() && b.is_up() && up_at.is_none() {
                up_at = Some(now);
            }
            if now < 3.0 && a.is_up() && b.is_up() {
                handshaken_by_3s = true;
            }
            now += STEP_SAMPLES as f64 / 48_000.0;
        }

        assert!(up_at.is_some(), "links never came up");
        assert!(handshaken_by_3s, "handshake took longer than 3 s");
        assert!(b.voice_delivered() > 0, "no voice delivered");
        assert!(a.voice_sent() > 0, "no voice sent");
        assert!(a.bad_voice() == 0);
    }
}
