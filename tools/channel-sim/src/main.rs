//! `channel-sim`: run 48 kHz mono audio through Discord's Opus path offline.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use channel_sim::{
    BenchConfig, Channel, ChannelConfig, OpusApp, PhyChoice, SAMPLE_RATE, run_bench,
};

#[derive(Parser)]
#[command(name = "channel-sim", version, about = "Discord Opus channel emulator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a 48 kHz mono WAV through the channel and write the output WAV.
    Wav(WavArgs),
    /// Modem bake-off: offered packets over the channel, delivered/corrupt counts.
    Bench(BenchArgs),
}

/// Channel flags shared by every subcommand.
#[derive(Args)]
struct ChannelArgs {
    /// Opus bitrate in bits/second.
    #[arg(long, default_value_t = 64_000)]
    bitrate: i32,
    /// Opus application profile.
    #[arg(long, value_enum, default_value = "voip")]
    app: AppArg,
    /// Packet loss probability per 20 ms Opus packet.
    #[arg(long, default_value_t = 0.0)]
    loss: f64,
    /// Gilbert-Elliott burstiness (0 = independent loss).
    #[arg(long, default_value_t = 0.0)]
    burst: f64,
    /// ChaCha8Rng seed.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Additive white noise SNR in dB relative to each 20 ms block (off by default).
    #[arg(long)]
    noise_db: Option<f64>,
    /// Linear gain applied before encode (Discord volume).
    #[arg(long, default_value_t = 1.0)]
    gain: f32,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum AppArg {
    Voip,
    Audio,
}

impl From<AppArg> for OpusApp {
    fn from(a: AppArg) -> Self {
        match a {
            AppArg::Voip => OpusApp::Voip,
            AppArg::Audio => OpusApp::Audio,
        }
    }
}

impl From<&ChannelArgs> for ChannelConfig {
    fn from(a: &ChannelArgs) -> Self {
        ChannelConfig {
            bitrate: a.bitrate,
            app: a.app.into(),
            loss: a.loss,
            burst: a.burst,
            seed: a.seed,
            noise_db: a.noise_db,
            gain: a.gain,
        }
    }
}

#[derive(Args)]
struct WavArgs {
    /// Input WAV: 48 kHz mono, f32 or i16.
    input: PathBuf,
    /// Output WAV (written as 48 kHz mono f32).
    output: PathBuf,
    #[command(flatten)]
    channel: ChannelArgs,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum PhyArg {
    Ofdm,
    Mfsk,
}

impl From<PhyArg> for PhyChoice {
    fn from(p: PhyArg) -> Self {
        match p {
            PhyArg::Ofdm => PhyChoice::Ofdm,
            PhyArg::Mfsk => PhyChoice::Mfsk,
        }
    }
}

#[derive(Args)]
struct BenchArgs {
    #[command(flatten)]
    channel: ChannelArgs,
    /// Modem PHY to benchmark.
    #[arg(long, value_enum, default_value = "ofdm")]
    phy: PhyArg,
    /// Simulated seconds of audio.
    #[arg(long, default_value_t = 600.0)]
    seconds: f64,
    /// Packet payload bytes (first 4 are a sequence number).
    #[arg(long, default_value_t = 88)]
    packet_bytes: usize,
    /// Offered load in packets/second (default: ~90% of net bitrate).
    #[arg(long)]
    pps: Option<f64>,
    /// Override Reed-Solomon ECC bytes per codeword.
    #[arg(long)]
    ecc: Option<usize>,
    /// Override the OFDM layout as FIRST_BIN,CARRIERS,BITS (e.g. 3,32,2).
    #[arg(long, value_parser = parse_layout)]
    layout: Option<(usize, usize, usize)>,
    /// Print the ModemConfig with {:?} before running.
    #[arg(long)]
    print_config: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Wav(args) => run_wav(args),
        Cmd::Bench(args) => run_bench_cmd(args),
    }
}

fn run_wav(args: WavArgs) -> Result<()> {
    let samples = read_wav(&args.input)?;
    let cfg = ChannelConfig::from(&args.channel);
    let mut channel = Channel::new(cfg)?;
    let out = channel.process(&samples);
    write_wav(&args.output, &out)?;
    let stats = channel.stats();
    eprintln!(
        "{} samples in, {} samples out; {} opus packets, {} lost, {} payload bytes",
        samples.len(),
        out.len(),
        stats.packets,
        stats.lost,
        stats.bytes
    );
    Ok(())
}

fn run_bench_cmd(args: BenchArgs) -> Result<()> {
    let phy = PhyChoice::from(args.phy);
    if args.print_config {
        println!("{:?}", channel_sim::modem_config(phy));
    }
    if args.packet_bytes < 4 {
        anyhow::bail!("--packet-bytes must be >= 4 to carry a sequence number");
    }
    let cfg = BenchConfig {
        channel: ChannelConfig::from(&args.channel),
        phy,
        seconds: args.seconds,
        packet_bytes: args.packet_bytes,
        pps: args.pps,
        ecc_len: args.ecc,
        ofdm_layout: args.layout,
    };
    let report = run_bench(&cfg)?;
    print_report(&report);
    Ok(())
}

fn parse_layout(s: &str) -> Result<(usize, usize, usize), String> {
    let v: Vec<usize> = s
        .split(',')
        .map(|x| x.trim().parse().map_err(|e| format!("{x}: {e}")))
        .collect::<Result<_, _>>()?;
    match v[..] {
        [b, n, k] if b > 0 && n > 0 && (1..=2).contains(&k) => Ok((b, n, k)),
        _ => Err("expected FIRST_BIN,CARRIERS,BITS with BITS 1 or 2".into()),
    }
}

fn print_report(r: &channel_sim::BenchReport) {
    println!("phy: {}", r.phy);
    println!("net_bitrate: {}", r.net_bitrate);
    println!("offered_bps: {}", r.offered_bps);
    println!("delivered_bps: {}", r.delivered_bps);
    println!("frames_ok: {}", r.frames_ok);
    println!("frames_failed: {}", r.frames_failed);
    println!("frame_error_rate: {}", r.frame_error_rate);
    println!("pre_fec_ber: {}", r.pre_fec_ber);
    println!("packets_sent: {}", r.packets_sent);
    println!("packets_delivered: {}", r.packets_delivered);
    println!("packets_corrupt: {}", r.packets_corrupt);
    println!("opus_packets: {}", r.opus_packets);
    println!("opus_lost: {}", r.opus_lost);
    println!("{}", serde_json::to_string(r).expect("serialize report"));
}

fn read_wav(path: &Path) -> Result<Vec<f32>> {
    let mut reader = hound::WavReader::open(path)?;
    let spec = reader.spec();
    if spec.channels != 1 {
        anyhow::bail!(
            "channel-sim requires a mono WAV (got {} channels)",
            spec.channels
        );
    }
    if spec.sample_rate != SAMPLE_RATE {
        anyhow::bail!(
            "channel-sim requires a {} Hz WAV (got {} Hz)",
            SAMPLE_RATE,
            spec.sample_rate
        );
    }
    let samples = match spec.sample_format {
        hound::SampleFormat::Float => reader
            .samples::<f32>()
            .collect::<std::result::Result<Vec<_>, _>>()?,
        hound::SampleFormat::Int => match spec.bits_per_sample {
            16 => {
                let mut samples = Vec::new();
                for s in reader.samples::<i16>() {
                    samples.push(s? as f32 / 32768.0);
                }
                samples
            }
            b => anyhow::bail!("unsupported integer sample width {b}: use 16-bit or f32 WAV"),
        },
    };
    Ok(samples)
}

fn write_wav(path: &Path, samples: &[f32]) -> Result<()> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let mut writer = hound::WavWriter::create(path, spec)?;
    for &s in samples {
        writer.write_sample(s)?;
    }
    writer.finalize()?;
    Ok(())
}
