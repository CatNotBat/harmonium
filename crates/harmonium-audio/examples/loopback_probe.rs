//! Probe: does WASAPI process loopback keep delivering samples while the target's
//! audio session is muted?
//!
//! Two modes:
//! * `loopback_probe play <seconds>` — play a 1000 Hz sine at amplitude 0.3 on the
//!   default output device (or `$HARMONIUM_PROBE_OUTPUT`) for `<seconds>`, then exit.
//! * `loopback_probe` — spawn the `play` child, capture it with [`ProcessLoopback`],
//!   and mute/unmute its session mid-run to measure whether loopback samples survive
//!   the mute.
//!
//! Windows-only; every other platform prints a one-line message and exits.

#[cfg(windows)]
use std::error::Error;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use harmonium_audio::{ProcessLoopback, set_process_mute, set_process_volume};
#[cfg(windows)]
use ringbuf::traits::Consumer;

#[cfg(not(windows))]
fn main() {
    eprintln!("loopback_probe is Windows-only");
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("play") => {
            let seconds: u64 = args
                .get(2)
                .ok_or("usage: loopback_probe play <seconds>")?
                .parse()?;
            play_tone(seconds)
        }
        Some(other) => Err(format!("unknown mode {other:?}").into()),
        None => run_probe(),
    }
}

/// Play a 1000 Hz sine at amplitude 0.3 on the default output device for `seconds`.
#[cfg(windows)]
fn play_tone(seconds: u64) -> Result<(), Box<dyn Error>> {
    use cpal::traits::{DeviceTrait, HostTrait};

    let host = cpal::default_host();
    // HARMONIUM_PROBE_OUTPUT picks another output by name substring (e.g. "CABLE Input"),
    // so the probe can run silently: process loopback captures whichever endpoint is used.
    let device = match std::env::var("HARMONIUM_PROBE_OUTPUT") {
        Ok(name) => {
            let needle = name.to_lowercase();
            host.devices()?
                .find(|d| d.supports_output() && d.to_string().to_lowercase().contains(&needle))
                .ok_or_else(|| format!("no output device containing {name:?}"))?
        }
        Err(_) => host
            .default_output_device()
            .ok_or("no default output device")?,
    };
    let config = device.default_output_config()?;
    let channels = config.channels() as usize;
    let stream_config: cpal::StreamConfig = config.config();

    match config.sample_format() {
        cpal::SampleFormat::F32 => run_tone::<f32>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::F64 => run_tone::<f64>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::I8 => run_tone::<i8>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::I16 => run_tone::<i16>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::I24 => run_tone::<cpal::I24>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::I32 => run_tone::<i32>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::I64 => run_tone::<i64>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::U8 => run_tone::<u8>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::U16 => run_tone::<u16>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::U24 => run_tone::<cpal::U24>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::U32 => run_tone::<u32>(&device, stream_config, channels, seconds),
        cpal::SampleFormat::U64 => run_tone::<u64>(&device, stream_config, channels, seconds),
        other => Err(format!("unsupported default output format {other:?}").into()),
    }
}

/// Build and run one output stream for a concrete sample type `T`.
#[cfg(windows)]
fn run_tone<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: usize,
    seconds: u64,
) -> Result<(), Box<dyn Error>>
where
    T: cpal::SizedSample + cpal::FromSample<f32>,
{
    use cpal::traits::{DeviceTrait, StreamTrait};

    let sample_rate = config.sample_rate as f32;
    let total_frames = (seconds as f32 * sample_rate) as usize;
    let mut frame_index = 0usize;

    let stream = device.build_output_stream::<T, _, _>(
        config,
        move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
            for frame in data.chunks_mut(channels) {
                let value = if frame_index < total_frames {
                    let t = frame_index as f32 / sample_rate;
                    0.3 * (std::f32::consts::TAU * 1000.0 * t).sin()
                } else {
                    0.0
                };
                // The same value goes to every channel of the frame.
                for sample in frame {
                    *sample = T::from_sample(value);
                }
                frame_index += 1;
            }
        },
        |err| eprintln!("output stream error: {err}"),
        None,
    )?;
    stream.play()?;
    std::thread::sleep(Duration::from_secs(seconds));
    Ok(())
}

/// Spawn the `play` child, capture it, and mute/unmute mid-run to measure whether
/// loopback survives the mute.
#[cfg(windows)]
fn run_probe() -> Result<(), Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let mut child = std::process::Command::new(&exe)
        .arg("play")
        .arg("11")
        .spawn()?;

    // Give the child a moment to open its output stream before capture starts.
    std::thread::sleep(Duration::from_secs(1));

    let (capture, mut consumer) = ProcessLoopback::start(child.id(), 1.0)?;

    // HARMONIUM_PROBE_VOLUME=<level> lowers the session volume instead of muting it.
    let volume: Option<f32> = match std::env::var("HARMONIUM_PROBE_VOLUME") {
        Ok(v) => Some(v.parse()?),
        Err(_) => None,
    };
    let quiet = |on: bool| match volume {
        Some(level) => set_process_volume(&[child.id()], if on { level } else { 1.0 }),
        None => set_process_mute(&[child.id()], on),
    };

    let mut block = vec![0.0f32; 48_000];
    let mut muted = false;
    let mut phase1: Vec<f32> = Vec::new();
    let mut phase2: Vec<f32> = Vec::new();
    let mut phase3: Vec<f32> = Vec::new();

    // Sample every 500 ms for 10 s (t = 0.5 .. 10.0). Mute at t=4.0, unmute at
    // t=7.0; the t=4.0 and t=7.0 drains fall between phases and are discarded.
    for step in 0..20 {
        let t = (step + 1) as f64 * 0.5;
        if step == 7 {
            let n = quiet(true)?;
            println!("mute: {n} session(s)");
            muted = true;
        }
        if step == 13 {
            let n = quiet(false)?;
            println!("unmute: {n} session(s)");
            muted = false;
        }

        std::thread::sleep(Duration::from_millis(500));

        let n = consumer.pop_slice(&mut block);
        let (rms, tone) = measure(&block[..n]);
        let muted_label = if muted { "yes" } else { "no" };
        println!("t={t:5.1}s n={n} rms={rms:.4} tone={tone:.3} muted={muted_label}");

        if (1.0..4.0).contains(&t) {
            phase1.push(tone);
        } else if (4.5..7.0).contains(&t) {
            phase2.push(tone);
        } else if (7.5..10.0).contains(&t) {
            phase3.push(tone);
        }
    }

    drop(capture);

    let _ = child.kill();
    let _ = child.wait();

    let m1 = mean(&phase1);
    let m2 = mean(&phase2);
    let m3 = mean(&phase3);
    println!("mean tone [1,4)s={m1:.4} [4.5,7)s={m2:.4} [7.5,10)s={m3:.4}");

    let verdict = if m1 < 0.01 {
        "no_signal"
    } else if m2 > 0.5 * m1 {
        "yes"
    } else {
        "no"
    };
    println!("VERDICT loopback_while_muted={verdict}");

    Ok(())
}

/// RMS and the normalised 1000 Hz Goertzel magnitude over `samples`.
#[cfg(windows)]
fn measure(samples: &[f32]) -> (f32, f32) {
    (rms(samples), goertzel(samples, 1000.0, 48_000))
}

#[cfg(windows)]
fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum_sq: f32 = samples.iter().map(|s| s * s).sum();
    (sum_sq / samples.len() as f32).sqrt()
}

/// Magnitude of the `target_hz` component, normalised so a full-scale sine of
/// amplitude A reads ~A.
#[cfg(windows)]
fn goertzel(samples: &[f32], target_hz: f32, sample_rate: u32) -> f32 {
    let n = samples.len();
    if n == 0 {
        return 0.0;
    }
    let k = (0.5 + n as f32 * target_hz / sample_rate as f32) as usize;
    let omega = std::f32::consts::TAU * k as f32 / n as f32;
    let coeff = 2.0 * omega.cos();
    let (mut s1, mut s2) = (0.0f32, 0.0f32);
    for &sample in samples {
        let s0 = sample + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    2.0 * power.sqrt() / n as f32
}

#[cfg(windows)]
fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}
