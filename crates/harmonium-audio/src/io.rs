//! Real-time audio streams bridged to the app thread over lock-free SPSC ring buffers.
//!
//! Every stream is opened at the device's *default* configuration, but the app-facing
//! side is always 48 kHz mono `f32`: channel count is mixed up/down in the callback and
//! sample format is converted with cpal's `FromSample`. A device whose default rate is
//! not 48 kHz is rejected (`AudioError::UnsupportedRate`) until resampling lands.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, Sample, SampleFormat, SizedSample, StreamConfig};
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use ringbuf::{HeapCons, HeapProd, HeapRb};

use crate::device::find_cpal_device;
use crate::error::AudioError;

/// The one sample rate the modem assumes; everything else is rejected for now.
const SAMPLE_RATE: u32 = 48_000;

/// One second of mono `f32` at 48 kHz. This is both the ring-buffer capacity and the
/// upper bound on how many frames a single callback is asked to convert, which lets the
/// conversion scratch buffers be allocated once up front (never inside a callback).
const RING_CAPACITY: usize = SAMPLE_RATE as usize;

/// How long to wait for the backend to open a stream before giving up.
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Which devices `AudioIo` connects, by cpal name.
///
/// `mic` / `speaker` are the user's own devices (`None` means the system default);
/// `to_discord` / `from_discord` are the virtual-device sides Harmonium owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioConfig {
    pub mic: Option<String>,
    pub speaker: Option<String>,
    pub to_discord: String,
    pub from_discord: String,
}

/// A special `AudioConfig::from_discord` value meaning "capture Discord's own audio
/// with WASAPI process loopback" instead of a cpal device (Windows only).
pub const DISCORD_PROCESS: &str = "process:discord";

/// Aggregate underrun/overrun counters across the four streams.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IoStats {
    /// Output callbacks that had to emit silence because the app fell behind.
    pub underruns: u64,
    /// Input callbacks that had to drop captured samples because the app fell behind.
    pub overruns: u64,
}

/// The receive side: a cpal capture device, or (on Windows) Discord process loopback.
enum FromDiscord {
    Device {
        _stream: cpal::Stream,
    },
    #[cfg(windows)]
    Process(crate::win_loopback::DiscordTap),
}

/// Open cpal streams, each connected to the app thread through a 1 s ring buffer.
///
/// The four streams are independent; this type is not `Send` and is meant to live on the
/// app thread, where the non-blocking `read_*`/`write_*` methods are called.
pub struct AudioIo {
    _mic: cpal::Stream,
    _speaker: cpal::Stream,
    _to_discord: cpal::Stream,
    _from_discord: FromDiscord,
    mic_consumer: HeapCons<f32>,
    speaker_producer: HeapProd<f32>,
    to_discord_producer: HeapProd<f32>,
    from_discord_consumer: HeapCons<f32>,
    underruns: Arc<AtomicU64>,
    overruns: Arc<AtomicU64>,
}

impl AudioIo {
    /// Open all four streams. Fails closed: any failure tears down the streams already
    /// opened and returns an error, leaving no half-open device.
    pub fn open(config: &AudioConfig) -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let underruns = Arc::new(AtomicU64::new(0));
        let overruns = Arc::new(AtomicU64::new(0));

        let mic_device = resolve_device(&host, config.mic.as_deref(), true, "input")?;
        let speaker_device = resolve_device(&host, config.speaker.as_deref(), false, "output")?;
        let to_discord_device = find_cpal_device(&host, &config.to_discord, false)?;

        let (mic_stream, mic_consumer) = open_input(&mic_device, overruns.clone())?;
        let (speaker_stream, speaker_producer) = open_output(&speaker_device, underruns.clone())?;
        let (to_discord_stream, to_discord_producer) =
            open_output(&to_discord_device, underruns.clone())?;

        let (from_discord, from_discord_consumer) = if config.from_discord == DISCORD_PROCESS {
            #[cfg(windows)]
            {
                let (tap, consumer) = crate::win_loopback::DiscordTap::start()?;
                (FromDiscord::Process(tap), consumer)
            }
            #[cfg(not(windows))]
            {
                return Err(AudioError::Unsupported);
            }
        } else {
            let device = find_cpal_device(&host, &config.from_discord, true)?;
            let (stream, consumer) = open_input(&device, overruns.clone())?;
            (FromDiscord::Device { _stream: stream }, consumer)
        };

        Ok(Self {
            _mic: mic_stream,
            _speaker: speaker_stream,
            _to_discord: to_discord_stream,
            _from_discord: from_discord,
            mic_consumer,
            speaker_producer,
            to_discord_producer,
            from_discord_consumer,
            underruns,
            overruns,
        })
    }

    /// Read captured mic samples (48 kHz mono). Returns the number of samples read;
    /// the rest of `out` is left untouched.
    pub fn read_mic(&mut self, out: &mut [f32]) -> usize {
        self.mic_consumer.pop_slice(out)
    }

    /// Read what Discord played into the virtual speaker (48 kHz mono).
    pub fn read_from_discord(&mut self, out: &mut [f32]) -> usize {
        self.from_discord_consumer.pop_slice(out)
    }

    /// Write samples to the user's speaker. Returns the number of samples accepted;
    /// a short return means the ring is full and the remainder was dropped.
    pub fn write_speaker(&mut self, samples: &[f32]) -> usize {
        self.speaker_producer.push_slice(samples)
    }

    /// Write modem samples into the virtual mic (48 kHz mono).
    pub fn write_to_discord(&mut self, samples: &[f32]) -> usize {
        self.to_discord_producer.push_slice(samples)
    }

    /// Samples written to the virtual mic that its device has not consumed yet. The app
    /// paces itself on this, so modem audio leaves at the device's clock, not the wall clock.
    pub fn to_discord_queued(&self) -> usize {
        self.to_discord_producer.occupied_len()
    }

    /// Drop the oldest captured mic samples so that at most `max` remain queued, bounding
    /// latency when the mic's clock runs faster than the app's. Returns how many were dropped.
    pub fn trim_mic_backlog(&mut self, max: usize) -> usize {
        let excess = self.mic_consumer.occupied_len().saturating_sub(max);
        self.mic_consumer.skip(excess)
    }

    /// Snapshot the aggregate underrun/overrun counters.
    pub fn stats(&self) -> IoStats {
        let overruns = self.overruns.load(Ordering::Relaxed);
        #[cfg(windows)]
        let overruns = overruns
            + match &self._from_discord {
                FromDiscord::Process(tap) => tap.overruns(),
                FromDiscord::Device { .. } => 0,
            };
        IoStats {
            underruns: self.underruns.load(Ordering::Relaxed),
            overruns,
        }
    }
}

fn resolve_device(
    host: &cpal::Host,
    name: Option<&str>,
    want_input: bool,
    what: &str,
) -> Result<cpal::Device, AudioError> {
    match name {
        Some(substring) => find_cpal_device(host, substring, want_input),
        None => {
            let device = if want_input {
                host.default_input_device()
            } else {
                host.default_output_device()
            };
            device.ok_or_else(|| AudioError::DeviceNotFound(format!("no default {what} device")))
        }
    }
}

fn check_rate(rate: u32) -> Result<(), AudioError> {
    if rate == SAMPLE_RATE {
        Ok(())
    } else {
        Err(AudioError::UnsupportedRate(rate))
    }
}

fn open_input(
    device: &cpal::Device,
    overruns: Arc<AtomicU64>,
) -> Result<(cpal::Stream, HeapCons<f32>), AudioError> {
    let config = device
        .default_input_config()
        .map_err(|e| AudioError::Cpal(e.to_string()))?;
    check_rate(config.sample_rate())?;
    let channels = config.channels() as usize;
    if channels == 0 {
        return Err(AudioError::Cpal("device reported zero channels".into()));
    }
    let stream_config: StreamConfig = config.config();
    match config.sample_format() {
        SampleFormat::F32 => open_input_typed::<f32>(device, stream_config, channels, overruns),
        SampleFormat::F64 => open_input_typed::<f64>(device, stream_config, channels, overruns),
        SampleFormat::I8 => open_input_typed::<i8>(device, stream_config, channels, overruns),
        SampleFormat::I16 => open_input_typed::<i16>(device, stream_config, channels, overruns),
        SampleFormat::I24 => {
            open_input_typed::<cpal::I24>(device, stream_config, channels, overruns)
        }
        SampleFormat::I32 => open_input_typed::<i32>(device, stream_config, channels, overruns),
        SampleFormat::I64 => open_input_typed::<i64>(device, stream_config, channels, overruns),
        SampleFormat::U8 => open_input_typed::<u8>(device, stream_config, channels, overruns),
        SampleFormat::U16 => open_input_typed::<u16>(device, stream_config, channels, overruns),
        SampleFormat::U24 => {
            open_input_typed::<cpal::U24>(device, stream_config, channels, overruns)
        }
        SampleFormat::U32 => open_input_typed::<u32>(device, stream_config, channels, overruns),
        SampleFormat::U64 => open_input_typed::<u64>(device, stream_config, channels, overruns),
        other => Err(AudioError::Cpal(format!(
            "unsupported sample format {other:?}"
        ))),
    }
}

fn open_output(
    device: &cpal::Device,
    underruns: Arc<AtomicU64>,
) -> Result<(cpal::Stream, HeapProd<f32>), AudioError> {
    let config = device
        .default_output_config()
        .map_err(|e| AudioError::Cpal(e.to_string()))?;
    check_rate(config.sample_rate())?;
    let channels = config.channels() as usize;
    if channels == 0 {
        return Err(AudioError::Cpal("device reported zero channels".into()));
    }
    let stream_config: StreamConfig = config.config();
    match config.sample_format() {
        SampleFormat::F32 => open_output_typed::<f32>(device, stream_config, channels, underruns),
        SampleFormat::F64 => open_output_typed::<f64>(device, stream_config, channels, underruns),
        SampleFormat::I8 => open_output_typed::<i8>(device, stream_config, channels, underruns),
        SampleFormat::I16 => open_output_typed::<i16>(device, stream_config, channels, underruns),
        SampleFormat::I24 => {
            open_output_typed::<cpal::I24>(device, stream_config, channels, underruns)
        }
        SampleFormat::I32 => open_output_typed::<i32>(device, stream_config, channels, underruns),
        SampleFormat::I64 => open_output_typed::<i64>(device, stream_config, channels, underruns),
        SampleFormat::U8 => open_output_typed::<u8>(device, stream_config, channels, underruns),
        SampleFormat::U16 => open_output_typed::<u16>(device, stream_config, channels, underruns),
        SampleFormat::U24 => {
            open_output_typed::<cpal::U24>(device, stream_config, channels, underruns)
        }
        SampleFormat::U32 => open_output_typed::<u32>(device, stream_config, channels, underruns),
        SampleFormat::U64 => open_output_typed::<u64>(device, stream_config, channels, underruns),
        other => Err(AudioError::Cpal(format!(
            "unsupported sample format {other:?}"
        ))),
    }
}

fn open_input_typed<T>(
    device: &cpal::Device,
    config: StreamConfig,
    channels: usize,
    overruns: Arc<AtomicU64>,
) -> Result<(cpal::Stream, HeapCons<f32>), AudioError>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let ring = HeapRb::<f32>::new(RING_CAPACITY);
    let (mut producer, consumer) = ring.split();

    // Scratch buffers, sized to the worst case and never touched by allocation inside
    // the callback.
    let mut interleaved = vec![0.0f32; RING_CAPACITY * channels];
    let mut mono = vec![0.0f32; RING_CAPACITY];

    let data_callback = move |data: &[T], _: &cpal::InputCallbackInfo| {
        let full = data.len() / channels;
        let frames = full.min(RING_CAPACITY);
        let n = frames * channels;
        for (dst, &src) in interleaved[..n].iter_mut().zip(data[..n].iter()) {
            *dst = f32::from_sample(src);
        }
        downmix_to_mono(&interleaved[..n], channels, &mut mono[..frames]);
        let pushed = producer.push_slice(&mono[..frames]);
        let dropped = full.saturating_sub(pushed) as u64;
        if dropped > 0 {
            overruns.fetch_add(dropped, Ordering::Relaxed);
        }
    };

    let stream = device
        .build_input_stream::<T, _, _>(config, data_callback, stream_err, Some(STREAM_TIMEOUT))
        .map_err(|e| AudioError::Cpal(e.to_string()))?;
    stream.play().map_err(|e| AudioError::Cpal(e.to_string()))?;
    Ok((stream, consumer))
}

fn open_output_typed<T>(
    device: &cpal::Device,
    config: StreamConfig,
    channels: usize,
    underruns: Arc<AtomicU64>,
) -> Result<(cpal::Stream, HeapProd<f32>), AudioError>
where
    T: SizedSample,
    T: FromSample<f32>,
{
    let ring = HeapRb::<f32>::new(RING_CAPACITY);
    let (producer, mut consumer) = ring.split();

    let mut mono = vec![0.0f32; RING_CAPACITY];
    let mut interleaved = vec![0.0f32; RING_CAPACITY * channels];

    let data_callback = move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
        let full = data.len() / channels;
        let frames = full.min(RING_CAPACITY);
        let got = consumer.pop_slice(&mut mono[..frames]);
        let n = got * channels;
        upmix_from_mono(&mono[..got], channels, &mut interleaved[..n]);
        for (dst, &src) in data[..n].iter_mut().zip(interleaved[..n].iter()) {
            *dst = T::from_sample(src);
        }
        // Anything beyond what the ring supplied is silence.
        for dst in data[n..].iter_mut() {
            *dst = T::EQUILIBRIUM;
        }
        let missed = full.saturating_sub(got) as u64;
        if missed > 0 {
            underruns.fetch_add(missed, Ordering::Relaxed);
        }
    };

    let stream = device
        .build_output_stream::<T, _, _>(config, data_callback, stream_err, Some(STREAM_TIMEOUT))
        .map_err(|e| AudioError::Cpal(e.to_string()))?;
    stream.play().map_err(|e| AudioError::Cpal(e.to_string()))?;
    Ok((stream, producer))
}

fn stream_err(err: cpal::Error) {
    tracing::error!("audio stream error: {err}");
}

/// Down-mix interleaved `channels`-channel `f32` into mono by averaging each frame.
fn downmix_to_mono(input: &[f32], channels: usize, out: &mut [f32]) {
    debug_assert!(channels > 0);
    for (frame, dst) in input.chunks_exact(channels).zip(out.iter_mut()) {
        *dst = frame.iter().sum::<f32>() / channels as f32;
    }
}

/// Up-mix mono `f32` into interleaved `channels`-channel `f32` by duplicating each sample.
fn upmix_from_mono(mono: &[f32], channels: usize, out: &mut [f32]) {
    debug_assert!(channels > 0);
    for (src, frame) in mono.iter().zip(out.chunks_exact_mut(channels)) {
        for slot in frame {
            *slot = *src;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stereo_to_mono_averages_pairs() {
        let stereo = [0.0f32, 1.0, 0.5, 0.5, -1.0, -1.0];
        let mut mono = [0.0f32; 3];
        downmix_to_mono(&stereo, 2, &mut mono);
        assert_eq!(mono, [0.5, 0.5, -1.0]);
    }

    #[test]
    fn mono_to_stereo_duplicates_samples() {
        let mono = [0.25f32, -0.75, 1.0];
        let mut stereo = [0.0f32; 6];
        upmix_from_mono(&mono, 2, &mut stereo);
        assert_eq!(stereo, [0.25, 0.25, -0.75, -0.75, 1.0, 1.0]);
    }

    #[test]
    fn mono_passthrough_is_identity() {
        let input = [0.1f32, 0.2, 0.3];
        let mut out = [0.0f32; 3];
        downmix_to_mono(&input, 1, &mut out);
        assert_eq!(out, input);
        let mut back = [0.0f32; 3];
        upmix_from_mono(&input, 1, &mut back);
        assert_eq!(back, input);
    }

    #[test]
    fn surround_downmix_averages_all_channels() {
        // Two frames of four channels.
        let quad = [1.0f32, 2.0, 3.0, 4.0, 0.0, 0.0, 0.0, 8.0];
        let mut mono = [0.0f32; 2];
        downmix_to_mono(&quad, 4, &mut mono);
        assert_eq!(mono, [2.5, 2.0]);
    }

    #[test]
    fn partial_trailing_frame_is_ignored() {
        // 5 samples at 2 channels: two full frames plus a lone trailing sample.
        let odd = [1.0f32, 2.0, 3.0, 4.0, 5.0];
        let mut mono = [0.0f32; 2];
        downmix_to_mono(&odd, 2, &mut mono);
        assert_eq!(mono, [1.5, 3.5]);
    }
}
