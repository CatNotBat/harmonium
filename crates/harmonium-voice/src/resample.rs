//! Streaming integer-ratio resamplers between 48 kHz and 8 kHz.
//!
//! Both directions share one windowed-sinc low-pass filter: a 127-tap
//! Blackman-windowed sinc with a 3600 Hz cutoff at 48 kHz. The downsampler
//! decimates by 6 and only computes every 6th output; the upsampler
//! zero-stuffs by 6 using the polyphase decomposition and re-applies the
//! missing factor of 6 as gain.

use core::f32::consts::PI;

/// FIR filter length, in taps at 48 kHz.
const TAPS: usize = 127;
/// 48 kHz to 8 kHz ratio.
const RATIO: usize = 6;
/// Low-pass cutoff frequency, in Hz, measured at 48 kHz.
const CUTOFF_HZ: f32 = 3600.0;
/// The 48 kHz side of the conversion.
const F48K: f32 = 48000.0;
/// Number of 8 kHz samples the upsampler must keep as history.
const UP_HISTORY: usize = TAPS.div_ceil(RATIO);

/// Build the shared windowed-sinc low-pass filter, normalised for unity DC
/// gain.
fn build_taps() -> Box<[f32]> {
    let fc = CUTOFF_HZ / F48K;
    let center = (TAPS - 1) as f32 * 0.5;
    let mut taps = vec![0.0_f32; TAPS];
    let mut sum = 0.0_f32;
    for (i, tap) in taps.iter_mut().enumerate() {
        let n = i as f32 - center;
        let x = 2.0 * PI * fc * n;
        let sinc = if x == 0.0 { 1.0 } else { x.sin() / x };
        let phase = i as f32 / (TAPS - 1) as f32;
        let window = 0.42 - 0.5 * (2.0 * PI * phase).cos() + 0.08 * (4.0 * PI * phase).cos();
        *tap = sinc * window;
        sum += *tap;
    }
    for tap in &mut taps {
        *tap /= sum;
    }
    taps.into_boxed_slice()
}

/// Clamp an f32 sample to the signed 16-bit range.
fn to_i16(sample: f32) -> i16 {
    (sample * 32768.0).round().clamp(-32768.0, 32767.0) as i16
}

/// Streaming 48 kHz (f32) → 8 kHz (i16) decimating resampler.
///
/// Keeps the last 126 input samples between calls so output is continuous
/// across arbitrary chunk boundaries.
pub struct Downsampler48k {
    taps: Box<[f32]>,
    history: Vec<f32>,
    pos: usize,
}

impl Downsampler48k {
    #[must_use]
    pub fn new() -> Self {
        Self {
            taps: build_taps(),
            history: Vec::with_capacity(TAPS - 1),
            pos: 0,
        }
    }

    /// Filter and decimate `input`, appending i16 samples to `out`.
    pub fn process(&mut self, input: &[f32], out: &mut Vec<i16>) {
        if input.is_empty() {
            return;
        }

        let base = self.pos - self.history.len();
        let mut buf = Vec::with_capacity(self.history.len() + input.len());
        buf.extend_from_slice(&self.history);
        buf.extend_from_slice(input);

        let mut j = self.history.len();
        while j < buf.len() {
            let abs = base + j;
            if !abs.is_multiple_of(RATIO) {
                j += 1;
                continue;
            }
            let mut acc = 0.0_f32;
            for (d, tap) in self.taps.iter().enumerate() {
                let sample = if j >= d { buf[j - d] } else { 0.0 };
                acc += tap * sample;
            }
            out.push(to_i16(acc));
            j += RATIO;
        }

        self.pos += input.len();
        if buf.len() > TAPS - 1 {
            self.history = buf[buf.len() - (TAPS - 1)..].to_vec();
        } else {
            self.history = buf;
        }
    }
}

impl Default for Downsampler48k {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming 8 kHz (i16) → 48 kHz (f32) interpolating resampler.
pub struct Upsampler8k {
    taps: Box<[f32]>,
    history: Vec<i16>,
}

impl Upsampler8k {
    #[must_use]
    pub fn new() -> Self {
        Self {
            taps: build_taps(),
            history: Vec::with_capacity(UP_HISTORY),
        }
    }

    /// Zero-stuff, filter and gain-correct `input`, appending f32 samples to
    /// `out`. Each input sample produces exactly `RATIO` output samples.
    pub fn process(&mut self, input: &[i16], out: &mut Vec<f32>) {
        for &sample in input {
            self.history.push(sample);
            if self.history.len() > UP_HISTORY {
                self.history.remove(0);
            }
            let len = self.history.len();
            for phase in 0..RATIO {
                let mut acc = 0.0_f32;
                let ntaps = (TAPS - 1 - phase) / RATIO + 1;
                for j in 0..ntaps {
                    if j >= len {
                        break;
                    }
                    acc += self.taps[phase + j * RATIO]
                        * (f32::from(self.history[len - 1 - j]) / 32768.0);
                }
                out.push(acc * RATIO as f32);
            }
        }
    }
}

impl Default for Upsampler8k {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR48: usize = 48000;

    fn sine_48k(freq: f32, seconds: f32, amp: f32) -> Vec<f32> {
        let n = (SR48 as f32 * seconds) as usize;
        (0..n)
            .map(|i| amp * (2.0 * PI * freq * i as f32 / SR48 as f32).sin())
            .collect()
    }

    fn rms(samples: &[f32]) -> f32 {
        let sum: f32 = samples.iter().map(|s| s * s).sum();
        (sum / samples.len() as f32).sqrt()
    }

    fn zero_crossings(samples: &[f32]) -> usize {
        samples
            .windows(2)
            .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
            .count()
    }

    fn down_up(input: &[f32]) -> Vec<f32> {
        let mut down = Downsampler48k::new();
        let mut mid = Vec::new();
        down.process(input, &mut mid);
        let mut up = Upsampler8k::new();
        let mut out = Vec::new();
        up.process(&mid, &mut out);
        out
    }

    #[test]
    fn sine_1k_survives_round_trip() {
        // 1.2 s of input so a full, steady 1 s window can be read after the
        // filter has settled.
        let input = sine_48k(1000.0, 1.2, 0.5);
        let out = down_up(&input);

        let start = 100 * 48; // 100 ms in
        let window = &out[start..start + SR48];
        assert_eq!(window.len(), SR48);

        let crossings = zero_crossings(window);
        assert!(
            (crossings as isize - 2000).abs() <= 2,
            "expected ~2000 zero crossings, got {crossings}"
        );

        let peak = window.iter().fold(0.0_f32, |m, &s| m.max(s.abs()));
        let db = 20.0 * (peak / 0.5).log10();
        assert!(db.abs() < 1.0, "peak {peak} is {db:.2} dB off");
    }

    #[test]
    fn sine_6k_is_attenuated() {
        let input = sine_48k(6000.0, 1.0, 0.5);
        let mut down = Downsampler48k::new();
        let mut mid = Vec::new();
        down.process(&input, &mut mid);

        let steady: Vec<f32> = mid[2000..]
            .iter()
            .map(|&s| f32::from(s) / 32768.0)
            .collect();
        let in_rms = rms(&input);
        let out_rms = rms(&steady);
        let attenuation = 20.0 * (out_rms / in_rms).log10();
        assert!(
            attenuation < -40.0,
            "expected >40 dB attenuation, got {attenuation:.2} dB"
        );
    }

    #[test]
    fn chunked_matches_oneshot() {
        let input = sine_48k(1000.0, 0.1, 0.5);

        let mut one = Downsampler48k::new();
        let mut one_out = Vec::new();
        one.process(&input, &mut one_out);

        for &chunk in &[1usize, 7, 997] {
            let mut d = Downsampler48k::new();
            let mut out = Vec::new();
            for slice in input.chunks(chunk) {
                d.process(slice, &mut out);
            }
            assert_eq!(out, one_out, "downsampler disagrees at chunk size {chunk}");
        }

        let mut one_up = Upsampler8k::new();
        let mut one_up_out = Vec::new();
        one_up.process(&one_out, &mut one_up_out);

        for &chunk in &[1usize, 7, 997] {
            let mut u = Upsampler8k::new();
            let mut out = Vec::new();
            for slice in one_out.chunks(chunk) {
                u.process(slice, &mut out);
            }
            assert_eq!(out, one_up_out, "upsampler disagrees at chunk size {chunk}");
        }
    }
}
