//! Chirp preamble generation and streaming normalized cross-correlation detection.

use std::collections::VecDeque;
use std::f32::consts::PI;
use std::sync::Arc;

use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};

/// Length of the synchronization chirp, in samples.
pub const CHIRP_LEN: usize = 960;
/// Silence gap after the chirp, in samples.
pub const CHIRP_GAP: usize = 48;

/// Raised-cosine taper length at each end of the chirp, in samples.
const TAPER: usize = 48;
/// Detection threshold on the normalized cross-correlation.
const THRESHOLD: f32 = 0.6;
/// Half-width of the local-maximum window, in samples.
const LOCAL_MAX_HALF: usize = 48;
/// FFT block size used by the overlap-save correlator.
pub(crate) const BLOCK: usize = 2048;
/// Sample rate the modem runs at.
const SAMPLE_RATE: f32 = 48_000.0;

/// The linear up-chirp preamble: 960 samples sweeping 600 Hz → 6000 Hz, amplitude 0.5,
/// with a raised-cosine taper at each end.
pub fn chirp() -> Vec<f32> {
    const F0: f32 = 600.0;
    const F1: f32 = 6000.0;
    let mut out = vec![0.0f32; CHIRP_LEN];
    let duration = (CHIRP_LEN - 1) as f32 / SAMPLE_RATE;
    for (n, s) in out.iter_mut().enumerate() {
        let t = n as f32 / SAMPLE_RATE;
        let phase = 2.0 * PI * (F0 * t + (F1 - F0) * t * t / (2.0 * duration));
        let mut v = 0.5 * phase.cos();
        if n < TAPER {
            v *= 0.5 * (1.0 - (PI * n as f32 / TAPER as f32).cos());
        } else if n >= CHIRP_LEN - TAPER {
            let m = CHIRP_LEN - 1 - n;
            v *= 0.5 * (1.0 - (PI * m as f32 / TAPER as f32).cos());
        }
        *s = v;
    }
    out
}

/// Streaming detector for the chirp preamble, using normalized cross-correlation computed
/// with an FFT overlap-save correlator.
pub struct SyncDetector {
    chirp_norm: f32,
    chirp_spectrum: Vec<Complex<f32>>,
    forward: Arc<dyn Fft<f32>>,
    inverse: Arc<dyn Fft<f32>>,
    work: Vec<Complex<f32>>,
    overlap: Vec<f32>,
    pending: Vec<f32>,
    next_new: usize,
    ncc_base: usize,
    ncc: VecDeque<f32>,
    scan_from: usize,
}

impl SyncDetector {
    /// Create a detector.
    pub fn new() -> Self {
        let mut planner = FftPlanner::<f32>::new();
        let forward = planner.plan_fft_forward(BLOCK);
        let inverse = planner.plan_fft_inverse(BLOCK);

        let chirp = chirp();
        let chirp_norm = chirp.iter().map(|s| s * s).sum::<f32>().sqrt();
        let mut chirp_spectrum = vec![Complex::new(0.0, 0.0); BLOCK];
        for (i, &s) in chirp.iter().enumerate() {
            chirp_spectrum[i] = Complex::new(s, 0.0);
        }
        forward.process(&mut chirp_spectrum);

        Self {
            chirp_norm,
            chirp_spectrum,
            forward,
            inverse,
            work: vec![Complex::new(0.0, 0.0); BLOCK],
            overlap: vec![0.0; CHIRP_LEN - 1],
            pending: Vec::new(),
            next_new: 0,
            ncc_base: 0,
            ncc: VecDeque::new(),
            scan_from: 0,
        }
    }

    /// Feed samples and return the global sample indices of detected chirps.
    pub fn push(&mut self, samples: &[f32]) -> Vec<usize> {
        self.pending.extend_from_slice(samples);
        self.process_blocks();
        self.scan()
    }

    /// Forget all detection state older than global sample index `g`.
    pub fn drop_before(&mut self, g: usize) {
        let count = g.saturating_sub(self.ncc_base).min(self.ncc.len());
        for _ in 0..count {
            self.ncc.pop_front();
        }
        self.ncc_base += count;
        if self.scan_from < g {
            self.scan_from = g;
        }
    }

    #[cfg(test)]
    pub(crate) fn backlog(&self) -> usize {
        self.ncc.len() + self.pending.len()
    }

    fn process_blocks(&mut self) {
        let valid = BLOCK - CHIRP_LEN + 1;
        let need = BLOCK - self.overlap.len();
        while self.pending.len() >= need {
            let mut block = Vec::with_capacity(BLOCK);
            block.extend_from_slice(&self.overlap);
            block.extend(self.pending.drain(..need));

            for (i, &s) in block.iter().enumerate() {
                self.work[i] = Complex::new(s, 0.0);
            }
            self.forward.process(&mut self.work);
            for (w, &c) in self.work.iter_mut().zip(self.chirp_spectrum.iter()) {
                *w *= c.conj();
            }
            self.inverse.process(&mut self.work);

            let mut prefix = [0.0f32; BLOCK + 1];
            let mut acc = 0.0f32;
            for (i, &s) in block.iter().enumerate() {
                acc += s * s;
                prefix[i + 1] = acc;
            }
            let scale = self.chirp_norm * BLOCK as f32;
            // `block[0]` is the sample at global index `next_new - (CHIRP_LEN - 1)`;
            // output `m` therefore corresponds to sample `next_new - (CHIRP_LEN - 1) + m`.
            let block_first = self.next_new as isize - (CHIRP_LEN - 1) as isize;
            for m in 0..valid {
                let idx = block_first + m as isize;
                if idx < 0 {
                    continue; // before the stream began; not a real sample position
                }
                let sum_sq = prefix[m + CHIRP_LEN] - prefix[m];
                let denom = sum_sq.sqrt() * scale;
                let ncc = if denom > 1e-12 {
                    self.work[m].re / denom
                } else {
                    0.0
                };
                self.ncc.push_back(ncc);
            }

            self.overlap = block[BLOCK - (CHIRP_LEN - 1)..].to_vec();
            self.next_new += valid;
        }
    }

    fn scan(&mut self) -> Vec<usize> {
        let mut detections = Vec::new();
        let base = self.ncc_base;
        let len = self.ncc.len();
        let mut t = self.scan_from.max(base);
        while t + LOCAL_MAX_HALF < base + len {
            let i = t - base;
            let v = self.ncc[i];
            if v >= THRESHOLD {
                let mut local_max = true;
                for d in 1..=LOCAL_MAX_HALF {
                    if i >= d && self.ncc[i - d] > v {
                        local_max = false;
                        break;
                    }
                    if self.ncc[i + d] > v {
                        local_max = false;
                        break;
                    }
                }
                if local_max {
                    detections.push(t);
                }
            }
            t += 1;
        }
        self.scan_from = t;
        detections
    }
}

impl Default for SyncDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn detects_chirp_in_noise_at_exact_offset() {
        for gain in [0.05f32, 3.0] {
            let mut rng = ChaCha8Rng::seed_from_u64(11);
            let offset = 4000usize;
            let total = offset + CHIRP_LEN + 2000;
            let mut signal = vec![0.0f32; total];
            for s in &mut signal {
                *s = rng.random_range(-0.005..0.005);
            }
            let c = chirp();
            for (i, &v) in c.iter().enumerate() {
                signal[offset + i] += v * gain;
            }

            let mut det = SyncDetector::new();
            let dets = det.push(&signal);
            assert!(!dets.is_empty(), "no detection for gain {gain}");
            let t = dets[0];
            let diff = (t as isize - offset as isize).abs();
            assert!(diff <= 1, "gain {gain}: detected {t}, expected {offset}");
        }
    }

    #[test]
    fn no_detection_in_pure_noise() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);
        let mut signal = vec![0.0f32; SAMPLE_RATE as usize * 10];
        for s in &mut signal {
            *s = rng.random_range(-0.1..0.1);
        }
        let mut det = SyncDetector::new();
        let dets = det.push(&signal);
        assert!(dets.is_empty(), "false detections: {dets:?}");
    }
}
