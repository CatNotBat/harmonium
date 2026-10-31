//! MFSK PHY: the robust noncoherent baseline.

use std::f32::consts::PI;
use std::sync::Arc;

use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};

use crate::Phy;
use crate::sync;

/// Raised-cosine ramp length at each symbol edge, in samples.
const RAMP: usize = 24;

/// MFSK parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfskParams {
    /// Samples per symbol.
    pub symbol_len: usize,
    /// Number of tones per band (`log2(tones)` bits per band).
    pub tones: usize,
    /// Number of bands per symbol.
    pub bands: usize,
    /// First active frequency bin.
    pub first_bin: usize,
}

impl Default for MfskParams {
    fn default() -> Self {
        Self {
            symbol_len: 480,
            tones: 16,
            bands: 4,
            first_bin: 6,
        }
    }
}

pub(crate) struct Mfsk {
    params: MfskParams,
    fft: Arc<dyn Fft<f32>>,
    pre_len: usize,
    bits_per_symbol: usize,
}

impl Mfsk {
    pub(crate) fn new(params: MfskParams) -> Self {
        let mut planner = FftPlanner::<f32>::new();
        let fft = planner.plan_fft_forward(params.symbol_len);
        Self {
            params,
            fft,
            pre_len: sync::CHIRP_LEN + sync::CHIRP_GAP,
            bits_per_symbol: params.bands * params.tones.ilog2() as usize,
        }
    }

    fn symbols(&self, coded_len: usize) -> usize {
        (coded_len * 8).div_ceil(self.bits_per_symbol)
    }

    fn bits_at(&self, coded: &[u8], s: usize, band: usize, coded_bits: usize) -> u8 {
        let bits_per_band = self.bits_per_symbol / self.params.bands;
        let start = s * self.bits_per_symbol + band * bits_per_band;
        let mut val = 0u8;
        for p in 0..bits_per_band {
            let idx = start + p;
            if idx >= coded_bits {
                break;
            }
            let bit = (coded[idx / 8] >> (7 - (idx % 8))) & 1;
            val = (val << 1) | bit;
        }
        val
    }
}

impl Phy for Mfsk {
    fn name(&self) -> &'static str {
        "mfsk"
    }

    fn frame_len(&self, coded_len: usize) -> usize {
        self.pre_len + self.symbols(coded_len) * self.params.symbol_len
    }

    fn modulate(&self, coded: &[u8], out: &mut Vec<f32>) {
        let p = &self.params;
        let coded_bits = coded.len() * 8;
        let n_sym = self.symbols(coded.len());

        let mut frame = Vec::with_capacity(self.frame_len(coded.len()));
        let chirp = sync::chirp();
        frame.extend_from_slice(&chirp);
        frame.resize(self.pre_len, 0.0);

        for s in 0..n_sym {
            let mut sym = vec![0.0f32; p.symbol_len];
            for band in 0..p.bands {
                let tone = self.bits_at(coded, s, band, coded_bits) as usize;
                // Tones sit on exact FFT bins, so each symbol is a whole number of cycles:
                // per-band phase is automatically continuous across symbol boundaries.
                let bin = p.first_bin + band * p.tones + tone;
                let n = p.symbol_len as f32;
                for (i, v) in sym.iter_mut().enumerate() {
                    *v += (2.0 * PI * bin as f32 * i as f32 / n).cos();
                }
            }
            for i in 0..RAMP {
                let w = 0.5 * (1.0 - (PI * i as f32 / RAMP as f32).cos());
                sym[i] *= w;
                sym[p.symbol_len - 1 - i] *= w;
            }
            frame.extend_from_slice(&sym);
        }

        let peak = frame.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        let scale = if peak > 1e-12 { 0.5 / peak } else { 1.0 };
        for s in &mut frame {
            *s *= scale;
        }
        out.extend_from_slice(&frame);
    }

    fn demodulate(&self, frame: &[f32], coded_len: usize) -> Vec<u8> {
        let p = &self.params;
        let coded_bits = coded_len * 8;
        let n_sym = self.symbols(coded_len);
        let bits_per_band = self.bits_per_symbol / p.bands;
        let mut out = vec![0u8; coded_len];

        for s in 0..n_sym {
            let start = self.pre_len + s * p.symbol_len;
            // Rectangular window: the tones are spaced by exactly one bin, so a
            // rectangular FFT keeps them orthogonal; a Hann window's -6 dB lobe at
            // ±1 bin would let adjacent-band tones flip a max-energy decision.
            let mut buf: Vec<Complex<f32>> = frame[start..start + p.symbol_len]
                .iter()
                .map(|&x| Complex::new(x, 0.0))
                .collect();
            self.fft.process(&mut buf);

            for band in 0..p.bands {
                let band_start = p.first_bin + band * p.tones;
                let mut best = 0usize;
                let mut best_e = -1.0f32;
                for (t, c) in buf.iter().enumerate().skip(band_start).take(p.tones) {
                    let e = c.norm_sqr();
                    if e > best_e {
                        best_e = e;
                        best = t - band_start;
                    }
                }
                for b in 0..bits_per_band {
                    let idx = s * self.bits_per_symbol + band * bits_per_band + b;
                    if idx >= coded_bits {
                        break;
                    }
                    let bit = (best as u8 >> (bits_per_band - 1 - b)) & 1;
                    out[idx / 8] |= bit << (7 - (idx % 8));
                }
            }
        }
        out
    }
}
