//! OFDM-DQPSK PHY: the high-rate modulation candidate.

use std::f32::consts::PI;
use std::sync::Arc;

use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};

use crate::Phy;
use crate::sync;

/// Reference-symbol phase sequence seed ("HARM").
const REF_SEED: u32 = 0x4841_524D;

/// Largest per-symbol timing slip (samples) the demodulator searches for: half a symbol, so
/// the search never locks onto a neighbouring symbol's prefix.
pub(crate) const MAX_SLIP: isize = 288;

/// How much better (normalized correlation) a shifted cyclic-prefix match must be before the
/// demodulator moves a symbol's window. Opus smears the prefix, so clean symbols score anywhere
/// from ~0.2 to ~0.9; only a large jump is a real slip.
const SLIP_MARGIN: f32 = 0.8;

/// OFDM-DQPSK parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfdmParams {
    /// FFT length per symbol.
    pub fft_len: usize,
    /// Cyclic-prefix length per symbol.
    pub cp_len: usize,
    /// First active subcarrier bin.
    pub first_bin: usize,
    /// Number of active subcarriers.
    pub n_carriers: usize,
    /// Bits per subcarrier (`1` = DBPSK, `2` = DQPSK).
    pub bits_per_carrier: usize,
}

impl Default for OfdmParams {
    fn default() -> Self {
        Self {
            fft_len: 480,
            cp_len: 96,
            first_bin: 3,
            n_carriers: 34,
            bits_per_carrier: 2,
        }
    }
}

pub(crate) struct Ofdm {
    params: OfdmParams,
    fft: Arc<dyn Fft<f32>>,
    ifft: Arc<dyn Fft<f32>>,
    sym_len: usize,
    pre_len: usize,
}

impl Ofdm {
    pub(crate) fn new(params: OfdmParams) -> Self {
        let mut planner = FftPlanner::<f32>::new();
        let fft = planner.plan_fft_forward(params.fft_len);
        let ifft = planner.plan_fft_inverse(params.fft_len);
        Self {
            params,
            fft,
            ifft,
            sym_len: params.cp_len + params.fft_len,
            pre_len: sync::CHIRP_LEN + sync::CHIRP_GAP,
        }
    }

    fn data_symbols(&self, coded_len: usize) -> usize {
        (coded_len * 8).div_ceil(self.params.n_carriers * self.params.bits_per_carrier)
    }

    fn reference_phases(&self) -> Vec<f32> {
        let mut state = REF_SEED;
        (0..self.params.n_carriers)
            .map(|_| {
                state = xorshift32(state);
                (state as f32 / u32::MAX as f32) * 2.0 * PI
            })
            .collect()
    }

    fn bits_at(&self, coded: &[u8], s: usize, k: usize, coded_bits: usize) -> u8 {
        let bpc = self.params.bits_per_carrier;
        let start = s * self.params.n_carriers * bpc + k * bpc;
        let mut val = 0u8;
        for p in 0..bpc {
            let idx = start + p;
            if idx >= coded_bits {
                break;
            }
            let bit = (coded[idx / 8] >> (7 - (idx % 8))) & 1;
            val = (val << 1) | bit;
        }
        val
    }

    fn gray_to_angle(&self, bits: u8) -> f32 {
        match self.params.bits_per_carrier {
            1 => {
                if bits & 1 == 0 {
                    0.0
                } else {
                    PI
                }
            }
            _ => match bits {
                0b00 => 0.0,
                0b01 => PI / 2.0,
                0b11 => PI,
                0b10 => 3.0 * PI / 2.0,
                _ => 0.0,
            },
        }
    }

    fn angle_to_gray(&self, angle: f32) -> u8 {
        let bpc = self.params.bits_per_carrier;
        let levels = 1 << bpc;
        let step = 2.0 * PI / levels as f32;
        let idx = (angle / step).round().rem_euclid(levels as f32) as usize;
        match bpc {
            1 => idx as u8,
            _ => [0b00, 0b01, 0b11, 0b10][idx],
        }
    }

    /// Normalized correlation between the cyclic prefix at `pos` and the symbol tail it copies.
    fn cp_metric(&self, frame: &[f32], pos: usize) -> f32 {
        let (cp, n) = (self.params.cp_len, self.params.fft_len);
        let head = &frame[pos..pos + cp];
        let tail = &frame[pos + n..pos + n + cp];
        let (mut xy, mut xx, mut yy) = (0.0f32, 0.0f32, 0.0f32);
        for (&a, &b) in head.iter().zip(tail) {
            xy += a * b;
            xx += a * a;
            yy += b * b;
        }
        xy / ((xx * yy).sqrt() + 1e-12)
    }

    /// Offset from `nominal` to the symbol start whose cyclic prefix matches best within
    /// ±[`MAX_SLIP`], or 0 unless that match beats `nominal`'s by [`SLIP_MARGIN`]. The result
    /// keeps the symbol inside `frame`.
    fn timing_offset(&self, frame: &[f32], nominal: isize) -> isize {
        let last = frame.len() as isize - self.sym_len as isize;
        let lo = (nominal - MAX_SLIP).max(0);
        let hi = (nominal + MAX_SLIP).min(last);
        if nominal < lo || nominal > hi {
            // Only when the frame slice is truncated: stay as close to nominal as indexing allows.
            return nominal.clamp(0, last.max(0)) - nominal;
        }
        let here = self.cp_metric(frame, nominal as usize);
        let (mut best, mut best_m) = (nominal, here);
        for pos in lo..=hi {
            let m = self.cp_metric(frame, pos as usize);
            if m > best_m {
                (best, best_m) = (pos, m);
            }
        }
        if best_m > here + SLIP_MARGIN {
            best - nominal
        } else {
            0
        }
    }

    /// Carrier bins of the symbol whose cyclic prefix starts at `pos`.
    fn carriers_at(&self, frame: &[f32], pos: usize) -> Vec<Complex<f32>> {
        let p = &self.params;
        let start = pos + p.cp_len / 2;
        let mut buf: Vec<Complex<f32>> = frame[start..start + p.fft_len]
            .iter()
            .map(|&x| Complex::new(x, 0.0))
            .collect();
        self.fft.process(&mut buf);
        (0..p.n_carriers).map(|k| buf[p.first_bin + k]).collect()
    }

    fn synthesize_symbol(&self, phases: &[f32]) -> Vec<f32> {
        let p = &self.params;
        let n = p.fft_len;
        let mut freq = vec![Complex::new(0.0, 0.0); n];
        for (k, &ph) in phases.iter().enumerate() {
            let bin = p.first_bin + k;
            let c = Complex::from_polar(1.0, ph);
            freq[bin] = c;
            freq[n - bin] = c.conj();
        }
        self.ifft.process(&mut freq);

        let mut sym = vec![0.0f32; self.sym_len];
        for (i, c) in freq.iter().enumerate() {
            sym[p.cp_len + i] = c.re;
        }
        let cp = p.cp_len;
        let (head, tail) = sym.split_at_mut(n);
        head[..cp].copy_from_slice(&tail[..cp]);
        sym
    }
}

impl Phy for Ofdm {
    fn name(&self) -> &'static str {
        "ofdm-dqpsk"
    }

    fn frame_len(&self, coded_len: usize) -> usize {
        self.pre_len + self.sym_len * (1 + self.data_symbols(coded_len))
    }

    fn modulate(&self, coded: &[u8], out: &mut Vec<f32>) {
        let coded_bits = coded.len() * 8;
        let data_symbols = self.data_symbols(coded.len());

        let mut phases = Vec::with_capacity(1 + data_symbols);
        phases.push(self.reference_phases());
        for s in 0..data_symbols {
            let prev = phases[s].clone();
            let mut ph = Vec::with_capacity(self.params.n_carriers);
            for (k, &prev_phase) in prev.iter().enumerate() {
                let bits = self.bits_at(coded, s, k, coded_bits);
                let step = self.gray_to_angle(bits);
                ph.push((prev_phase + step).rem_euclid(2.0 * PI));
            }
            phases.push(ph);
        }

        let mut frame = Vec::with_capacity(self.frame_len(coded.len()));
        frame.extend_from_slice(&sync::chirp());
        frame.resize(self.pre_len, 0.0);

        // Scale only the symbols to peak 0.5. The chirp keeps its own 0.5 amplitude: scaling the
        // whole frame by the (much larger) raw IFFT peak left the chirp ~40 dB below the data,
        // where Opus at 64 kbps barely codes it and sync failed on most frames.
        let mut symbols =
            Vec::with_capacity(phases.len() * (self.params.cp_len + self.params.fft_len));
        for ph in &phases {
            symbols.extend_from_slice(&self.synthesize_symbol(ph));
        }
        let peak = symbols.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        let scale = if peak > 1e-12 { 0.5 / peak } else { 1.0 };
        frame.extend(symbols.iter().map(|s| s * scale));
        out.extend_from_slice(&frame);
    }

    fn demodulate(&self, frame: &[f32], coded_len: usize) -> Vec<u8> {
        let p = &self.params;
        let data_symbols = self.data_symbols(coded_len);
        let n_sym = 1 + data_symbols;

        // The live receive path drops or repeats a few ms of audio mid-frame (seen live: 120-240
        // samples, more than the cyclic prefix can absorb), which would shift every later symbol.
        // So re-find each symbol's start from its cyclic prefix and carry the slip forward.
        let mut drift: isize = 0;
        let mut symbols: Vec<Vec<Complex<f32>>> = Vec::with_capacity(n_sym);
        for s in 0..n_sym {
            let nominal = (self.pre_len + s * self.sym_len) as isize + drift;
            let o = self.timing_offset(frame, nominal);
            let carriers = self.carriers_at(frame, (nominal + o) as usize);
            drift += o;
            symbols.push(carriers);
        }

        let coded_bits = coded_len * 8;
        let mut out = vec![0u8; coded_len];
        for s in 1..n_sym {
            let d = s - 1;
            for (k, (cur, prev)) in symbols[s].iter().zip(symbols[s - 1].iter()).enumerate() {
                let start = d * p.n_carriers * p.bits_per_carrier + k * p.bits_per_carrier;
                if start >= coded_bits {
                    break;
                }
                let diff = *cur * prev.conj();
                let bits = self.angle_to_gray(diff.arg());
                for b in 0..p.bits_per_carrier {
                    let idx = start + b;
                    if idx >= coded_bits {
                        break;
                    }
                    let bit = (bits >> (p.bits_per_carrier - 1 - b)) & 1;
                    out[idx / 8] |= bit << (7 - (idx % 8));
                }
            }
        }
        out
    }
}

fn xorshift32(mut x: u32) -> u32 {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}
