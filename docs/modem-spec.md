# harmonium-modem: design

The modem turns a stream of link packets (WireGuard datagrams, 32–148+ bytes) into 48 kHz mono
`f32` audio that survives Discord's Opus path, and back. It is the unproven part of the project,
so every number below is a starting parameter that `channel-sim` measures; none is a promise.

All modem audio is **48 kHz mono f32 in [-1, 1]**, the rate Discord's Opus runs at, so no
resampling sits inside the modem path. Peak output amplitude is at most 0.5 (headroom).

## Layers (top to bottom)

```
packets (Vec<u8>, 1..=1500 bytes)
  │ framer.rs   append CRC-16, COBS-encode + 0x00 delimiter → byte stream → cut into frame payloads
  ▼             (a short final chunk is padded with 0x00: empty delimiters, ignored on receive)
frame payload (FecParams::payload_len() bytes)
  │ fec.rs      split into C Reed-Solomon codewords RS(k+e, k), byte-interleave the codewords
  ▼
coded frame (C*(k+e) bytes) → bits, MSB first
  │ phy (ofdm.rs | mfsk.rs)  preamble chirp + symbols → audio
  ▼
audio
```

Receive runs the same in reverse. A frame whose RS decode fails is reported as lost and the
framer **discards any partial packet** in progress (it inserts a virtual delimiter and drops the
fragment) so a lost frame costs whole packets, never corrupts one. WireGuard would drop a
corrupted packet anyway; this keeps the replay window and stats honest.

## FEC (fec.rs)

`FecParams { data_len: k, ecc_len: e, codewords: C }`, default `k=64, e=40, C=4` (RS(104,64)). The modem bake-off at 68 carriers showed e=32 cannot absorb one lost 20 ms Opus packet (~4 OFDM symbols); at 34 carriers those 4 symbols are 34 bytes, ~9 per codeword, inside e/2 = 20.
- `payload_len() = C*k`, `coded_len() = C*(k+e)`. Require `k+e <= 255`.
- Encode: payload chunk `i` (bytes `i*k..(i+1)*k`) → codeword `i` via `reed_solomon::Encoder::new(e)`.
  Interleave: coded byte `j*C + i` = byte `j` of codeword `i`. So a burst of `B` consecutive
  coded bytes costs each codeword at most `ceil(B/C)` bytes.
- Decode: de-interleave, `reed_solomon::Decoder::new(e).correct(cw, None)` per codeword.
  Returns `FecResult { payload: Option<Vec<u8>>, corrected_bytes: usize, bit_errors: usize }`;
  `payload` is `None` if any codeword fails. `bit_errors` = Hamming distance between the received
  coded bytes and the re-encoded corrected codewords (only meaningful when decode succeeds) —
  this is the pre-FEC bit-error count channel-sim reports.

## Preamble and sync (sync.rs)

Every frame starts with a **linear up-chirp**: 960 samples (20 ms), 600 Hz → 6000 Hz,
amplitude 0.5, raised-cosine taper of 48 samples at each end. Then a 48-sample gap of silence.

Receiver (streaming): keep a sample buffer. Search for the chirp with a **normalized
cross-correlation** `ncc(t) = <x[t..t+L], c> / (||x[t..t+L]|| * ||c||)`; compute via FFT
(overlap-save, rustfft) rather than a direct 960-tap loop. A detection is the first `t` with
`ncc >= 0.6` that is also the local maximum within ±48 samples. On detection, wait until the
buffer holds the full frame plus `FRAME_SLACK` = 288 samples (so a frame Discord stretched still
has its last symbol), demodulate it, then resume the search at `t + frame_len - 2*FRAME_SLACK`,
one symbol early, so a frame Discord shortened does not lose the next chirp. Samples older than the search point are
dropped so memory stays bounded. `ncc` is gain-invariant, so Discord's level changes do not
matter.

## PHY A: OFDM-DQPSK (ofdm.rs) — the high-rate candidate

`OfdmParams { fft_len: 480, cp_len: 96, first_bin: 3, n_carriers: 34, bits_per_carrier: 2 }`.
- Subcarrier spacing 48000/480 = 100 Hz; carriers on bins `first_bin..first_bin+n_carriers`
  (300 Hz – 3.7 kHz by default). The band is narrow on purpose: Opus spends few bits on
  noise-like content above ~4 kHz, so live Discord audio garbled the upper carriers of the
  original 68-carrier (300 Hz – 7 kHz) layout. In `channel-sim bench` that layout fails every
  frame below ~56 kbps; 34 carriers with RS(104,64) lose none down to 40 kbps. Symbol = `cp_len + fft_len` = 576 samples (12 ms).
  Cyclic prefix absorbs Opus/MDCT smearing and small timing error.
- `bits_per_carrier` ∈ {1, 2}: DBPSK or DQPSK (Gray-coded: 00→0, 01→π/2, 11→π, 10→3π/2).
- After the chirp+gap: one **reference symbol** whose carrier phases are a fixed pseudo-random
  sequence (seed constant `0x4841524D` "HARM", a simple xorshift32 inside the crate — this is not
  crypto, just a known pattern), then `ceil(coded_bits / (n_carriers*bits_per_carrier))` data
  symbols. Each data symbol's carrier phase = previous symbol's phase on that carrier + the
  data phase step (differential in time, per carrier). Unused trailing bits are 0.
- Bit mapping: coded bits fill symbol 0 carriers 0..n-1, then symbol 1, … (frequency first).
- Time-domain: IFFT of the carrier vector (Hermitian-symmetric so output is real), prepend the
  last `cp_len` samples, scale so the frame's peak is 0.5.
- Demod: for each symbol skip the CP (start the FFT window `cp_len/2` samples into the CP to
  tolerate ±cp_len/2 timing error), FFT, take carrier bins, phase difference to the previous
  symbol's bins (`angle(Y_k[s] * conj(Y_k[s-1]))`), hard-decide to the nearest constellation
  point. Frame length is fixed by params, so no header is sent.
- Per-symbol timing tracking: the live receive path drops or repeats 120–240 samples mid-frame
  (seen mostly on Windows), more than the CP absorbs. Before each symbol's FFT the demodulator
  scores the normalized correlation of the CP against the symbol tail at every start within
  ±288 samples (half a symbol) of the expected one, and moves the window only if the best
  score beats the expected position's by 0.8 (Opus smears the CP, so clean symbols score
  0.2–0.9). The move carries forward to all later symbols of the frame. On the 31 Oct live
  captures this took Windows receive from 572 to 788 good frames out of ~890.
- Default frame: 20 ms chirp + 1 ms gap + 12 ms ref + 49 × 12 ms data ≈ 621 ms for 256 payload
  bytes ≈ 3.3 kbps net (Codec 2 1300 voice over WireGuard needs ~2.5 kbps).

## PHY B: MFSK (mfsk.rs) — the robust baseline

`MfskParams { symbol_len: 480, tones: 16, bands: 4, first_bin: 6 }`.
- One tone per band per symbol; tone spacing = 48000/symbol_len = 100 Hz; band `b` uses bins
  `first_bin + b*tones .. + tones` (600 Hz – 7 kHz by default). `log2(tones)` bits per band per
  symbol, bands filled in order, MSB first. Equal amplitude per band, phase-continuous per band,
  24-sample raised-cosine ramp at each symbol edge. Default: 16 bits / 10 ms = 1.6 kbps raw.
- After chirp+gap, data symbols only (noncoherent, no reference).
- Demod: per symbol, FFT of the central `symbol_len` samples (Hann window), pick the max-energy
  bin in each band.

## Public API (lib.rs) — names fixed

```rust
pub trait Phy: Send {
    fn name(&self) -> &'static str;
    /// Audio samples for one frame carrying exactly `coded.len()` bytes (always FecParams::coded_len()).
    fn modulate(&self, coded: &[u8], out: &mut Vec<f32>);
    /// Demodulate one frame whose chirp starts at `frame[0]`; returns hard-decided coded bytes.
    fn demodulate(&self, frame: &[f32], coded_len: usize) -> Vec<u8>;
    /// Total samples in one frame (chirp + gap + symbols) for `coded_len` bytes.
    fn frame_len(&self, coded_len: usize) -> usize;
}

pub struct ModemConfig { pub phy: PhyKind, pub fec: FecParams }      // PhyKind::Ofdm(OfdmParams) | Mfsk(MfskParams)

pub struct Transmitter;   // new(cfg); send(packet: &[u8]); next_frame() -> Vec<f32>
                          // (always returns a frame: idle frames carry only padding, keeping
                          //  Discord's VAD open and the receiver in sync); pending_bytes()
pub struct Receiver;      // new(cfg); push(samples: &[f32]) -> Vec<Vec<u8>> (complete packets);
                          // stats() -> RxStats
pub struct RxStats { pub frames_ok: u64, pub frames_failed: u64, pub corrected_bytes: u64,
                     pub bit_errors: u64, pub coded_bits: u64, pub packets: u64 }
impl RxStats { pub fn pre_fec_ber(&self) -> f64 }   // bit_errors / coded_bits over ok frames
pub fn net_bitrate(cfg: &ModemConfig) -> f64;      // payload_len*8 / frame seconds
```

Idle detection on receive is free: an idle frame decodes to all-zero payload, which the COBS
framer reads as empty delimiters.

## Not here

No crypto (WireGuard is the only integrity check that matters; RS only corrects). No sample
clock recovery beyond per-frame chirp resync and the per-symbol slip tracking above: a 621 ms
frame at ±100 ppm drifts < 3 samples, well inside `cp_len/2`.
