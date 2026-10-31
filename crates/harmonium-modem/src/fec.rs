//! Interleaved Reed-Solomon forward error correction.

use reed_solomon::{Decoder, Encoder};

/// Reed-Solomon forward error correction parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecParams {
    /// Data bytes per codeword (`k`).
    pub data_len: usize,
    /// Error-correction bytes per codeword (`e`); up to `e/2` byte errors are corrected.
    pub ecc_len: usize,
    /// Number of interleaved codewords per frame (`C`).
    pub codewords: usize,
}

impl Default for FecParams {
    fn default() -> Self {
        Self {
            data_len: 64,
            ecc_len: 40,
            codewords: 4,
        }
    }
}

impl FecParams {
    /// Payload bytes carried by one coded frame (`C*k`).
    pub fn payload_len(&self) -> usize {
        self.data_len * self.codewords
    }

    /// Coded bytes in one frame (`C*(k+e)`).
    pub fn coded_len(&self) -> usize {
        (self.data_len + self.ecc_len) * self.codewords
    }

    /// Encode one payload chunk (exactly [`Self::payload_len`] bytes) into an interleaved
    /// coded frame.
    pub fn encode(&self, payload: &[u8]) -> Vec<u8> {
        debug_assert_eq!(payload.len(), self.payload_len());
        let k = self.data_len;
        let e = self.ecc_len;
        let c = self.codewords;
        let enc = Encoder::new(e);
        let mut out = vec![0u8; self.coded_len()];
        for i in 0..c {
            let buf = enc.encode(&payload[i * k..(i + 1) * k]);
            let data = buf.data();
            let ecc = buf.ecc();
            for j in 0..k {
                out[j * c + i] = data[j];
            }
            for j in 0..e {
                out[(k + j) * c + i] = ecc[j];
            }
        }
        out
    }

    /// Decode one interleaved coded frame (exactly [`Self::coded_len`] bytes).
    pub fn decode(&self, coded: &[u8]) -> FecResult {
        debug_assert_eq!(coded.len(), self.coded_len());
        let k = self.data_len;
        let e = self.ecc_len;
        let c = self.codewords;
        let n = k + e;
        let dec = Decoder::new(e);

        let mut payload = Vec::with_capacity(self.payload_len());
        let mut corrected_bytes = 0usize;

        for i in 0..c {
            let mut cw = vec![0u8; n];
            for j in 0..n {
                cw[j] = coded[j * c + i];
            }
            match dec.correct(&cw, None) {
                Ok(buf) => {
                    let data = buf.data();
                    let ecc = buf.ecc();
                    for j in 0..k {
                        if data[j] != cw[j] {
                            corrected_bytes += 1;
                        }
                    }
                    for j in 0..e {
                        if ecc[j] != cw[k + j] {
                            corrected_bytes += 1;
                        }
                    }
                    payload.extend_from_slice(data);
                }
                Err(_) => {
                    return FecResult {
                        payload: None,
                        corrected_bytes: 0,
                        bit_errors: 0,
                    };
                }
            }
        }

        let canonical = self.encode(&payload);
        let bit_errors = canonical
            .iter()
            .zip(coded.iter())
            .map(|(&a, &b)| (a ^ b).count_ones() as usize)
            .sum();

        FecResult {
            payload: Some(payload),
            corrected_bytes,
            bit_errors,
        }
    }
}

/// Result of decoding one coded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecResult {
    /// The corrected payload, or `None` if any codeword was unrecoverable.
    pub payload: Option<Vec<u8>>,
    /// Bytes whose value the decoder corrected.
    pub corrected_bytes: usize,
    /// Hamming distance between the received coded bytes and the re-encoded corrected codewords.
    pub bit_errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn random_payload(seed: u64, fec: &FecParams) -> Vec<u8> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut payload = vec![0u8; fec.payload_len()];
        rng.fill(&mut payload[..]);
        payload
    }

    fn distinct_positions(rng: &mut ChaCha8Rng, count: usize, limit: usize) -> Vec<usize> {
        let mut v = Vec::new();
        while v.len() < count {
            let x = rng.random_range(0..limit);
            if !v.contains(&x) {
                v.push(x);
            }
        }
        v
    }

    #[test]
    fn round_trip() {
        let fec = FecParams::default();
        let payload = random_payload(1, &fec);
        let coded = fec.encode(&payload);
        let res = fec.decode(&coded);
        assert_eq!(res.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(res.corrected_bytes, 0);
        assert_eq!(res.bit_errors, 0);
    }

    #[test]
    fn corrects_half_ecc_per_codeword() {
        let fec = FecParams::default();
        let payload = random_payload(2, &fec);
        let mut coded = fec.encode(&payload);
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let k = fec.data_len;
        let e = fec.ecc_len;
        let c = fec.codewords;
        let n = k + e;

        let mut flipped = 0usize;
        for i in 0..c {
            for j in distinct_positions(&mut rng, e / 2, n) {
                let idx = j * c + i;
                let flip = rng.random_range(1u8..=255);
                coded[idx] ^= flip;
                flipped += flip.count_ones() as usize;
            }
        }

        let res = fec.decode(&coded);
        assert_eq!(res.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(res.corrected_bytes, (e / 2) * c);
        assert_eq!(res.bit_errors, flipped);
    }

    #[test]
    fn corrects_burst_of_half_ecc_times_codewords() {
        let fec = FecParams::default();
        let payload = random_payload(4, &fec);
        let mut coded = fec.encode(&payload);
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let burst = fec.ecc_len / 2 * fec.codewords;
        let start = rng.random_range(0..=coded.len() - burst);

        let mut flipped = 0usize;
        for b in coded.iter_mut().skip(start).take(burst) {
            let flip = rng.random_range(1u8..=255);
            *b ^= flip;
            flipped += flip.count_ones() as usize;
        }

        let res = fec.decode(&coded);
        assert_eq!(res.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(res.bit_errors, flipped);
    }

    #[test]
    fn too_many_errors_in_one_codeword_fails() {
        let fec = FecParams::default();
        let payload = random_payload(6, &fec);
        let mut coded = fec.encode(&payload);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let n = fec.data_len + fec.ecc_len;
        for j in distinct_positions(&mut rng, fec.ecc_len / 2 + 1, n) {
            let idx = j * fec.codewords; // codeword 0
            coded[idx] ^= 0xFF;
        }
        let res = fec.decode(&coded);
        assert_eq!(res.payload, None);
    }
}
