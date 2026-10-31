//! Voice packet framing and bit packing.

use thiserror::Error;

use crate::codec::VoiceMode;

/// A packet of Codec 2 voice frames, ready for the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoicePacket {
    pub mode: VoiceMode,
    pub seq: u16,
    pub frames: usize,
    /// Tightly bit-packed codec bits, MSB-first: `ceil(frames * bits_per_frame / 8)` bytes.
    pub bits: Vec<u8>,
}

/// Errors produced while parsing a [`VoicePacket`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VoiceError {
    #[error("unknown voice mode id {0}")]
    UnknownMode(u8),
    #[error("packet must contain at least one frame")]
    NoFrames,
    #[error("packet length mismatch: expected {expected} bytes, got {got}")]
    LengthMismatch { expected: usize, got: usize },
}

impl VoicePacket {
    /// Serialise to the wire format:
    /// `[mode id][seq u16 big-endian][n_frames][tightly packed bits]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.bits.len());
        out.push(self.mode.id());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.frames as u8);
        out.extend_from_slice(&self.bits);
        out
    }

    /// Parse from the wire format, rejecting unknown modes, bad lengths and
    /// empty packets.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VoiceError> {
        if bytes.len() < 4 {
            return Err(VoiceError::LengthMismatch {
                expected: 4,
                got: bytes.len(),
            });
        }
        let mode = VoiceMode::from_id(bytes[0]).ok_or(VoiceError::UnknownMode(bytes[0]))?;
        let seq = u16::from_be_bytes([bytes[1], bytes[2]]);
        let frames = usize::from(bytes[3]);
        if frames == 0 {
            return Err(VoiceError::NoFrames);
        }
        let n_bits = frames * mode.bits_per_frame();
        let n_bytes = n_bits.div_ceil(8);
        let expected = 4 + n_bytes;
        if bytes.len() != expected {
            return Err(VoiceError::LengthMismatch {
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self {
            mode,
            seq,
            frames,
            bits: bytes[4..].to_vec(),
        })
    }
}

/// Append the `n_bits` most-significant bits of `frame` (left-aligned,
/// MSB-first, in `ceil(n_bits / 8)` bytes) to `bits`, which is a tight
/// MSB-first bitstream of `bit_len` bits.
pub(crate) fn push_frame_bits(
    bits: &mut Vec<u8>,
    bit_len: &mut usize,
    frame: &[u8],
    n_bits: usize,
) {
    for i in 0..n_bits {
        let bit = (frame[i >> 3] >> (7 - (i & 7))) & 1;
        let pos = *bit_len;
        let byte = pos >> 3;
        if byte == bits.len() {
            bits.push(0);
        }
        bits[byte] |= bit << (7 - (pos & 7));
        *bit_len += 1;
    }
}

/// Extract `n_bits` MSB-first bits starting at `bit_offset` of `bits` into
/// `frame`, left-aligned (MSB-first) with any trailing bits zeroed.
pub(crate) fn read_frame_bits(frame: &mut [u8], bits: &[u8], bit_offset: usize, n_bits: usize) {
    frame.fill(0);
    for i in 0..n_bits {
        let pos = bit_offset + i;
        let bit = (bits[pos >> 3] >> (7 - (pos & 7))) & 1;
        frame[i >> 3] |= bit << (7 - (i & 7));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_bits_len(mode: VoiceMode, frames: usize) -> usize {
        (frames * mode.bits_per_frame()).div_ceil(8)
    }

    #[test]
    fn round_trip_all_modes_and_frame_counts() {
        for mode in VoiceMode::ALL {
            for frames in 1..=10usize {
                let n_bytes = packet_bits_len(mode, frames);
                let bits: Vec<u8> = (0..n_bytes).map(|i| (i * 37 + frames * 11) as u8).collect();
                let packet = VoicePacket {
                    mode,
                    seq: frames as u16 * 0x1234,
                    frames,
                    bits: bits.clone(),
                };
                let parsed = VoicePacket::from_bytes(&packet.to_bytes()).unwrap();
                assert_eq!(parsed, packet);
            }
        }
    }

    #[test]
    fn bit_packing_known_patterns() {
        // 52 significant bits, all ones -> six full 0xFF bytes plus 0xF0.
        let all_ones = [0xFFu8; 7];
        let mut bits = Vec::new();
        let mut bit_len = 0;
        push_frame_bits(&mut bits, &mut bit_len, &all_ones, 52);
        assert_eq!(bit_len, 52);
        assert_eq!(bits, vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]);

        // Alternating 1010... -> 0xAA bytes, then 0xA0.
        let mut alternating = [0u8; 7];
        for i in 0..52 {
            if i % 2 == 0 {
                alternating[i >> 3] |= 1 << (7 - (i & 7));
            }
        }
        let mut bits = Vec::new();
        let mut bit_len = 0;
        push_frame_bits(&mut bits, &mut bit_len, &alternating, 52);
        assert_eq!(bits, vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA0]);

        // And the reverse direction recovers the left-aligned pattern.
        let mut back = [0u8; 7];
        read_frame_bits(&mut back, &bits, 0, 52);
        assert_eq!(back, alternating);
    }

    #[test]
    fn from_bytes_rejects_bad_input() {
        assert_eq!(
            VoicePacket::from_bytes(&[6, 0, 0, 1]),
            Err(VoiceError::UnknownMode(6))
        );

        // M1300, one frame: 52 bits -> 7 bytes + 4 header = 11 bytes.
        let good = [4u8, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            VoicePacket::from_bytes(&good[..10]),
            Err(VoiceError::LengthMismatch { .. })
        ));
        let mut oversized = good.to_vec();
        oversized.push(0);
        assert!(matches!(
            VoicePacket::from_bytes(&oversized),
            Err(VoiceError::LengthMismatch { .. })
        ));

        assert_eq!(
            VoicePacket::from_bytes(&[4, 0, 0, 0]),
            Err(VoiceError::NoFrames)
        );
    }
}
