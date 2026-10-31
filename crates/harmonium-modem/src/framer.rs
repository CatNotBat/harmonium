//! COBS packet framing: packets become a self-delimiting byte stream cut into
//! fixed-size payload chunks, and back.

/// Append the COBS encoding of `data` (including its terminating `0x00` delimiter) to `out`.
pub fn cobs_encode_into(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i <= data.len() {
        let mut j = i;
        while j < data.len() && data[j] != 0 && j - i < 254 {
            j += 1;
        }
        let run = j - i;
        if run == 254 {
            out.push(255);
            out.extend_from_slice(&data[i..i + 254]);
            i += 254;
        } else if j < data.len() {
            out.push((run + 1) as u8);
            out.extend_from_slice(&data[i..j]);
            i = j + 1;
        } else {
            out.push((run + 1) as u8);
            out.extend_from_slice(&data[i..j]);
            break;
        }
    }
    out.push(0);
}

/// COBS-encode `data`, including the terminating `0x00` delimiter.
pub fn cobs_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 2);
    cobs_encode_into(data, &mut out);
    out
}

/// COBS-decode one delimited frame (the bytes between two `0x00` delimiters).
///
/// Returns `None` if the frame is malformed (a code byte runs past the end).
pub fn cobs_decode(frame: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(frame.len());
    let mut i = 0;
    while i < frame.len() {
        let code = frame[i] as usize;
        i += 1;
        if code == 0 {
            return None;
        }
        let n = code - 1;
        if i + n > frame.len() {
            return None;
        }
        out.extend_from_slice(&frame[i..i + n]);
        i += n;
        if code < 255 && i < frame.len() {
            out.push(0);
        }
    }
    Some(out)
}

/// Bytes of CRC appended to every packet before COBS encoding.
pub const CRC_LEN: usize = 2;

/// Longest COBS frame a legal packet (1..=1500 bytes plus CRC) encodes to. The deframer drops
/// anything longer that has no delimiter, so noise cannot grow its buffer without bound.
const MAX_ENCODED: usize = 1500 + CRC_LEN + (1500 + CRC_LEN) / 254 + 1;

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). An integrity check, not crypto: WireGuard
/// authenticates everything above it.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Splits a COBS byte stream into fixed-size payload chunks.
pub struct Framer {
    payload_len: usize,
    buf: Vec<u8>,
}

impl Framer {
    /// Create a framer that emits `payload_len`-byte chunks.
    pub fn new(payload_len: usize) -> Self {
        Self {
            payload_len,
            buf: Vec::new(),
        }
    }

    /// Append `packet` plus its CRC-16, COBS-encoded with its delimiter, to the pending stream.
    pub fn push(&mut self, packet: &[u8]) {
        let mut checked = Vec::with_capacity(packet.len() + CRC_LEN);
        checked.extend_from_slice(packet);
        checked.extend_from_slice(&crc16(packet).to_be_bytes());
        cobs_encode_into(&checked, &mut self.buf);
    }

    /// Bytes still waiting to be emitted.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Take the next payload chunk (exactly `payload_len` bytes, zero-padded at the end).
    pub fn next_chunk(&mut self) -> Vec<u8> {
        let n = self.payload_len.min(self.buf.len());
        let mut chunk: Vec<u8> = self.buf.drain(..n).collect();
        chunk.resize(self.payload_len, 0);
        chunk
    }
}

/// Reassembles a COBS byte stream from payload chunks and yields packets.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    malformed: u64,
}

impl Deframer {
    /// Create an empty deframer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one payload chunk; returns the complete packets decoded from it.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut packets = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == 0) {
            let frame = self.buf[..pos].to_vec();
            self.buf.drain(..=pos);
            if frame.is_empty() {
                continue; // empty delimiter: padding or idle frame
            }
            // The CRC rejects both RS miscorrections and the tail of a packet whose head was in
            // a lost frame (which would otherwise COBS-decode as a shorter, wrong packet).
            match cobs_decode(&frame) {
                Some(mut p) if p.len() > CRC_LEN => {
                    let body = p.len() - CRC_LEN;
                    if p[body..] == crc16(&p[..body]).to_be_bytes() {
                        p.truncate(body);
                        packets.push(p);
                    } else {
                        self.malformed += 1;
                    }
                }
                _ => self.malformed += 1,
            }
        }
        if self.buf.len() > MAX_ENCODED {
            self.buf.clear();
            self.malformed += 1;
        }
        packets
    }

    /// Discard the partial packet currently in progress (used when a frame is lost).
    pub fn lost(&mut self) {
        self.buf.clear();
    }

    /// Number of malformed or empty packets dropped.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn cobs_round_trip() {
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        for n in [1usize, 2, 253, 254, 255, 1500] {
            let mut p = vec![0u8; n];
            rng.fill(&mut p[..]);
            let enc = cobs_encode(&p);
            let dec = cobs_decode(&enc[..enc.len() - 1]).unwrap();
            assert_eq!(dec, p, "size {n}");
        }
        // A packet full of zeros stresses the empty-run code path.
        let p = vec![0u8; 1500];
        let enc = cobs_encode(&p);
        let dec = cobs_decode(&enc[..enc.len() - 1]).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn framer_deframer_round_trip() {
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let mut packets = Vec::new();
        for n in [1usize, 2, 253, 254, 255, 1500] {
            let mut p = vec![0u8; n];
            rng.fill(&mut p[..]);
            packets.push(p);
        }
        packets.push(vec![0u8; 1500]);

        let mut framer = Framer::new(256);
        for p in &packets {
            framer.push(p);
        }
        let mut deframer = Deframer::new();
        let mut got = Vec::new();
        while framer.pending() > 0 {
            let chunk = framer.next_chunk();
            got.extend(deframer.push(&chunk));
        }
        got.extend(deframer.push(&framer.next_chunk())); // idle flush
        assert_eq!(got, packets);
    }

    #[test]
    fn lost_drops_partial_packet_only() {
        let a = vec![1u8, 2, 3, 4, 5];
        let b = vec![6u8, 7, 8];
        let c = vec![9u8, 10];
        let mut framer = Framer::new(64);
        framer.push(&a);
        let split = framer.pending() - 1;
        framer.push(&b);
        framer.push(&c);
        let stream = framer.next_chunk();

        // Feed everything of A except its trailing delimiter, then lose it.
        let mut deframer = Deframer::new();
        assert!(deframer.push(&stream[..split]).is_empty());
        deframer.lost();
        let out = deframer.push(&stream[split..]);
        assert_eq!(out, vec![b, c]);
    }

    #[test]
    fn tail_of_lost_packet_is_rejected_by_crc() {
        let a = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = vec![9u8, 10, 11];
        let mut framer = Framer::new(64);
        framer.push(&a);
        framer.push(&b);
        let stream = framer.next_chunk();

        // The frame holding A's head was lost; its tail arrives first and must not decode.
        let mut deframer = Deframer::new();
        let out = deframer.push(&stream[4..]);
        assert_eq!(out, vec![b]);
        assert_eq!(deframer.malformed(), 1);
    }

    #[test]
    fn delimiter_free_noise_does_not_grow_the_buffer() {
        let mut deframer = Deframer::new();
        for _ in 0..100 {
            assert!(deframer.push(&[0xAA; 200]).is_empty());
        }
        assert!(deframer.buf.len() <= MAX_ENCODED);
        assert!(deframer.malformed() > 0);
        // A real packet after the noise still decodes once a delimiter resyncs the stream.
        let mut framer = Framer::new(64);
        framer.push(b"hello");
        let mut got = deframer.push(&[0]);
        while framer.pending() > 0 {
            got.extend(deframer.push(&framer.next_chunk()));
        }
        assert_eq!(got, vec![b"hello".to_vec()]);
    }
}
