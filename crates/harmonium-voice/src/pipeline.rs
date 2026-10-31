//! Encoder and decoder pipelines between 48 kHz PCM and [`VoicePacket`]s.

use std::collections::VecDeque;

use crate::codec::{VoiceCodec, VoiceMode};
use crate::packet::{VoicePacket, push_frame_bits, read_frame_bits};
use crate::resample::{Downsampler48k, Upsampler8k};

/// Most silence one packet gap may insert: 1 s at 8 kHz, so a peer cannot grow the queue
/// without bound through sequence-number gaps.
pub const MAX_CONCEAL_SAMPLES: usize = 8000;

/// Most decoded audio the decoder holds: 2 s at 8 kHz. Beyond it the oldest samples are
/// dropped, so a peer sending faster than real time adds no memory and no extra delay.
pub const MAX_QUEUE_SAMPLES: usize = 16000;

/// Turns 48 kHz microphone audio into small [`VoicePacket`]s.
pub struct VoiceEncoder {
    codec: VoiceCodec,
    downsampler: Downsampler48k,
    frames_per_packet: usize,
    seq: u16,
    /// 8 kHz samples not yet grouped into whole codec frames.
    pending: Vec<i16>,
    /// Tightly packed bits of the packet currently being built.
    packet_bits: Vec<u8>,
    packet_bit_len: usize,
    packet_frames: usize,
    /// Scratch buffer for one codec frame's encoded bits.
    frame_bits: Vec<u8>,
    /// Scratch buffer for one codec frame's samples.
    frame_samples: Vec<i16>,
}

impl VoiceEncoder {
    #[must_use]
    pub fn new(mode: VoiceMode, packet_ms: u32) -> Self {
        let frame_ms = mode.frame_ms();
        assert!(
            packet_ms.is_multiple_of(frame_ms),
            "packet_ms must be a whole number of codec frames"
        );
        let frames_per_packet = (packet_ms / frame_ms) as usize;
        assert!(
            (1..=255).contains(&frames_per_packet),
            "packet_ms must cover 1..=255 frames (n_frames is one byte on the wire)"
        );

        let bits_per_frame = mode.bits_per_frame();
        let samples_per_frame = mode.samples_per_frame();
        Self {
            codec: VoiceCodec::new(mode),
            downsampler: Downsampler48k::new(),
            frames_per_packet,
            seq: 0,
            pending: Vec::new(),
            packet_bits: Vec::new(),
            packet_bit_len: 0,
            packet_frames: 0,
            frame_bits: vec![0u8; bits_per_frame.div_ceil(8)],
            frame_samples: vec![0i16; samples_per_frame],
        }
    }

    /// Resample and encode `pcm`, emitting a [`VoicePacket`] whenever a whole
    /// packet's worth of frames has accumulated. Any leftover samples wait
    /// for the next call.
    #[must_use]
    pub fn push_48k(&mut self, pcm: &[f32]) -> Vec<VoicePacket> {
        let mut packets = Vec::new();
        let mut pcm8 = Vec::new();
        self.downsampler.process(pcm, &mut pcm8);
        self.pending.extend_from_slice(&pcm8);

        let samples_per_frame = self.codec.mode().samples_per_frame();
        let bits_per_frame = self.codec.mode().bits_per_frame();
        while self.pending.len() >= samples_per_frame {
            self.frame_samples.clear();
            self.frame_samples
                .extend_from_slice(&self.pending[..samples_per_frame]);
            self.pending.drain(..samples_per_frame);

            self.codec.encode(&mut self.frame_bits, &self.frame_samples);
            push_frame_bits(
                &mut self.packet_bits,
                &mut self.packet_bit_len,
                &self.frame_bits,
                bits_per_frame,
            );
            self.packet_frames += 1;

            if self.packet_frames == self.frames_per_packet {
                packets.push(self.take_packet());
            }
        }
        packets
    }

    fn take_packet(&mut self) -> VoicePacket {
        let packet = VoicePacket {
            mode: self.codec.mode(),
            seq: self.seq,
            frames: self.frames_per_packet,
            bits: std::mem::take(&mut self.packet_bits),
        };
        self.seq = self.seq.wrapping_add(1);
        self.packet_bit_len = 0;
        self.packet_frames = 0;
        packet
    }
}

/// Reassembles [`VoicePacket`]s back into 48 kHz PCM.
pub struct VoiceDecoder {
    /// Decoded 8 kHz samples waiting to be upsampled.
    queue: VecDeque<i16>,
    /// Upsampled 48 kHz samples waiting to be pulled.
    buffer: VecDeque<f32>,
    upsampler: Upsampler8k,
    codec: Option<VoiceCodec>,
    mode: Option<VoiceMode>,
    last_seq: Option<u16>,
    underruns: usize,
}

impl VoiceDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            buffer: VecDeque::new(),
            upsampler: Upsampler8k::new(),
            codec: None,
            mode: None,
            last_seq: None,
            underruns: 0,
        }
    }

    /// Decode a packet into the internal 8 kHz queue.
    ///
    /// A forward sequence-number gap of fewer than 100 inserts one packet's
    /// worth of silence per missing packet (using the arriving packet's
    /// duration, capped at `MAX_CONCEAL_SAMPLES`); duplicate and old
    /// sequence numbers are ignored. The codec is recreated when the packet's
    /// mode changes. The queue keeps at most `MAX_QUEUE_SAMPLES`, newest kept.
    pub fn push_packet(&mut self, packet: &VoicePacket) {
        if let Some(last) = self.last_seq {
            let gap = packet.seq.wrapping_sub(last);
            if gap == 0 {
                return; // duplicate
            }
            if gap >= 100 {
                return; // old or too far behind
            }
            let missing = gap as usize - 1;
            let silence = packet.frames * packet.mode.samples_per_frame();
            let fill = (missing * silence).min(MAX_CONCEAL_SAMPLES);
            self.queue.extend(std::iter::repeat_n(0i16, fill));
        }

        if self.mode != Some(packet.mode) {
            self.codec = Some(VoiceCodec::new(packet.mode));
            self.mode = Some(packet.mode);
        }

        let codec = self.codec.as_mut().expect("codec set above");
        let samples_per_frame = packet.mode.samples_per_frame();
        let bits_per_frame = packet.mode.bits_per_frame();
        let mut frame_bits = vec![0u8; bits_per_frame.div_ceil(8)];
        let mut samples = vec![0i16; samples_per_frame];
        for frame in 0..packet.frames {
            read_frame_bits(
                &mut frame_bits,
                &packet.bits,
                frame * bits_per_frame,
                bits_per_frame,
            );
            codec.decode(&mut samples, &frame_bits);
            self.queue.extend(samples.iter().copied());
        }
        if let Some(excess) = self.queue.len().checked_sub(MAX_QUEUE_SAMPLES) {
            self.queue.drain(..excess);
        }

        self.last_seq = Some(packet.seq);
    }

    /// Return exactly `n` 48 kHz samples, padding with silence (and counting
    /// underrun samples) when the queue runs dry.
    #[must_use]
    pub fn pull_48k(&mut self, n: usize) -> Vec<f32> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if self.buffer.is_empty() {
                if self.queue.is_empty() {
                    let remaining = n - out.len();
                    out.extend(std::iter::repeat_n(0.0, remaining));
                    self.underruns += remaining;
                    break;
                }
                let take = self.queue.len().min(256);
                let chunk: Vec<i16> = self.queue.drain(..take).collect();
                let mut up = Vec::with_capacity(chunk.len() * 6);
                self.upsampler.process(&chunk, &mut up);
                self.buffer.extend(up);
            }
            if let Some(sample) = self.buffer.pop_front() {
                out.push(sample);
            }
        }
        out
    }

    /// Number of 48 kHz samples that were produced as silence because the
    /// queue ran dry.
    #[must_use]
    pub fn underruns(&self) -> usize {
        self.underruns
    }
}

impl Default for VoiceDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR48: usize = 48000;

    fn speech_like(seconds: f32) -> Vec<f32> {
        let n = (SR48 as f32 * seconds) as usize;
        (0..n)
            .map(|i| {
                let t = i as f32 / SR48 as f32;
                let envelope = 0.5 + 0.5 * (2.0 * core::f32::consts::PI * 4.0 * t).sin();
                // A 200 Hz fundamental with 700 Hz and 1500 Hz harmonics at a
                // speech-like rolloff.
                let s = (2.0 * core::f32::consts::PI * 200.0 * t).sin()
                    + 0.3 * (2.0 * core::f32::consts::PI * 700.0 * t).sin()
                    + 0.09 * (2.0 * core::f32::consts::PI * 1500.0 * t).sin();
                envelope * s * 0.2
            })
            .collect()
    }

    fn rms(samples: &[f32]) -> f32 {
        let sum: f32 = samples.iter().map(|s| s * s).sum();
        (sum / samples.len() as f32).sqrt()
    }

    #[test]
    fn full_round_trip_preserves_length_and_level() {
        let input = speech_like(2.0);
        let in_rms = rms(&input);

        let mut encoder = VoiceEncoder::new(VoiceMode::M1300, 320);
        let packets = encoder.push_48k(&input);
        assert_eq!(packets.len(), 6);

        let mut decoder = VoiceDecoder::new();
        for packet in &packets {
            let parsed = VoicePacket::from_bytes(&packet.to_bytes()).unwrap();
            decoder.push_packet(&parsed);
        }

        let out = decoder.pull_48k(SR48 * 2);
        assert_eq!(out.len(), SR48 * 2);

        let out_rms = rms(&out);
        assert!(
            out_rms > in_rms / 3.0 && out_rms < in_rms * 3.0,
            "in_rms {in_rms}, out_rms {out_rms}"
        );
    }

    #[test]
    fn m1300_320ms_packet_is_56_bytes() {
        let input = speech_like(1.0);
        let mut encoder = VoiceEncoder::new(VoiceMode::M1300, 320);
        let packets = encoder.push_48k(&input);
        assert!(!packets.is_empty());
        for packet in &packets {
            assert_eq!(packet.frames, 8);
            assert_eq!(packet.bits.len(), 52);
            assert_eq!(packet.to_bytes().len(), 56);
        }
    }

    #[test]
    fn dropped_packet_inserts_silence_and_keeps_place() {
        let input = speech_like(2.0);
        let mut encoder = VoiceEncoder::new(VoiceMode::M1300, 320);
        let packets = encoder.push_48k(&input);
        assert!(packets.len() >= 6);

        let mut decoder = VoiceDecoder::new();
        for (i, packet) in packets.iter().enumerate() {
            if i == 2 {
                continue; // drop seq 2
            }
            decoder.push_packet(packet);
        }

        // 6 packet slots of 320 ms each.
        let out = decoder.pull_48k(6 * 320 * 48);
        assert_eq!(out.len(), 6 * 320 * 48);

        // The dropped packet's slot (640..960 ms) is silent, away from the
        // filter settling tails at its edges.
        let silent = &out[700 * 48..900 * 48];
        assert!(
            silent.iter().all(|&s| s == 0.0),
            "gap is not silent (first nonzero at {:?})",
            silent.iter().position(|&s| s != 0.0)
        );

        // The last packet still occupies the final slot (1600..1920 ms).
        let last_rms = rms(&out[1600 * 48..1920 * 48]);
        assert!(last_rms > 0.01, "last packet missing, rms {last_rms}");
    }

    #[test]
    fn queue_is_bounded_when_audio_arrives_faster_than_it_is_pulled() {
        let mut encoder = VoiceEncoder::new(VoiceMode::M1300, 320);
        let packets = encoder.push_48k(&speech_like(10.0));
        let mut decoder = VoiceDecoder::new();
        for packet in &packets {
            decoder.push_packet(packet);
        }
        assert_eq!(decoder.queue.len(), MAX_QUEUE_SAMPLES);
    }

    #[test]
    fn duplicate_packets_are_ignored() {
        let input = speech_like(1.0);
        let mut encoder = VoiceEncoder::new(VoiceMode::M1300, 320);
        let packets = encoder.push_48k(&input);
        assert!(packets.len() >= 2);

        let mut decoder = VoiceDecoder::new();
        decoder.push_packet(&packets[0]);
        decoder.push_packet(&packets[0]); // duplicate
        decoder.push_packet(&packets[1]);

        // Only two packets of audio should exist.
        let out = decoder.pull_48k(2 * 320 * 48);
        assert_eq!(out.len(), 2 * 320 * 48);

        let more = decoder.pull_48k(1);
        assert_eq!(more, vec![0.0]);
        assert_eq!(decoder.underruns(), 1);
    }

    #[test]
    fn mode_change_between_packets_is_allowed() {
        let input = speech_like(1.0);
        let mut fast = VoiceEncoder::new(VoiceMode::M3200, 320);
        let mut slow = VoiceEncoder::new(VoiceMode::M1300, 320);
        let p1 = fast.push_48k(&input);
        let p2 = slow.push_48k(&input);
        assert!(!p1.is_empty() && !p2.is_empty());

        let mut decoder = VoiceDecoder::new();
        decoder.push_packet(&p1[0]);
        decoder.push_packet(&p2[0]);

        let out = decoder.pull_48k(320 * 48 * 2);
        assert_eq!(out.len(), 320 * 48 * 2);
    }
}
