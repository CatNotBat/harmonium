//! End-to-end transmitter → receiver loopback tests for both PHYs.

use harmonium_modem::{
    MfskParams, ModemConfig, OfdmParams, PhyKind, Receiver, RxStats, Transmitter,
};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

fn config(kind: PhyKind) -> ModemConfig {
    ModemConfig {
        phy: kind,
        fec: harmonium_modem::FecParams::default(),
    }
}

fn random_packets(seed: u64, n: usize) -> Vec<Vec<u8>> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut packets = Vec::with_capacity(n);
    for _ in 0..n {
        let len = rng.random_range(32..=148usize);
        let mut p = vec![0u8; len];
        rng.fill(&mut p[..]);
        packets.push(p);
    }
    packets
}

/// Build the audio for `packets`, returning the individual frames (data + 2 idle) and the
/// concatenated audio.
fn build_audio(kind: PhyKind, packets: &[Vec<u8>]) -> (Vec<Vec<f32>>, Vec<f32>) {
    let mut tx = Transmitter::new(config(kind));
    for p in packets {
        tx.send(p);
    }
    let mut frames = Vec::new();
    while tx.pending_bytes() > 0 {
        frames.push(tx.next_frame());
    }
    frames.push(tx.next_frame()); // idle
    frames.push(tx.next_frame()); // idle
    let audio: Vec<f32> = frames.iter().flatten().copied().collect();
    (frames, audio)
}

fn run_receiver(cfg: &ModemConfig, audio: &[f32]) -> (Vec<Vec<u8>>, RxStats) {
    let mut rx = Receiver::new(cfg.clone());
    let mut got = Vec::new();
    for chunk in audio.chunks(997) {
        got.extend(rx.push(chunk));
    }
    (got, rx.stats())
}

fn is_subsequence<T: PartialEq>(sub: &[T], full: &[T]) -> bool {
    let mut j = 0;
    for x in sub {
        let mut found = false;
        while j < full.len() {
            if &full[j] == x {
                j += 1;
                found = true;
                break;
            }
            j += 1;
        }
        if !found {
            return false;
        }
    }
    true
}

fn phy_cases() -> Vec<PhyKind> {
    vec![
        PhyKind::Ofdm(OfdmParams::default()),
        PhyKind::Mfsk(MfskParams::default()),
    ]
}

#[test]
fn loopback_clean() {
    for kind in phy_cases() {
        let packets = random_packets(30, 200);
        let (_, audio) = build_audio(kind, &packets);
        let (got, stats) = run_receiver(&config(kind), &audio);
        assert_eq!(got, packets, "{kind:?}");
        assert_eq!(stats.frames_failed, 0, "{kind:?}");
    }
}

#[test]
fn loopback_with_zeroed_opus_frame() {
    for kind in phy_cases() {
        let packets = random_packets(31, 200);
        let (frames, audio) = build_audio(kind, &packets);

        let data_frames = frames.len() - 2;
        let fz = data_frames / 2; // a frame safely in the middle of the data

        // Map each packet to its byte range in the COBS stream.
        let fec = harmonium_modem::FecParams::default();
        let payload_len = fec.payload_len();
        let mut offsets = Vec::with_capacity(packets.len());
        let mut stream_len = 0usize;
        for p in &packets {
            offsets.push(stream_len);
            stream_len += harmonium_modem::framer::cobs_encode(p).len();
        }
        let frame_byte_start = fz * payload_len;
        let frame_byte_end = frame_byte_start + payload_len;
        let expected_lost: Vec<usize> = (0..packets.len())
            .filter(|&i| {
                let s = offsets[i];
                let e = s + harmonium_modem::framer::cobs_encode(&packets[i]).len();
                s < frame_byte_end && e > frame_byte_start
            })
            .collect();

        // Zero one Opus frame (960 samples) in the middle of frame `fz`.
        let mut zeroed = Vec::with_capacity(audio.len());
        for (i, f) in frames.iter().enumerate() {
            if i == fz {
                let mut g = f.clone();
                let mid = g.len() / 2;
                for s in &mut g[mid..mid + 960] {
                    *s = 0.0;
                }
                zeroed.extend_from_slice(&g);
            } else {
                zeroed.extend_from_slice(f);
            }
        }

        let (got, _stats) = run_receiver(&config(kind), &zeroed);

        let survivors: Vec<Vec<u8>> = (0..packets.len())
            .filter(|i| !expected_lost.contains(i))
            .map(|i| packets[i].clone())
            .collect();
        assert!(
            is_subsequence(&survivors, &got),
            "{kind:?}: packets touching frame {fz} were the only losses"
        );
    }
}
