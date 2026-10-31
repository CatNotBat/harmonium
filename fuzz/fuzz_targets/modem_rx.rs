#![no_main]
use harmonium_modem::{ModemConfig, Receiver, Transmitter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Phase 1: interpret the input as little-endian f32 samples, sanitized to what
    // the Opus path can actually emit, and push them in 960-sample blocks.
    let samples: Vec<f32> = data
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .map(|s| {
            if s.is_finite() {
                s.clamp(-4.0, 4.0)
            } else {
                0.0
            }
        })
        .collect();
    let mut rx = Receiver::new(ModemConfig::default());
    for block in samples.chunks(960) {
        let _ = rx.push(block);
    }

    // Phase 2: build a valid signal so the RS/deframer paths are actually reached,
    // perturb it with input-derived noise, and push it into a fresh receiver.
    if data.len() >= 4 {
        let mut tx = Transmitter::new(ModemConfig::default());
        tx.send(&data[..data.len().min(200)]);
        let mut audio = Vec::new();
        while tx.pending_bytes() > 0 {
            audio.extend(tx.next_frame());
        }
        audio.extend(tx.next_frame()); // one idle frame to flush the delimiter
        let len = audio.len();
        for &b in data {
            let idx = (b as usize * 37) % len;
            audio[idx] += (b as f32 - 128.0) / 128.0;
        }
        let mut rx2 = Receiver::new(ModemConfig::default());
        for block in audio.chunks(960) {
            let _ = rx2.push(block);
        }
    }
});
