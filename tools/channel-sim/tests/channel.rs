//! Integration tests for the channel and the bake-off loop.

use std::f32::consts::PI;

use channel_sim::{BenchConfig, Channel, ChannelConfig, FRAME, LossModel, PhyChoice, run_bench};

fn rms(samples: &[f32]) -> f64 {
    let mean_sq = samples
        .iter()
        .map(|&s| (s as f64) * (s as f64))
        .sum::<f64>()
        / samples.len() as f64;
    mean_sq.sqrt()
}

/// A lossless channel passes a 1 kHz sine with output RMS within 3 dB of input,
/// once Opus's own startup delay is skipped.
#[test]
fn sine_survives_within_3db() {
    let mut ch = Channel::new(ChannelConfig::default()).unwrap();
    let amp = 0.3f32;
    let n = FRAME * 20;
    let input: Vec<f32> = (0..n)
        .map(|i| amp * (2.0 * PI * 1000.0 * i as f32 / 48_000.0).sin())
        .collect();
    let out = ch.process(&input);
    assert_eq!(out.len(), n);

    let in_rms = rms(&input[2 * FRAME..]);
    let out_rms = rms(&out[2 * FRAME..]);
    let db = 20.0 * (out_rms / in_rms).log10();
    assert!(
        (-3.0..3.0).contains(&db),
        "input RMS {in_rms} -> output RMS {out_rms} ({db} dB)"
    );
}

/// Independent loss at p = 0.5 lands within [0.45, 0.55] over 2000 packets.
#[test]
fn loss_rate_independent() {
    let mut ch = Channel::new(ChannelConfig {
        loss: 0.5,
        seed: 42,
        ..Default::default()
    })
    .unwrap();
    let zeros = vec![0.0f32; 2000 * FRAME];
    let _ = ch.process(&zeros);
    let s = ch.stats();
    let frac = s.lost as f64 / s.packets as f64;
    assert!(
        (0.45..=0.55).contains(&frac),
        "lost fraction {frac} (lost {}, packets {})",
        s.lost,
        s.packets
    );
}

/// Gilbert-Elliott at burst = 0.8 keeps the stationary rate near 0.5 and bursts
/// (mean lost-run length) above 2.
#[test]
fn loss_rate_gilbert_elliott_bursts() {
    let mut ch = Channel::new(ChannelConfig {
        loss: 0.5,
        burst: 0.8,
        seed: 7,
        ..Default::default()
    })
    .unwrap();
    let zeros = vec![0.0f32; 2000 * FRAME];
    let _ = ch.process(&zeros);
    let s = ch.stats();
    let frac = s.lost as f64 / s.packets as f64;
    assert!(
        (0.43..=0.57).contains(&frac),
        "lost fraction {frac} (lost {}, packets {})",
        s.lost,
        s.packets
    );

    // Drive the same generator directly to measure burst structure.
    let mut model = LossModel::new(0.5, 0.8, 7);
    let mut lost_total = 0usize;
    let mut runs = Vec::new();
    let mut cur = 0usize;
    for _ in 0..2000 {
        if model.decide() {
            lost_total += 1;
            cur += 1;
        } else if cur > 0 {
            runs.push(cur);
            cur = 0;
        }
    }
    if cur > 0 {
        runs.push(cur);
    }
    let model_frac = lost_total as f64 / 2000.0;
    assert!(
        (0.43..=0.57).contains(&model_frac),
        "model lost fraction {model_frac}"
    );
    let mean_burst = lost_total as f64 / runs.len() as f64;
    assert!(mean_burst > 2.0, "mean burst length {mean_burst}");
}

/// The same seed produces identical output (loss + noise path both deterministic).
#[test]
fn deterministic_output() {
    let cfg = ChannelConfig {
        loss: 0.1,
        burst: 0.3,
        noise_db: Some(20.0),
        seed: 99,
        ..Default::default()
    };
    let mut a = Channel::new(cfg.clone()).unwrap();
    let mut b = Channel::new(cfg).unwrap();
    let input: Vec<f32> = (0..FRAME * 30)
        .map(|i| 0.4 * (2.0 * PI * 440.0 * i as f32 / 48_000.0).sin())
        .collect();
    let out_a = a.process(&input);
    let out_b = b.process(&input);
    assert_eq!(out_a, out_b);
}

/// A short bake-off over a clean channel delivers packets with zero corruption.
///
/// If the modem fails to get even one packet through Opus, this is marked `#[ignore]`
/// so the bake-off numbers are reported rather than the test silently weakened.
#[test]
fn bench_short_ofdm_clean_delivers() {
    let cfg = BenchConfig {
        channel: ChannelConfig::default(),
        phy: PhyChoice::Ofdm,
        seconds: 5.0,
        packet_bytes: 88,
        pps: None,
        ecc_len: None,
        ofdm_layout: None,
    };
    let report = run_bench(&cfg).unwrap();
    println!(
        "short bench: sent {}, delivered {}, corrupt {}, frames ok/fail {}/{}",
        report.packets_sent,
        report.packets_delivered,
        report.packets_corrupt,
        report.frames_ok,
        report.frames_failed
    );
    assert!(
        report.packets_delivered >= 1,
        "expected at least one delivered packet"
    );
    assert_eq!(report.packets_corrupt, 0, "no post-FEC errors expected");
}
