//! Write modem audio carrying random packets to a 48 kHz WAV, to listen to or to feed through
//! `channel-sim wav`: `cargo run --release --example encode_wav -- out.wav 10`.

use harmonium_modem::{ModemConfig, Transmitter};
use rand::{RngCore, SeedableRng};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: encode_wav <out.wav> [seconds]");
    let seconds: f32 = args.next().map_or(Ok(10.0), |s| s.parse())?;
    let mut tx = Transmitter::new(ModemConfig::default());
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 48_000,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let mut wav = hound::WavWriter::create(&path, spec)?;
    let mut written = 0usize;
    while (written as f32) < seconds * 48_000.0 {
        let mut packet = [0u8; 120];
        rng.fill_bytes(&mut packet);
        tx.send(&packet);
        for s in tx.next_frame() {
            wav.write_sample(s)?;
            written += 1;
        }
    }
    wav.finalize()?;
    Ok(())
}
