//! Decode a recorded modem WAV (e.g. `harmonium call --record-rx`) with the default modem
//! and print the receiver statistics: `cargo run --release --example decode_wav -- rx.wav`.

use harmonium_modem::{ModemConfig, Receiver};

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("usage: decode_wav <file.wav>");
    let mut reader = hound::WavReader::open(&path)?;
    let samples: Vec<f32> = match reader.spec().sample_format {
        hound::SampleFormat::Float => reader.samples::<f32>().collect::<Result<_, _>>()?,
        hound::SampleFormat::Int => reader
            .samples::<i16>()
            .map(|s| s.map(|v| v as f32 / 32768.0))
            .collect::<Result<_, _>>()?,
    };
    let mut rx = Receiver::new(ModemConfig::default());
    let mut packets = 0usize;
    for chunk in samples.chunks(960) {
        packets += rx.push(chunk).len();
    }
    let s = rx.stats();
    println!(
        "{path}: frames_ok={} frames_failed={} packets={packets} pre_fec_ber={:.4}",
        s.frames_ok,
        s.frames_failed,
        s.pre_fec_ber()
    );
    Ok(())
}
