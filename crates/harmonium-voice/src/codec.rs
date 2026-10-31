//! Codec 2 wrapper: voice modes and a paired encoder/decoder.

use std::sync::LazyLock;

use codec2::{Codec2, Codec2Mode};

/// A Codec 2 bit-rate mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceMode {
    M3200,
    M2400,
    M1600,
    M1400,
    M1300,
    M1200,
}

impl VoiceMode {
    /// Every supported mode, in wire-id order.
    pub const ALL: [VoiceMode; 6] = [
        VoiceMode::M3200,
        VoiceMode::M2400,
        VoiceMode::M1600,
        VoiceMode::M1400,
        VoiceMode::M1300,
        VoiceMode::M1200,
    ];

    fn codec2_mode(self) -> Codec2Mode {
        match self {
            VoiceMode::M3200 => Codec2Mode::MODE_3200,
            VoiceMode::M2400 => Codec2Mode::MODE_2400,
            VoiceMode::M1600 => Codec2Mode::MODE_1600,
            VoiceMode::M1400 => Codec2Mode::MODE_1400,
            VoiceMode::M1300 => Codec2Mode::MODE_1300,
            VoiceMode::M1200 => Codec2Mode::MODE_1200,
        }
    }

    /// Wire-format identifier, `0..=5`.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            VoiceMode::M3200 => 0,
            VoiceMode::M2400 => 1,
            VoiceMode::M1600 => 2,
            VoiceMode::M1400 => 3,
            VoiceMode::M1300 => 4,
            VoiceMode::M1200 => 5,
        }
    }

    /// Reverse of [`VoiceMode::id`].
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(VoiceMode::M3200),
            1 => Some(VoiceMode::M2400),
            2 => Some(VoiceMode::M1600),
            3 => Some(VoiceMode::M1400),
            4 => Some(VoiceMode::M1300),
            5 => Some(VoiceMode::M1200),
            _ => None,
        }
    }

    /// Number of compressed bits per frame, from codec2.
    #[must_use]
    pub fn bits_per_frame(self) -> usize {
        codec2_params(self).0
    }

    /// Number of 8 kHz samples per frame, from codec2.
    #[must_use]
    pub fn samples_per_frame(self) -> usize {
        codec2_params(self).1
    }

    /// Frame duration in milliseconds.
    #[must_use]
    pub fn frame_ms(self) -> u32 {
        self.samples_per_frame() as u32 * 1000 / 8000
    }
}

/// Cache the per-mode `(bits, samples)` pair so it is queried from codec2
/// exactly once per mode instead of constructing a `Codec2` on every call.
fn codec2_params(mode: VoiceMode) -> (usize, usize) {
    static PARAMS: LazyLock<[(usize, usize); 6]> = LazyLock::new(|| {
        let mut params = [(0usize, 0usize); 6];
        for (i, mode) in VoiceMode::ALL.iter().enumerate() {
            let codec = Codec2::new(mode.codec2_mode());
            params[i] = (codec.bits_per_frame(), codec.samples_per_frame());
        }
        params
    });
    PARAMS[mode.id() as usize]
}

/// One Codec 2 encoder and one decoder, bound to a single mode.
pub struct VoiceCodec {
    mode: VoiceMode,
    encoder: Codec2,
    decoder: Codec2,
}

impl VoiceCodec {
    #[must_use]
    pub fn new(mode: VoiceMode) -> Self {
        let codec2_mode = mode.codec2_mode();
        Self {
            mode,
            encoder: Codec2::new(codec2_mode),
            decoder: Codec2::new(codec2_mode),
        }
    }

    #[must_use]
    pub fn mode(&self) -> VoiceMode {
        self.mode
    }

    /// Encode one frame of `samples_per_frame()` i16 samples into
    /// `bits_per_frame()` bits (rounded up to whole bytes).
    pub fn encode(&mut self, bits: &mut [u8], speech: &[i16]) {
        self.encoder.encode(bits, speech);
    }

    /// Decode one frame of bits back into `samples_per_frame()` i16 samples.
    pub fn decode(&mut self, speech: &mut [i16], bits: &[u8]) {
        self.decoder.decode(speech, bits);
    }
}
