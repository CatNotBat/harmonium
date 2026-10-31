//! Turns 48 kHz microphone audio into small Codec 2 voice packets and back.
//!
//! This crate is the resample / codec / packet layer of Harmonium's voice
//! path. It contains no cryptography and performs no I/O: callers hand it
//! 48 kHz PCM and receive [`VoicePacket`]s, or hand it packets and receive
//! 48 kHz PCM.

#![forbid(unsafe_code)]

mod codec;
mod packet;
mod pipeline;
mod resample;

pub use codec::{VoiceCodec, VoiceMode};
pub use packet::{VoiceError, VoicePacket};
pub use pipeline::{VoiceDecoder, VoiceEncoder};
pub use resample::{Downsampler48k, Upsampler8k};
