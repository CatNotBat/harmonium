//! Error type shared by the audio backend.

use thiserror::Error;

/// All failures the platform audio layer can surface to the app.
#[derive(Debug, Error)]
pub enum AudioError {
    /// An error reported by the cpal audio backend.
    #[error("audio backend error: {0}")]
    Cpal(String),

    /// A device matching the requested name could not be found.
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    /// The VB-CABLE virtual cable is not installed on this Windows machine.
    #[error("VB-CABLE virtual audio cable not found; install it from https://vb-audio.com/Cable/")]
    VbCableMissing,

    /// This platform has no supported audio backend.
    #[error("audio I/O is unsupported on this platform")]
    Unsupported,

    /// The device's native sample rate differs from the 48 kHz the modem assumes.
    ///
    /// Resampling is not done here; the caller gets the offending rate back.
    #[error("unsupported sample rate {0} Hz (only 48000 Hz is supported for now)")]
    UnsupportedRate(u32),

    /// An error reported by the Windows audio APIs (WASAPI or the `windows` crate).
    #[error("Windows audio API error: {0}")]
    Windows(String),

    /// A helper process (e.g. `pw-loopback`) could not be spawned.
    #[error("failed to spawn audio helper process: {0}")]
    Spawn(String),

    /// The virtual devices did not appear within the polling window.
    #[error("timed out waiting for virtual audio devices to appear")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vb_cable_missing_display_contains_url() {
        let text = AudioError::VbCableMissing.to_string();
        assert!(
            text.contains("https://vb-audio.com/Cable/"),
            "Display text should point at the VB-CABLE download page, got: {text}"
        );
    }
}
