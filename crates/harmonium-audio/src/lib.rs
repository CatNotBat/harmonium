//! Platform audio layer: device discovery, virtual audio devices for Discord, and
//! real-time cpal streams bridged to the app thread through lock-free ring buffers.
//!
//! Every other crate in the workspace is pure; all platform-specific code lives here.

mod device;
mod error;
mod io;
mod virtual_dev;
#[cfg(windows)]
mod win_loopback;

pub use device::{DeviceInfo, find_input, find_output, list_devices};
pub use error::AudioError;
pub use io::{AudioConfig, AudioIo, DISCORD_PROCESS, IoStats};
pub use virtual_dev::{MIC_NAME, SPEAKER_NAME, VirtualDevices};
#[cfg(windows)]
pub use win_loopback::{DiscordTap, ProcessLoopback, set_process_mute, set_process_volume};
