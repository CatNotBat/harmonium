//! Virtual audio devices that Discord is pointed at.
//!
//! On Linux we create them on the fly with two `pw-loopback` processes (one virtual
//! microphone, one virtual speaker) and tear them down when dropped. On Windows we
//! rely on VB-CABLE being installed already, so nothing is created.

#[cfg(target_os = "linux")]
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::device::list_devices;
use crate::error::AudioError;

/// The source Discord selects as its *input* (microphone). Backed by the PipeWire
/// source node `harmonium_mic`.
pub const MIC_NAME: &str = "Harmonium Mic";

/// The sink Discord selects as its *output* (speaker). Backed by the PipeWire
/// sink node `harmonium_speaker`.
pub const SPEAKER_NAME: &str = "Harmonium Speaker";

// The names cpal (PipeWire host) reports for the two sides *Harmonium* opens, which
// are the opposite ends of each loopback. Determined empirically on this machine:
//
//   $ pw-loopback -n harmonium-mic    --capture-props='media.class=Audio/Sink   node.name=harmonium_mic_in   ...'
//                                       --playback-props='media.class=Audio/Source node.name=harmonium_mic ...'
//   $ pw-loopback -n harmonium-speaker --capture-props='media.class=Audio/Sink   node.name=harmonium_speaker ...'
//                                       --playback-props='media.class=Audio/Source node.name=harmonium_speaker_out ...'
//
// cpal's PipeWire host exposes each node by its `node.description`; the sink nodes are
// reported as duplex (both input and output capable) and the source nodes as input-only.
//
//   "Harmonium Mic Input"     -> sink we play the modem into      (app output side)
//   "Harmonium Speaker Output"-> source we record Discord from    (app input side)
#[cfg(target_os = "linux")]
const APP_INPUT_NAME: &str = "Harmonium Speaker Output";
#[cfg(target_os = "linux")]
const APP_OUTPUT_NAME: &str = "Harmonium Mic Input";

/// How long to wait for the virtual nodes to show up in cpal's device list.
#[cfg(target_os = "linux")]
const APPEAR_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "linux")]
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Owns the helper processes that back the virtual devices, cleaning them up on drop.
pub struct VirtualDevices {
    #[cfg(target_os = "linux")]
    children: Vec<Child>,
    #[cfg(not(target_os = "linux"))]
    _unused: (),
}

impl VirtualDevices {
    /// Create (Linux) or verify (Windows) the virtual devices.
    pub fn create() -> Result<Self, AudioError> {
        #[cfg(target_os = "linux")]
        {
            Self::create_linux()
        }
        #[cfg(target_os = "windows")]
        {
            Self::create_windows()
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(AudioError::Unsupported)
        }
    }

    /// Name of the device the app plays into (the app's output side).
    pub fn app_output_name() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            APP_OUTPUT_NAME
        }
        #[cfg(target_os = "windows")]
        {
            "CABLE Input"
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            ""
        }
    }

    /// Name of the device the app records from (the app's input side).
    pub fn app_input_name() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            APP_INPUT_NAME
        }
        #[cfg(target_os = "windows")]
        {
            // The receive side is Discord's own process audio (see win_loopback), so
            // only one VB-CABLE (the send side) is needed.
            crate::io::DISCORD_PROCESS
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            ""
        }
    }

    /// Kill and reap the helper processes. Idempotent; `Drop` also calls this.
    pub fn teardown(&mut self) {
        #[cfg(target_os = "linux")]
        for mut child in self.children.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[cfg(target_os = "linux")]
    fn create_linux() -> Result<Self, AudioError> {
        let mut children = vec![
            spawn_loopback(
                "harmonium-mic",
                "media.class=Audio/Sink node.name=harmonium_mic_in node.description=\"Harmonium Mic Input\" audio.channels=1 audio.rate=48000",
                "media.class=Audio/Source node.name=harmonium_mic node.description=\"Harmonium Mic\" audio.channels=1 audio.rate=48000",
            )?,
            spawn_loopback(
                "harmonium-speaker",
                "media.class=Audio/Sink node.name=harmonium_speaker node.description=\"Harmonium Speaker\" audio.channels=1 audio.rate=48000",
                "media.class=Audio/Source node.name=harmonium_speaker_out node.description=\"Harmonium Speaker Output\" node.passive=true node.autoconnect=false audio.channels=1 audio.rate=48000",
            )?,
        ];

        let deadline = Instant::now() + APPEAR_TIMEOUT;
        loop {
            let ready = list_devices()
                .map(|devices| {
                    let has_output = devices
                        .iter()
                        .any(|d| d.name.eq_ignore_ascii_case(APP_OUTPUT_NAME));
                    let has_input = devices
                        .iter()
                        .any(|d| d.name.eq_ignore_ascii_case(APP_INPUT_NAME));
                    has_output && has_input
                })
                .unwrap_or(false);
            if ready {
                return Ok(Self { children });
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        for mut child in children.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(AudioError::Timeout)
    }

    #[cfg(target_os = "windows")]
    fn create_windows() -> Result<Self, AudioError> {
        let devices = list_devices()?;
        let has_cable_input = devices
            .iter()
            .any(|d| d.is_output && d.name.to_lowercase().contains("cable input"));
        let has_cable_output = devices
            .iter()
            .any(|d| d.is_input && d.name.to_lowercase().contains("cable output"));
        if !has_cable_input || !has_cable_output {
            return Err(AudioError::VbCableMissing);
        }
        // Only the send side needs the cable: the receive side records Discord's own audio
        // with WASAPI process loopback (see `win_loopback`).
        Ok(Self { _unused: () })
    }
}

impl Drop for VirtualDevices {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(target_os = "linux")]
fn spawn_loopback(
    name: &str,
    capture_props: &str,
    playback_props: &str,
) -> Result<Child, AudioError> {
    // Args are passed as separate argv entries (never through a shell); the embedded
    // double quotes around node.description are stripped by pw-loopback's property
    // parser (`pw_properties_update_string_checked`), yielding a clean description.
    Command::new("pw-loopback")
        .arg("-n")
        .arg(name)
        .arg("-c")
        .arg("1")
        .arg("--capture-props")
        .arg(capture_props)
        .arg("--playback-props")
        .arg(playback_props)
        .spawn()
        .map_err(|e| AudioError::Spawn(format!("pw-loopback: {e}")))
}
