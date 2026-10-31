//! Device discovery over cpal's default host.

use cpal::traits::{DeviceTrait, HostTrait};

use crate::error::AudioError;

/// A single audio device as seen by the default cpal host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Human-readable device name (matches cpal's `Device::to_string()` /
    /// `description()?.name()`; there is no `name()` accessor in cpal 0.18).
    pub name: String,
    /// Whether the device can be opened as an input stream.
    pub is_input: bool,
    /// Whether the device can be opened as an output stream.
    pub is_output: bool,
    /// The device's default sample rate, if any default config is available.
    pub default_rate: Option<u32>,
}

/// Enumerate every device on the default host.
pub fn list_devices() -> Result<Vec<DeviceInfo>, AudioError> {
    let host = cpal::default_host();
    let devices = host
        .devices()
        .map_err(|e| AudioError::Cpal(e.to_string()))?;

    let mut out = Vec::new();
    for device in devices {
        let name = device.to_string();
        let is_input = device
            .supported_input_configs()
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
        let is_output = device
            .supported_output_configs()
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
        let default_rate = device
            .default_input_config()
            .map(|c| c.sample_rate())
            .or_else(|_| device.default_output_config().map(|c| c.sample_rate()))
            .ok();

        out.push(DeviceInfo {
            name,
            is_input,
            is_output,
            default_rate,
        });
    }
    Ok(out)
}

/// First input device whose name contains `name_substring` (case-insensitive).
pub fn find_input(name_substring: &str) -> Result<DeviceInfo, AudioError> {
    let devices = list_devices()?;
    find_matching(&devices, name_substring, true)
        .cloned()
        .ok_or_else(|| {
            AudioError::DeviceNotFound(format!("no input device containing {name_substring:?}"))
        })
}

/// First output device whose name contains `name_substring` (case-insensitive).
pub fn find_output(name_substring: &str) -> Result<DeviceInfo, AudioError> {
    let devices = list_devices()?;
    find_matching(&devices, name_substring, false)
        .cloned()
        .ok_or_else(|| {
            AudioError::DeviceNotFound(format!("no output device containing {name_substring:?}"))
        })
}

/// Case-insensitive substring match with a direction filter, first hit wins.
fn find_matching<'a>(
    devices: &'a [DeviceInfo],
    name_substring: &str,
    want_input: bool,
) -> Option<&'a DeviceInfo> {
    let needle = name_substring.to_lowercase();
    devices.iter().find(|d| {
        let direction_ok = if want_input { d.is_input } else { d.is_output };
        direction_ok && d.name.to_lowercase().contains(&needle)
    })
}

/// Resolve a named (or default) device on the given host, for use when opening streams.
pub(crate) fn find_cpal_device(
    host: &cpal::Host,
    name_substring: &str,
    want_input: bool,
) -> Result<cpal::Device, AudioError> {
    let needle = name_substring.to_lowercase();
    let devices = host
        .devices()
        .map_err(|e| AudioError::Cpal(e.to_string()))?;
    for device in devices {
        let direction_ok = if want_input {
            device.supports_input()
        } else {
            device.supports_output()
        };
        if direction_ok && device.to_string().to_lowercase().contains(&needle) {
            return Ok(device);
        }
    }
    Err(AudioError::DeviceNotFound(format!(
        "no {} device containing {name_substring:?}",
        if want_input { "input" } else { "output" }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, is_input: bool, is_output: bool) -> DeviceInfo {
        DeviceInfo {
            name: name.to_owned(),
            is_input,
            is_output,
            default_rate: Some(48_000),
        }
    }

    #[test]
    fn matcher_is_case_insensitive() {
        let devices = vec![dev("Harmonium Mic", true, false)];
        assert!(find_matching(&devices, "harmonium mic", true).is_some());
        assert!(find_matching(&devices, "HARMONIUM", true).is_some());
    }

    #[test]
    fn matcher_filters_by_direction() {
        // cpal's PipeWire host reports the mic sink as duplex, so both devices are
        // input-capable; the shorter needle hits the sink first on an input search.
        let devices = vec![
            dev("Harmonium Mic Input", true, true),
            dev("Harmonium Mic", true, false),
        ];
        assert_eq!(
            find_matching(&devices, "Harmonium Mic", true).unwrap().name,
            "Harmonium Mic Input"
        );
        // An output search skips the source and finds the sink.
        assert_eq!(
            find_matching(&devices, "Harmonium Mic", false)
                .unwrap()
                .name,
            "Harmonium Mic Input"
        );
    }

    #[test]
    fn matcher_first_hit_wins() {
        let devices = vec![
            dev("CABLE Input", false, true),
            dev("CABLE Input (VB-Audio Virtual Cable)", false, true),
        ];
        assert_eq!(
            find_matching(&devices, "cable input", false).unwrap().name,
            "CABLE Input"
        );
    }

    #[test]
    fn matcher_misses_when_no_direction_match() {
        let devices = vec![dev("Only an output", false, true)];
        assert!(find_matching(&devices, "only an output", true).is_none());
    }

    #[test]
    fn matcher_misses_entirely() {
        let devices = vec![dev("Something Else", true, false)];
        assert!(find_matching(&devices, "harmonium", true).is_none());
    }
}
