//! Integration test for the PipeWire virtual devices. Needs a running PipeWire
//! session, so it is `#[ignore]`d by default and run explicitly.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

use harmonium_audio::{AudioConfig, AudioIo, MIC_NAME, SPEAKER_NAME, VirtualDevices, list_devices};

fn pw_loopback_running(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore = "needs a running PipeWire session"]
fn virtual_devices_appear_route_audio_and_teardown() {
    let devices = VirtualDevices::create().expect("create virtual devices");

    // Both Discord-facing nodes and both app-facing sides show up in cpal's list.
    let names: Vec<String> = list_devices()
        .expect("list devices")
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(
        names.iter().any(|n| n == MIC_NAME),
        "virtual mic missing from {names:?}"
    );
    assert!(
        names.iter().any(|n| n == SPEAKER_NAME),
        "virtual speaker missing from {names:?}"
    );
    assert!(names.iter().any(|n| n == VirtualDevices::app_output_name()));
    assert!(names.iter().any(|n| n == VirtualDevices::app_input_name()));

    // Open the four streams and push a 1 kHz tone into the virtual mic side.
    let mut io = AudioIo::open(&AudioConfig {
        mic: None,
        speaker: None,
        to_discord: VirtualDevices::app_output_name().to_owned(),
        from_discord: VirtualDevices::app_input_name().to_owned(),
    })
    .expect("open AudioIo");

    const RATE: f32 = 48_000.0;
    let mut phase = 0.0f32;
    let dt = 1_000.0 / RATE; // seconds per sample, phase in Hz
    let mut buffer = [0.0f32; 4_800];
    for _ in 0..10 {
        for sample in &mut buffer {
            *sample = 0.2 * (std::f32::consts::TAU * 1_000.0 * phase).sin();
            phase += dt;
        }
        // The ring starts empty, so the first write should be accepted in full.
        io.write_to_discord(&buffer);
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(io);

    // Dropping the devices must kill and reap both pw-loopback children.
    drop(devices);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !pw_loopback_running("harmonium-mic"),
        "mic pw-loopback still running after teardown"
    );
    assert!(
        !pw_loopback_running("harmonium-speaker"),
        "speaker pw-loopback still running after teardown"
    );

    // And the nodes themselves should be gone from cpal's list.
    let names: Vec<String> = list_devices()
        .expect("list devices")
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(
        !names.iter().any(|n| n == MIC_NAME),
        "virtual mic node survived teardown: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == SPEAKER_NAME),
        "virtual speaker node survived teardown: {names:?}"
    );
}
