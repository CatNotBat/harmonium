//! Virtual audio device commands.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use harmonium_audio::{MIC_NAME, SPEAKER_NAME, VirtualDevices, list_devices};

use crate::cli::DeviceCmd;

/// Create the virtual devices and keep them alive until Ctrl-C.
///
/// Prints the two device names Discord must be pointed at, then blocks until
/// the user interrupts. Dropping [`VirtualDevices`] tears the helper processes
/// down.
pub fn setup() -> Result<()> {
    let devices = VirtualDevices::create().context("failed to create virtual devices")?;
    println!("Discord input (microphone): {MIC_NAME}");
    println!("Discord output (speaker):   {SPEAKER_NAME}");
    println!("Press Ctrl-C to tear the devices down.");

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .context("failed to install Ctrl-C handler")?;

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    // `devices` drops here, killing and reaping the pw-loopback processes.
    drop(devices);
    println!("virtual devices removed");
    Ok(())
}

/// Explain the teardown semantics.
///
/// On Linux the devices are `pw-loopback` children of the `setup` process, so
/// they die with it; there is nothing for a standalone `teardown` to reach.
pub fn teardown() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        println!(
            "On Linux the virtual devices are child processes of `harmonium devices setup` \
             and die when that process exits (or is interrupted). There is nothing to tear \
             down here."
        );
    }
    #[cfg(target_os = "windows")]
    {
        println!(
            "On Windows Harmonium uses VB-CABLE; no devices are created at runtime, so there \
             is nothing to tear down."
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        println!("No virtual audio devices on this platform.");
    }
    Ok(())
}

/// List devices and report whether the virtual devices / VB-CABLE are present.
pub fn check() -> Result<()> {
    let devices = list_devices().context("failed to enumerate audio devices")?;
    println!("Audio devices:");
    for device in &devices {
        let rate = device
            .default_rate
            .map(|r| format!(" @ {r} Hz"))
            .unwrap_or_default();
        let dirs = match (device.is_input, device.is_output) {
            (true, true) => "in+out",
            (true, false) => "in",
            (false, true) => "out",
            (false, false) => "-",
        };
        println!("  {dirs:<7} {}{rate}", device.name);
    }

    println!();
    check_virtual(&devices);
    Ok(())
}

fn check_virtual(devices: &[harmonium_audio::DeviceInfo]) {
    // Same rule `AudioIo::open` uses: a case-insensitive substring, since Windows appends the
    // driver name ("CABLE Input (VB-Audio Virtual Cable)").
    let has = |name: &str| {
        let needle = name.to_lowercase();
        devices
            .iter()
            .any(|d| d.name.to_lowercase().contains(&needle))
    };

    #[cfg(target_os = "linux")]
    {
        let mic = has(MIC_NAME);
        let speaker = has(SPEAKER_NAME);
        println!("virtual mic     ({MIC_NAME}): {}", present(mic));
        println!("virtual speaker ({SPEAKER_NAME}): {}", present(speaker));
        println!(
            "Run `harmonium devices setup` to create them, then point Discord's input at \
             {MIC_NAME} and its output at {SPEAKER_NAME}."
        );
    }
    #[cfg(target_os = "windows")]
    {
        let cable_in = has("CABLE Input");
        let cable_out = has("CABLE Output");
        println!("VB-CABLE input  (\"CABLE Input\"): {}", present(cable_in));
        println!("VB-CABLE output (\"CABLE Output\"): {}", present(cable_out));
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = has;
        println!("No virtual audio devices on this platform.");
    }
}

fn present(yes: bool) -> &'static str {
    if yes { "present" } else { "MISSING" }
}

/// `harmonium devices ...`. Returns the process exit code.
pub fn run(cmd: &DeviceCmd) -> Result<u8> {
    match cmd {
        DeviceCmd::Setup => setup()?,
        DeviceCmd::Teardown => teardown()?,
        DeviceCmd::Check => check()?,
    }
    Ok(0)
}
