//! WASAPI *process loopback* capture and per-process session attenuation.
//!
//! The receive path must record what Discord renders without the user hearing the
//! modem noise. The plan: capture a process tree with WASAPI process loopback
//! (Windows 10 2004+), and lower the process's audio *session* (the volume-mixer
//! level) to inaudibility so the speakers stay silent while the loopback stream keeps
//! delivering samples. Muting the session would also silence the loopback, so we
//! attenuate to -60 dB instead and multiply the captured samples back up by the
//! inverse factor.
//!
//! The capture side mirrors the `record_application` example from the `wasapi`
//! crate: an event-driven shared-mode capture client, initialized as a process
//! loopback client for the target process and its children, at 48 kHz mono `f32`.
//! Samples are pushed into a lock-free ring buffer on a background thread, just
//! like the cpal streams in [`crate::io`].

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use ringbuf::traits::{Producer, Split};
use ringbuf::{HeapCons, HeapProd, HeapRb};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Media::Audio::{
    DEVICE_STATE_ACTIVE, IAudioSessionControl, IAudioSessionControl2, IAudioSessionEnumerator,
    IAudioSessionManager2, IMMDevice, IMMDeviceCollection, IMMDeviceEnumerator, ISimpleAudioVolume,
    MMDeviceEnumerator, eRender,
};
use windows::Win32::System::Com::{CLSCTX_ALL, CoCreateInstance};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::core::Interface;

use crate::error::AudioError;

/// The one sample rate the modem assumes; matches [`crate::io`]'s value.
const SAMPLE_RATE: u32 = 48_000;

/// One second of mono `f32` at 48 kHz, matching [`crate::io`]'s ring capacity.
const RING_CAPACITY: usize = SAMPLE_RATE as usize;

/// How long [`ProcessLoopback::start`] waits for the capture thread to report a
/// running stream before giving up.
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// The volume-mixer level Discord's audio sessions are lowered to while the tap is
/// running. At -60 dB it is inaudible but, unlike the session mute, process loopback
/// still taps the session post-volume in the float path, so multiplying captured
/// samples by `1.0 / ATTENUATION` restores the signal exactly (measured 30 Oct 2026).
pub(crate) const ATTENUATION: f32 = 0.001;

/// The Discord executables whose process trees render the audio we capture.
const DISCORD_EXES: [&str; 3] = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"];

/// Map a Windows or wasapi error into the crate-wide [`AudioError`].
fn to_audio_error(error: impl std::fmt::Display) -> AudioError {
    AudioError::Windows(error.to_string())
}

/// Mute or unmute every audio session owned by any of `pids`, on every active render
/// endpoint. Returns how many sessions were changed.
pub fn set_process_mute(pids: &[u32], mute: bool) -> Result<usize, AudioError> {
    for_each_process_session(pids, |_process_id, volume| unsafe {
        volume.SetMute(mute, std::ptr::null())
    })
}

/// Set the volume-mixer level (0.0..=1.0) of every audio session owned by any of
/// `pids`, on every active render endpoint. Returns how many sessions were changed.
pub fn set_process_volume(pids: &[u32], level: f32) -> Result<usize, AudioError> {
    let level = level.clamp(0.0, 1.0);
    for_each_process_session(pids, |_process_id, volume| unsafe {
        volume.SetMasterVolume(level, std::ptr::null())
    })
}

/// Apply `change` to the session volume control of every session owned by `pids`,
/// passing the owning process id alongside the control.
fn for_each_process_session(
    pids: &[u32],
    change: impl Fn(u32, &ISimpleAudioVolume) -> windows::core::Result<()>,
) -> Result<usize, AudioError> {
    // Ignore the result: S_FALSE / RPC_E_CHANGED_MODE just mean COM was already
    // initialized (possibly in a different apartment), which is fine here.
    let _ = wasapi::initialize_mta();

    let enumerator: IMMDeviceEnumerator =
        unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }
            .map_err(to_audio_error)?;
    let devices: IMMDeviceCollection =
        unsafe { enumerator.EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE) }
            .map_err(to_audio_error)?;
    let device_count = unsafe { devices.GetCount() }.map_err(to_audio_error)?;

    let mut changed = 0usize;
    for device_index in 0..device_count {
        let device: IMMDevice = unsafe { devices.Item(device_index) }.map_err(to_audio_error)?;
        let manager: IAudioSessionManager2 =
            unsafe { device.Activate::<IAudioSessionManager2>(CLSCTX_ALL, None) }
                .map_err(to_audio_error)?;
        let sessions: IAudioSessionEnumerator =
            unsafe { manager.GetSessionEnumerator() }.map_err(to_audio_error)?;
        let session_count = unsafe { sessions.GetCount() }.map_err(to_audio_error)?;

        for session_index in 0..session_count {
            let session: IAudioSessionControl =
                unsafe { sessions.GetSession(session_index) }.map_err(to_audio_error)?;
            let control: IAudioSessionControl2 = session.cast().map_err(to_audio_error)?;
            // System-sound sessions have no owning process and report an error
            // here; skip them rather than failing the whole pass.
            let process_id = match unsafe { control.GetProcessId() } {
                Ok(id) => id,
                Err(_) => continue,
            };
            if pids.contains(&process_id) {
                let volume: ISimpleAudioVolume = session.cast().map_err(to_audio_error)?;
                change(process_id, &volume).map_err(to_audio_error)?;
                changed += 1;
            }
        }
    }

    Ok(changed)
}

/// Captures everything a process tree renders, as 48 kHz mono `f32`, on a background
/// thread.
pub struct ProcessLoopback {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    overruns: Arc<AtomicU64>,
}

impl ProcessLoopback {
    /// Starts capturing `pid` and its children, multiplying every captured sample by
    /// `gain`. Returns once the stream is running, or the startup error.
    pub fn start(pid: u32, gain: f32) -> Result<(Self, HeapCons<f32>), AudioError> {
        let ring = HeapRb::<f32>::new(RING_CAPACITY);
        let (producer, consumer) = ring.split();

        let stop = Arc::new(AtomicBool::new(false));
        let overruns = Arc::new(AtomicU64::new(0));
        let (tx, rx) = sync_channel::<Result<(), AudioError>>(1);

        let thread_stop = Arc::clone(&stop);
        let thread_overruns = Arc::clone(&overruns);
        let thread = std::thread::Builder::new()
            .name("process-loopback".to_string())
            .spawn(move || capture_thread(pid, gain, producer, thread_stop, thread_overruns, tx))
            .map_err(|error| AudioError::Windows(error.to_string()))?;

        match rx.recv_timeout(STREAM_TIMEOUT) {
            Ok(Ok(())) => Ok((
                Self {
                    stop,
                    thread: Some(thread),
                    overruns,
                },
                consumer,
            )),
            Ok(Err(error)) => {
                stop.store(true, Ordering::Relaxed);
                Err(error)
            }
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                Err(AudioError::Timeout)
            }
        }
    }

    /// The number of captured samples dropped because the ring was full.
    pub fn overruns(&self) -> u64 {
        self.overruns.load(Ordering::Relaxed)
    }
}

impl Drop for ProcessLoopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The wasapi resources owned by one running capture stream.
struct CaptureSession {
    audio_client: wasapi::AudioClient,
    capture_client: wasapi::AudioCaptureClient,
    event: wasapi::Handle,
    blockalign: usize,
}

fn open_capture(pid: u32) -> Result<CaptureSession, AudioError> {
    let _ = wasapi::initialize_mta();

    let format = wasapi::WaveFormat::new(
        32,
        32,
        &wasapi::SampleType::Float,
        SAMPLE_RATE as usize,
        1,
        None,
    );
    let blockalign = format.get_blockalign() as usize;

    let mut audio_client =
        wasapi::AudioClient::new_application_loopback_client(pid, true).map_err(to_audio_error)?;
    audio_client
        .initialize_client(
            &format,
            &wasapi::Direction::Capture,
            &wasapi::StreamMode::EventsShared {
                autoconvert: true,
                buffer_duration_hns: 0,
            },
        )
        .map_err(to_audio_error)?;
    let event = audio_client.set_get_eventhandle().map_err(to_audio_error)?;
    let capture_client = audio_client
        .get_audiocaptureclient()
        .map_err(to_audio_error)?;
    audio_client.start_stream().map_err(to_audio_error)?;

    Ok(CaptureSession {
        audio_client,
        capture_client,
        event,
        blockalign,
    })
}

fn capture_thread(
    pid: u32,
    gain: f32,
    mut producer: HeapProd<f32>,
    stop: Arc<AtomicBool>,
    overruns: Arc<AtomicU64>,
    tx: SyncSender<Result<(), AudioError>>,
) {
    let session = match open_capture(pid) {
        Ok(session) => session,
        Err(error) => {
            let _ = tx.send(Err(error));
            return;
        }
    };
    // The stream is running; report success so `start` can return.
    let _ = tx.send(Ok(()));

    let mut queue = VecDeque::<u8>::new();
    let mut samples = Vec::<f32>::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // A timeout just means the process produced no packets since the last wait;
        // that is not an error.
        let _ = session.event.wait_for_event(100);
        if let Err(error) = drain(
            &session.capture_client,
            session.blockalign,
            gain,
            &mut queue,
            &mut samples,
            &mut producer,
            &overruns,
        ) {
            tracing::warn!("process loopback capture failed: {error}");
            break;
        }
    }

    if let Err(error) = session.audio_client.stop_stream() {
        tracing::warn!("failed to stop process loopback stream: {error}");
    }
}

/// Pull every packet queued on `capture`, convert the little-endian `f32` bytes into
/// samples, multiply them by `gain`, and push them into the ring. Samples that do not
/// fit are counted as overruns. All buffers are reused between calls.
fn drain(
    capture: &wasapi::AudioCaptureClient,
    blockalign: usize,
    gain: f32,
    queue: &mut VecDeque<u8>,
    samples: &mut Vec<f32>,
    producer: &mut HeapProd<f32>,
    overruns: &AtomicU64,
) -> Result<(), AudioError> {
    loop {
        let frames = capture
            .get_next_packet_size()
            .map_err(to_audio_error)?
            .unwrap_or(0);
        if frames == 0 {
            break;
        }
        let additional =
            (frames as usize * blockalign).saturating_sub(queue.capacity() - queue.len());
        queue.reserve(additional);
        capture
            .read_from_device_to_deque(queue)
            .map_err(to_audio_error)?;
    }

    samples.clear();
    samples.reserve(queue.len() / 4);
    for bytes in queue.make_contiguous().as_chunks::<4>().0 {
        samples.push(f32::from_le_bytes(*bytes));
    }
    queue.clear();

    for sample in samples.iter_mut() {
        *sample *= gain;
    }
    let pushed = producer.push_slice(samples);
    let dropped = samples.len() - pushed;
    if dropped > 0 {
        overruns.fetch_add(dropped as u64, Ordering::Relaxed);
    }
    Ok(())
}

/// Closes a Toolhelp32 snapshot handle on drop, so every early return is safe.
struct SnapshotGuard(HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Snapshot every running process as `(pid, parent pid, exe name)`.
fn process_table() -> Result<Vec<(u32, u32, String)>, AudioError> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(to_audio_error)?;
    let _guard = SnapshotGuard(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Process32FirstW(snapshot, &mut entry) }.map_err(to_audio_error)?;

    let mut table = Vec::new();
    loop {
        let nul = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        table.push((
            entry.th32ProcessID,
            entry.th32ParentProcessID,
            String::from_utf16_lossy(&entry.szExeFile[..nul]),
        ));
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            break;
        }
    }
    Ok(table)
}

/// Pids whose exe name is one of [`DISCORD_EXES`], ASCII case-insensitive.
fn discord_pids(table: &[(u32, u32, String)]) -> Vec<u32> {
    table
        .iter()
        .filter(|(_, _, exe)| {
            DISCORD_EXES
                .iter()
                .any(|name| name.eq_ignore_ascii_case(exe))
        })
        .map(|(pid, _, _)| *pid)
        .collect()
}

/// The first pid in `pids` whose parent is not itself in `pids` — Discord's main
/// process, whose children render the audio we capture. `None` when `pids` is empty.
fn tree_root(table: &[(u32, u32, String)], pids: &[u32]) -> Option<u32> {
    pids.iter().copied().find(|pid| {
        table
            .iter()
            .find(|(id, _, _)| id == pid)
            .map(|(_, parent, _)| !pids.contains(parent))
            .unwrap_or(true)
    })
}

/// The level to restore a session to. A session already sitting at [`ATTENUATION`] is
/// the leftover of a crashed run rather than the user's choice, so restore it to full
/// volume instead of the observed near-zero level.
fn original_level(observed: f32) -> f32 {
    if observed <= ATTENUATION * 1.5 {
        1.0
    } else {
        observed
    }
}

/// Owns a running Discord capture: the [`ProcessLoopback`] on Discord's process tree,
/// plus a guard thread that keeps every Discord audio session attenuated (Discord only
/// starts its voice process when a call is joined and may restart it).
pub struct DiscordTap {
    loopback: Option<ProcessLoopback>,
    stop: Arc<AtomicBool>,
    guard: Option<JoinHandle<()>>,
    saved: Arc<Mutex<HashMap<u32, f32>>>,
}

impl DiscordTap {
    /// Attenuate every running Discord session, start capturing the Discord process
    /// tree, and spawn the re-attenuation guard thread. Restores the user's volumes on
    /// drop. Fails if Discord is not running.
    pub fn start() -> Result<(Self, HeapCons<f32>), AudioError> {
        let table = process_table()?;
        let pids = discord_pids(&table);
        if pids.is_empty() {
            return Err(AudioError::DeviceNotFound("Discord is not running".into()));
        }
        let root = tree_root(&table, &pids).ok_or_else(|| {
            AudioError::Windows("no root process among the Discord processes".into())
        })?;

        let saved = Arc::new(Mutex::new(HashMap::new()));
        attenuate(&pids, &saved)?;

        let (loopback, consumer) = match ProcessLoopback::start(root, 1.0 / ATTENUATION) {
            Ok(pair) => pair,
            Err(error) => {
                restore(&saved);
                return Err(error);
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let guard_stop = Arc::clone(&stop);
        let guard_saved = Arc::clone(&saved);
        let guard = match std::thread::Builder::new()
            .name("discord-tap-guard".to_string())
            .spawn(move || guard_loop(guard_stop, guard_saved))
        {
            Ok(guard) => guard,
            Err(error) => {
                restore(&saved);
                return Err(AudioError::Windows(error.to_string()));
            }
        };

        Ok((
            Self {
                loopback: Some(loopback),
                stop,
                guard: Some(guard),
                saved,
            },
            consumer,
        ))
    }

    /// The number of captured samples dropped because the ring was full.
    pub fn overruns(&self) -> u64 {
        self.loopback
            .as_ref()
            .map(|loopback| loopback.overruns())
            .unwrap_or(0)
    }
}

impl Drop for DiscordTap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(guard) = self.guard.take() {
            let _ = guard.join();
        }
        restore(&self.saved);
        self.loopback.take();
    }
}

/// Lower every matching Discord session to [`ATTENUATION`], recording the level to
/// restore in `saved` (first observation wins). Sessions already at [`ATTENUATION`]
/// are left alone. Returns how many sessions were seen.
fn attenuate(pids: &[u32], saved: &Mutex<HashMap<u32, f32>>) -> Result<usize, AudioError> {
    for_each_process_session(pids, |process_id, volume| unsafe {
        let observed = volume.GetMasterVolume()?;
        if (observed - ATTENUATION).abs() > 1e-6 {
            if let Ok(mut map) = saved.lock() {
                map.entry(process_id)
                    .or_insert_with(|| original_level(observed));
            }
            volume.SetMasterVolume(ATTENUATION, std::ptr::null())?;
        }
        Ok(())
    })
}

/// The guard thread: keep every Discord session attenuated until `stop` is set.
/// Discord starts its voice process only once a call is joined, so re-scan the
/// process table every 500 ms. Errors are logged, never fatal.
fn guard_loop(stop: Arc<AtomicBool>, saved: Arc<Mutex<HashMap<u32, f32>>>) {
    while !stop.load(Ordering::Relaxed) {
        match process_table() {
            Ok(table) => {
                let pids = discord_pids(&table);
                if !pids.is_empty()
                    && let Err(error) = attenuate(&pids, &saved)
                {
                    tracing::warn!("discord tap: attenuate failed: {error}");
                }
            }
            Err(error) => tracing::warn!("discord tap: process scan failed: {error}"),
        }
        // Sleep in 50 ms slices so `stop` is noticed quickly.
        for _ in 0..10 {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Restore every Discord session's volume: pids recorded in `saved` return to their
/// saved level, and any still-running Discord session left at [`ATTENUATION`] that was
/// never recorded (a crashed run's leftover) returns to 1.0. Errors are logged, never
/// propagated, so this is safe to call from `Drop`.
fn restore(saved: &Mutex<HashMap<u32, f32>>) {
    let saved: HashMap<u32, f32> = match saved.lock() {
        Ok(map) => map.clone(),
        Err(_) => HashMap::new(),
    };

    if !saved.is_empty() {
        let pids: Vec<u32> = saved.keys().copied().collect();
        if let Err(error) = for_each_process_session(&pids, |process_id, volume| unsafe {
            let level = saved.get(&process_id).copied().unwrap_or(1.0);
            volume.SetMasterVolume(level, std::ptr::null())
        }) {
            tracing::warn!("discord tap: restore failed: {error}");
        }
    }

    match process_table() {
        Ok(table) => {
            let unrecorded: Vec<u32> = discord_pids(&table)
                .into_iter()
                .filter(|pid| !saved.contains_key(pid))
                .collect();
            if !unrecorded.is_empty()
                && let Err(error) =
                    for_each_process_session(&unrecorded, |_process_id, volume| unsafe {
                        let observed = volume.GetMasterVolume()?;
                        if (observed - ATTENUATION).abs() <= 1e-6 {
                            volume.SetMasterVolume(1.0, std::ptr::null())?;
                        }
                        Ok(())
                    })
            {
                tracing::warn!("discord tap: restore failed: {error}");
            }
        }
        Err(error) => tracing::warn!("discord tap: process scan during restore failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, parent: u32, exe: &str) -> (u32, u32, String) {
        (pid, parent, exe.to_string())
    }

    #[test]
    fn discord_pids_matches_all_variants_case_insensitively() {
        let table = vec![
            row(100, 1, "discord.exe"),
            row(200, 1, "DiscordPTB.EXE"),
            row(300, 1, "DISCORDCANARY.exe"),
            row(400, 1, "Discordo.exe"),
            row(500, 1, "notdiscord.exe"),
        ];
        let mut pids = discord_pids(&table);
        pids.sort();
        assert_eq!(pids, vec![100, 200, 300]);
    }

    #[test]
    fn tree_root_is_the_process_with_a_non_discord_parent() {
        // explorer (10) -> main (100) -> child (200) -> grandchild (300)
        let table = vec![
            row(10, 0, "explorer.exe"),
            row(100, 10, "Discord.exe"),
            row(200, 100, "Discord.exe"),
            row(300, 200, "Discord.exe"),
        ];
        assert_eq!(tree_root(&table, &[100, 200, 300]), Some(100));
    }

    #[test]
    fn tree_root_with_a_child_listed_first_still_finds_the_root() {
        let table = vec![
            row(10, 0, "explorer.exe"),
            row(100, 10, "Discord.exe"),
            row(200, 100, "Discord.exe"),
            row(300, 200, "Discord.exe"),
        ];
        assert_eq!(tree_root(&table, &[300, 200, 100]), Some(100));
    }

    #[test]
    fn tree_root_of_an_empty_pid_list_is_none() {
        let table = vec![row(100, 10, "Discord.exe")];
        assert_eq!(tree_root(&table, &[]), None);
    }

    #[test]
    fn original_level_recovers_leftovers_but_not_user_choices() {
        assert_eq!(original_level(0.001), 1.0);
        assert_eq!(original_level(0.0014), 1.0);
        assert_eq!(original_level(0.5), 0.5);
        assert_eq!(original_level(1.0), 1.0);
    }
}
