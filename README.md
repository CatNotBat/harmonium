# Harmonium

End-to-end encrypted voice and text over an ordinary Discord call. Discord carries only modem
audio and ASCII-armored ciphertext; the keys never leave your machines.

![A: here I am, here I am, here I am. B: so glad you are, so glad you are, so glad you are.
Discord gets the same modem noise both times](docs/img/here-i-am.png)

Both lines went through `harmonium selftest` (simulated Opus, 2% packet loss). Listen to what
Discord got ([A](docs/demo/a-discord.mp3), [B](docs/demo/b-discord.mp3)) and what came out the
other end ([A](docs/demo/a-heard.mp3), [B](docs/demo/b-heard.mp3)).

```
mic → Codec 2 (1300 bps) → WireGuard (GotaTun) → modem → virtual mic → Discord (Opus)
                                                                          ↓
speaker ← Codec 2 ← WireGuard ← modem demod ← virtual speaker ← Discord (Opus)
```

> **Proof of concept.** It works live between Linux and Windows, with about 1.5 s of delay and
> audible gaps, and it has not been audited. Do not rely on it to protect anything that matters.

**Start here: [How Harmonium works](docs/how-it-works.md)**, the idea, the pipeline and the
results in plain language. Modem details: `docs/modem-spec.md`. Threat model:
`docs/threat-model.md`.

## Status

What works:

- Live encrypted voice between Linux and Windows over a real Discord DM call (numbers below).
- Encrypted text: `harmonium text encrypt`, paste it into Discord, copy it back, decrypt.
- `harmonium selftest` runs the whole voice loop offline through a simulated Opus channel.
- Fuzz targets in `fuzz/`, a threat model in docs/threat-model.md, signed releases.

The modem in the simulator (600 s, 2% Opus packet loss, `channel-sim bench --phy ofdm`): 34
carriers, 300 Hz – 3.7 kHz, RS(104,64)×4, 3.30 kbps net, 0 corrupt packets, 1.7% frames lost.
Codec 2 1300 over WireGuard needs ~2.5 kbps. An earlier 68-carrier layout did 3.93 kbps in the
simulator but lost its upper carriers on real Discord audio.

Live (31 Oct 2026): a real Discord DM call between a Linux laptop and a Windows PC,
full duplex for 600 s, Harmonium on both ends, synthetic speech in (no mic):

| Direction | Voice packets lost | Modem frames failed | Pre-FEC BER | Corrupt voice |
|---|---|---|---|---|
| Windows → Linux | 15.3% (278/1815) | 74/915 | 0.0080 | 0 |
| Linux → Windows | 26.9% (501/1860) | 142/883 | 0.0146 | 0 |

One-way voice latency ≈ 1.55 s (mean of the two directions, which cancels the clocks'
offset; p95 ≈ 1.9 s). Link up after ~19 s, 9 handshakes (rekeys) in 10 min. Discord drops or
repeats 120–240 samples mid-frame, mostly on the Windows receive path; per-symbol timing
tracking in the OFDM demodulator (docs/modem-spec.md) cut Linux → Windows loss from 42% to
~27%. Loss varies a lot run to run (Windows → Linux: 5–15% across three runs). What is left
is real frame loss inside Discord's path, not timing, and costs audible gaps.

On Windows, Harmonium records Discord's own audio with WASAPI process loopback and
turns Discord's volume-mixer level down to -60 dB while a call runs (then scales the capture
back up; measured exact). Muting instead would also silence the loopback. So Windows needs
only one VB-CABLE, for the send side.

Unfinished work lives on branches until it has run on a real call: Rosenpass post-quantum key
exchange is on `pq-rosenpass` (passes offline, never tested live).

## Using it

Both people run Harmonium; Discord is just the carrier. Once per friend:

```
harmonium keygen                    # your identity (WireGuard + age keys)
harmonium id                        # your bundle + fingerprint: send the bundle to your friend
harmonium peer add alice harmonium1:...
harmonium peer verify alice         # compare fingerprints out-of-band (in person, phone)
```

Point Discord at Harmonium by hand: Harmonium never changes Discord's settings or your default
devices. In Discord, **Settings → Voice & Video**:

| | Input Device | Output Device |
|---|---|---|
| Linux | Harmonium Mic | Harmonium Speaker |
| Windows | CABLE Output (VB-Audio Virtual Cable) | your headphones (unchanged) |

Also turn off Discord's Noise Suppression, Echo Cancellation and Automatic Gain Control there:
they treat modem audio as noise. Then join a Discord call with your friend and both run
`harmonium call alice`. Your real mic and speakers are Harmonium's (`--mic`, `--speaker`,
default: the system defaults); what Discord sends and plays is modem noise. On Linux the
virtual devices exist only while `harmonium call` (or `harmonium devices setup`) runs.

Windows needs [VB-CABLE](https://vb-audio.com/Cable/) installed. On the receive side
Harmonium records Discord's own output and, for the call only, lowers Discord's level in the
Windows volume mixer to -60 dB so the modem noise stays out of your headphones (it puts the
level back when the call ends; it never changes the device). If Harmonium is killed instead of
stopped with Ctrl-C, Discord stays quiet until the next `harmonium call` ends, or until you raise
Discord's level in the volume mixer yourself.

**After the call, switch Discord's devices back** (Input to your mic, and on Linux Output to
your speakers), or your next ordinary Discord call is silent.

## Ground rules

- **No custom crypto.** Primitives come only from GotaTun (WireGuard) and age. `deny.toml`
  bans every primitive crate unless it is pulled in through one of them.
- **Fail closed.** If the tunnel is down, Harmonium sends silence (or idle modem frames), never
  the plain microphone.
- **Everything runs offline.** Every stage is file-in, file-out, so it can be tested without
  Discord.
- **Platform code lives in `harmonium-audio`.** Every other crate is pure.

## Layout

| Crate | Role |
|---|---|
| `harmonium-voice` | Codec 2 encode/decode, 48 kHz ↔ 8 kHz resampling, voice packets |
| `harmonium-link` | WireGuard session over the modem (GotaTun `Tunn`), channels, timers |
| `harmonium-modem` | packets ↔ audio: COBS framing, Reed-Solomon, chirp sync, OFDM / MFSK |
| `harmonium-keys` | identities, peer bundles, fingerprints, QR codes, key pinning |
| `harmonium-text` | age-encrypted text messages that fit Discord's 2000-character limit |
| `harmonium-audio` | virtual devices (PipeWire / VB-CABLE) and audio I/O |
| `harmonium-cli` | the `harmonium` binary |
| `tools/channel-sim` | offline Opus channel (loss, bursts, noise) and the modem bake-off |

## Build

```
cargo test --workspace --release
cargo deny check
```

Linux needs ALSA headers and CMake (libopus is built from source by the `opus` crate).
Windows needs CMake and a C toolchain.

## Release

`scripts/release.sh --container` builds both OSes on a Linux machine inside the pinned
`Containerfile` image (podman or docker): Windows is cross-built with
[llvm-mingw](https://github.com/mstorsjo/llvm-mingw) for `x86_64-pc-windows-gnullvm`, statically
linked, so the exe needs only system DLLs. It packs both into `out/release/<version>/`, writes
`SHA256SUMS` and signs it on the host with an SSH key (`ssh-keygen -Y sign`, namespace
`harmonium-release`), so the key never enters the container. Without `--container` it uses the
host toolchain (set `LLVM_MINGW`). CI builds the same archives unsigned on every push to main.
Check a download with:

```
scripts/verify-release.sh <dir>     # or by hand:
ssh-keygen -Y verify -f docs/allowed_signers -I release@harmonium -n harmonium-release \
    -s SHA256SUMS.sig < SHA256SUMS && sha256sum -c SHA256SUMS
```

## Licensing

Harmonium is MPL-2.0. `codec2` is LGPL-2.1-only: fine for source distribution; a binary
release must let users relink against a modified codec2.
