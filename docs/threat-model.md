# Threat model

What Harmonium protects, from whom, and where the edges are. Update it
when the code changes what any line below claims.

## The claim, precisely

Discord calls are already end-to-end encrypted (DAVE). Harmonium removes the need to trust
**Discord's client, Discord's key distribution and Discord's identity binding**. Nothing more.

With Harmonium, Discord carries only modem audio (WireGuard packets) and age ciphertext. A party
that controls Discord's servers or its client can hear modem noise and read armored text, but
cannot recover speech or plaintext, cannot impersonate your friend, and cannot replay or alter
packets without detection.

## Assets

| Asset | Where it lives |
|---|---|
| Speech content | mic → Codec 2 → WireGuard, never leaves the machine in clear |
| Text content | age-encrypted before it touches the clipboard / Discord |
| Long-term identity (Curve25519 WireGuard key + age X25519 key) | `<config_dir>/harmonium/identity.toml` |
| Rosenpass keys (Classic McEliece + Kyber) | same directory, `pq` feature only |
| Peer pins (public keys, verified flag) | same directory |

## Adversaries

1. **Discord (server or client), or anyone with access to its data.** Sees and can modify all
   call audio and messages. Main adversary; fully in scope.
2. **A network attacker between you and Discord.** Strictly weaker than (1): TLS/DTLS to Discord,
   then WireGuard inside. In scope.
3. **A future quantum attacker recording calls today.** In scope only with `--pq`: Rosenpass puts
   a post-quantum secret into WireGuard's PSK slot. Without `--pq`, recorded calls rest on
   Curve25519.
4. **Malware or another user on your own machine.** Out of scope. It can read the mic before
   encryption and the key files. See "Local machine" for what we still do.
5. **The person you call.** Trusted with the content (they hear it), not trusted with your keys.

## What the protocol gives you

- **Confidentiality and integrity**: WireGuard (GotaTun `Tunn`): Noise IKpsk2, ChaCha20-Poly1305,
  per-direction keys, rekey every 2 minutes, forward secrecy across rekeys.
- **Replay protection**: WireGuard's 64-bit counter and sliding replay window.
- **Authentication**: both peers' static keys are pinned. A call to an unverified peer is refused
  unless `--allow-unverified` is passed.
- **Fail closed**: if the tunnel is down, the modem sends idle frames, never the microphone. With
  `--pq`, voice is held back until the session is keyed with the PQ PSK and has completed a
  handshake. Each new PSK goes into the next handshake. If a PSK expires before the next one
  arrives, voice is held back again.
- **No custom crypto**: primitives come only from GotaTun, Rosenpass and age, enforced by
  `deny.toml`.

## The one human step

The trust model is a single fingerprint comparison per friend, done once over a channel Discord
does not control (in person, a QR code, Signal). If you skip it and accept a bundle that Discord
swapped, Discord sits in the middle of every later call. Do not compare fingerprints by reading
them aloud on the Discord call itself: that audio is exactly what an adversary in position (1)
controls (voice cloning is cheap).

## What is NOT protected

- **Metadata.** Discord still sees who calls whom, when, and for how long, which servers and DMs
  you use, and message timing and length. This is the same limit DAVE states.
- **The fact that you use Harmonium.** Modem audio is obviously not speech. This is not covert
  communication, and Discord could detect and block it.
- **Speech activity.** Codec 2 encodes every 20 ms frame whether you talk or not, so packet timing
  does not reveal when you speak. Do not rely on this as a hard guarantee: it is a property of
  the current send loop, not a design invariant enforced by a test.
- **Text length.** age ciphertext length tracks plaintext length. Armoring adds a fixed
  overhead, then base64 grows it by a third.
- **Availability.** Discord can drop, delay or garble the audio at will. Harmonium detects this
  but cannot prevent it.
- **Post-quantum caveat.** Rosenpass uses pre-standard round-3 Kyber-512, not final ML-KEM. If
  Rosenpass fails, WireGuard's classical security still holds. Text (age X25519) has no
  post-quantum protection.

## Attack surface: untrusted input

Everything that arrives from Discord is attacker-controlled. In order:

1. **Audio samples** → modem demodulator (chirp sync, OFDM-DQPSK / MFSK). Bounded buffers; no
   parsing.
2. **Modem deframer**: COBS decode, CRC-16 check, Reed-Solomon decode. First parser of
   attacker bytes. Fuzzed (`deframer`, `modem_rx`).
3. **WireGuard** `Tunn::decapsulate`: GotaTun, independently audited (Jan–Feb 2026). Anything not
   authenticated is dropped here.
4. **Voice packet parser** (`VoicePacket::from_bytes`) and the link's channel header. These only
   see authenticated packets from a pinned peer. Fuzzed (`voice_packet`, and `link_receive`,
   which also feeds raw bytes to the link before and after the handshake).
5. **Rosenpass messages** (`pq`): parsed by the Rosenpass crate. Its responder cost is dominated
   by McEliece decapsulation, so unauthenticated InitHello floods cost CPU. The 3.9 kbps modem
   caps that at about one message every 2–3 seconds.
6. **Armored text** pasted from Discord: armor extraction, then age decryption. A malformed blob
   is an error, never a panic. Fuzzed (`text_decrypt`).

A parser bug in (2) can be reached by anyone who can inject audio into the call. Bugs in (4) need
the peer's keys.

The fuzz targets live in `fuzz/` (its own workspace, nightly toolchain):
`cargo +nightly fuzz run -O <target>`. A first run of 60 s per target (about 28 million inputs in
all) found no crashes.

## Local machine

Out of scope as an adversary, but we still:

- write key files atomically, with mode 0600 on Unix. On Windows they live in `%APPDATA%`, which
  only the user, SYSTEM and Administrators can read by default. Harmonium sets no explicit ACL.
- never log keys, PSKs or plaintext.
- on Windows, turn Discord's volume-mixer level down to -60 dB during a call (the receive path
  records Discord's own audio with WASAPI process loopback), and restore it afterwards. A
  session already at Harmonium's level is treated as left over from a crashed run and restored to
  100%.

- wipe Harmonium's own copies of secrets when they are dropped (`zeroize`): the WireGuard
  private key, the key file text and decoded bytes, the PQ secret key and every PSK. GotaTun,
  Rosenpass and age manage their own copies. Short-lived stack copies (passing a key by value)
  are not tracked, so swap and crash dumps can still hold key bytes.

A responder only counts a WireGuard session as up once a packet from the initiator decrypts under
it (key confirmation). With a mismatched PSK, neither side ever reports the link up.

## Windows specifics

- **Kernel driver trust.** The send side uses VB-CABLE, a signed third-party audio driver. Install
  it from VB-Audio only. The receive side needs no driver (WASAPI process loopback, Windows 10
  2004+).
- **Terms of service.** Harmonium does not modify Discord or automate an account. It only changes
  which audio device Discord uses, and on Windows the volume-mixer level of Discord's audio
  session.
