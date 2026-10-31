// libsodium and liboqs get randomness from advapi32 (RtlGenRandom, CryptGenRandom), but their
// -sys crates don't link it on windows-gnu. GNU ld resolves left to right, so it must come after
// -lsodium/-loqs: a link-arg is appended at the end, a #[link] attribute is not. This covers the
// crate's own tests; dependents (harmonium-cli) get advapi32 through the windows crate.
fn main() {
    let cfg = |name: &str| std::env::var(name).unwrap_or_default();
    if cfg("CARGO_CFG_TARGET_OS") == "windows" && cfg("CARGO_CFG_TARGET_ENV") == "gnu" {
        println!("cargo:rustc-link-arg=-ladvapi32");
    }
}
