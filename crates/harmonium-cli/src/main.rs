//! The `harmonium` binary: encrypted voice and text over a Discord call.

mod call;
mod cli;
mod devices;
mod keys;
mod selftest;
mod text;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};
use harmonium_keys::Store;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            1
        }
    };
    ExitCode::from(code)
}

fn run(cli: Cli) -> Result<u8> {
    let dir = cli.home.unwrap_or_else(Store::default_dir);
    let store = Store::open(&dir);

    match cli.command {
        Command::Keygen { force } => keys::run_keygen(&store, &dir, force),
        Command::Id => keys::run_id(&store),
        Command::Peer { cmd } => keys::run_peer(&store, &cmd),
        Command::Devices { cmd } => devices::run(&cmd),
        Command::Text { cmd } => text::run(&store, &cmd),
        Command::Selftest(opts) => selftest::run(&opts),
        Command::Call(opts) => {
            call::run_call(&store, &opts)?;
            Ok(0)
        }
    }
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
