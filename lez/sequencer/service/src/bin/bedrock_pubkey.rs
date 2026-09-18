//! Prints the sequencer's bedrock signing public key (hex) without booting it.
//!
//! Loads `<home>/bedrock_signing_key` from the given sequencer config, creating
//! the key if it doesn't exist yet, so that a node can be accredited into the
//! channel committee before its first boot.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    /// Override the config's home directory, matching the sequencer's --home.
    #[clap(long)]
    home: Option<PathBuf>,
}

#[expect(
    clippy::print_stdout,
    reason = "the hex pubkey on stdout is this binary's output"
)]
fn main() -> Result<()> {
    let Args { config_path, home } = Args::parse();

    let config = sequencer_service::SequencerConfig::from_path(&config_path)?;
    let home = home.unwrap_or(config.home);
    let key = sequencer_core::load_or_create_signing_key(&home.join("bedrock_signing_key"))?;
    println!("{}", hex::encode(key.public_key().to_bytes()));

    Ok(())
}
