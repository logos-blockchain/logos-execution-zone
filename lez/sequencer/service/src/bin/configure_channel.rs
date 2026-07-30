//! Posts a `ChannelConfig` op (accredited keys + rotation params) to bedrock,
//! signed with `<home>/bedrock_signing_key`, without booting the sequencer.
//!
//! Authorization is holding the admin key file — the L1 rejects non-admin
//! signers. Acceptance is asynchronous: a rejection only shows up in node
//! logs and on-chain behavior.

use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use sequencer_core::block_publisher::{Ed25519PublicKey, post_channel_config};

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    /// Override the config's home directory, matching the sequencer's --home.
    #[clap(long)]
    home: Option<PathBuf>,
    /// Accredited ed25519 public keys (hex), admin (this node's key) first.
    #[clap(long, required = true, value_delimiter = ',')]
    keys: Vec<String>,
    /// Slots a sequencer's posting turn lasts.
    #[clap(long)]
    posting_timeframe: u32,
    /// Slots after which a stalled turn can be taken over.
    #[clap(long)]
    posting_timeout: u32,
    /// Signatures required for future config changes.
    #[clap(long, default_value_t = 1)]
    configuration_threshold: u16,
    /// Signatures required for channel transfers.
    #[clap(long, default_value_t = 1)]
    transfer_threshold: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config = sequencer_service::SequencerConfig::from_path(&args.config_path)?;
    let home = args.home.unwrap_or(config.home);
    let signing_key =
        sequencer_core::load_or_create_signing_key(&home.join("bedrock_signing_key"))?;
    let keys = args
        .keys
        .iter()
        .map(|key| parse_key(key))
        .collect::<Result<Vec<_>>>()?;

    post_channel_config(
        &config.bedrock_config,
        &signing_key,
        keys,
        args.posting_timeframe,
        args.posting_timeout,
        args.configuration_threshold,
        args.transfer_threshold,
    )
    .await
}

fn parse_key(hex_key: &str) -> Result<Ed25519PublicKey> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(hex_key, &mut bytes)
        .with_context(|| format!("Invalid hex-encoded key {hex_key}"))?;
    Ed25519PublicKey::from_bytes(&bytes).map_err(|err| anyhow!("Invalid Ed25519 public key: {err}"))
}
