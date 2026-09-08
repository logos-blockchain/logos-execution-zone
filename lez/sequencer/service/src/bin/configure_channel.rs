//! Posts a `ChannelConfig` op (accredited keys + rotation params) to bedrock,
//! signed with `<home>/bedrock_signing_key`, without booting the sequencer.
//!
//! Authorization is holding the admin key file — the L1 rejects non-admin
//! signers. Acceptance is asynchronous: a rejection only shows up in node
//! logs and on-chain behavior.

use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use kameo::actor::Spawn as _;
use sequencer_core::Ed25519PublicKey;

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
    let Args {
        config_path,
        home,
        keys,
        posting_timeframe,
        posting_timeout,
        configuration_threshold,
        transfer_threshold,
    } = Args::parse();

    let config = sequencer_service::SequencerConfig::from_path(&config_path)?;
    let home = home.unwrap_or(config.home);
    let bedrock_signing_key =
        sequencer_core::load_or_create_signing_key(&home.join("bedrock_signing_key"))?;
    let keys = keys
        .iter()
        .map(|key| parse_key(key))
        .collect::<Result<Vec<_>>>()?;

    let bedrock_config = sequencer_bedrock_actor::config::Config {
        node_url: config.bedrock_config.node_url,
        basic_auth: config.bedrock_config.auth.map(Into::into),
        channel_id: config.bedrock_config.channel_id,
        bedrock_signing_key,
        funding_pk: config.bedrock_config.funding_key,
        priority_fee_percent: config.bedrock_config.priority_fee_percent,
        resubmit_interval: config.retry_pending_blocks_timeout,
    };

    let mut mock_storage = sequencer_storage_actor::mock::MockStorageActor::default();
    mock_storage
        .expect_handle_get_zone_checkpoint_bytes()
        .returning(|_msg, _ctx| Ok(None));
    let mock_storage_ref = sequencer_storage_actor::mock::MockStorageActor::spawn(mock_storage);

    let broker_ref = kameo_actors::broker::Broker::spawn(kameo_actors::broker::Broker::new(
        kameo_actors::DeliveryStrategy::Guaranteed,
    ));

    let bedrock =
        sequencer_bedrock_actor::BedrockActor::new(bedrock_config, mock_storage_ref, broker_ref)
            .await
            .context("Failed to setup Bedrock Actor")?;
    let bedrock_ref = sequencer_bedrock_actor::BedrockActor::spawn(bedrock);

    bedrock_ref
        .ask(sequencer_bedrock_actor::protocol::ChangeChannelConfig {
            new_keys: keys,
            posting_timeframe,
            posting_timeout,
            configuration_threshold,
            transfer_threshold,
        })
        .await?;

    Ok(())
}

fn parse_key(hex_key: &str) -> Result<Ed25519PublicKey> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(hex_key, &mut bytes)
        .with_context(|| format!("Invalid hex-encoded key {hex_key}"))?;
    Ed25519PublicKey::from_bytes(&bytes).map_err(|err| anyhow!("Invalid Ed25519 public key: {err}"))
}
