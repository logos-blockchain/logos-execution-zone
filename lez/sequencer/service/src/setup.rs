//! What `sequencer_service setup` does, shared with embedders such as `core_ffi`, which prepare a
//! home the same way before starting out of it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use sequencer_core::{Ed25519PublicKey, config::GenesisAction};
use sequencer_stake_core::SequencerKey;
use serde::Deserialize;

use crate::{CONFIG_FILE, SequencerConfig};

/// What `setup` prepares a home with, as flags or, for embedders, JSON fields of the same names.
#[derive(Debug, clap::Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupArgs {
    /// Config to copy into the home, e.g. one of `lez/sequencer/service/networks/`.
    #[clap(long)]
    pub config: PathBuf,
    /// Public key, in hex, of a funded key in the Bedrock node's wallet; it pays the
    /// node's inscriptions.
    #[clap(long)]
    pub funding_public_key: String,
    /// Keeps the config's `genesis`, so `start` creates the channel if it does not exist.
    #[clap(long)]
    #[serde(default)]
    pub create_channel: bool,
}

impl SetupArgs {
    /// Sets up `home` with these args, see [`setup`].
    pub fn run(&self, home: &Path) -> Result<SetUp> {
        let template = std::fs::read_to_string(&self.config)
            .with_context(|| format!("Failed to read {}", self.config.display()))?;
        setup(
            home,
            &template,
            &self.funding_public_key,
            self.create_channel,
        )
    }
}

/// A home [`setup`] prepared.
pub struct SetUp {
    /// The home, canonicalized.
    pub home: PathBuf,
    /// What the node signs the channel with: the key to stake, unless `staked_at_genesis`.
    pub channel_public_key: Ed25519PublicKey,
    /// Whether creating the channel stakes the channel key at genesis.
    pub staked_at_genesis: bool,
}

/// Creates `home` with its config, channel signing key and Bedrock funding public key.
///
/// The config is `template` with `home` filled in, keeping its genesis only with
/// `create_channel`. An existing channel signing key is kept: it may already be staked. A home
/// that is already set up is refused.
pub fn setup(
    home: &Path,
    template: &str,
    funding_public_key: &str,
    create_channel: bool,
) -> Result<SetUp> {
    ensure!(
        !home.join(CONFIG_FILE).exists(),
        "{} is already set up",
        home.display()
    );
    sequencer_core::parse_funding_public_key(funding_public_key)
        .context("Invalid --funding-public-key")?;
    std::fs::create_dir_all(home)
        .with_context(|| format!("Failed to create {}", home.display()))?;
    let home = home
        .canonicalize()
        .with_context(|| format!("Failed to resolve {}", home.display()))?;

    // Not `SequencerConfig::from_path`: its genesis checks don't apply to a joiner, who drops it.
    let mut config: SequencerConfig =
        serde_json::from_str(template).context("Failed to read the config")?;
    config.home.clone_from(&home);
    if create_channel {
        let genesis = config
            .genesis
            .as_ref()
            .context("--create-channel needs a config with a `genesis`")?;
        sequencer_core::config::check_channel_params(
            &genesis.channel_params,
            config.block_create_timeout,
        )?;
    } else {
        // Without it, a node pointed at the wrong channel fails instead of creating that one.
        config.genesis = None;
    }
    // An existing key is kept: it may already be staked.
    let channel_key = sequencer_core::load_or_create_signing_key(
        &home.join(sequencer_core::CHANNEL_SIGNING_KEY_FILE),
    )?;
    std::fs::write(
        home.join(sequencer_core::BEDROCK_FUNDING_PUBLIC_KEY_FILE),
        funding_public_key.trim(),
    )
    .context("Failed to write the funding public key")?;
    let config_json =
        serde_json::to_string_pretty(&config).context("Failed to serialize the config")?;
    std::fs::write(home.join(CONFIG_FILE), config_json).context("Failed to write the config")?;

    // Creating the channel self-stakes the key unless the genesis lists founding stakes.
    let own_key = SequencerKey::new(channel_key.public_key().to_bytes());
    let staked_at_genesis = create_channel
        && config.genesis.as_ref().is_some_and(|genesis| {
            let founding: Vec<_> = genesis
                .actions
                .iter()
                .filter_map(|action| match action {
                    GenesisAction::StakeSequencer { sequencer_key, .. } => Some(*sequencer_key),
                    GenesisAction::SupplyAccount { .. }
                    | GenesisAction::SupplyPrivateAccount { .. } => None,
                })
                .collect();
            founding.is_empty() || own_key.is_some_and(|key| founding.contains(&key))
        });

    Ok(SetUp {
        home,
        channel_public_key: channel_key.public_key(),
        staked_at_genesis,
    })
}
