//! Regenerate what the four-node docker devnet runs on
//! (`lez/sequencer/service/docker-compose.devnet.yml`): one sequencer config
//! all four nodes share, and a key directory per node.
//!
//! The shared config carries the genesis that stakes all four block-signing
//! keys, so the leader opens the channel already accrediting the whole
//! committee and the followers replay the same chain — the arrangement
//! `integration_tests/tests/multi_sequencer.rs` drives in-process. What is left
//! per node is its keys, handed to the binary with `--signing-key`.
//!
//! Run via `just regenerate-devnet-configs`, then commit the result. See this
//! crate's README for what is safe to edit by hand instead.

#![expect(clippy::print_stdout, reason = "It's normal in this small cli")]

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use lee::{PrivateKey, PublicKey};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_core::{
    config::{ChannelParams, GenesisAction, GossipConfig, SequencerConfig},
    sign_genesis_stake,
};
use sequencer_stake_core::SequencerKey;

/// Committee size the devnet compose file runs.
const NODES: usize = 4;

/// Slots a node's posting turn lasts on the devnet channel.
///
/// Below the production default the template carries: at 300 slots a turn comes
/// back round to a given node only every twenty minutes, so a devnet started to
/// watch rotation would show none.
const POSTING_TIMEFRAME: u32 = 60;

/// Every interface, on an OS-assigned port: peers find each other over mDNS, so
/// nothing has to be reachable at a fixed address.
const GOSSIP_LISTEN_ADDR: &str = "/ip4/0.0.0.0/udp/0/quic-v1";

/// The single-node config the devnet extends, and where its own go. The devnet
/// runs as part of the all-in-one compose project, so it inherits that config's
/// genesis and its Bedrock node, reached over the compose network.
const CONFIGS_DIR: &str = "lez/configs/docker-all-in-one";

/// Name of the shared config the compose file mounts into every node.
const CONFIG_NAME: &str = "sequencer_config.json";

fn main() -> Result<()> {
    let devnet_dir = repo_root().join(CONFIGS_DIR).join("devnet");
    let template_path = repo_root().join(CONFIGS_DIR).join(CONFIG_NAME);
    let mut config = SequencerConfig::from_path(&template_path).with_context(|| {
        format!(
            "Failed to read the single-node template config at {}",
            template_path.display()
        )
    })?;

    // Nothing here may differ between the nodes: they build this genesis
    // independently and have to arrive at the same chain.
    config.bedrock_config.channel_params.posting_timeframe = POSTING_TIMEFRAME;
    config.gossip = Some(GossipConfig {
        listen_addr: GOSSIP_LISTEN_ADDR
            .parse()
            .expect("hardcoded gossip listen multiaddr is valid"),
        bootstrap_peers: vec![],
    });
    // Each node is given its own with --signing-key instead.
    config.signing_key = None;

    let signing_keys: Vec<[u8; 32]> = std::iter::repeat_with(random_key).take(NODES).collect();
    let stakes = genesis_sequencer_stakes(&signing_keys, config.bedrock_config.channel_params)
        .context("Failed to build the founding sequencer stakes")?;
    // Ahead of the template's supplies: the stakes are funded from the faucet,
    // and the accounts they credit are not the supplied ones.
    config.genesis = stakes.into_iter().chain(config.genesis).collect();

    write_config(&devnet_dir, &config)?;
    println!("✅ Wrote {}", devnet_dir.join(CONFIG_NAME).display());

    for (index, signing_key) in signing_keys.iter().enumerate() {
        let dir = devnet_dir.join(format!("seq-{index}"));
        write_keys(&dir, *signing_key)
            .with_context(|| format!("Failed to write the keys for node {index}"))?;
        println!("✅ Wrote {}", dir.display());
    }

    Ok(())
}

/// Fresh 32 bytes for one identity.
///
/// Minted as a `PrivateKey` rather than straight off the RNG because a node's
/// key is read back as one through `--signing-key`, and not every 32 bytes are
/// a valid one — this is the constructor that keeps drawing until they are.
fn random_key() -> [u8; 32] {
    *PrivateKey::new_os_random().value()
}

/// Genesis entries staking every node, so the leader opens the channel already
/// accrediting all of them.
///
/// `channel_params` must be the ones the channel is created with: the minimum
/// stake is signed over, and a founding stake below it accredits nobody.
fn genesis_sequencer_stakes(
    signing_keys: &[[u8; 32]],
    channel_params: ChannelParams,
) -> Result<Vec<GenesisAction>> {
    let minimum_stake = channel_params.minimum_sequencer_stake;
    signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let public_key = Ed25519Key::from_bytes(signing_key).public_key();
            let sequencer_key = SequencerKey::new(public_key.to_bytes())
                .context("Sequencer signing key is not a valid Ed25519 point")?;
            // Separate from the signing key: block signing and stake control
            // are distinct roles.
            let owner = PrivateKey::new_os_random();
            Ok(GenesisAction::StakeSequencer {
                sequencer_key,
                ownership_public_key: PublicKey::new_from_private_key(&owner),
                // The index is signed over too, so these must stay in the order
                // they are written to the genesis list.
                stake_signature: sign_genesis_stake(index, sequencer_key, &owner, minimum_stake),
            })
        })
        .collect()
}

fn write_config(dir: &Path, config: &SequencerConfig) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;

    let mut serialized =
        serde_json::to_string_pretty(config).context("Failed to serialize the sequencer config")?;
    serialized.push('\n');
    let path = dir.join(CONFIG_NAME);
    std::fs::write(&path, serialized).context("Failed to write the sequencer config")?;
    // The node reads this back at boot, and a config it rejects there is a
    // devnet that only fails once it is started.
    SequencerConfig::from_path(&path).context("Wrote a config the sequencer cannot load")?;

    Ok(())
}

/// Writes one node's two identities. Both are the same 32 bytes: the stake in
/// the shared genesis accredits this key, and it is the Bedrock identity that
/// has to post under it.
fn write_keys(dir: &Path, signing_key: [u8; 32]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;

    for name in ["signing_key", "bedrock_signing_key"] {
        std::fs::write(dir.join(name), signing_key)
            .with_context(|| format!("Failed to write {name}"))?;
    }

    Ok(())
}

/// This crate sits two levels down, at `tools/devnet_configs`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
