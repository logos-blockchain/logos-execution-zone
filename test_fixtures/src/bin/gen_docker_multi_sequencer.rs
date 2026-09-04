//! Regenerate the committed docker configs that run four sequencers on one
//! channel, staked at genesis. Run via `just regenerate-multi-sequencer-configs`,
//! then commit the result.
//!
//! Every node gets the same genesis (the all-in-one genesis plus one
//! `StakeSequencer` per node, in a fixed order the signatures commit to), so
//! whichever node creates the channel opens it already accrediting all four.
//! The signatures pin the nodes' Bedrock keys, so those are written out too:
//! a node generating its own would not be the one staked.

#![expect(clippy::print_stdout, reason = "It's normal in this small cli")]

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use sequencer_core::config::SequencerConfig;
use test_fixtures::config;

/// Sequencers to configure. Their signing keys are `SEQUENCER_SIGNING_KEY` for
/// node 0 and `sequencer_signing_key_from_seed(i)` after it, matching the
/// multi-node test context.
const NUM_SEQUENCERS: usize = 4;

/// The single-sequencer docker config the generated ones are derived from:
/// same Bedrock node, channel and account supply, only genesis and keys differ.
const BASE_CONFIG: &str = "lez/configs/docker-all-in-one/sequencer_config.json";

/// Where the generated configs and Bedrock signing keys land.
const OUT_DIR: &str = "lez/configs/docker-multi-sequencer";

fn main() -> Result<()> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("test_fixtures has no parent directory")?
        .to_owned();
    let out_dir = repo_root.join(OUT_DIR);
    let keys_dir = out_dir.join("keys");
    std::fs::create_dir_all(&keys_dir)
        .with_context(|| format!("Failed to create {}", keys_dir.display()))?;

    let base = SequencerConfig::from_path(&repo_root.join(BASE_CONFIG))
        .context("Failed to read the base sequencer config")?;

    let signing_keys = signing_keys()?;
    let mut genesis = config::genesis_sequencer_stakes(&signing_keys)
        .context("Failed to build the founding sequencer stakes")?;
    genesis.extend(base.genesis.iter().cloned());

    for (index, signing_key) in signing_keys.iter().enumerate() {
        let config = SequencerConfig {
            signing_key: *signing_key,
            genesis: genesis.clone(),
            ..base.clone()
        };
        let config_path = out_dir.join(format!("sequencer_config_{index}.json"));
        write(&config_path, {
            let mut json = serde_json::to_string_pretty(&config)
                .context("Failed to serialize the sequencer config")?;
            json.push('\n');
            json.into_bytes()
        })?;
        SequencerConfig::from_path(&config_path)
            .context("Generated a sequencer config the service cannot read back")?;
        write(
            &keys_dir.join(format!("bedrock_signing_key_{index}")),
            signing_key.to_vec(),
        )?;
    }

    println!(
        "✅ Wrote {NUM_SEQUENCERS} sequencer configs to {}",
        out_dir.display()
    );
    Ok(())
}

/// The nodes' Bedrock signing keys, also used as their block signing keys.
/// Order is what the genesis stake signatures commit to.
fn signing_keys() -> Result<Vec<[u8; 32]>> {
    (0..NUM_SEQUENCERS)
        .map(|index| match index {
            0 => Ok(config::SEQUENCER_SIGNING_KEY),
            _ => Ok(config::sequencer_signing_key_from_seed(
                u32::try_from(index).context("Sequencer index does not fit a u32")?,
            )),
        })
        .collect()
}

fn write(path: &Path, contents: Vec<u8>) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("Failed to write {}", path.display()))
}
