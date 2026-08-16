use std::{io::Write as _, path::Path, time::Duration};

use anyhow::{Context as _, Result};
use common::config::BasicAuth;
use humantime_serde;
use log::warn;
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_CALLIBRATION_LIMIT: usize = 100;
const DEFAULT_DISTRIBUTION_LIMIT: usize = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerConnectionData {
    /// Connection data of all known sequencers.
    pub sequencer_addr: Url,
    /// Basic authentication credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Gas spent per deploying one byte of data.
    pub gas_fee_per_byte_deploy: u64,
    /// Gas spent per reading one byte of data in VM.
    pub gas_fee_per_input_buffer_runtime: u64,
    /// Gas spent per one byte of contract data in runtime.
    pub gas_fee_per_byte_runtime: u64,
    /// Cost of one gas of runtime in public balance.
    pub gas_cost_runtime: u64,
    /// Cost of one gas of deployment in public balance.
    pub gas_cost_deploy: u64,
    /// Gas limit for deployment.
    pub gas_limit_deploy: u64,
    /// Gas limit for runtime.
    pub gas_limit_runtime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSequencerClientConfig {
    /// Maximum numbers of sequencers to send requests. Client can have AT MOST
    /// `distribution_limit` active clients.
    pub distribution_limit: usize,
    /// Limit number of sequencer polls during callibration, should not be zero.
    pub calibration_limit: usize,
}

impl Default for MultiSequencerClientConfig {
    fn default() -> Self {
        Self {
            distribution_limit: DEFAULT_DISTRIBUTION_LIMIT,
            calibration_limit: DEFAULT_CALLIBRATION_LIMIT,
        }
    }
}

#[optfield::optfield(pub WalletConfigOverrides, rewrap, attrs = (derive(Debug, Default, Clone)))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Legacy top-level sequencer address for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_addr: Option<Url>,
    /// Connection data of all known sequencers.
    pub sequencers: Vec<SequencerConnectionData>,
    /// Sequencer polling duration for new blocks.
    #[serde(with = "humantime_serde")]
    pub seq_poll_timeout: Duration,
    /// Sequencer polling max number of blocks to find transaction.
    pub seq_tx_poll_max_blocks: usize,
    /// Sequencer polling max number error retries.
    pub seq_poll_max_retries: u64,
    /// Max amount of blocks to poll in one request.
    pub seq_block_poll_max_amount: u64,
    #[serde(default = "MultiSequencerClientConfig::default")]
    pub multi_sequencer_client_config: MultiSequencerClientConfig,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            sequencer_addr: None,
            sequencers: vec![SequencerConnectionData {
                sequencer_addr: "https://testnet.lez.logos.co".parse().unwrap(),
                basic_auth: None,
            }],
            seq_poll_timeout: Duration::from_secs(12),
            seq_tx_poll_max_blocks: 5,
            seq_poll_max_retries: 5,
            seq_block_poll_max_amount: 100,
            multi_sequencer_client_config: MultiSequencerClientConfig::default(),
        }
    }
}

impl WalletConfig {
    pub fn from_path_or_initialize_default(config_path: &Path) -> Result<Self> {
        match std::fs::File::open(config_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let mut config: WalletConfig = serde_json::from_reader(reader)?;
                if config.sequencers.is_empty() {
                    if let Some(ref addr) = config.sequencer_addr {
                        config.sequencers.push(SequencerConnectionData {
                            sequencer_addr: addr.clone(),
                            basic_auth: None,
                        });
                    }
                }
                Ok(config)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                println!("Config not found, setting up default config");

                let config_home = config_path.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not get parent directory of config file at {}",
                        config_path.display()
                    )
                })?;
                std::fs::create_dir_all(config_home)?;

                println!("Created configs dir at path {}", config_home.display());

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(config_path)?;

                let config = Self::default();
                let default_config_serialized = serde_json::to_vec_pretty(&config).unwrap();

                file.write_all(&default_config_serialized)?;

                println!("Configs set up");
                Ok(config)
            }
            Err(err) => Err(err).context("IO error"),
        }
    }

    pub fn apply_overrides(&mut self, overrides: WalletConfigOverrides) {
        let Self {
            sequencers,
            seq_poll_timeout,
            seq_tx_poll_max_blocks,
            seq_poll_max_retries,
            seq_block_poll_max_amount,
            multi_sequencer_client_config,
        } = self;

        let WalletConfigOverrides {
            sequencers: o_sequencers,
            seq_poll_timeout: o_seq_poll_timeout,
            seq_tx_poll_max_blocks: o_seq_tx_poll_max_blocks,
            seq_poll_max_retries: o_seq_poll_max_retries,
            seq_block_poll_max_amount: o_seq_block_poll_max_amount,
            multi_sequencer_client_config: o_multi_sequencer_client_config,
        } = overrides;

        if let Some(v) = o_sequencers {
            warn!("Overriding wallet config 'sequencers' to {v:?}");
            *sequencers = v;
        }
        if let Some(v) = o_seq_poll_timeout {
            warn!("Overriding wallet config 'seq_poll_timeout' to {v:?}");
            *seq_poll_timeout = v;
        }
        if let Some(v) = o_seq_tx_poll_max_blocks {
            warn!("Overriding wallet config 'seq_tx_poll_max_blocks' to {v}");
            *seq_tx_poll_max_blocks = v;
        }
        if let Some(v) = o_seq_poll_max_retries {
            warn!("Overriding wallet config 'seq_poll_max_retries' to {v}");
            *seq_poll_max_retries = v;
        }
        if let Some(v) = o_seq_block_poll_max_amount {
            warn!("Overriding wallet config 'seq_block_poll_max_amount' to {v}");
            *seq_block_poll_max_amount = v;
        }
        if let Some(v) = o_multi_sequencer_client_config {
            warn!("Overriding wallet config 'multi_sequencer_client_config' to {v:?}");
            *multi_sequencer_client_config = v;
        }
    }
}
