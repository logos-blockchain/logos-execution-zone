use std::{io::Write as _, path::Path, time::Duration};

use anyhow::{Context as _, Result};
use common::config::BasicAuth;
use humantime_serde;
use log::warn;
use serde::{Deserialize, Serialize};
use url::Url;

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

#[optfield::optfield(pub WalletConfigOverrides, rewrap, attrs = (derive(Debug, Default, Clone)))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Sequencer URL.
    pub sequencer_addr: Url,
    /// Sequencer polling duration for new blocks.
    #[serde(with = "humantime_serde")]
    pub seq_poll_timeout: Duration,
    /// Sequencer polling max number of blocks to find transaction.
    pub seq_tx_poll_max_blocks: usize,
    /// Sequencer polling max number error retries.
    pub seq_poll_max_retries: u64,
    /// Max amount of blocks to poll in one request.
    pub seq_block_poll_max_amount: u64,
    /// Basic authentication credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            sequencer_addr: "http://127.0.0.1:3040".parse().unwrap(),
            seq_poll_timeout: Duration::from_secs(12),
            seq_tx_poll_max_blocks: 5,
            seq_poll_max_retries: 5,
            seq_block_poll_max_amount: 100,
            basic_auth: None,
        }
    }
}

impl WalletConfig {
    pub fn from_path_or_initialize_default(config_path: &Path) -> Result<Self> {
        match std::fs::File::open(config_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                Ok(serde_json::from_reader(reader)?)
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
            sequencer_addr,
            seq_poll_timeout,
            seq_tx_poll_max_blocks,
            seq_poll_max_retries,
            seq_block_poll_max_amount,
            basic_auth,
        } = self;

        let WalletConfigOverrides {
            sequencer_addr: o_sequencer_addr,
            seq_poll_timeout: o_seq_poll_timeout,
            seq_tx_poll_max_blocks: o_seq_tx_poll_max_blocks,
            seq_poll_max_retries: o_seq_poll_max_retries,
            seq_block_poll_max_amount: o_seq_block_poll_max_amount,
            basic_auth: o_basic_auth,
        } = overrides;

        if let Some(v) = o_sequencer_addr {
            warn!("Overriding wallet config 'sequencer_addr' to {v}");
            *sequencer_addr = v;
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
        if let Some(v) = o_basic_auth {
            warn!("Overriding wallet config 'basic_auth' to {v:#?}");
            *basic_auth = v;
        }
    }
}
