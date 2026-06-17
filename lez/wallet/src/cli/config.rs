use anyhow::Result;
use clap::Subcommand;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Represents generic config CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigSubcommand {
    /// Getter of config fields.
    Get {
        /// Print all config fields.
        #[arg(short, long)]
        all: bool,
        /// Config field key to get.
        key: Option<String>,
    },
    /// Setter of config fields.
    Set { key: String, value: String },
    /// Prints description of corresponding field.
    Description { key: String },
}

impl ConfigSubcommand {
    async fn handle_get(
        all: bool,
        key: Option<String>,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let config = wallet_core.config();
        if all {
            let config_str = serde_json::to_string_pretty(&config)?;

            println!("{config_str}");
        } else if let Some(key) = key {
            match key.as_str() {
                "sequencer_addr" => {
                    println!("{}", config.sequencer_addr);
                }
                "seq_poll_timeout" => {
                    println!("{:?}", config.seq_poll_timeout);
                }
                "seq_tx_poll_max_blocks" => {
                    println!("{}", config.seq_tx_poll_max_blocks);
                }
                "seq_poll_max_retries" => {
                    println!("{}", config.seq_poll_max_retries);
                }
                "seq_block_poll_max_amount" => {
                    println!("{}", config.seq_block_poll_max_amount);
                }
                "basic_auth" => {
                    if let Some(basic_auth) = &config.basic_auth {
                        println!("{basic_auth}");
                    } else {
                        println!("Not set");
                    }
                }
                _ => {
                    println!("Unknown field");
                }
            }
        } else {
            println!("Please provide a key or use --all flag");
        }

        Ok(SubcommandReturnValue::Empty)
    }

    async fn handle_set(
        key: String,
        value: String,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let mut config = wallet_core.config().clone();
        match key.as_str() {
            "sequencer_addr" => {
                config.sequencer_addr = value.parse()?;
            }
            "seq_poll_timeout" => {
                config.seq_poll_timeout = humantime::parse_duration(&value)
                    .map_err(|e| anyhow::anyhow!("Invalid duration: {e}"))?;
            }
            "seq_tx_poll_max_blocks" => {
                config.seq_tx_poll_max_blocks = value.parse()?;
            }
            "seq_poll_max_retries" => {
                config.seq_poll_max_retries = value.parse()?;
            }
            "seq_block_poll_max_amount" => {
                config.seq_block_poll_max_amount = value.parse()?;
            }
            "basic_auth" => {
                config.basic_auth = Some(value.parse()?);
            }
            "initial_accounts" => {
                anyhow::bail!("Setting this field from wallet is not supported");
            }
            _ => {
                anyhow::bail!("Unknown field");
            }
        }

        wallet_core.set_config(config);
        wallet_core.store_config_changes().await?;

        Ok(SubcommandReturnValue::Empty)
    }

    async fn handle_description(
        key: String,
        _wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match key.as_str() {
            "override_rust_log" => {
                println!("Value of variable RUST_LOG to override, affects logging");
            }
            "sequencer_addr" => {
                println!("HTTP V4 account_id of sequencer");
            }
            "seq_poll_timeout" => {
                println!(
                    "Sequencer client retry variable: how much time to wait between retries (human readable duration)"
                );
            }
            "seq_tx_poll_max_blocks" => {
                println!(
                    "Sequencer client polling variable: max number of blocks to poll to find a transaction"
                );
            }
            "seq_poll_max_retries" => {
                println!(
                    "Sequencer client retry variable: max number of retries before failing(can be zero)"
                );
            }
            "seq_block_poll_max_amount" => {
                println!(
                    "Sequencer client polling variable: max number of blocks to request in one polling call"
                );
            }
            "initial_accounts" => {
                println!("List of initial accounts' keys(both public and private)");
            }
            "basic_auth" => {
                println!("Basic authentication credentials for sequencer HTTP requests");
            }
            _ => {
                println!("Unknown field");
            }
        }

        Ok(SubcommandReturnValue::Empty)
    }
}

impl WalletSubcommand for ConfigSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Get { all, key } => Self::handle_get(all, key, wallet_core).await,
            Self::Set { key, value } => Self::handle_set(key, value, wallet_core).await,
            Self::Description { key } => Self::handle_description(key, wallet_core).await,
        }
    }
}
