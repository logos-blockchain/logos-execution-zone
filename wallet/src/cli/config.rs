use anyhow::Result;
use clap::Subcommand;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    config::InitialAccountData,
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

impl WalletSubcommand for ConfigSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Get { all, key } => {
                if all {
                    let config_str =
                        serde_json::to_string_pretty(&wallet_core.storage.wallet_config)?;

                    println!("{config_str}");
                } else if let Some(key) = key {
                    match key.as_str() {
                        "sequencer_addr" => {
                            println!("{}", wallet_core.storage.wallet_config.sequencer_addr);
                        }
                        "seq_poll_timeout" => {
                            println!("{:?}", wallet_core.storage.wallet_config.seq_poll_timeout);
                        }
                        "seq_tx_poll_max_blocks" => {
                            println!(
                                "{}",
                                wallet_core.storage.wallet_config.seq_tx_poll_max_blocks
                            );
                        }
                        "seq_poll_max_retries" => {
                            println!("{}", wallet_core.storage.wallet_config.seq_poll_max_retries);
                        }
                        "seq_block_poll_max_amount" => {
                            println!(
                                "{}",
                                wallet_core.storage.wallet_config.seq_block_poll_max_amount
                            );
                        }
                        "initial_accounts" => {
                            println!(
                                "{:#?}",
                                wallet_core
                                    .storage
                                    .wallet_config
                                    .initial_accounts
                                    .clone()
                                    .unwrap_or_else(
                                        InitialAccountData::create_initial_accounts_data
                                    )
                            );
                        }
                        "basic_auth" => {
                            if let Some(basic_auth) = &wallet_core.storage.wallet_config.basic_auth
                            {
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
            }
            Self::Set { key, value } => {
                match key.as_str() {
                    "sequencer_addr" => {
                        wallet_core.storage.wallet_config.sequencer_addr = value.parse()?;
                    }
                    "seq_poll_timeout" => {
                        wallet_core.storage.wallet_config.seq_poll_timeout =
                            humantime::parse_duration(&value)
                                .map_err(|e| anyhow::anyhow!("Invalid duration: {e}"))?;
                    }
                    "seq_tx_poll_max_blocks" => {
                        wallet_core.storage.wallet_config.seq_tx_poll_max_blocks = value.parse()?;
                    }
                    "seq_poll_max_retries" => {
                        wallet_core.storage.wallet_config.seq_poll_max_retries = value.parse()?;
                    }
                    "seq_block_poll_max_amount" => {
                        wallet_core.storage.wallet_config.seq_block_poll_max_amount =
                            value.parse()?;
                    }
                    "basic_auth" => {
                        wallet_core.storage.wallet_config.basic_auth = Some(value.parse()?);
                    }
                    "initial_accounts" => {
                        anyhow::bail!("Setting this field from wallet is not supported");
                    }
                    _ => {
                        anyhow::bail!("Unknown field");
                    }
                }

                wallet_core.store_config_changes().await?;
            }
            Self::Description { key } => match key.as_str() {
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
            },
        }

        Ok(SubcommandReturnValue::Empty)
    }
}
