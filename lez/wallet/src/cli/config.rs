use anyhow::Result;
use clap::Subcommand;
use common::config::BasicAuth;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    config::SequencerConnectionData,
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
    /// Adds a new sequencer to the list.
    AddSequencer {
        addr: String,
        user: Option<String>,
        password: Option<String>,
    },
    /// Remove sequencer from a list.
    RemoveSequencer { addr: String },
}

impl ConfigSubcommand {
    fn handle_get(
        all: bool,
        key: Option<String>,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let config = wallet_core.config();
        if all {
            let config_str = serde_json::to_string_pretty(&config)?;

            println!("{config_str}");
        } else if let Some(key) = key {
            match key.as_str() {
                "sequencers" => {
                    println!("{:?}", config.sequencers);
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
                "distribution_limit" => {
                    println!(
                        "{}",
                        config.multi_sequencer_client_config.distribution_limit
                    );
                }
                "calibration_limit" => {
                    println!("{}", config.multi_sequencer_client_config.calibration_limit);
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
            "sequencers" => {
                anyhow::bail!("Not settable via this method, use add-sequencer subcommand");
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
            "distribution_limit" => {
                config.multi_sequencer_client_config.distribution_limit = value.parse()?;
            }
            "calibration_limit" => {
                config.multi_sequencer_client_config.calibration_limit = value.parse()?;
            }
            _ => {
                anyhow::bail!("Unknown field");
            }
        }

        wallet_core.set_config(config);
        wallet_core.store_config_changes().await?;

        Ok(SubcommandReturnValue::Empty)
    }

    fn handle_description(key: &str, _wallet_core: &WalletCore) -> SubcommandReturnValue {
        match key {
            "override_rust_log" => {
                println!("Value of variable RUST_LOG to override, affects logging");
            }
            "sequencer" => {
                println!("A list of HTTP V4 addresses of sequencer, with authorization");
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
            "distribution_limit" => {
                println!(
                    "Sequencer multi node variable: max number of nodes to distribute transaction(can not be zero)"
                );
            }
            "calibration_limit" => {
                println!(
                    "Sequencer multi node variable: max number of callibration runs before the end of handshake(can not be zero)"
                );
            }
            _ => {
                println!("Unknown field");
            }
        }

        SubcommandReturnValue::Empty
    }
}

impl WalletSubcommand for ConfigSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Get { all, key } => Self::handle_get(all, key, wallet_core),
            Self::Set { key, value } => Self::handle_set(key, value, wallet_core).await,
            Self::Description { key } => Ok(Self::handle_description(&key, wallet_core)),
            Self::AddSequencer {
                addr,
                user,
                password,
            } => {
                let url_addr = addr.parse()?;

                let basic_auth = user.map(|user| {
                    let mut basic_auth = BasicAuth {
                        username: user,
                        password: None,
                    };

                    if password.is_some() {
                        basic_auth.password = password;
                    }

                    basic_auth
                });

                let seq_connection_data = SequencerConnectionData {
                    sequencer_addr: url_addr,
                    basic_auth,
                };

                wallet_core.add_sequencer(seq_connection_data);

                Ok(SubcommandReturnValue::Empty)
            }
            Self::RemoveSequencer { addr } => {
                let url_addr = addr.parse()?;

                wallet_core.remove_sequencer(&url_addr)?;

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
