use anyhow::Result;
use clap::Subcommand;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    config::SequencerConnectionData,
    multi_client::{calibrate_client, make_subclient},
};

/// Represents generic config CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum StatisticsSubcommand {
    /// Show the list of the current leaders.
    ShowLeaders,
    /// Execute client list rotation, applies all statistics, the re-chooses the leaders.
    ExecuteRotation,
    /// (Re)callibrate the client.
    Callibrate { addr: String },
    /// Shpw the statistics of the client.
    ShowStatistics { addr: String },
}

impl WalletSubcommand for StatisticsSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::ShowLeaders => {
                let leader_urls = wallet_core
                    .leaders()
                    .iter()
                    .map(|(_, url)| url)
                    .collect::<Vec<_>>();

                println!("Leader URLs is {leader_urls:?}");

                Ok(SubcommandReturnValue::Empty)
            }
            Self::ExecuteRotation => {
                wallet_core.client_rotation().await?;

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Callibrate { addr } => {
                let url_addr = addr.parse()?;
                let calibration_limit = wallet_core
                    .config()
                    .multi_sequencer_client_config
                    .calibration_limit;
                let SequencerConnectionData {
                    sequencer_addr,
                    basic_auth,
                } = wallet_core
                    .config()
                    .sequencers
                    .iter()
                    .find(|conn_data| conn_data.sequencer_addr == url_addr)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Sequencer with this addr was not found in config")
                    })?;
                let client = make_subclient(sequencer_addr, basic_auth)?;

                let statistics = calibrate_client(client, calibration_limit)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("Failed to callibrate the sequencer"))?;

                wallet_core.statistics.insert(url_addr, statistics);

                Ok(SubcommandReturnValue::Empty)
            }
            Self::ShowStatistics { addr } => {
                let url_addr = addr.parse()?;

                println!(
                    "Statistics of a {url_addr:?} is {:?}",
                    wallet_core.get_statistics(&url_addr)
                );

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
