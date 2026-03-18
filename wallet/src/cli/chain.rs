use anyhow::Result;
use clap::Subcommand;
use common::HashType;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum ChainSubcommand {
    /// Get current block id from sequencer.
    CurrentBlockId,
    /// Get block at id from sequencer.
    Block {
        #[arg(short, long)]
        id: u64,
    },
    /// Get transaction at hash from sequencer.
    Transaction {
        /// hash - valid 32 byte hex string.
        #[arg(short = 't', long)]
        hash: HashType,
    },
}

impl WalletSubcommand for ChainSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::CurrentBlockId => {
                let latest_block_res = wallet_core.sequencer_client.get_last_block().await?;

                println!("Last block id is {}", latest_block_res.last_block);
            }
            Self::Block { id } => {
                let block_res = wallet_core.sequencer_client.get_block(id).await?;

                println!("Last block id is {:#?}", block_res.block);
            }
            Self::Transaction { hash } => {
                let tx_res = wallet_core
                    .sequencer_client
                    .get_transaction_by_hash(hash)
                    .await?;

                println!("Last block id is {:#?}", tx_res.transaction);
            }
        }
        Ok(SubcommandReturnValue::Empty)
    }
}
