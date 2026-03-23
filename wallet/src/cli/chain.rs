use anyhow::Result;
use clap::Subcommand;
use common::HashType;
use sequencer_service_rpc::RpcClient as _;

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
                let latest_block_id = wallet_core.sequencer_client.get_last_block_id().await?;

                println!("Last block id is {latest_block_id}");
            }
            Self::Block { id } => {
                let block = wallet_core.sequencer_client.get_block(id).await?;

                println!("Last block id is {block:#?}");
            }
            Self::Transaction { hash } => {
                let tx = wallet_core.sequencer_client.get_transaction(hash).await?;

                println!("Transaction is {tx:#?}");
            }
        }
        Ok(SubcommandReturnValue::Empty)
    }
}
