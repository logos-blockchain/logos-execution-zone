use std::time::Duration;

use anyhow::Result;
use common::{HashType, block::Block, transaction::LeeTransaction};
use lee_core::BlockId;
use log::warn;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use tokio::task::JoinSet;

use crate::config::WalletConfig;

#[derive(Clone)]
/// Helperstruct to poll transactions.
pub struct TxPoller {
    polling_max_blocks_to_query: usize,
    polling_max_error_attempts: u64,
    polling_delay: Duration,
    block_poll_max_amount: u64,
    client: SequencerClient,
}

impl TxPoller {
    #[must_use]
    pub const fn new(config: &WalletConfig, client: SequencerClient) -> Self {
        Self {
            polling_delay: config.seq_poll_timeout,
            polling_max_blocks_to_query: config.seq_tx_poll_max_blocks,
            polling_max_error_attempts: config.seq_poll_max_retries,
            block_poll_max_amount: config.seq_block_poll_max_amount,
            client,
        }
    }

    // TODO: this polling is not based on blocks, but on timeouts, need to fix this.
    pub async fn poll_tx(&self, tx_hash: HashType) -> Result<(LeeTransaction, BlockId)> {
        let max_blocks_to_query = self.polling_max_blocks_to_query;

        log::info!("Starting poll for transaction {tx_hash}");
        for poll_id in 1..max_blocks_to_query {
            log::info!("Poll {poll_id}");

            let mut try_error_counter = 0_u64;

            loop {
                match self.client.get_transaction(tx_hash).await {
                    Ok(Some((tx, block_id))) => return Ok((tx, block_id)),
                    Ok(None) => {}
                    Err(err) => {
                        warn!("Failed to get transaction by hash {tx_hash} with error: {err:#?}");
                    }
                }

                try_error_counter = try_error_counter
                    .checked_add(1)
                    .expect("We check error counter in this loop");

                if try_error_counter > self.polling_max_error_attempts {
                    break;
                }
            }

            tokio::time::sleep(self.polling_delay).await;
        }

        anyhow::bail!("Transaction not found in preconfigured amount of blocks");
    }

    pub fn poll_block_range(
        &self,
        range: std::ops::RangeInclusive<u64>,
    ) -> impl futures::Stream<Item = Result<Block>> {
        async_stream::stream! {
            let mut chunk_start = *range.start();

            loop {
                let chunk_end = std::cmp::min(chunk_start.saturating_add(self.block_poll_max_amount).saturating_sub(1), *range.end());

                let blocks = self.client.get_block_range(chunk_start, chunk_end).await?;
                for block in blocks {
                    yield Ok(block);
                }

                chunk_start = chunk_end.saturating_add(1);
                if chunk_start > *range.end() {
                    break;
                }
            }
        }
    }
}

pub async fn multi_poll(
    pollers: Vec<TxPoller>,
    tx_hash: HashType,
) -> Result<(LeeTransaction, BlockId)> {
    let mut set = JoinSet::new();

    for poller in pollers {
        set.spawn(async move { poller.poll_tx(tx_hash).await });
    }

    while let Some(res) = set.join_next().await {
        if let Ok(Ok(tx_res)) = res {
            return Ok(tx_res);
        }
        // There is no point handling failed poll here
    }

    anyhow::bail!("All pollers failed")
}
