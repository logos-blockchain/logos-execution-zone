use std::{sync::Arc, time::Duration};

use anyhow::Result;
use common::{HashType, block::HashableBlockData, sequencer_client::SequencerClient};
use log::{info, warn};

use crate::config::WalletConfig;

#[derive(Clone)]
/// Helperstruct to poll transactions.
pub struct TxPoller {
    polling_max_blocks_to_query: usize,
    polling_max_error_attempts: u64,
    polling_delay: Duration,
    block_poll_max_amount: u64,
    client: Arc<SequencerClient>,
}

impl TxPoller {
    #[must_use]
    pub const fn new(config: &WalletConfig, client: Arc<SequencerClient>) -> Self {
        Self {
            polling_delay: config.seq_poll_timeout,
            polling_max_blocks_to_query: config.seq_tx_poll_max_blocks,
            polling_max_error_attempts: config.seq_poll_max_retries,
            block_poll_max_amount: config.seq_block_poll_max_amount,
            client,
        }
    }

    // TODO: this polling is not based on blocks, but on timeouts, need to fix this.
    pub async fn poll_tx(&self, tx_hash: HashType) -> Result<String> {
        let max_blocks_to_query = self.polling_max_blocks_to_query;

        info!("Starting poll for transaction {tx_hash}");
        for poll_id in 1..max_blocks_to_query {
            info!("Poll {poll_id}");

            let mut try_error_counter = 0_u64;

            let tx_obj = loop {
                let tx_obj = self
                    .client
                    .get_transaction_by_hash(tx_hash)
                    .await
                    .inspect_err(|err| {
                        warn!("Failed to get transaction by hash {tx_hash} with error: {err:#?}");
                    });

                if let Ok(tx_obj) = tx_obj {
                    break tx_obj;
                }
                try_error_counter = try_error_counter
                    .checked_add(1)
                    .expect("We check error counter in this loop");

                if try_error_counter > self.polling_max_error_attempts {
                    anyhow::bail!("Number of retries exceeded");
                }
            };

            if let Some(tx) = tx_obj.transaction {
                return Ok(tx);
            }

            tokio::time::sleep(self.polling_delay).await;
        }

        anyhow::bail!("Transaction not found in preconfigured amount of blocks");
    }

    pub fn poll_block_range(
        &self,
        range: std::ops::RangeInclusive<u64>,
    ) -> impl futures::Stream<Item = Result<HashableBlockData>> {
        async_stream::stream! {
            let mut chunk_start = *range.start();

            loop {
                let chunk_end = std::cmp::min(chunk_start.saturating_add(self.block_poll_max_amount).saturating_sub(1), *range.end());

                let blocks = self.client.get_block_range(chunk_start..=chunk_end).await?.blocks;
                for block in blocks {
                    let block = borsh::from_slice::<HashableBlockData>(&block)?;
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
