use std::{error::Error, fmt, fmt::Display, time::Duration};

use common::HashType;
use indexer_service_protocol::HashType as IndexerHashType;
use indexer_service_rpc::RpcClient as _;
use sequencer_service_rpc::RpcClient as _;

use super::{LezIndexerClient, LezSequencerClient};

/// Failure modes while waiting for the indexer to reach the sequencer.
#[derive(Debug)]
pub enum IndexerCatchUpError {
    /// The sequencer height could not be queried.
    SequencerQuery {
        /// Diagnostic returned by the sequencer RPC client.
        message: String,
    },
    /// The indexer height could not be queried.
    IndexerQuery {
        /// Diagnostic returned by the indexer RPC client.
        message: String,
    },
    /// The indexer did not reach the target within the configured duration.
    Timeout {
        /// Sequencer block height the indexer was expected to reach.
        target: u64,
        /// Highest indexer block height observed while polling.
        last_observed: u64,
        /// Duration spent polling before timing out.
        elapsed: Duration,
    },
}

impl Display for IndexerCatchUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequencerQuery { message } => {
                write!(
                    f,
                    "failed to query sequencer while waiting for indexer: {message}"
                )
            }
            Self::IndexerQuery { message } => {
                write!(
                    f,
                    "failed to query indexer while waiting for catch-up: {message}"
                )
            }
            Self::Timeout {
                target,
                last_observed,
                elapsed,
            } => write!(
                f,
                "indexer failed to catch up to sequencer block {target}; last observed indexer \
                 block {last_observed} after {elapsed:?}"
            ),
        }
    }
}

impl Error for IndexerCatchUpError {}

/// Polls the indexer until it reaches the sequencer's current last block.
pub async fn wait_for_indexer_to_catch_up(
    indexer: &LezIndexerClient,
    sequencer: &LezSequencerClient,
) -> Result<u64, IndexerCatchUpError> {
    wait_for_indexer_to_catch_up_with_timeout(indexer, sequencer, Duration::from_secs(360)).await
}

/// Polls the indexer until it reaches the sequencer's current last block or the timeout elapses.
pub async fn wait_for_indexer_to_catch_up_with_timeout(
    indexer: &LezIndexerClient,
    sequencer: &LezSequencerClient,
    timeout: Duration,
) -> Result<u64, IndexerCatchUpError> {
    let block_id_to_catch_up = sequencer
        .client()
        .get_last_block_id()
        .await
        .map_err(|error| IndexerCatchUpError::SequencerQuery {
            message: error.to_string(),
        })?;
    wait_for_indexer_to_reach_with_timeout(indexer, block_id_to_catch_up, timeout).await
}

/// Polls the indexer until it reaches a specific finalized block or the timeout elapses.
pub async fn wait_for_indexer_to_reach_with_timeout(
    indexer: &LezIndexerClient,
    block_id_to_reach: u64,
    timeout: Duration,
) -> Result<u64, IndexerCatchUpError> {
    let mut last_indexer_block = 0;

    let poll = async {
        loop {
            let indexer_block = indexer
                .client()
                .get_last_finalized_block_id()
                .await
                .map_err(|error| error.to_string())?
                .unwrap_or(0);
            last_indexer_block = indexer_block;

            if indexer_block >= block_id_to_reach && indexer_block > 0 {
                return Ok::<u64, String>(indexer_block);
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    match tokio::time::timeout(timeout, poll).await {
        Ok(Ok(height)) => Ok(height),
        Ok(Err(error)) => Err(IndexerCatchUpError::IndexerQuery { message: error }),
        Err(_elapsed) => Err(IndexerCatchUpError::Timeout {
            target: block_id_to_reach,
            last_observed: last_indexer_block,
            elapsed: timeout,
        }),
    }
}

/// Polls the indexer until all supplied transactions are present in its
/// finalized transaction store or the timeout elapses.
pub async fn wait_for_indexer_to_index_transactions_with_timeout(
    indexer: &LezIndexerClient,
    transaction_hashes: &[HashType],
    target_block: u64,
    timeout: Duration,
) -> Result<u64, IndexerCatchUpError> {
    let mut last_indexer_block = 0;

    let poll = async {
        loop {
            last_indexer_block = indexer
                .client()
                .get_last_finalized_block_id()
                .await
                .map_err(|error| error.to_string())?
                .unwrap_or(0);

            let mut all_indexed = true;
            for hash in transaction_hashes {
                let indexed = indexer_service_rpc::RpcClient::get_transaction(
                    &**indexer.client(),
                    IndexerHashType(hash.0),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_some();
                all_indexed &= indexed;
            }

            if all_indexed {
                return Ok::<u64, String>(last_indexer_block);
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    match tokio::time::timeout(timeout, poll).await {
        Ok(Ok(height)) => Ok(height),
        Ok(Err(error)) => Err(IndexerCatchUpError::IndexerQuery { message: error }),
        Err(_elapsed) => Err(IndexerCatchUpError::Timeout {
            target: target_block,
            last_observed: last_indexer_block,
            elapsed: timeout,
        }),
    }
}
