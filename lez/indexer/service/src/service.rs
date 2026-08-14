use std::{path::Path, pin::pin, sync::Arc};

use anyhow::{Context as _, Result, bail};
use arc_swap::ArcSwap;
use futures::StreamExt as _;
use indexer_core::{IndexerCore, config::IndexerConfig};
use indexer_service_protocol::{
    Account, AccountId, Block, BlockId, HashType, IndexerStatus, Transaction,
};
use jsonrpsee::{
    SubscriptionSink,
    core::{Serialize, SubscriptionResult, async_trait},
    types::{ErrorCode, ErrorObject, ErrorObjectOwned},
};
use log::{debug, error, warn};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

pub struct IndexerService {
    subscription_service: SubscriptionService,
    indexer: IndexerCore,
}

impl IndexerService {
    pub async fn new(
        config: IndexerConfig,
        storage_dir: &Path,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let indexer = IndexerCore::new(config, storage_dir).await?;
        let subscription_service = SubscriptionService::spawn_new(indexer.clone(), shutdown);

        Ok(Self {
            subscription_service,
            indexer,
        })
    }
}

#[async_trait]
impl indexer_service_rpc::RpcServer for IndexerService {
    async fn subscribe_to_finalized_blocks(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        log::info!(
            "Accepted new subscription to finalized blocks with ID {:?}",
            sink.subscription_id()
        );
        self.subscription_service
            .add_subscription(Subscription::new(sink))
            .await?;

        Ok(())
    }

    async fn get_last_finalized_block_id(&self) -> Result<Option<BlockId>, ErrorObjectOwned> {
        self.indexer.store.get_last_block_id().map_err(db_error)
    }

    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_block_at_id(block_id)
            .map_err(db_error)?
            .map(Into::into))
    }

    async fn get_block_by_hash(
        &self,
        block_hash: HashType,
    ) -> Result<Option<Block>, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_block_by_hash(block_hash.0)
            .map_err(db_error)?
            .map(Into::into))
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .account_current_state(&account_id.into())
            .await
            .map_err(db_error)?
            .into())
    }

    async fn get_account_at_block(
        &self,
        account_id: AccountId,
        block_id: BlockId,
    ) -> Result<Account, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .account_state_at_block(&account_id.into(), block_id)
            .map_err(db_error)?
            .into())
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<Transaction>, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_transaction_by_hash(tx_hash.0)
            .map_err(db_error)?
            .map(Into::into))
    }

    async fn get_blocks(
        &self,
        before: Option<BlockId>,
        limit: u64,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let blocks = self
            .indexer
            .store
            .get_block_batch(before, limit)
            .map_err(db_error)?;

        let mut block_res = vec![];

        for block in blocks {
            block_res.push(block.into());
        }

        Ok(block_res)
    }

    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned> {
        let transactions = self
            .indexer
            .store
            .get_transactions_by_account(account_id.value, offset, limit)
            .map_err(db_error)?;

        let mut tx_res = vec![];

        for tx in transactions {
            tx_res.push(tx.into());
        }

        Ok(tx_res)
    }

    async fn get_status(&self) -> Result<IndexerStatus, ErrorObjectOwned> {
        Ok(self.indexer.status().into())
    }

    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned> {
        // Checking, that indexer can calculate last state
        let _ = self
            .indexer
            .store
            .recalculate_final_state()
            .map_err(db_error)?;

        Ok(())
    }
}

struct SubscriptionService {
    parts: ArcSwap<SubscriptionLoopParts>,
    indexer: IndexerCore,
    /// Cancellation token that is used to signal the subscription service to shut down.
    ///
    /// NOTE: This will auto-cancel on `Drop`, so if your token is shared with other parts
    /// use [`CancellationToken::child_token()`] instead.
    shutdown: CancellationToken,
}

impl SubscriptionService {
    pub fn spawn_new(indexer: IndexerCore, shutdown: CancellationToken) -> Self {
        let parts = Self::spawn_respond_subscribers_loop(indexer.clone(), shutdown.clone());

        Self {
            parts: ArcSwap::new(Arc::new(parts)),
            indexer,
            shutdown,
        }
    }

    pub async fn add_subscription(&self, subscription: Subscription<BlockId>) -> Result<()> {
        let guard = self.parts.load();
        if let Err(send_err) = guard.new_subscription_sender.send(subscription) {
            error!(
                "Failed to send new subscription to subscription service with error: {send_err:#?}"
            );

            // Respawn the subscription service loop if it has finished (either with error or panic)
            if guard.handle.is_finished() && !self.shutdown.is_cancelled() {
                // A halt outside the accept-list would only re-derive the same
                // verdict, so respawning would churn: verify, halt, die, respawn.
                if self.halted_outside_accept_list() {
                    error!(
                        "Not respawning block ingestion: a cross-zone halt record is persisted and its hash is not in cross_zone_accept_unverified."
                    );
                    bail!(send_err)
                }
                drop(guard);
                let new_parts = Self::spawn_respond_subscribers_loop(
                    self.indexer.clone(),
                    self.shutdown.clone(),
                );
                let old_handle_and_sender = self.parts.swap(Arc::new(new_parts));
                let old_parts = Arc::into_inner(old_handle_and_sender)
                    .expect("There should be no other references to the old handle and sender");

                match old_parts.handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        error!(
                            "Subscription service loop has unexpectedly finished with error: {err:#}"
                        );
                    }
                    Err(err) => {
                        error!("Subscription service loop has panicked with err: {err:#}");
                    }
                }
            }

            bail!(send_err)
        }

        Ok(())
    }

    /// Whether a persisted cross-zone halt record names a hash the operator
    /// has not accept-listed. Ingestion respawned in that state re-derives the
    /// same verdict and dies again.
    fn halted_outside_accept_list(&self) -> bool {
        match self.indexer.store.get_cross_zone_halt() {
            Ok(Some(halt)) => !self
                .indexer
                .config
                .cross_zone_accept_unverified
                .contains(&halt.block_hash),
            Ok(None) => false,
            Err(err) => {
                warn!("Failed to read cross-zone halt record before respawn: {err:#}");
                false
            }
        }
    }

    fn spawn_respond_subscribers_loop(
        indexer: IndexerCore,
        shutdown: CancellationToken,
    ) -> SubscriptionLoopParts {
        let (new_subscription_sender, mut sub_receiver) =
            tokio::sync::mpsc::unbounded_channel::<Subscription<BlockId>>();

        let handle = tokio::spawn(async move {
            let run_loop = async {
                let mut subscribers = Vec::new();

                let mut block_stream = pin!(indexer.subscribe_parse_block_stream());

                #[expect(
                    clippy::integer_division_remainder_used,
                    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
                )]
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => {
                            log::info!("Shutdown requested; stopping block ingestion");
                            return Ok(());
                        }
                        sub = sub_receiver.recv() => {
                            let Some(subscription) = sub else {
                                bail!("Subscription receiver closed unexpectedly");
                            };
                            log::info!("Added new subscription with ID {:?}", subscription.sink.subscription_id());
                            subscribers.push(subscription);
                        }
                        block_opt = block_stream.next() => {
                            debug!("Got new block from block stream");
                            let Some(block) = block_opt else {
                                bail!("Block stream ended unexpectedly");
                            };
                            let block = block.context("Failed to get L2 block data")?;
                            let block: indexer_service_protocol::Block = block.into();

                            for sub in &mut subscribers {
                                if let Err(err) = sub.try_send(&block.header.block_id) {
                                    warn!(
                                        "Failed to send block ID {:?} to subscription ID {:?} with error: {err:#?}",
                                        block.header.block_id,
                                        sub.sink.subscription_id(),
                                    );
                                }
                            }
                        }
                    }
                }
            };
            let res: anyhow::Result<()> = run_loop.await;
            if let Err(err) = &res {
                error!("Subscription service loop has unexpectedly finished with error: {err:#?}");
            }
            res
        });
        SubscriptionLoopParts {
            handle,
            new_subscription_sender,
        }
    }
}

impl Drop for SubscriptionService {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.parts.load().handle.abort();
    }
}

struct SubscriptionLoopParts {
    handle: tokio::task::JoinHandle<Result<()>>,
    new_subscription_sender: UnboundedSender<Subscription<BlockId>>,
}

struct Subscription<T> {
    sink: SubscriptionSink,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Subscription<T> {
    const fn new(sink: SubscriptionSink) -> Self {
        Self {
            sink,
            _marker: std::marker::PhantomData,
        }
    }

    fn try_send(&mut self, item: &T) -> Result<()>
    where
        T: Serialize,
    {
        let json = serde_json::value::to_raw_value(item)
            .context("Failed to serialize item for subscription")?;
        self.sink.try_send(json)?;
        Ok(())
    }
}

impl<T> Drop for Subscription<T> {
    fn drop(&mut self) {
        log::info!(
            "Subscription with ID {:?} is being dropped",
            self.sink.subscription_id()
        );
    }
}

#[must_use]
pub fn not_yet_implemented_error() -> ErrorObjectOwned {
    ErrorObject::owned(
        ErrorCode::InternalError.code(),
        "Not yet implemented",
        Option::<String>::None,
    )
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Error is consumed to extract details for error response"
)]
fn db_error(err: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "DBError".to_owned(),
        Some(format!("{err:#?}")),
    )
}
