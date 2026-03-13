use std::{pin::pin, sync::Arc};

use anyhow::{Context as _, Result, bail};
use arc_swap::ArcSwap;
use futures::{StreamExt as _, never::Never};
use indexer_core::{IndexerCore, config::IndexerConfig};
use indexer_service_protocol::{Account, AccountId, Block, BlockId, HashType, Transaction};
use jsonrpsee::{
    SubscriptionSink,
    core::{Serialize, SubscriptionResult},
    types::{ErrorCode, ErrorObject, ErrorObjectOwned},
};
use log::{debug, error, info, warn};
use tokio::sync::mpsc::UnboundedSender;

pub struct IndexerService {
    subscription_service: SubscriptionService,
    indexer: IndexerCore,
}

impl IndexerService {
    pub fn new(config: IndexerConfig) -> Result<Self> {
        let indexer = IndexerCore::new(config)?;
        let subscription_service = SubscriptionService::spawn_new(indexer.clone());

        Ok(Self {
            subscription_service,
            indexer,
        })
    }
}

#[async_trait::async_trait]
impl indexer_service_rpc::RpcServer for IndexerService {
    async fn subscribe_to_finalized_blocks(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = subscription_sink.accept().await?;
        info!(
            "Accepted new subscription to finalized blocks with ID {:?}",
            sink.subscription_id()
        );
        self.subscription_service
            .add_subscription(Subscription::new(sink))
            .await?;

        Ok(())
    }

    async fn get_last_finalized_block_id(&self) -> Result<BlockId, ErrorObjectOwned> {
        self.indexer.store.get_last_block_id().map_err(db_error)
    }

    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Block, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_block_at_id(block_id)
            .map_err(db_error)?
            .into())
    }

    async fn get_block_by_hash(&self, block_hash: HashType) -> Result<Block, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_block_by_hash(block_hash.0)
            .map_err(db_error)?
            .into())
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_account_final(&account_id.into())
            .await
            .map_err(db_error)?
            .into())
    }

    async fn get_transaction(&self, tx_hash: HashType) -> Result<Transaction, ErrorObjectOwned> {
        Ok(self
            .indexer
            .store
            .get_transaction_by_hash(tx_hash.0)
            .map_err(db_error)?
            .into())
    }

    async fn get_blocks(
        &self,
        before: Option<u64>,
        limit: u32,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let blocks = self
            .indexer
            .store
            .get_block_batch(before, limit as u64)
            .map_err(db_error)?;

        let mut block_res = vec![];

        for block in blocks {
            block_res.push(block.into())
        }

        Ok(block_res)
    }

    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned> {
        let transactions = self
            .indexer
            .store
            .get_transactions_by_account(account_id.value, offset as u64, limit as u64)
            .map_err(db_error)?;

        let mut tx_res = vec![];

        for tx in transactions {
            tx_res.push(tx.into())
        }

        Ok(tx_res)
    }

    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned> {
        // Checking, that indexer can calculate last state
        let _ = self.indexer.store.final_state_db().map_err(db_error)?;

        Ok(())
    }
}

struct SubscriptionService {
    parts: ArcSwap<SubscriptionLoopParts>,
    indexer: IndexerCore,
}

impl SubscriptionService {
    pub fn spawn_new(indexer: IndexerCore) -> Self {
        let parts = Self::spawn_respond_subscribers_loop(indexer.clone());

        Self {
            parts: ArcSwap::new(Arc::new(parts)),
            indexer,
        }
    }

    pub async fn add_subscription(&self, subscription: Subscription<BlockId>) -> Result<()> {
        let guard = self.parts.load();
        if let Err(err) = guard.new_subscription_sender.send(subscription) {
            error!("Failed to send new subscription to subscription service with error: {err:#?}");

            // Respawn the subscription service loop if it has finished (either with error or panic)
            if guard.handle.is_finished() {
                drop(guard);
                let new_parts = Self::spawn_respond_subscribers_loop(self.indexer.clone());
                let old_handle_and_sender = self.parts.swap(Arc::new(new_parts));
                let old_parts = Arc::into_inner(old_handle_and_sender)
                    .expect("There should be no other references to the old handle and sender");

                match old_parts.handle.await {
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

            bail!(err);
        };

        Ok(())
    }

    fn spawn_respond_subscribers_loop(mut indexer: IndexerCore) -> SubscriptionLoopParts {
        let (new_subscription_sender, mut sub_receiver) =
            tokio::sync::mpsc::unbounded_channel::<Subscription<BlockId>>();

        let handle = tokio::spawn(async move {
            let mut subscribers = Vec::new();

            let mut block_stream = pin!(indexer.subscribe_parse_block_stream().await);

            loop {
                tokio::select! {
                    sub = sub_receiver.recv() => {
                        let Some(subscription) = sub else {
                            bail!("Subscription receiver closed unexpectedly");
                        };
                        info!("Added new subscription with ID {:?}", subscription.sink.subscription_id());
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
        });
        SubscriptionLoopParts {
            handle,
            new_subscription_sender,
        }
    }
}

impl Drop for SubscriptionService {
    fn drop(&mut self) {
        self.parts.load().handle.abort();
    }
}

struct SubscriptionLoopParts {
    handle: tokio::task::JoinHandle<Result<Never>>,
    new_subscription_sender: UnboundedSender<Subscription<BlockId>>,
}

struct Subscription<T> {
    sink: SubscriptionSink,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Subscription<T> {
    fn new(sink: SubscriptionSink) -> Self {
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
        info!(
            "Subscription with ID {:?} is being dropped",
            self.sink.subscription_id()
        );
    }
}

pub fn not_yet_implemented_error() -> ErrorObjectOwned {
    ErrorObject::owned(
        ErrorCode::InternalError.code(),
        "Not yet implemented",
        Option::<String>::None,
    )
}

fn db_error(err: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "DBError".to_string(),
        Some(format!("{err:#?}")),
    )
}
