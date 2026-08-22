use std::{
    path::Path,
    pin::pin,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, bail};
use arc_swap::ArcSwap;
use futures::StreamExt as _;
use indexer_core::{IndexerCore, config::IndexerConfig, event_filter::EventFilter};
use indexer_service_protocol::{
    Account, AccountId, Block, BlockId, EventRecord, EventSubscriptionFilter, GetEventsFilter,
    HashType, IndexerStatus, ProgramId, Selector, Transaction, resolve_event_block_range,
};
use jsonrpsee::{
    SubscriptionSink,
    core::{Serialize, SubscriptionResult, async_trait},
    types::{ErrorCode, ErrorObject, ErrorObjectOwned},
};
use log::{debug, error, warn};
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};
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

    #[cfg(not(feature = "mock-responses"))]
    pub(crate) fn subscription_shutdown(&self) -> SubscriptionShutdown {
        self.subscription_service.shutdown_handle()
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
            .add_subscription(NewSubscription::Blocks(Subscription::new(sink)))
            .await?;

        Ok(())
    }

    async fn subscribe_to_events(
        &self,
        subscription_sink: jsonrpsee::PendingSubscriptionSink,
        filter: EventSubscriptionFilter,
    ) -> SubscriptionResult {
        if let Err(err) = check_event_coverage(
            self.indexer.store.live_filter(),
            filter.program_id,
            filter.selector,
        ) {
            subscription_sink.reject(err).await;
            return Ok(());
        }
        let sink = subscription_sink.accept().await?;
        log::info!(
            "Accepted new subscription to events with ID {:?}",
            sink.subscription_id()
        );
        self.subscription_service
            .add_subscription(NewSubscription::Events(Subscription::new(sink), filter))
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

    async fn get_events(
        &self,
        filter: GetEventsFilter,
    ) -> Result<Vec<EventRecord>, ErrorObjectOwned> {
        let tip = self
            .indexer
            .store
            .get_last_block_id()
            .map_err(db_error)?
            .unwrap_or(0);

        let records = match plan_query(&filter, tip)? {
            EventQuery::ByTxHash(tx_hash) => {
                // Coverage is judged at the transaction's height, resolved BEFORE the
                // events read: a filtered-out tx has no events row, and gating on the
                // row's presence would serve `[]` for exactly the dropped domains.
                let block_id = self
                    .indexer
                    .store
                    .block_id_by_tx_hash(tx_hash.0)
                    .map_err(db_error)?
                    .ok_or_else(unknown_transaction_error)?;
                check_range_coverage(
                    self.indexer.store.filter_segments(),
                    block_id,
                    block_id,
                    filter.program_id,
                    filter.selector,
                )?;
                self.indexer
                    .store
                    .get_events_for_block(block_id)
                    .map_err(db_error)?
                    .and_then(|groups| {
                        groups
                            .into_iter()
                            .find(|group| group.tx_hash.0 == tx_hash.0)
                    })
                    .map(|group| EventRecord::from_tx_events(block_id, group))
                    .unwrap_or_default()
            }
            EventQuery::ByRange {
                from_block,
                to_block,
            } => {
                check_range_coverage(
                    self.indexer.store.filter_segments(),
                    from_block,
                    to_block,
                    filter.program_id,
                    filter.selector,
                )?;
                let mut records = vec![];
                for (block_id, groups) in self
                    .indexer
                    .store
                    .get_events_range(from_block, to_block)
                    .map_err(db_error)?
                {
                    for group in groups {
                        records.extend(EventRecord::from_tx_events(block_id, group));
                    }
                }
                records
            }
        };

        Ok(records
            .into_iter()
            .filter(|record| record.matches_fields(filter.program_id, filter.selector))
            .collect())
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
    parts: Arc<ArcSwap<SubscriptionLoopParts>>,
    indexer: IndexerCore,
    /// Cancellation token that is used to signal the subscription service to shut down.
    ///
    /// NOTE: This will auto-cancel on `Drop`, so if your token is shared with other parts
    /// use [`CancellationToken::child_token()`] instead.
    shutdown: CancellationToken,
}

impl SubscriptionService {
    pub fn spawn_new(indexer: IndexerCore, shutdown: CancellationToken) -> Self {
        let parts = Arc::new(ArcSwap::new(Arc::new(
            Self::spawn_respond_subscribers_loop(indexer.clone(), shutdown.clone()),
        )));

        Self {
            parts,
            indexer,
            shutdown,
        }
    }

    #[cfg(not(feature = "mock-responses"))]
    fn shutdown_handle(&self) -> SubscriptionShutdown {
        SubscriptionShutdown {
            parts: Arc::clone(&self.parts),
            shutdown: self.shutdown.clone(),
        }
    }

    pub async fn add_subscription(&self, subscription: NewSubscription) -> Result<()> {
        let guard = self.parts.load();
        if let Err(send_err) = guard.new_subscription_sender.send(subscription) {
            error!(
                "Failed to send new subscription to subscription service with error: {send_err:#?}"
            );

            // Respawn the subscription service loop if it has finished (either with error or panic)
            let loop_finished = guard
                .handle
                .lock()
                .ok()
                .is_some_and(|handle| handle.as_ref().is_some_and(JoinHandle::is_finished));
            if loop_finished && !self.shutdown.is_cancelled() {
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

                if let Some(handle) = old_parts
                    .handle
                    .lock()
                    .ok()
                    .and_then(|mut handle| handle.take())
                {
                    match handle.await {
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
            tokio::sync::mpsc::unbounded_channel::<NewSubscription>();

        let handle = tokio::spawn(async move {
            let run_loop = async {
                let mut block_subscribers: Vec<Subscription<BlockId>> = Vec::new();
                let mut event_subscribers: Vec<(
                    Subscription<EventRecord>,
                    EventSubscriptionFilter,
                )> = Vec::new();

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
                            match subscription {
                                NewSubscription::Blocks(subscription) => {
                                    log::info!("Added new block subscription with ID {:?}", subscription.sink.subscription_id());
                                    block_subscribers.push(subscription);
                                }
                                NewSubscription::Events(subscription, filter) => {
                                    log::info!("Added new event subscription with ID {:?}", subscription.sink.subscription_id());
                                    event_subscribers.push((subscription, filter));
                                }
                            }
                        }
                        block_opt = block_stream.next() => {
                            debug!("Got new block from block stream");
                            let Some(block) = block_opt else {
                                bail!("Block stream ended unexpectedly");
                            };
                            let block = block.context("Failed to get L2 block data")?;
                            let block: indexer_service_protocol::Block = block.into();

                            let block_id = block.header.block_id;

                            // Reap closed sinks first: one dead event subscriber would
                            // otherwise hold the `is_empty` gate below open, charging every
                            // later block a store read.
                            block_subscribers.retain(|sub| !sub.sink.is_closed());
                            event_subscribers.retain(|(sub, _)| !sub.sink.is_closed());

                            for sub in &mut block_subscribers {
                                if let Err(err) = sub.try_send(&block_id) {
                                    warn!(
                                        "Failed to send block ID {:?} to subscription ID {:?} with error: {err:#?}",
                                        block_id,
                                        sub.sink.subscription_id(),
                                    );
                                }
                            }

                            // Fan-out must not gate ingestion: a store read failure is
                            // logged, never propagated.
                            if !event_subscribers.is_empty() {
                                match indexer.store.get_events_for_block(block_id) {
                                    Ok(groups) => {
                                        let records: Vec<EventRecord> = groups
                                            .unwrap_or_default()
                                            .into_iter()
                                            .flat_map(|group| {
                                                EventRecord::from_tx_events(block_id, group)
                                            })
                                            .collect();
                                        // An event that cannot be queued would leave an
                                        // undetectable hole in the stream, so the subscription
                                        // ends instead: the client re-subscribes and backfills.
                                        let mut dead = vec![false; event_subscribers.len()];
                                        for record in &records {
                                            // Serialized once per record; every matching sink
                                            // receives the same bytes.
                                            let mut payload: Option<Box<serde_json::value::RawValue>> = None;
                                            for (idx, (sub, filter)) in event_subscribers.iter_mut().enumerate() {
                                                if dead[idx] || !matches_subscription_filter(record, filter) {
                                                    continue;
                                                }
                                                let json = payload
                                                    .get_or_insert_with(|| {
                                                        serde_json::value::to_raw_value(record)
                                                            .expect("event records serialize")
                                                    })
                                                    .clone();
                                                if let Err(err) = sub.sink.try_send(json) {
                                                    warn!(
                                                        "Dropping event subscription ID {:?}: {err:#?}",
                                                        sub.sink.subscription_id(),
                                                    );
                                                    dead[idx] = true;
                                                }
                                            }
                                        }
                                        if dead.contains(&true) {
                                            let mut idx = 0;
                                            event_subscribers.retain(|_| {
                                                let keep = !dead[idx];
                                                idx = idx.saturating_add(1);
                                                keep
                                            });
                                        }
                                    }
                                    Err(err) => warn!(
                                        "Failed to read events for block {block_id} for event subscribers: {err:#}"
                                    ),
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
            handle: Mutex::new(Some(handle)),
            new_subscription_sender,
        }
    }
}

impl Drop for SubscriptionService {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Ok(mut handle) = self.parts.load().handle.lock()
            && let Some(handle) = handle.take()
        {
            handle.abort();
        }
    }
}

struct SubscriptionLoopParts {
    handle: Mutex<Option<JoinHandle<Result<()>>>>,
    new_subscription_sender: UnboundedSender<NewSubscription>,
}

#[derive(Clone)]
pub(crate) struct SubscriptionShutdown {
    parts: Arc<ArcSwap<SubscriptionLoopParts>>,
    shutdown: CancellationToken,
}

impl SubscriptionShutdown {
    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.shutdown.cancel();

        let handle = self
            .parts
            .load()
            .handle
            .lock()
            .ok()
            .and_then(|mut handle| handle.take());

        let Some(handle) = handle else {
            return Ok(());
        };

        match handle.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
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

enum NewSubscription {
    Blocks(Subscription<BlockId>),
    Events(Subscription<EventRecord>, EventSubscriptionFilter),
}

pub(crate) enum EventQuery {
    ByTxHash(HashType),
    ByRange {
        from_block: BlockId,
        to_block: BlockId,
    },
}

#[must_use]
pub fn not_yet_implemented_error() -> ErrorObjectOwned {
    ErrorObject::owned(
        ErrorCode::InternalError.code(),
        "Not yet implemented",
        Option::<String>::None,
    )
}

pub(crate) fn plan_query(
    filter: &GetEventsFilter,
    tip: BlockId,
) -> Result<EventQuery, ErrorObjectOwned> {
    if let Some(tx_hash) = filter.tx_hash {
        return Ok(EventQuery::ByTxHash(tx_hash));
    }
    let (from_block, to_block) = resolve_block_range(filter, tip)?;
    Ok(EventQuery::ByRange {
        from_block,
        to_block,
    })
}

fn resolve_block_range(
    filter: &GetEventsFilter,
    tip: BlockId,
) -> Result<(BlockId, BlockId), ErrorObjectOwned> {
    let Some(from_block) = filter.from_block else {
        return Err(invalid_params_error(
            "getEvents requires either `tx_hash` or `from_block`",
        ));
    };
    resolve_event_block_range(from_block, filter.to_block, tip)
        .map_err(|err| invalid_params_error(format!("getEvents {err}")))
}

pub(crate) fn matches_subscription_filter(
    record: &EventRecord,
    filter: &EventSubscriptionFilter,
) -> bool {
    record.matches_fields(filter.program_id, filter.selector)
        && filter
            .tx_hash
            .is_none_or(|tx_hash| tx_hash == record.tx_hash)
}

// Coverage is judged against the filters the store was WRITTEN under: a query
// they do not fully cover would be answered from a knowingly incomplete store.
// Subscriptions are forward-only, so they check the live filter.
pub(crate) fn check_event_coverage(
    stored: &EventFilter,
    program_id: Option<ProgramId>,
    selector: Option<Selector>,
) -> Result<(), ErrorObjectOwned> {
    if stored.covers(program_id.map(|id| id.0), selector.map(|s| s.0)) {
        Ok(())
    } else {
        Err(uncovered_query_error())
    }
}

pub(crate) fn check_range_coverage(
    segments: &[(EventFilter, u64)],
    from: u64,
    to: u64,
    program_id: Option<ProgramId>,
    selector: Option<Selector>,
) -> Result<(), ErrorObjectOwned> {
    if indexer_core::event_filter::covered_over_range(
        segments,
        from,
        to,
        program_id.map(|id| id.0),
        selector.map(|s| s.0),
    ) {
        Ok(())
    } else {
        Err(uncovered_query_error())
    }
}

fn uncovered_query_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "UncoveredEventQuery".to_owned(),
        Some(
            "this indexer's event filter does not cover the requested events; query a declared \
             program and selector, or an archival indexer"
                .to_owned(),
        ),
    )
}

fn invalid_params_error(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "InvalidParams".to_owned(),
        Some(message.into()),
    )
}

pub(crate) fn unknown_transaction_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "UnknownTransaction".to_owned(),
        Some(
            "no indexed transaction has the requested hash; it may not be ingested yet".to_owned(),
        ),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use indexer_core::event_filter::SelectorFilter;
    use indexer_service_protocol::{MAX_EVENT_QUERY_BLOCK_SPAN, ProgramId, Selector};

    use super::*;

    fn record(block_id: BlockId, program: u32, selector: u8) -> EventRecord {
        EventRecord {
            block_id,
            tx_index: 0,
            tx_hash: HashType([0_u8; 32]),
            program_id: ProgramId([program; 8]),
            selector: Selector([selector; 8]),
            data: vec![],
        }
    }

    #[test]
    fn range_requires_from_block() {
        let err = resolve_block_range(&GetEventsFilter::default(), 10).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidParams.code());
    }

    #[test]
    fn tx_hash_takes_precedence_over_the_block_range() {
        // Range fields that would otherwise be rejected (over the span cap) are ignored.
        let filter = GetEventsFilter {
            tx_hash: Some(HashType([3_u8; 32])),
            from_block: Some(1),
            to_block: Some(MAX_EVENT_QUERY_BLOCK_SPAN.saturating_mul(9)),
            ..GetEventsFilter::default()
        };
        assert!(matches!(
            plan_query(&filter, 0).unwrap(),
            EventQuery::ByTxHash(hash) if hash == HashType([3_u8; 32])
        ));
    }

    #[test]
    fn without_tx_hash_the_query_is_a_range() {
        let filter = GetEventsFilter {
            from_block: Some(2),
            ..GetEventsFilter::default()
        };
        assert!(matches!(
            plan_query(&filter, 6).unwrap(),
            EventQuery::ByRange {
                from_block: 2,
                to_block: 6
            }
        ));
    }

    fn subscription_filter(
        program: Option<u32>,
        selector: Option<u8>,
        tx_hash: Option<u8>,
    ) -> EventSubscriptionFilter {
        EventSubscriptionFilter {
            program_id: program.map(|p| ProgramId([p; 8])),
            selector: selector.map(|s| Selector([s; 8])),
            tx_hash: tx_hash.map(|h| HashType([h; 32])),
        }
    }

    #[test]
    fn subscription_filter_matches_on_every_field() {
        let mut target = record(1, 7, 2);
        target.tx_hash = HashType([5_u8; 32]);

        // Empty filter takes everything.
        assert!(matches_subscription_filter(
            &target,
            &EventSubscriptionFilter::default()
        ));

        // Each field alone discriminates.
        assert!(matches_subscription_filter(
            &target,
            &subscription_filter(Some(7), None, None)
        ));
        assert!(!matches_subscription_filter(
            &target,
            &subscription_filter(Some(8), None, None)
        ));
        assert!(matches_subscription_filter(
            &target,
            &subscription_filter(None, Some(2), None)
        ));
        assert!(!matches_subscription_filter(
            &target,
            &subscription_filter(None, Some(3), None)
        ));
        assert!(matches_subscription_filter(
            &target,
            &subscription_filter(None, None, Some(5))
        ));
        assert!(!matches_subscription_filter(
            &target,
            &subscription_filter(None, None, Some(6))
        ));

        // All three together are conjunctive: one mismatch rejects.
        assert!(matches_subscription_filter(
            &target,
            &subscription_filter(Some(7), Some(2), Some(5))
        ));
        assert!(!matches_subscription_filter(
            &target,
            &subscription_filter(Some(7), Some(2), Some(6))
        ));
    }

    #[test]
    fn both_filter_types_agree_on_the_shared_fields() {
        let target = record(1, 7, 2);

        for (program, selector) in [(7_u32, 2_u8), (7, 3), (8, 2), (8, 3)] {
            let query = GetEventsFilter {
                program_id: Some(ProgramId([program; 8])),
                selector: Some(Selector([selector; 8])),
                ..GetEventsFilter::default()
            };
            let subscription = subscription_filter(Some(program), Some(selector), None);
            assert_eq!(
                target.matches_fields(query.program_id, query.selector),
                matches_subscription_filter(&target, &subscription)
            );
        }
    }

    #[test]
    fn filters_are_exact_and_conjunctive() {
        let target = record(1, 7, 2);
        let program = Some(ProgramId([7; 8]));
        let selector = Some(Selector([2; 8]));

        assert!(target.matches_fields(None, None));

        assert!(target.matches_fields(program, None));
        assert!(!record(1, 8, 2).matches_fields(program, None));

        assert!(target.matches_fields(None, selector));
        assert!(!record(1, 7, 3).matches_fields(None, selector));

        // Both set: a record must satisfy each.
        assert!(target.matches_fields(program, selector));
        assert!(!record(1, 7, 3).matches_fields(program, selector));
        assert!(!record(1, 8, 2).matches_fields(program, selector));
    }

    #[test]
    fn coverage_check_accepts_archival_and_declared_sources() {
        assert!(check_event_coverage(&EventFilter::Archival, None, None).is_ok());

        let declared = EventFilter::Sources(HashMap::from([([7; 8], SelectorFilter::All)]));
        assert!(
            check_event_coverage(&declared, Some(ProgramId([7; 8])), Some(Selector([1; 8])))
                .is_ok()
        );
    }

    #[test]
    fn range_coverage_follows_segment_history() {
        let declared = EventFilter::Sources(HashMap::from([([7; 8], SelectorFilter::All)]));
        let segments = [(declared, 0), (EventFilter::Archival, 100)];

        assert!(check_range_coverage(&segments, 100, 200, None, None).is_ok());
        assert!(check_range_coverage(&segments, 50, 150, Some(ProgramId([7; 8])), None).is_ok());
        let err = check_range_coverage(&segments, 50, 150, None, None).unwrap_err();
        assert_eq!(err.message(), "UncoveredEventQuery");
    }

    #[test]
    fn uncovered_query_is_rejected() {
        let err = check_event_coverage(&EventFilter::default(), Some(ProgramId([7; 8])), None)
            .unwrap_err();
        assert_eq!(err.message(), "UncoveredEventQuery");
    }
}
