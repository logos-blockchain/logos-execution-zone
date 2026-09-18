use indexer_service_protocol::{
    Account, AccountId, Block, BlockId, EventRecord, EventSubscriptionFilter, GetEventsFilter,
    HashType, IndexerStatus, Transaction,
};
use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::{core::SubscriptionResult, types::ErrorObjectOwned};
use schemars::JsonSchema;

#[cfg(all(not(feature = "server"), not(feature = "client")))]
compile_error!("At least one of `server` or `client` features must be enabled.");

/// Schema roots for the block and event query surface; types not reachable from `Block`.
#[derive(JsonSchema)]
#[expect(
    dead_code,
    reason = "Fields exist only to root the generated JSON schema"
)]
struct ProtocolSchema {
    block: Block,
    event_record: EventRecord,
    get_events_filter: GetEventsFilter,
    event_subscription_filter: EventSubscriptionFilter,
}

#[cfg_attr(all(feature = "server", not(feature = "client")), rpc(server))]
#[cfg_attr(all(feature = "client", not(feature = "server")), rpc(client))]
#[cfg_attr(all(feature = "server", feature = "client"), rpc(server, client))]
pub trait Rpc {
    #[method(name = "getSchema")]
    fn get_schema(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        // TODO: Canonical solution would be to provide `describe` method returning OpenRPC spec,
        // But for now it's painful to implement, although can be done if really needed.
        // Currently we can wait until we can auto-generated it: https://github.com/paritytech/jsonrpsee/issues/737
        // and just return JSON schema.

        // `Block` reaches most protocol types transitively, but the event request/response
        // types are not reachable from it, so the schema is derived from a wrapper naming
        // every root a client needs.
        let schema = schemars::schema_for!(ProtocolSchema);
        Ok(serde_json::to_value(schema).expect("Schema serialization should not fail"))
    }

    #[subscription(name = "subscribeToFinalizedBlocks", item = BlockId)]
    async fn subscribe_to_finalized_blocks(&self) -> SubscriptionResult;

    #[subscription(name = "subscribeToEvents", item = EventRecord)]
    async fn subscribe_to_events(&self, filter: EventSubscriptionFilter) -> SubscriptionResult;

    #[method(name = "getLastFinalizedBlockId")]
    async fn get_last_finalized_block_id(&self) -> Result<Option<BlockId>, ErrorObjectOwned>;

    #[method(name = "getBlockById")]
    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned>;

    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        block_hash: HashType,
    ) -> Result<Option<Block>, ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getAccountAtBlock")]
    async fn get_account_at_block(
        &self,
        account_id: AccountId,
        block_id: BlockId,
    ) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getTransaction")]
    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<Transaction>, ErrorObjectOwned>;

    #[method(name = "getBlocks")]
    async fn get_blocks(
        &self,
        before: Option<BlockId>,
        limit: u64,
    ) -> Result<Vec<Block>, ErrorObjectOwned>;

    #[method(name = "getTransactionsByAccount")]
    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned>;

    #[method(name = "getEvents")]
    async fn get_events(
        &self,
        filter: GetEventsFilter,
    ) -> Result<Vec<EventRecord>, ErrorObjectOwned>;

    #[method(name = "getStatus")]
    async fn get_status(&self) -> Result<IndexerStatus, ErrorObjectOwned>;

    // ToDo: expand healthcheck response into some kind of report
    #[method(name = "checkHealth")]
    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned>;
}
