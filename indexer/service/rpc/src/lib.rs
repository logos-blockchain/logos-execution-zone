use indexer_service_protocol::{Account, AccountId, Block, BlockId, HashType, Transaction};
use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::{core::SubscriptionResult, types::ErrorObjectOwned};

#[cfg(all(not(feature = "server"), not(feature = "client")))]
compile_error!("At least one of `server` or `client` features must be enabled.");

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

        // Block schema contains all other types used in the protocol, so it's sufficient to return
        // its schema.
        let block_schema = schemars::schema_for!(Block);
        Ok(serde_json::to_value(block_schema).expect("Schema serialization should not fail"))
    }

    #[subscription(name = "subscribeToFinalizedBlocks", item = BlockId)]
    async fn subscribe_to_finalized_blocks(&self) -> SubscriptionResult;

    #[method(name = "getLastFinalizedBlockId")]
    async fn get_last_finalized_block_id(&self) -> Result<BlockId, ErrorObjectOwned>;

    #[method(name = "getBlockById")]
    async fn get_block_by_id(&self, block_id: BlockId) -> Result<Block, ErrorObjectOwned>;

    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, block_hash: HashType) -> Result<Block, ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_hash: HashType) -> Result<Transaction, ErrorObjectOwned>;

    #[method(name = "getBlocks")]
    async fn get_blocks(
        &self,
        before: Option<u64>,
        limit: u32,
    ) -> Result<Vec<Block>, ErrorObjectOwned>;

    #[method(name = "getTransactionsByAccount")]
    async fn get_transactions_by_account(
        &self,
        account_id: AccountId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Transaction>, ErrorObjectOwned>;

    // ToDo: expand healthcheck response into some kind of report
    #[method(name = "checkHealth")]
    async fn healthcheck(&self) -> Result<(), ErrorObjectOwned>;
}
