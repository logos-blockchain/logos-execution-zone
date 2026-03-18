use std::collections::BTreeMap;

use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::types::ErrorObjectOwned;
#[cfg(feature = "client")]
pub use jsonrpsee::{core::ClientError, http_client::HttpClientBuilder as SequencerClientBuilder};
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, Commitment, HashType, MembershipProof, NSSATransaction,
    Nonce, ProgramId,
};

#[cfg(all(not(feature = "server"), not(feature = "client")))]
compile_error!("At least one of `server` or `client` features must be enabled.");

/// Type alias for RPC client. Only available when `client` feature is enabled.
///
/// It's cheap to clone this client, so it can be cloned and shared across the application.
///
/// # Example
///
/// ```no_run
/// use common::transaction::NSSATransaction;
/// use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
///
/// let url = "http://localhost:3040".parse()?;
/// let client = SequencerClientBuilder::default().build(url)?;
///
/// let tx: NSSATransaction = unimplemented!("Construct your transaction here");
/// let tx_hash = client.send_transaction(tx).await?;
/// ```
#[cfg(feature = "client")]
pub type SequencerClient = jsonrpsee::http_client::HttpClient;

#[cfg_attr(all(feature = "server", not(feature = "client")), rpc(server))]
#[cfg_attr(all(feature = "client", not(feature = "server")), rpc(client))]
#[cfg_attr(all(feature = "server", feature = "client"), rpc(server, client))]
pub trait Rpc {
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, tx: NSSATransaction) -> Result<HashType, ErrorObjectOwned>;

    // TODO: expand healthcheck response into some kind of report
    #[method(name = "checkHealth")]
    async fn check_health(&self) -> Result<(), ErrorObjectOwned>;

    // TODO: These functions should be removed after wallet starts using indexer
    // for this type of queries.
    //
    // =============================================================================================

    #[method(name = "getBlock")]
    async fn get_block(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned>;

    #[method(name = "getBlockRange")]
    async fn get_block_range(
        &self,
        start_block_id: BlockId,
        end_block_id: BlockId,
    ) -> Result<Vec<Block>, ErrorObjectOwned>;

    #[method(name = "getLastBlockId")]
    async fn get_last_block_id(&self) -> Result<BlockId, ErrorObjectOwned>;

    #[method(name = "getAccountBalance")]
    async fn get_account_balance(&self, account_id: AccountId) -> Result<u128, ErrorObjectOwned>;

    #[method(name = "getTransaction")]
    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<NSSATransaction>, ErrorObjectOwned>;

    #[method(name = "getAccountsNonces")]
    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned>;

    #[method(name = "getProofForCommitment")]
    async fn get_proof_for_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<Option<MembershipProof>, ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getProgramIds")]
    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned>;

    // =============================================================================================
}
