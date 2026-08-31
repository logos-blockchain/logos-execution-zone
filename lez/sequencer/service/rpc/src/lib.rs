use std::collections::BTreeMap;

use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::types::ErrorObjectOwned;
#[cfg(feature = "client")]
pub use jsonrpsee::{core::ClientError, http_client::HttpClientBuilder as SequencerClientBuilder};
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, ChannelId, Commitment, CommitmentSetDigest,
    CrossZoneDeadLetterReport, CrossZoneDeadLetterRequeue, HashType, LeeTransaction,
    MembershipProof, Nonce, ProgramId,
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
/// use common::transaction::LeeTransaction;
/// use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
///
/// let url = "http://localhost:3040".parse()?;
/// let client = SequencerClientBuilder::default().build(url)?;
///
/// let tx: LeeTransaction = unimplemented!("Construct your transaction here");
/// let tx_hash = client.send_transaction(tx).await?;
/// ```
#[cfg(feature = "client")]
pub type SequencerClient = jsonrpsee::http_client::HttpClient;

#[cfg_attr(all(feature = "server", not(feature = "client")), rpc(server))]
#[cfg_attr(all(feature = "client", not(feature = "server")), rpc(client))]
#[cfg_attr(all(feature = "server", feature = "client"), rpc(server, client))]
pub trait Rpc {
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, tx: LeeTransaction) -> Result<HashType, ErrorObjectOwned>;

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
    ) -> Result<Option<(LeeTransaction, BlockId)>, ErrorObjectOwned>;

    #[method(name = "getAccountsNonces")]
    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned>;

    #[method(name = "getProofsAndRoot")]
    async fn get_proofs_and_root(
        &self,
        commitments: Vec<Commitment>,
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest), ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getProgramIds")]
    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned>;

    #[method(name = "getChannelId")]
    async fn get_channel_id(&self) -> Result<ChannelId, ErrorObjectOwned>;

    /// The cross-zone deliveries this sequencer has given up on.
    ///
    /// Its own method rather than folded into `checkHealth`: one undeliverable
    /// peer message must not read as an unhealthy node.
    #[method(name = "getCrossZoneDeadLetters")]
    async fn get_cross_zone_dead_letters(
        &self,
    ) -> Result<CrossZoneDeadLetterReport, ErrorObjectOwned>;

    /// Restores a dead-lettered cross-zone delivery to the pending list, with a
    /// clean attempt count.
    ///
    /// The operator move once the cause of the failures has cleared: a raised
    /// mint cap, a fixed target program. A delivery that fails again is
    /// dead-lettered again.
    ///
    /// Like the rest of this surface it carries no authentication, so anyone
    /// who can reach the RPC can requeue; the blast radius is bounded to
    /// re-attempting deliveries this node already accepted from a peer.
    #[method(name = "requeueCrossZoneDeadLetter")]
    async fn requeue_cross_zone_dead_letter(
        &self,
        message_key: HashType,
    ) -> Result<CrossZoneDeadLetterRequeue, ErrorObjectOwned>;
}
