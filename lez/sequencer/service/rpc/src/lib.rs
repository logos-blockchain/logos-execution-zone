use std::collections::BTreeMap;

use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::types::ErrorObjectOwned;
#[cfg(feature = "client")]
pub use jsonrpsee::{core::ClientError, http_client::HttpClientBuilder as SequencerClientBuilder};
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, ChannelId, Commitment, CommitmentSetDigest, HashType,
    LeeTransaction, MembershipProof, Nonce, ProgramId,
};

/// Maximum number of full accounts returned by one `getAccounts` request.
///
/// A full account may contain 100 KiB of data. JSON encodes each byte as a decimal number, so this
/// limit keeps a worst-case batch below jsonrpsee's default 10 MiB response-body limit, with at
/// least 512 KiB of headroom for the JSON-RPC envelope.
pub const MAX_ACCOUNTS_PER_REQUEST: usize = 24;

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

    /// Get full account states in input order.
    ///
    /// Returns an invalid-params error when more than [`MAX_ACCOUNTS_PER_REQUEST`] IDs are
    /// supplied.
    #[method(name = "getAccounts")]
    async fn get_accounts(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Account>, ErrorObjectOwned>;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_ACCOUNT_DATA_SIZE: usize = 100 * 1024;
    const DEFAULT_MAX_RESPONSE_BODY_SIZE: usize = 10 * 1024 * 1024;
    const RESPONSE_BODY_HEADROOM: usize = 512 * 1024;

    #[test]
    fn maximum_accounts_response_fits_default_response_body_limit() {
        let mut account = Account {
            program_owner: [u32::MAX; 8],
            balance: u128::MAX,
            nonce: u128::MAX.into(),
            ..Account::default()
        };
        account.data = vec![u8::MAX; MAX_ACCOUNT_DATA_SIZE]
            .try_into()
            .expect("maximum-size account data should be valid");

        let mut encoded = br#"{"jsonrpc":"2.0","result":"#.to_vec();
        serde_json::to_writer(&mut encoded, &vec![account; MAX_ACCOUNTS_PER_REQUEST])
            .expect("response result should serialize");
        encoded.extend_from_slice(br#", "id":18446744073709551615}"#);

        assert!(
            encoded.len() <= DEFAULT_MAX_RESPONSE_BODY_SIZE - RESPONSE_BODY_HEADROOM,
            "maximum batch response is {} bytes",
            encoded.len()
        );
    }
}
