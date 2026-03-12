use std::collections::BTreeMap;

use common::{
    HashType,
    block::{Block, BlockId},
    transaction::NSSATransaction,
};
use jsonrpsee::proc_macros::rpc;
#[cfg(feature = "server")]
use jsonrpsee::types::ErrorObjectOwned;
use nssa::{Account, AccountId, ProgramId};
use nssa_core::{Commitment, MembershipProof, account::Nonce};

#[cfg(all(not(feature = "server"), not(feature = "client")))]
compile_error!("At least one of `server` or `client` features must be enabled.");

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

    #[method(name = "getBlockData")]
    async fn get_block_data(&self, block_id: BlockId) -> Result<Block, ErrorObjectOwned>;

    #[method(name = "getBlockRangeData")]
    async fn get_block_range_data(
        &self,
        start_block_id: BlockId,
        end_block_id: BlockId,
    ) -> Result<Vec<Block>, ErrorObjectOwned>;

    #[method(name = "getLastBlockId")]
    async fn get_last_block_id(&self) -> Result<BlockId, ErrorObjectOwned>;

    #[method(name = "getAccountBalance")]
    async fn get_account_balance(&self, account_id: AccountId) -> Result<u128, ErrorObjectOwned>;

    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        hash: HashType,
    ) -> Result<NSSATransaction, ErrorObjectOwned>;

    #[method(name = "getAccountsNonces")]
    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned>;

    #[method(name = "getProofForCommitment")]
    async fn get_proof_for_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<MembershipProof, ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned>;

    #[method(name = "getProgramIds")]
    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned>;

    // =============================================================================================
}
