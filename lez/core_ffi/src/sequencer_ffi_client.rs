use std::sync::Arc;

use anyhow::Result;
use wallet::WalletSequencerClient;

use crate::{
    primitives::types::FfiOption,
    sequencer::{
        SequencerServiceFFI,
        api::query::{
            sequencer_ffi_query_account, sequencer_ffi_query_block, sequencer_ffi_query_block_vec,
            sequencer_ffi_query_last_block, sequencer_ffi_query_transaction,
            sequencer_ffi_send_transaction,
        },
    },
};

#[derive(Clone)]
pub struct SequencerServiceFFIWrapper(Arc<*const SequencerServiceFFI>);

impl WalletSequencerClient for SequencerServiceFFIWrapper {
    fn from_config(_config: &wallet::config::WalletConfig) -> Result<Self> {
        anyhow::bail!("Not intended way");
    }

    async fn get_account(&self, account_id: lee::AccountId) -> Result<lee::Account> {
        let res = unsafe { sequencer_ffi_query_account(*self.0, account_id.into()) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        let ffi_account = unsafe { res.value.read() };
        let std_account = ffi_account
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed cast"))?;
        Ok(std_account)
    }

    async fn get_account_balance(&self, account_id: lee::AccountId) -> Result<u128> {
        let res = unsafe { sequencer_ffi_query_account(*self.0, account_id.into()) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        let ffi_account = unsafe { res.value.read() };
        let std_account: lee::Account = ffi_account
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed cast"))?;
        Ok(std_account.data.native_balance()?)
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<lee::AccountId>,
    ) -> Result<Vec<lee_core::account::Nonce>> {
        let mut nonce_vec = vec![];
        for account_id in account_ids {
            let res = unsafe { sequencer_ffi_query_account(*self.0, account_id.into()) };
            if res.error.is_error() {
                anyhow::bail!("Sequencer FFI error: {:?}", res.error);
            }
            let ffi_account = unsafe { res.value.read() };
            let std_account: lee::Account = ffi_account
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed cast"))?;
            nonce_vec.push(std_account.nonce);
        }
        Ok(nonce_vec)
    }

    async fn get_block(&self, block_id: lee_core::BlockId) -> Result<Option<common::block::Block>> {
        let res = unsafe { sequencer_ffi_query_block(*self.0, block_id) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        let ffi_opt_block = unsafe { res.value.read() };
        if !ffi_opt_block.is_some {
            return Ok(None);
        }
        let ffi_block = unsafe { ffi_opt_block.value.read() };
        let std_block = ffi_block
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed cast"))?;
        Ok(Some(std_block))
    }

    async fn get_block_range(
        &self,
        start_block_id: lee_core::BlockId,
        end_block_id: lee_core::BlockId,
    ) -> Result<Vec<common::block::Block>> {
        let before = FfiOption::from_value(end_block_id);
        let limit = end_block_id.saturating_sub(start_block_id);
        let res = unsafe { sequencer_ffi_query_block_vec(*self.0, before, limit) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        let ffi_vec_block = unsafe { res.value.read() };
        let std_vec_ffi_block: Vec<_> = ffi_vec_block.into();
        let mut std_vec_block = Vec::with_capacity(limit as usize);

        for ffi_block in std_vec_ffi_block {
            let std_block = ffi_block
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed cast"))?;
            std_vec_block.push(std_block);
        }

        Ok(std_vec_block)
    }

    async fn get_last_block_id(&self) -> Result<lee_core::BlockId> {
        let res = unsafe { sequencer_ffi_query_last_block(*self.0) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        if !res.is_some {
            return Ok(0);
        }
        Ok(res.block_id)
    }

    async fn get_transaction(
        &self,
        tx_hash: common::HashType,
    ) -> Result<Option<(common::transaction::LeeTransaction, lee_core::BlockId)>> {
        let res = unsafe { sequencer_ffi_query_transaction(*self.0, tx_hash.into()) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        let ffi_opt_tx = unsafe { res.value.read() };
        if !ffi_opt_tx.is_some {
            return Ok(None);
        }
        let ffi_tx = unsafe { ffi_opt_tx.value.read() };
        let std_tx: common::transaction::LeeTransaction = ffi_tx
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed cast"))?;
        // !TODO!: fix zero resp.
        Ok(Some((std_tx, 0)))
    }

    async fn send_transaction(
        &self,
        tx: common::transaction::LeeTransaction,
    ) -> Result<common::HashType> {
        let res = unsafe { sequencer_ffi_send_transaction(*self.0, tx.into()) };
        if res.error.is_error() {
            anyhow::bail!("Sequencer FFI error: {:?}", res.error);
        }
        // !TODO!: fix zero resp.
        Ok([0u8; 32].into())
    }

    async fn get_account_view(
        &self,
        _shard_selector: lee::ProgramShardSelector,
    ) -> Result<lee::Account> {
        // !TODO!: Add.
        todo!()
    }

    async fn get_program_ids(&self) -> Result<std::collections::BTreeMap<String, lee::ProgramId>> {
        // !TODO!: Add.
        todo!()
    }

    async fn get_proofs_and_root(
        &self,
        _commitments: Vec<lee_core::Commitment>,
    ) -> Result<(
        Vec<Option<lee_core::MembershipProof>>,
        lee_core::CommitmentSetDigest,
    )> {
        // !TODO!: Add.
        todo!()
    }
}
