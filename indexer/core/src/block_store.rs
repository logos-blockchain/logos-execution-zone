use std::{path::Path, sync::Arc};

use anyhow::Result;
use bedrock_client::HeaderId;
use common::{
    block::{BedrockStatus, Block},
    transaction::NSSATransaction,
};
use nssa::{Account, AccountId, V02State};
use storage::indexer::RocksDBIO;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    final_state: Arc<RwLock<V02State>>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    ///
    /// ATTENTION: Will overwrite genesis block.
    pub fn open_db_with_genesis(
        location: &Path,
        start_data: Option<(Block, V02State)>,
    ) -> Result<Self> {
        let dbio = RocksDBIO::open_or_create(location, start_data)?;
        let final_state = dbio.final_state()?;

        Ok(Self {
            dbio: Arc::new(dbio),
            final_state: Arc::new(RwLock::new(final_state)),
        })
    }

    /// Reopening existing database
    pub fn open_db_restart(location: &Path) -> Result<Self> {
        Self::open_db_with_genesis(location, None)
    }

    pub fn last_observed_l1_lib_header(&self) -> Result<Option<HeaderId>> {
        Ok(self
            .dbio
            .get_meta_last_observed_l1_lib_header_in_db()?
            .map(HeaderId::from))
    }

    pub fn get_last_block_id(&self) -> Result<u64> {
        Ok(self.dbio.get_meta_last_block_in_db()?)
    }

    pub fn get_block_at_id(&self, id: u64) -> Result<Block> {
        Ok(self.dbio.get_block(id)?)
    }

    pub fn get_block_batch(&self, before: Option<u64>, limit: u64) -> Result<Vec<Block>> {
        Ok(self.dbio.get_block_batch(before, limit)?)
    }

    pub fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Result<NSSATransaction> {
        let block = self.get_block_at_id(self.dbio.get_block_id_by_tx_hash(tx_hash)?)?;
        let transaction = block
            .body
            .transactions
            .iter()
            .find(|enc_tx| enc_tx.hash().0 == tx_hash)
            .ok_or_else(|| anyhow::anyhow!("Transaction not found in DB"))?;

        Ok(transaction.clone())
    }

    pub fn get_block_by_hash(&self, hash: [u8; 32]) -> Result<Block> {
        self.get_block_at_id(self.dbio.get_block_id_by_hash(hash)?)
    }

    pub fn get_transactions_by_account(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> Result<Vec<NSSATransaction>> {
        Ok(self.dbio.get_acc_transactions(acc_id, offset, limit)?)
    }

    pub fn genesis_id(&self) -> u64 {
        self.dbio
            .get_meta_first_block_in_db()
            .expect("Must be set at the DB startup")
    }

    pub fn last_block(&self) -> u64 {
        self.dbio
            .get_meta_last_block_in_db()
            .expect("Must be set at the DB startup")
    }

    pub fn get_state_at_block(&self, block_id: u64) -> Result<V02State> {
        Ok(self.dbio.calculate_state_for_id(block_id)?)
    }

    pub fn final_state_db(&self) -> Result<V02State> {
        Ok(self.dbio.final_state()?)
    }

    pub async fn get_account_final(&self, account_id: &AccountId) -> Result<Account> {
        let account = {
            let state_guard = self.final_state.read().await;
            state_guard.get_account_by_id(*account_id)
        };

        Ok(account)
    }

    pub async fn put_block(&mut self, mut block: Block, l1_header: HeaderId) -> Result<()> {
        {
            let mut state_guard = self.final_state.write().await;

            for transaction in &block.body.transactions {
                transaction
                    .clone()
                    .transaction_stateless_check()?
                    .execute_check_on_state(&mut state_guard)?;
            }
        }

        // ToDo: Currently we are fetching only finalized blocks
        // if it changes, the following lines need to be updated
        // to represent correct block finality
        block.bedrock_status = BedrockStatus::Finalized;

        Ok(self.dbio.put_block(block, l1_header.into())?)
    }
}

#[cfg(test)]
mod tests {
    use nssa::AccountId;
    use tempfile::tempdir;

    use super::*;

    fn genesis_block() -> Block {
        common::test_utils::produce_dummy_block(1, None, vec![])
    }

    fn acc1() -> AccountId {
        AccountId::new([
            148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237, 112, 83,
            153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
        ])
    }

    fn acc2() -> AccountId {
        AccountId::new([
            30, 145, 107, 3, 207, 73, 192, 230, 160, 63, 238, 207, 18, 69, 54, 216, 103, 244, 92,
            94, 124, 248, 42, 16, 141, 19, 119, 18, 14, 226, 140, 204,
        ])
    }

    fn acc1_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([1; 32]).unwrap()
    }

    fn acc2_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([2; 32]).unwrap()
    }

    fn initial_state() -> V02State {
        nssa::V02State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[])
    }

    fn transfer(amount: u128, nonce: u128, direction: bool) -> NSSATransaction {
        let from;
        let to;
        let sign_key;

        if direction {
            from = acc1();
            to = acc2();
            sign_key = acc1_sign_key();
        } else {
            from = acc2();
            to = acc1();
            sign_key = acc2_sign_key();
        }

        common::test_utils::create_transaction_native_token_transfer(
            from, nonce, to, amount, sign_key,
        )
    }

    #[test]
    fn test_correct_startup() {
        let storage = IndexerStore::open_db_with_genesis(
            tempdir().unwrap().as_ref(),
            Some((genesis_block(), initial_state())),
        )
        .unwrap();

        let block = storage.get_block_at_id(1).unwrap();
        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(block.header.hash, genesis_block().header.hash);
        assert_eq!(final_id, 1);
    }

    #[actix_rt::test]
    async fn test_state_transition() {
        let mut storage = IndexerStore::open_db_with_genesis(
            tempdir().unwrap().as_ref(),
            Some((genesis_block(), initial_state())),
        )
        .unwrap();

        let mut prev_hash = genesis_block().header.hash;

        for i in 2..10 {
            let tx = transfer(10, i - 2, true);
            let next_block =
                common::test_utils::produce_dummy_block(i as u64, Some(prev_hash), vec![tx]);
            prev_hash = next_block.header.hash;

            storage
                .put_block(next_block, HeaderId::from([i as u8; 32]))
                .await
                .unwrap();
        }

        let acc1_val = storage.get_account_final(&acc1()).await.unwrap();
        let acc2_val = storage.get_account_final(&acc2()).await.unwrap();

        assert_eq!(acc1_val.balance, 9920);
        assert_eq!(acc2_val.balance, 20080);
    }
}
