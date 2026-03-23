use std::{path::Path, sync::Arc};

use anyhow::Result;
use bedrock_client::HeaderId;
use common::{
    block::{BedrockStatus, Block, BlockId},
    transaction::NSSATransaction,
};
use nssa::{Account, AccountId, V03State};
use storage::indexer::RocksDBIO;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    current_state: Arc<RwLock<V03State>>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    ///
    /// ATTENTION: Will overwrite genesis block.
    pub fn open_db_with_genesis(
        location: &Path,
        genesis_block: &Block,
        initial_state: &V03State,
    ) -> Result<Self> {
        let dbio = RocksDBIO::open_or_create(location, genesis_block, initial_state)?;
        let current_state = dbio.final_state()?;

        Ok(Self {
            dbio: Arc::new(dbio),
            current_state: Arc::new(RwLock::new(current_state)),
        })
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

    pub fn get_block_at_id(&self, id: u64) -> Result<Option<Block>> {
        Ok(self.dbio.get_block(id)?)
    }

    pub fn get_block_batch(&self, before: Option<BlockId>, limit: u64) -> Result<Vec<Block>> {
        Ok(self.dbio.get_block_batch(before, limit)?)
    }

    pub fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Result<Option<NSSATransaction>> {
        let Some(block_id) = self.dbio.get_block_id_by_tx_hash(tx_hash)? else {
            return Ok(None);
        };
        let Some(block) = self.get_block_at_id(block_id)? else {
            return Ok(None);
        };
        Ok(block
            .body
            .transactions
            .into_iter()
            .find(|enc_tx| enc_tx.hash().0 == tx_hash))
    }

    pub fn get_block_by_hash(&self, hash: [u8; 32]) -> Result<Option<Block>> {
        let Some(id) = self.dbio.get_block_id_by_hash(hash)? else {
            return Ok(None);
        };
        self.get_block_at_id(id)
    }

    pub fn get_transactions_by_account(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> Result<Vec<NSSATransaction>> {
        Ok(self.dbio.get_acc_transactions(acc_id, offset, limit)?)
    }

    #[must_use]
    pub fn genesis_id(&self) -> u64 {
        self.dbio
            .get_meta_first_block_in_db()
            .expect("Must be set at the DB startup")
    }

    #[must_use]
    pub fn last_block(&self) -> u64 {
        self.dbio
            .get_meta_last_block_in_db()
            .expect("Must be set at the DB startup")
    }

    pub fn get_state_at_block(&self, block_id: u64) -> Result<V03State> {
        Ok(self.dbio.calculate_state_for_id(block_id)?)
    }

    /// Recalculation of final state directly from DB.
    ///
    /// Used for indexer healthcheck.
    pub fn recalculate_final_state(&self) -> Result<V03State> {
        Ok(self.dbio.final_state()?)
    }

    pub async fn account_current_state(&self, account_id: &AccountId) -> Result<Account> {
        Ok(self
            .current_state
            .read()
            .await
            .get_account_by_id(*account_id))
    }

    pub async fn put_block(&self, mut block: Block, l1_header: HeaderId) -> Result<()> {
        {
            let mut state_guard = self.current_state.write().await;

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

        Ok(self.dbio.put_block(&block, l1_header.into())?)
    }
}

#[cfg(test)]
mod tests {
    use nssa::{AccountId, PublicKey};
    use tempfile::tempdir;

    use super::*;

    fn genesis_block() -> Block {
        common::test_utils::produce_dummy_block(1, None, vec![])
    }

    fn acc1_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([1; 32]).unwrap()
    }

    fn acc2_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([2; 32]).unwrap()
    }

    fn acc1() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(&acc1_sign_key()))
    }

    fn acc2() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(&acc2_sign_key()))
    }

    #[test]
    fn correct_startup() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db_with_genesis(
            home.as_ref(),
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let block = storage.get_block_at_id(1).unwrap().unwrap();
        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(block.header.hash, genesis_block().header.hash);
        assert_eq!(final_id, 1);
    }

    #[tokio::test]
    async fn state_transition() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db_with_genesis(
            home.as_ref(),
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let mut prev_hash = genesis_block().header.hash;

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        for i in 2..10 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                i - 2,
                to,
                10,
                &sign_key,
            );

            let next_block = common::test_utils::produce_dummy_block(
                u64::try_from(i).unwrap(),
                Some(prev_hash),
                vec![tx],
            );
            prev_hash = next_block.header.hash;

            storage
                .put_block(next_block, HeaderId::from([u8::try_from(i).unwrap(); 32]))
                .await
                .unwrap();
        }

        let acc1_val = storage.account_current_state(&acc1()).await.unwrap();
        let acc2_val = storage.account_current_state(&acc2()).await.unwrap();

        assert_eq!(acc1_val.balance, 9920);
        assert_eq!(acc2_val.balance, 20080);
    }
}
