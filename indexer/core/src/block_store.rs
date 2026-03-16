use std::{path::Path, sync::Arc};

use anyhow::Result;
use bedrock_client::HeaderId;
use common::{
    block::{BedrockStatus, Block},
    transaction::NSSATransaction,
};
use nssa::{Account, AccountId, V02State};
use storage::indexer::RocksDBIO;

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
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

        Ok(Self {
            dbio: Arc::new(dbio),
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

    pub fn final_state(&self) -> Result<V02State> {
        Ok(self.dbio.final_state()?)
    }

    pub fn get_account_final(&self, account_id: &AccountId) -> Result<Account> {
        Ok(self.final_state()?.get_account_by_id(*account_id))
    }

    pub fn put_block(&self, mut block: Block, l1_header: HeaderId) -> Result<()> {
        let mut final_state = self.dbio.final_state()?;

        for transaction in &block.body.transactions {
            transaction
                .clone()
                .transaction_stateless_check()?
                .execute_check_on_state(&mut final_state)?;
        }

        // ToDo: Currently we are fetching only finalized blocks
        // if it changes, the following lines need to be updated
        // to represent correct block finality
        block.bedrock_status = BedrockStatus::Finalized;

        Ok(self.dbio.put_block(block, l1_header.into())?)
    }
}
