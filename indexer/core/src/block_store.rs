use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{
    block::{BedrockStatus, Block},
    transaction::{NSSATransaction, clock_invocation},
};
use log::info;
use logos_blockchain_core::{header::HeaderId, mantle::ops::channel::MsgId};
use logos_blockchain_zone_sdk::Slot;
use nssa::{Account, AccountId, V03State};
use nssa_core::BlockId;
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
    pub fn open_db(location: &Path) -> Result<Self> {
        let initial_state = testnet_initial_state::initial_state();
        let dbio = RocksDBIO::open_or_create(location, &initial_state)?;

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

    pub fn get_last_block_id(&self) -> Result<Option<u64>> {
        self.dbio.get_meta_last_block_id_in_db().map_err(Into::into)
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

    pub fn genesis_id(&self) -> Result<Option<u64>> {
        self.dbio
            .get_meta_first_block_id_in_db()
            .map_err(Into::into)
    }

    pub fn last_block(&self) -> Result<Option<u64>> {
        self.dbio.get_meta_last_block_id_in_db().map_err(Into::into)
    }

    pub fn get_state_at_block(&self, block_id: u64) -> Result<V03State> {
        Ok(self.dbio.calculate_state_for_id(block_id)?)
    }

    pub fn get_zone_cursor(&self) -> Result<Option<(MsgId, Slot)>> {
        let Some(bytes) = self.dbio.get_zone_sdk_indexer_cursor_bytes()? else {
            return Ok(None);
        };
        let cursor: (MsgId, Slot) = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored zone-sdk indexer cursor")?;
        Ok(Some(cursor))
    }

    pub fn set_zone_cursor(&self, cursor: &(MsgId, Slot)) -> Result<()> {
        let bytes =
            serde_json::to_vec(cursor).context("Failed to serialize zone-sdk indexer cursor")?;
        self.dbio.put_zone_sdk_indexer_cursor_bytes(&bytes)?;
        Ok(())
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

    pub fn account_state_at_block(&self, account_id: &AccountId, block_id: u64) -> Result<Account> {
        Ok(self
            .get_state_at_block(block_id)?
            .get_account_by_id(*account_id))
    }

    pub async fn put_block(&self, mut block: Block, l1_header: HeaderId) -> Result<()> {
        info!("Applying block {}", block.header.block_id);
        {
            let mut state_guard = self.current_state.write().await;

            let (clock_tx, user_txs) = block
                .body
                .transactions
                .split_last()
                .ok_or_else(|| anyhow::anyhow!("Block has no transactions"))?;

            anyhow::ensure!(
                *clock_tx == NSSATransaction::Public(clock_invocation(block.header.timestamp)),
                "Last transaction in block must be the clock invocation for the block timestamp"
            );

            let is_genesis = block.header.block_id == 1;
            for transaction in user_txs {
                if is_genesis {
                    let genesis_tx = match transaction {
                        NSSATransaction::Public(public_tx) => public_tx,
                        NSSATransaction::PrivacyPreserving(_)
                        | NSSATransaction::ProgramDeployment(_) => {
                            anyhow::bail!("Genesis block should contain only public transactions")
                        }
                    };
                    state_guard
                        .transition_from_public_transaction(
                            genesis_tx,
                            block.header.block_id,
                            block.header.timestamp,
                        )
                        .context("Failed to execute genesis public transaction")?;
                } else {
                    transaction
                        .clone()
                        .transaction_stateless_check()?
                        .execute_check_on_state(
                            &mut state_guard,
                            block.header.block_id,
                            block.header.timestamp,
                        )?;
                }
            }

            // Apply the clock invocation directly (it is expected to modify clock accounts).
            let NSSATransaction::Public(clock_public_tx) = clock_tx else {
                anyhow::bail!("Clock invocation must be a public transaction");
            };
            state_guard.transition_from_public_transaction(
                clock_public_tx,
                block.header.block_id,
                block.header.timestamp,
            )?;
        }

        // ToDo: Currently we are fetching only finalized blocks
        // if it changes, the following lines need to be updated
        // to represent correct block finality
        block.bedrock_status = BedrockStatus::Finalized;

        info!("Putting block {} into DB", block.header.block_id);
        Ok(self.dbio.put_block(&block, l1_header.into())?)
    }
}

#[cfg(test)]
mod tests {
    use common::{HashType, block::HashableBlockData};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;

    #[test]
    fn correct_startup() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db(home.as_ref()).unwrap();

        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(final_id, None);
    }

    #[tokio::test]
    async fn state_transition() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db(home.as_ref()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        // Submit genesis block
        let clock_tx = NSSATransaction::Public(clock_invocation(0));
        let genesis_block_data = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType::default(),
            timestamp: 0,
            transactions: vec![clock_tx],
        };
        let genesis_block = genesis_block_data.into_pending_block(
            &common::test_utils::sequencer_sign_key_for_testing(),
            [0; 32],
        );
        let mut prev_hash = Some(genesis_block.header.hash);
        storage
            .put_block(genesis_block, HeaderId::from([0_u8; 32]))
            .await
            .unwrap();

        for i in 0..10 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from, i, to, 10, &sign_key,
            );
            let block_id = u64::try_from(i + 1).unwrap();

            let next_block = common::test_utils::produce_dummy_block(block_id, prev_hash, vec![tx]);
            prev_hash = Some(next_block.header.hash);

            storage
                .put_block(
                    next_block,
                    HeaderId::from([u8::try_from(i + 1).unwrap(); 32]),
                )
                .await
                .unwrap();
        }

        let acc1_val = storage.account_current_state(&from).await.unwrap();
        let acc2_val = storage.account_current_state(&to).await.unwrap();

        assert_eq!(acc1_val.balance, 9900);
        assert_eq!(acc2_val.balance, 20100);
    }

    #[tokio::test]
    async fn account_state_at_block() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db(home.as_ref()).unwrap();

        let mut prev_hash = None;

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        for i in 0..10 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from, i, to, 10, &sign_key,
            );
            let block_id = u64::try_from(i + 1).unwrap();

            let next_block = common::test_utils::produce_dummy_block(block_id, prev_hash, vec![tx]);
            prev_hash = Some(next_block.header.hash);

            storage
                .put_block(
                    next_block,
                    HeaderId::from([u8::try_from(i + 1).unwrap(); 32]),
                )
                .await
                .unwrap();
        }

        // Genesis block: no transfers applied yet.
        let acc1_at_1 = storage.account_state_at_block(&from, 1).unwrap();
        let acc2_at_1 = storage.account_state_at_block(&to, 1).unwrap();
        assert_eq!(acc1_at_1.balance, 9990);
        assert_eq!(acc2_at_1.balance, 20010);

        // After block 5: 4 transfers of 10 applied (one each in blocks 2..=5).
        let acc1_at_5 = storage.account_state_at_block(&from, 5).unwrap();
        let acc2_at_5 = storage.account_state_at_block(&to, 5).unwrap();
        assert_eq!(acc1_at_5.balance, 9950);
        assert_eq!(acc2_at_5.balance, 20050);

        // After final block 9: 8 transfers applied; should match current state.
        let acc1_at_9 = storage.account_state_at_block(&from, 9).unwrap();
        let acc2_at_9 = storage.account_state_at_block(&to, 9).unwrap();
        assert_eq!(acc1_at_9.balance, 9910);
        assert_eq!(acc2_at_9.balance, 20090);
    }
}
