use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{
    block::{BedrockStatus, Block},
    transaction::{NSSATransaction, clock_invocation},
};
use log::info;
use logos_blockchain_core::{header::HeaderId, mantle::ops::channel::MsgId};
use logos_blockchain_zone_sdk::Slot;
use nssa::{Account, AccountId, V03State, ValidatedStateDiff};
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
                    let state_diff = ValidatedStateDiff::from_public_genesis_transaction(
                        genesis_tx,
                        &state_guard,
                    )
                    .context("Failed to create state diff from genesis transaction")?;
                    state_guard.apply_state_diff(state_diff);
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
    use nssa::{AccountId, CLOCK_01_PROGRAM_ACCOUNT_ID, PublicKey, PublicTransaction};
    use tempfile::tempdir;

    use super::*;

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

    fn genesis_mint_tx(account: AccountId, balance: u128) -> NSSATransaction {
        let message = nssa::public_transaction::Message::try_new(
            nssa::program::Program::authenticated_transfer_program().id(),
            vec![account, CLOCK_01_PROGRAM_ACCOUNT_ID],
            vec![],
            authenticated_transfer_core::Instruction::Mint { amount: balance },
        )
        .unwrap();
        let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness_set).into()
    }

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

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        // Submit genesis block
        let clock_tx = NSSATransaction::Public(clock_invocation(0));
        let supply_from_tx = genesis_mint_tx(from, 10000);
        let supply_to_tx = genesis_mint_tx(to, 20000);
        let genesis_block_data = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType::default(),
            timestamp: 0,
            transactions: vec![supply_from_tx, supply_to_tx, clock_tx],
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

        for i in 2..10 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                i - 2,
                to,
                10,
                &sign_key,
            );
            let block_id = u64::try_from(i).unwrap();

            let next_block = common::test_utils::produce_dummy_block(block_id, prev_hash, vec![tx]);
            prev_hash = Some(next_block.header.hash);

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
