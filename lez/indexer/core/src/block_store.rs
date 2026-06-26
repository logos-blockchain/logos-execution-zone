use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockHeader},
    transaction::{LeeTransaction, clock_invocation},
};
use lee::{Account, AccountId, GENESIS_BLOCK_ID, V03State};
use lee_core::BlockId;
use log::info;
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::Slot;
use storage::indexer::RocksDBIO;
use tokio::sync::RwLock;

use crate::{chain_breaker::ChainBreaker, ingest_error::BlockIngestError};

struct Tip {
    block_id: u64,
    hash: HashType,
}

/// Outcome of feeding a parsed L2 block to the validated tip.
pub enum AcceptOutcome {
    /// Chained and applied; tip and L1 read cursor both advance.
    Applied,
    /// Did not chain or failed to apply; tip stays frozen, breaker recorded.
    Parked(BlockIngestError),
}

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    current_state: Arc<RwLock<V03State>>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    pub fn open_db(location: &Path) -> Result<Self> {
        #[cfg(not(feature = "testnet"))]
        let initial_state = testnet_initial_state::initial_state();

        #[cfg(feature = "testnet")]
        let initial_state = testnet_initial_state::initial_state_testnet();

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

    pub fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Result<Option<LeeTransaction>> {
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
    ) -> Result<Vec<LeeTransaction>> {
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

    pub fn get_zone_cursor(&self) -> Result<Option<Slot>> {
        let Some(bytes) = self.dbio.get_zone_sdk_indexer_cursor_bytes()? else {
            return Ok(None);
        };
        let cursor: Slot = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored zone-sdk indexer cursor")?;
        Ok(Some(cursor))
    }

    pub fn set_zone_cursor(&self, cursor: &Slot) -> Result<()> {
        let bytes =
            serde_json::to_vec(cursor).context("Failed to serialize zone-sdk indexer cursor")?;
        self.dbio.put_zone_sdk_indexer_cursor_bytes(&bytes)?;
        Ok(())
    }

    pub fn get_chain_breaker(&self) -> Result<Option<ChainBreaker>> {
        let Some(bytes) = self.dbio.get_chain_breaker_bytes()? else {
            return Ok(None);
        };
        let breaker: Option<ChainBreaker> =
            serde_json::from_slice(&bytes).context("Failed to deserialize stored chain breaker")?;
        Ok(breaker)
    }

    pub fn set_chain_breaker(&self, breaker: &Option<ChainBreaker>) -> Result<()> {
        let bytes = serde_json::to_vec(breaker).context("Failed to serialize chain breaker")?;
        self.dbio.put_chain_breaker_bytes(&bytes)?;
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

    /// The last successfully applied block as `{block_id, hash}`, or `None` before
    /// any block is stored (cold start). Read fresh from the store each call.
    fn validated_tip(&self) -> Result<Option<Tip>> {
        let Some(block_id) = self.dbio.get_meta_last_block_id_in_db()? else {
            return Ok(None);
        };
        let Some(block) = self.dbio.get_block(block_id)? else {
            return Ok(None);
        };
        Ok(Some(Tip {
            block_id,
            hash: block.header.hash,
        }))
    }

    /// Returns `Some(err)` if `block` is not the valid continuation of the tip:
    /// hash integrity, then block-id continuity, then `prev_block_hash` linkage.
    fn acceptance_error(&self, block: &Block) -> Result<Option<BlockIngestError>> {
        let computed = block.recompute_hash();
        if computed != block.header.hash {
            return Ok(Some(BlockIngestError::HashMismatch {
                computed,
                header: block.header.hash,
            }));
        }

        match self.validated_tip()? {
            None => {
                if block.header.block_id != GENESIS_BLOCK_ID {
                    return Ok(Some(BlockIngestError::UnexpectedBlockId {
                        expected: GENESIS_BLOCK_ID,
                        got: block.header.block_id,
                    }));
                }
            }
            Some(tip) => {
                let expected = tip.block_id.checked_add(1).expect("block id overflow");
                if block.header.block_id != expected {
                    return Ok(Some(BlockIngestError::UnexpectedBlockId {
                        expected,
                        got: block.header.block_id,
                    }));
                }
                if block.header.prev_block_hash != tip.hash {
                    return Ok(Some(BlockIngestError::BrokenChainLink {
                        expected_prev: tip.hash,
                        got_prev: block.header.prev_block_hash,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Records the chain breaker: the first break is stored verbatim; subsequent
    /// breaks only bump `orphans_since`, preserving the original cause.
    fn record_break(
        &self,
        header: Option<&BlockHeader>,
        l1_slot: serde_json::Value,
        error: BlockIngestError,
    ) -> Result<()> {
        let breaker = match self.get_chain_breaker()? {
            Some(mut existing) => {
                existing.orphans_since = existing.orphans_since.saturating_add(1);
                existing
            }
            None => ChainBreaker {
                block_id: header.map(|h| h.block_id),
                block_hash: header.map(|h| h.hash),
                prev_block_hash: header.map(|h| h.prev_block_hash),
                first_seen: header.map(|h| h.timestamp),
                l1_slot,
                error,
                orphans_since: 0,
            },
        };
        self.set_chain_breaker(&Some(breaker))
    }

    /// Records a breaker for an inscription that could not even be parsed.
    pub fn record_deserialize_break(
        &self,
        l1_slot: serde_json::Value,
        error: String,
    ) -> Result<()> {
        self.record_break(None, l1_slot, BlockIngestError::Deserialize(error))
    }

    /// Validates `block` against the tip and, if it chains, applies it atomically
    /// (scratch clone, commit only on full success) and advances the tip. On any
    /// failure records the breaker and returns `Parked` without touching state.
    pub async fn accept_block(
        &self,
        block: &Block,
        l1_slot: serde_json::Value,
    ) -> Result<AcceptOutcome> {
        if let Some(err) = self.acceptance_error(block)? {
            self.record_break(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        // TODO: we use scratch state to be atomic, but need to revisit how expensive a clone is
        let mut scratch = self.current_state.read().await.clone();
        if let Err(err) = apply_block_to_scratch(block, &mut scratch) {
            self.record_break(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        let mut stored = block.clone();
        stored.bedrock_status = BedrockStatus::Finalized;
        if let Err(err) = self.dbio.put_block(&stored, [0_u8; 32]) {
            let ingest_err = BlockIngestError::Storage(err.to_string());
            self.record_break(Some(&block.header), l1_slot, ingest_err.clone())?;
            return Ok(AcceptOutcome::Parked(ingest_err));
        }

        // Commit in-memory state (infallible) only after the DB write succeeded.
        *self.current_state.write().await = scratch;
        self.set_chain_breaker(&None)?;
        Ok(AcceptOutcome::Applied)
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
                *clock_tx == LeeTransaction::Public(clock_invocation(block.header.timestamp)),
                "Last transaction in block must be the clock invocation for the block timestamp"
            );

            let is_genesis = block.header.block_id == 1;
            for transaction in user_txs {
                if is_genesis {
                    let genesis_tx = match transaction {
                        LeeTransaction::Public(public_tx) => public_tx,
                        LeeTransaction::PrivacyPreserving(_)
                        | LeeTransaction::ProgramDeployment(_) => {
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
                    transaction.clone().execute_on_state(
                        &mut state_guard,
                        block.header.block_id,
                        block.header.timestamp,
                    )?;
                }
            }

            // Apply the clock invocation directly (it is expected to modify clock accounts).
            let LeeTransaction::Public(clock_public_tx) = clock_tx else {
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

/// Applies a block's transactions to `state`, mapping every failure to a
/// [`BlockIngestError`] so the caller can park rather than crash. Operates on a
/// scratch state; the caller commits only on `Ok`.
fn apply_block_to_scratch(block: &Block, state: &mut V03State) -> Result<(), BlockIngestError> {
    let (clock_tx, user_txs) =
        block.body.transactions.split_last().ok_or_else(|| {
            BlockIngestError::StateTransition("block has no transactions".to_owned())
        })?;

    let expected_clock = LeeTransaction::Public(clock_invocation(block.header.timestamp));
    if *clock_tx != expected_clock {
        return Err(BlockIngestError::StateTransition(
            "last transaction must be the clock invocation for the block timestamp".to_owned(),
        ));
    }

    let is_genesis = block.header.block_id == GENESIS_BLOCK_ID;
    for transaction in user_txs {
        if is_genesis {
            let LeeTransaction::Public(public_tx) = transaction else {
                return Err(BlockIngestError::StateTransition(
                    "genesis block should contain only public transactions".to_owned(),
                ));
            };
            state
                .transition_from_public_transaction(
                    public_tx,
                    block.header.block_id,
                    block.header.timestamp,
                )
                .map_err(|err| BlockIngestError::StateTransition(format!("{err:?}")))?;
        } else {
            transaction
                .clone()
                .execute_on_state(state, block.header.block_id, block.header.timestamp)
                .map_err(|err| BlockIngestError::StateTransition(format!("{err:?}")))?;
        }
    }

    let LeeTransaction::Public(clock_public_tx) = clock_tx else {
        return Err(BlockIngestError::StateTransition(
            "clock invocation must be a public transaction".to_owned(),
        ));
    };
    state
        .transition_from_public_transaction(
            clock_public_tx,
            block.header.block_id,
            block.header.timestamp,
        )
        .map_err(|err| BlockIngestError::StateTransition(format!("{err:?}")))?;

    Ok(())
}

#[cfg(test)]
mod chain_breaker_tests {
    use common::HashType;

    use super::*;
    use crate::{chain_breaker::ChainBreaker, ingest_error::BlockIngestError};

    #[tokio::test]
    async fn chain_breaker_roundtrips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        assert!(store.get_chain_breaker().expect("get").is_none());

        let breaker = ChainBreaker {
            block_id: Some(7),
            block_hash: Some(HashType([1_u8; 32])),
            prev_block_hash: Some(HashType([2_u8; 32])),
            l1_slot: serde_json::Value::Null,
            error: BlockIngestError::StateTransition("boom".to_owned()),
            first_seen: Some(99),
            orphans_since: 3,
        };
        store
            .set_chain_breaker(&Some(breaker))
            .expect("set breaker");

        let got = store.get_chain_breaker().expect("get").expect("present");
        assert_eq!(got.block_id, Some(7));
        assert_eq!(got.orphans_since, 3);
        assert!(matches!(got.error, BlockIngestError::StateTransition(_)));

        store.set_chain_breaker(&None).expect("clear");
        assert!(store.get_chain_breaker().expect("get").is_none());
    }
}

#[cfg(test)]
mod tests {
    use common::{HashType, block::HashableBlockData};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;

    struct TestFixture {
        storage: IndexerStore,
        from: AccountId,
        to: AccountId,
        _home: tempfile::TempDir,
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "test helper with bounded inputs"
    )]
    async fn store_with_transfer_blocks(
        block_count: u64,
        prev_hash: Option<common::HashType>,
    ) -> TestFixture {
        let home = tempdir().unwrap();
        let storage = IndexerStore::open_db(home.path()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let mut prev_hash = prev_hash;
        for i in 0..block_count {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                u128::from(i),
                to,
                10,
                &sign_key,
            );
            let block_id = i + 1;

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

        TestFixture {
            storage,
            from,
            to,
            _home: home,
        }
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

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let clock_tx = LeeTransaction::Public(clock_invocation(0));
        let genesis_block_data = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType::default(),
            timestamp: 0,
            transactions: vec![clock_tx],
        };
        let genesis_block = genesis_block_data
            .into_pending_block(&common::test_utils::sequencer_sign_key_for_testing());
        let mut prev_hash = Some(genesis_block.header.hash);
        storage
            .put_block(genesis_block, HeaderId::from([0_u8; 32]))
            .await
            .unwrap();

        for i in 0..10_u128 {
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
        let TestFixture {
            storage,
            from,
            to,
            _home,
        } = store_with_transfer_blocks(10, None).await;

        let acc1_at_1 = storage.account_state_at_block(&from, 1).unwrap();
        let acc2_at_1 = storage.account_state_at_block(&to, 1).unwrap();
        assert_eq!(acc1_at_1.balance, 9990);
        assert_eq!(acc2_at_1.balance, 20010);

        let acc1_at_5 = storage.account_state_at_block(&from, 5).unwrap();
        let acc2_at_5 = storage.account_state_at_block(&to, 5).unwrap();
        assert_eq!(acc1_at_5.balance, 9950);
        assert_eq!(acc2_at_5.balance, 20050);

        let acc1_at_9 = storage.account_state_at_block(&from, 9).unwrap();
        let acc2_at_9 = storage.account_state_at_block(&to, 9).unwrap();
        assert_eq!(acc1_at_9.balance, 9910);
        assert_eq!(acc2_at_9.balance, 20090);
    }
}

#[cfg(test)]
mod accept_tests {
    use common::{HashType, block::HashableBlockData};

    use super::*;
    use crate::ingest_error::BlockIngestError;

    fn signing_key() -> lee::PrivateKey {
        lee::PrivateKey::try_new([7_u8; 32]).expect("valid key")
    }

    // A block with a correct hash but empty body — enough to exercise the
    // acceptance checks (id/link/hash), which run before any state application.
    fn valid_hash_block(block_id: u64, prev: HashType) -> common::block::Block {
        HashableBlockData {
            block_id,
            prev_block_hash: prev,
            timestamp: 0,
            transactions: vec![],
        }
        .into_pending_block(&signing_key())
    }

    #[tokio::test]
    async fn non_genesis_first_block_parks_with_unexpected_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let block = valid_hash_block(2, HashType([0_u8; 32]));
        let outcome = store
            .accept_block(&block, serde_json::Value::Null)
            .await
            .expect("accept");

        assert!(matches!(
            outcome,
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 1,
                got: 2
            })
        ));
        let breaker = store.get_chain_breaker().expect("get").expect("present");
        assert_eq!(breaker.block_id, Some(2));
        assert_eq!(breaker.orphans_since, 0);
    }

    #[tokio::test]
    async fn hash_mismatch_parks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let mut block = valid_hash_block(1, HashType([0_u8; 32]));
        block.header.timestamp = 999; // invalidates the stored hash

        let outcome = store
            .accept_block(&block, serde_json::Value::Null)
            .await
            .expect("accept");
        assert!(matches!(
            outcome,
            AcceptOutcome::Parked(BlockIngestError::HashMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn second_break_bumps_orphan_count_and_keeps_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let first = valid_hash_block(2, HashType([0_u8; 32]));
        store
            .accept_block(&first, serde_json::Value::Null)
            .await
            .expect("accept");
        let second = valid_hash_block(3, HashType([0_u8; 32]));
        store
            .accept_block(&second, serde_json::Value::Null)
            .await
            .expect("accept");

        let breaker = store.get_chain_breaker().expect("get").expect("present");
        assert_eq!(breaker.block_id, Some(2), "first breaker preserved");
        assert_eq!(breaker.orphans_since, 1, "second break counted as orphan");
    }

    #[tokio::test]
    async fn deserialize_break_records_breaker_without_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        store
            .record_deserialize_break(serde_json::Value::Null, "bad bytes".to_owned())
            .expect("record");

        let breaker = store.get_chain_breaker().expect("get").expect("present");
        assert_eq!(breaker.block_id, None);
        assert!(matches!(breaker.error, BlockIngestError::Deserialize(_)));
    }
}
