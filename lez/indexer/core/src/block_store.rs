use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use chain_state::{
    AcceptOutcome, BlockIngestError, StallReason, Tip, apply_block_to_state, validate_against_tip,
};
use common::{
    block::{BedrockStatus, Block, BlockHeader},
    transaction::LeeTransaction,
};
use lee::{Account, AccountId, V03State};
use lee_core::BlockId;
use log::warn;
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::Slot;
use storage::indexer::RocksDBIO;
use tokio::sync::RwLock;

use crate::status::CrossZoneHalt;

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    current_state: Arc<RwLock<V03State>>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    pub fn open_db(location: &Path, genesis_seed: Vec<(AccountId, Account)>) -> Result<Self> {
        #[cfg(not(feature = "testnet"))]
        let base = testnet_initial_state::initial_state();

        #[cfg(feature = "testnet")]
        let base = testnet_initial_state::initial_state_testnet();

        // Seed any zone-specific genesis accounts (the bridge-lock holdings) so the
        // indexer's replayed state matches the sequencer's; none are produced by a
        // transaction. Cross-zone programs are base builtins, and their config
        // accounts are reconstructed by replaying the genesis block's InitConfig txs.
        let initial_state = base.with_public_accounts(genesis_seed);
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

    /// The L1 inscription slot of the validated tip, written atomically with it
    /// by [`Self::accept_block`]. `None` on a cold store or one written before
    /// the slot was recorded.
    pub fn get_tip_slot(&self) -> Result<Option<Slot>> {
        Ok(self.dbio.get_meta_tip_slot_in_db()?.map(Slot::from))
    }

    pub fn get_cross_zone_halt(&self) -> Result<Option<CrossZoneHalt>> {
        let Some(bytes) = self.dbio.get_cross_zone_halt_bytes()? else {
            return Ok(None);
        };
        let halt: Option<CrossZoneHalt> = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored cross-zone halt record")?;
        Ok(halt)
    }

    pub fn set_cross_zone_halt(&self, halt: &Option<CrossZoneHalt>) -> Result<()> {
        let bytes =
            serde_json::to_vec(halt).context("Failed to serialize cross-zone halt record")?;
        self.dbio.put_cross_zone_halt_bytes(&bytes)?;
        Ok(())
    }

    pub fn get_stall_reason(&self) -> Result<Option<StallReason>> {
        let Some(bytes) = self.dbio.get_stall_reason_bytes()? else {
            return Ok(None);
        };
        let stall: Option<StallReason> =
            serde_json::from_slice(&bytes).context("Failed to deserialize stored stall reason")?;
        Ok(stall)
    }

    pub fn set_stall_reason(&self, stall: &Option<StallReason>) -> Result<()> {
        let bytes = serde_json::to_vec(stall).context("Failed to serialize stall reason")?;
        self.dbio.put_stall_reason_bytes(&bytes)?;
        Ok(())
    }

    /// Clears a recorded stall marker if one is present, skipping the write otherwise.
    fn clear_stall_if_present(&self) -> Result<()> {
        if self.get_stall_reason()?.is_some() {
            self.set_stall_reason(&None)?;
        }
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

    /// The last successfully applied block, or `None` on a cold store.
    /// Read fresh from the store each call.
    fn validated_tip(&self) -> Result<Option<Tip>> {
        let Some(block_id) = self.dbio.get_meta_last_block_id_in_db()? else {
            return Ok(None);
        };
        let Some(block) = self.dbio.get_block(block_id)? else {
            return Ok(None);
        };
        Ok(Some(Tip::from(&block)))
    }

    /// Record the stall reason.
    ///
    /// - First stall is stored verbatim
    /// - Subsequent stalls only bump `orphans_since`, preserving the original cause.
    pub fn record_stall(
        &self,
        header: Option<&BlockHeader>,
        l1_slot: Slot,
        error: BlockIngestError,
    ) -> Result<()> {
        let stall = self.get_stall_reason()?.map_or_else(
            || StallReason::new(header, l1_slot, error),
            StallReason::escalate,
        );
        self.set_stall_reason(&Some(stall))
    }

    /// Validates `block` against the tip and, if it chains, applies it atomically
    /// (scratch clone, commit only on full success) and advances the tip.
    /// Retryable apply failures return `RetryableFailure` without recording a stall
    /// or touching state; other failures record the stall and return `Parked`.
    pub async fn accept_block(&self, block: &Block, l1_slot: Slot) -> Result<AcceptOutcome> {
        let tip = self.validated_tip()?;

        // Re-delivery of an already-applied block is idempotent, not a divergence
        if let Some(tip) = &tip
            && block.header.block_id <= tip.block_id
            && let Some(stored) = self.get_block_at_id(block.header.block_id)?
            && stored.header.hash == block.header.hash
        {
            return Ok(AcceptOutcome::AlreadyApplied);
        }

        // Validate before paying for the scratch clone; validation failures
        // are never retryable, so parking immediately is exact.
        if let Err(err) = validate_against_tip(tip.as_ref(), block) {
            self.record_stall(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        // TODO: we use scratch state to be atomic, but need to revisit how expensive a clone is
        let mut scratch = self.current_state.read().await.clone();
        if let Err(err) = apply_block_to_state(block, &mut scratch) {
            if err.is_retryable() {
                return Ok(AcceptOutcome::RetryableFailure(err));
            }
            self.record_stall(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        let mut stored = block.clone();
        stored.bedrock_status = BedrockStatus::Finalized;
        self.dbio
            .put_block(&stored, [0_u8; 32], l1_slot.into_inner(), &scratch)
            .context("Failed to persist accepted block")?;

        // Commit in-memory state (infallible) only after the DB write succeeded.
        *self.current_state.write().await = scratch;
        // Best-effort: the block is durably applied, so a failed stall clear must not
        // fail the apply. It self-heals on the next clear.
        if let Err(err) = self.clear_stall_if_present() {
            warn!("Failed to clear stall marker after applying block: {err:#}");
        }
        Ok(AcceptOutcome::Applied)
    }
}

#[cfg(test)]
mod stall_reason_tests {
    use common::HashType;

    use super::*;

    #[tokio::test]
    async fn stall_reason_roundtrips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        assert!(store.get_stall_reason().expect("get").is_none());

        let stall = StallReason {
            block_id: Some(7),
            block_hash: Some(HashType([1_u8; 32])),
            prev_block_hash: Some(HashType([2_u8; 32])),
            l1_slot: Slot::from(42),
            error: BlockIngestError::StateTransition {
                tx_index: 0,
                reason: "boom".to_owned(),
            },
            first_seen: Some(99),
            orphans_since: 3,
        };
        store.set_stall_reason(&Some(stall)).expect("set stall");

        let got = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(got.block_id, Some(7));
        assert_eq!(got.orphans_since, 3);
        assert!(matches!(
            got.error,
            BlockIngestError::StateTransition { .. }
        ));
        assert_eq!(got.block_hash, Some(HashType([1_u8; 32])));
        assert_eq!(got.prev_block_hash, Some(HashType([2_u8; 32])));
        assert_eq!(got.l1_slot, Slot::from(42));
        assert_eq!(got.first_seen, Some(99));

        store.set_stall_reason(&None).expect("clear");
        assert!(store.get_stall_reason().expect("get").is_none());
    }

    #[tokio::test]
    async fn cross_zone_halt_roundtrips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        assert!(store.get_cross_zone_halt().expect("get").is_none());

        let halt = crate::status::CrossZoneHalt {
            block_id: 9,
            block_hash: HashType([0xAB_u8; 32]),
            src_zone: hex::encode([2_u8; 32]),
            src_block_id: 5,
            src_tx_index: 1,
            verdict: "re-derivation mismatch".to_owned(),
        };
        store
            .set_cross_zone_halt(&Some(halt.clone()))
            .expect("set halt");
        assert_eq!(store.get_cross_zone_halt().expect("get"), Some(halt));

        store.set_cross_zone_halt(&None).expect("clear");
        assert!(store.get_cross_zone_halt().expect("get").is_none());
    }
}

/// A block whose forced fee transaction carries the summary its transactions
/// settle to against `state`, which is advanced past the block.
#[cfg(test)]
fn settled_test_block(
    state: &mut lee::V03State,
    id: u64,
    prev_hash: Option<common::HashType>,
    txs: Vec<common::transaction::LeeTransaction>,
) -> common::block::Block {
    use common::{
        block::HashableBlockData,
        test_utils::sequencer_sign_key_for_testing,
        transaction::{LeeTransaction, clock_invocation, fee_invocation},
    };
    let timestamp = id.saturating_mul(100);
    let summary = chain_state::apply::derive_block_summary(state, &txs, id, timestamp)
        .expect("test transactions settle");
    let producer = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
        &sequencer_sign_key_for_testing(),
    ));
    let mut transactions = txs;
    transactions.push(LeeTransaction::Public(fee_invocation(summary, producer)));
    transactions.push(LeeTransaction::Public(clock_invocation(timestamp)));
    let block = HashableBlockData {
        block_id: id,
        prev_block_hash: prev_hash.unwrap_or_default(),
        timestamp,
        transactions,
    }
    .into_pending_block(&sequencer_sign_key_for_testing());
    chain_state::apply::apply_block_to_state(&block, state).expect("settled block applies");
    block
}

#[cfg(test)]
mod tests {
    use common::test_utils::{create_transaction_native_token_transfer, produce_dummy_block};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;

    #[test]
    fn correct_startup() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db(home.as_ref(), Vec::new()).unwrap();

        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(final_id, None);
    }

    #[tokio::test]
    async fn accept_block_applies_transfers_and_advances_tip() {
        let home = tempdir().unwrap();
        let store = IndexerStore::open_db(home.as_ref(), Vec::new()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        // Genesis (block 1): fee/clock only.
        let mut build_state = testnet_initial_state::initial_state();
        let initial_from = build_state.get_account_by_id(from).balance;
        let initial_to = build_state.get_account_by_id(to).balance;
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        let mut prev_hash = genesis.header.hash;
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        // Blocks 2..=11: one charged native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = settled_test_block(&mut build_state, i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        // The recipient gains exactly the transfers; the sender also pays fees.
        assert!(store.account_current_state(&from).await.unwrap().balance < initial_from - 100);
        assert_eq!(
            store.account_current_state(&to).await.unwrap().balance,
            initial_to + 100
        );
        // Tip advanced to the last applied block; a clean run leaves no stall.
        assert_eq!(store.get_last_block_id().unwrap(), Some(11));
        assert!(store.get_stall_reason().unwrap().is_none());
    }

    #[tokio::test]
    async fn account_state_at_block_reflects_history() {
        let home = tempdir().unwrap();
        let store = IndexerStore::open_db(home.as_ref(), Vec::new()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let mut build_state = testnet_initial_state::initial_state();
        let initial_from = build_state.get_account_by_id(from).balance;
        let initial_to = build_state.get_account_by_id(to).balance;
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        let mut prev_hash = genesis.header.hash;
        store.accept_block(&genesis, Slot::from(0)).await.unwrap();

        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = settled_test_block(&mut build_state, i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            store.accept_block(&block, Slot::from(0)).await.unwrap();
        }

        // State at block N is inclusive of block N.
        // Block 1 (genesis, clock-only): no transfers yet.
        assert_eq!(
            store.account_state_at_block(&from, 1).unwrap().balance,
            initial_from
        );
        assert_eq!(
            store.account_state_at_block(&to, 1).unwrap().balance,
            initial_to
        );
        // Through block 5: 4 transfers applied (blocks 2..=5); the sender also
        // pays a fee per charged transfer.
        assert!(store.account_state_at_block(&from, 5).unwrap().balance < initial_from - 40);
        assert_eq!(
            store.account_state_at_block(&to, 5).unwrap().balance,
            initial_to + 40
        );
        // Through block 9: 8 transfers applied (blocks 2..=9).
        assert!(store.account_state_at_block(&from, 9).unwrap().balance < initial_from - 80);
        assert_eq!(
            store.account_state_at_block(&to, 9).unwrap().balance,
            initial_to + 80
        );
    }
}

#[cfg(test)]
mod accept_tests {
    use common::{HashType, block::HashableBlockData, test_utils::produce_dummy_block};

    use super::*;

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
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let block = valid_hash_block(2, HashType([0_u8; 32]));
        let outcome = store
            .accept_block(&block, Slot::from(0))
            .await
            .expect("accept");

        assert!(matches!(
            outcome,
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 1,
                got: 2
            })
        ));
        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, Some(2));
        assert_eq!(stall.orphans_since, 0);
    }

    #[tokio::test]
    async fn hash_mismatch_parks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let mut block = valid_hash_block(1, HashType([0_u8; 32]));
        block.header.timestamp = 999; // invalidates the stored hash

        let outcome = store
            .accept_block(&block, Slot::from(0))
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
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let first = valid_hash_block(2, HashType([0_u8; 32]));
        store
            .accept_block(&first, Slot::from(0))
            .await
            .expect("accept");
        let second = valid_hash_block(3, HashType([0_u8; 32]));
        store
            .accept_block(&second, Slot::from(0))
            .await
            .expect("accept");

        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, Some(2), "first stall preserved");
        assert_eq!(stall.orphans_since, 1, "second break counted as orphan");
    }

    #[tokio::test]
    async fn deserialize_break_records_stall_without_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        store
            .record_stall(
                None,
                Slot::from(0),
                BlockIngestError::Deserialize("bad bytes".to_owned()),
            )
            .expect("record");

        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, None);
        assert!(matches!(stall.error, BlockIngestError::Deserialize(_)));
    }

    #[tokio::test]
    async fn parks_then_recovers_on_valid_continuation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        // Genesis (block 1, clock-only) applies and advances the tip.
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        // A block that skips ahead (id 3 while the tip is 1) parks the indexer.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&bad, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 2,
                got: 3
            })
        ));
        assert!(
            store.get_stall_reason().unwrap().is_some(),
            "indexer should be parked after the bad block"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(1),
            "validated tip must stay frozen at genesis while parked"
        );

        // The valid continuation (block 2 chaining on genesis) recovers the chain.
        let next = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&next, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "stall reason must clear on recovery"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(2),
            "tip must advance to the recovered block"
        );
    }

    #[tokio::test]
    async fn accept_block_records_tip_inscription_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        assert_eq!(store.get_tip_slot().expect("get"), None);

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(1_000))
            .await
            .expect("accept");
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_000)));

        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        store
            .accept_block(&block2, Slot::from(1_005))
            .await
            .expect("accept");
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));

        // A parked block freezes the tip, so its slot must not advance either.
        let bad = produce_dummy_block(4, Some(block2.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&bad, Slot::from(1_010)).await.unwrap(),
            AcceptOutcome::Parked(_)
        ));
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));

        // Neither must a re-delivered old block move it.
        assert!(matches!(
            store
                .accept_block(&genesis, Slot::from(1_015))
                .await
                .unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));
    }

    #[tokio::test]
    async fn redelivered_tip_block_is_idempotent_not_parked() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut build_state = testnet_initial_state::initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // Block 2: a single transfer of 10.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block = crate::block_store::settled_test_block(
            &mut build_state,
            2,
            Some(genesis.header.hash),
            vec![tx],
        );
        assert!(matches!(
            store.accept_block(&block, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        let balance_after = store.account_current_state(&from).await.unwrap().balance;

        // Re-deliver the exact same block: idempotent skip, no state change, no park.
        assert!(matches!(
            store.accept_block(&block, Slot::from(0)).await.unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            balance_after,
            "re-delivered block must not be applied twice"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(2),
            "tip must stay at the already-applied block"
        );
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "a benign duplicate must not park the indexer"
        );
    }

    #[tokio::test]
    async fn redelivered_block_below_tip_is_idempotent_not_parked() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Build a short chain: genesis (1) -> block 2 -> block 3, so the tip is 3.
        let mut build_state = testnet_initial_state::initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        let tx2 = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block2 = crate::block_store::settled_test_block(
            &mut build_state,
            2,
            Some(genesis.header.hash),
            vec![tx2],
        );
        assert!(matches!(
            store.accept_block(&block2, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let tx3 = common::test_utils::create_transaction_native_token_transfer(
            from, 1, to, 10, &sign_key,
        );
        let block3 = crate::block_store::settled_test_block(
            &mut build_state,
            3,
            Some(block2.header.hash),
            vec![tx3],
        );
        assert!(matches!(
            store.accept_block(&block3, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let balance_after = store.account_current_state(&from).await.unwrap().balance;

        // Re-deliver block 2 (id below the tip): a re-delivery, not a divergence.
        assert!(matches!(
            store.accept_block(&block2, Slot::from(0)).await.unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            balance_after,
            "re-delivered block below the tip must not be applied again"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(3),
            "tip must stay at the current head"
        );
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "a benign re-delivery must not park the indexer"
        );
    }

    #[tokio::test]
    async fn accept_block_snapshots_state_at_breakpoint_interval() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut build_state = testnet_initial_state::initial_state();
        let initial_from = build_state.get_account_by_id(from).balance;
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        let mut prev_hash = genesis.header.hash;

        // Blocks 2..=101: one charged transfer of 1 each; block 100 crosses the
        // interval.
        for i in 0..100_u64 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                i.into(),
                to,
                1,
                &sign_key,
            );
            let block = crate::block_store::settled_test_block(
                &mut build_state,
                i + 2,
                Some(prev_hash),
                vec![tx],
            );
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        // Snapshot at block 100 = genesis + 99 transfers (plus their fees),
        // written with the block.
        let bp1 = store.dbio.get_breakpoint(1).expect("breakpoint 1 present");
        assert!(bp1.get_account_by_id(from).balance < initial_from - 99);

        // The #605 restart: reopening past the boundary must work.
        drop(store);
        let reopened = IndexerStore::open_db(dir.path(), Vec::new()).expect("reopen");
        assert_eq!(reopened.last_block().unwrap(), Some(101));
    }

    #[tokio::test]
    async fn transient_apply_failure_returns_retryable_failure_without_stall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path(), Vec::new()).expect("open store");

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // A system-shaped bridge deposit (empty witness set, so fee-exempt by
        // classification) whose execution fails: the guest rejects the bogus
        // accounts → StateTransition → retryable. A charged overdraft no
        // longer works here: it reverts-with-fee inside a valid block.
        let bogus_deposit = {
            let message = lee::public_transaction::Message::try_new(
                programs::bridge().id(),
                vec![
                    lee::AccountId::new([1_u8; 32]),
                    lee::AccountId::new([2_u8; 32]),
                ],
                vec![],
                bridge_core::Instruction::Deposit {
                    l1_deposit_op_id: [7_u8; 32],
                    vault_program_id: programs::vault().id(),
                    recipient_id: lee::AccountId::new([3_u8; 32]),
                    amount: 5,
                },
            )
            .expect("valid message");
            common::transaction::LeeTransaction::Public(lee::PublicTransaction::new(
                message,
                lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
            ))
        };
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![bogus_deposit]);
        let outcome = store.accept_block(&block, Slot::from(0)).await.unwrap();

        assert!(matches!(
            outcome,
            AcceptOutcome::RetryableFailure(BlockIngestError::StateTransition { .. })
        ));
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "retryable failure must not persist a stall"
        );
        assert_eq!(store.get_last_block_id().unwrap(), Some(1), "tip frozen");
    }
}
