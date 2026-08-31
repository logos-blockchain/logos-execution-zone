use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result, ensure};
use chain_state::{
    AcceptOutcome, BlockIngestError, StallReason, Tip, apply_block_to_state, validate_against_tip,
};
use common::{
    block::{BedrockStatus, Block, BlockHeader},
    transaction::{LeeTransaction, TxEvents},
};
use lee::{Account, AccountId, V03State};
use lee_core::BlockId;
use log::warn;
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::Slot;
use storage::indexer::RocksDBIO;
use tokio::sync::RwLock;

use crate::{event_filter::EventFilter, status::CrossZoneHalt};

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    current_state: Arc<RwLock<V03State>>,
    filter_segments: Vec<(EventFilter, BlockId)>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    pub fn open_db(location: &Path, event_filter: EventFilter) -> Result<Self> {
        #[cfg(not(feature = "testnet"))]
        let initial_state = testnet_initial_state::initial_state();

        #[cfg(feature = "testnet")]
        let initial_state = testnet_initial_state::initial_state_testnet();

        // Nothing zone-specific is seeded here: cross-zone program configs and
        // bridge-lock holdings alike are reconstructed by replaying the genesis
        // block's transactions, so this state matches the sequencer's by
        // construction.
        let dbio = RocksDBIO::open_or_create(location, &initial_state)?;

        let current_state = dbio.final_state()?;
        let filter_segments = reconcile_filter_segments(&dbio, event_filter)?;
        if filter_segments
            .last()
            .is_some_and(|(filter, _)| filter.keeps_nothing())
        {
            warn!(
                "Configured event filter keeps no events: none are captured and every event \
                 query is rejected as uncovered"
            );
        }

        Ok(Self {
            dbio: Arc::new(dbio),
            current_state: Arc::new(RwLock::new(current_state)),
            filter_segments,
        })
    }

    /// The filter ingest currently applies — the last recorded segment.
    #[must_use]
    pub fn live_filter(&self) -> &EventFilter {
        &self
            .filter_segments
            .last()
            .expect("reconcile seeds at least one segment")
            .0
    }

    /// Applied filters with the height each took effect at, oldest first; the
    /// events column only holds what the filter of its era kept.
    #[must_use]
    pub fn filter_segments(&self) -> &[(EventFilter, BlockId)] {
        &self.filter_segments
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

    pub fn get_events_for_block(&self, block_id: BlockId) -> Result<Option<Vec<TxEvents>>> {
        Ok(self.dbio.get_block_events(block_id)?)
    }

    pub fn get_events_range(
        &self,
        from: BlockId,
        to: BlockId,
    ) -> Result<Vec<(BlockId, Vec<TxEvents>)>> {
        Ok(self.dbio.get_block_events_range(from, to)?)
    }

    pub fn block_id_by_tx_hash(&self, tx_hash: [u8; 32]) -> Result<Option<BlockId>> {
        Ok(self.dbio.get_block_id_by_tx_hash(tx_hash)?)
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
        let events = match apply_block_to_state(block, &mut scratch) {
            Ok(events) => events,
            Err(err) => {
                if err.is_retryable() {
                    return Ok(AcceptOutcome::RetryableFailure(err));
                }
                self.record_stall(Some(&block.header), l1_slot, err.clone())?;
                return Ok(AcceptOutcome::Parked(err));
            }
        };
        // The retained events come from the same application that produced `scratch`,
        // and are written in the same `put_block` batch as the block and that state.
        let events = self.live_filter().filter_block(events);

        let mut stored = block.clone();
        stored.bedrock_status = BedrockStatus::Finalized;
        self.dbio
            .put_block(&stored, [0_u8; 32], l1_slot.into_inner(), &scratch, &events)
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

// A filter change takes effect at the next ingested block: rows up to the old
// tip were written under the previous filter and stay attributed to it.
fn reconcile_filter_segments(
    dbio: &RocksDBIO,
    configured: EventFilter,
) -> Result<Vec<(EventFilter, BlockId)>> {
    let mut segments: Vec<(EventFilter, BlockId)> = match dbio.get_event_filter_segments_bytes()? {
        Some(bytes) => borsh::from_slice(&bytes)?,
        None => Vec::new(),
    };
    ensure!(
        segments.is_sorted_by(|left, right| left.1 < right.1),
        "persisted event-filter segments are not strictly ascending"
    );
    let seam = dbio
        .get_meta_last_block_id_in_db()?
        .map_or(0, |tip| tip.saturating_add(1));
    ensure!(
        segments.last().is_none_or(|(_, from)| *from <= seam),
        "persisted event-filter segments start beyond the next block to ingest"
    );
    let change = match segments.last_mut() {
        Some((filter, _)) if *filter == configured => None,
        Some((filter, from)) if *from == seam => {
            *filter = configured;
            Some("replaced the last")
        }
        _ => {
            segments.push((configured, seam));
            Some("appended a new")
        }
    };
    if let Some(change) = change {
        dbio.put_event_filter_segments_bytes(&borsh::to_vec(&segments)?)?;
        log::info!("Event filter changed: {change} segment, effective from block {seam}");
    }
    Ok(segments)
}

#[cfg(test)]
fn open_default(home: &Path) -> IndexerStore {
    open_with(home, EventFilter::default())
}

#[cfg(test)]
fn open_with(home: &Path, filter: EventFilter) -> IndexerStore {
    IndexerStore::open_db(home, filter).expect("open store")
}

#[cfg(test)]
mod stall_reason_tests {
    use common::HashType;

    use super::*;

    #[tokio::test]
    async fn stall_reason_roundtrips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use common::test_utils::{create_transaction_native_token_transfer, produce_dummy_block};
    use lee_core::program::{InstructionData, ProgramEvent, ProgramId};
    use storage::{DBIO as _, indexer::indexer_cells::EventFilterSegmentsCellOwned};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;
    use crate::event_filter::{SelectorFilter, covered_over_range};

    // Host-side mirror of the `event_emitter` test guest's instruction.
    #[derive(borsh::BorshSerialize)]
    struct EmitterInstruction {
        events: Vec<ProgramEvent>,
        chain: Vec<(ProgramId, InstructionData)>,
    }

    fn emitted(n: u8) -> ProgramEvent {
        ProgramEvent {
            selector: [n; 8],
            data: vec![n; 4],
        }
    }

    fn deploy_emitter_tx() -> LeeTransaction {
        LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
            lee::program_deployment_transaction::Message::new(
                test_methods::EVENT_EMITTER_ELF.to_vec(),
            ),
        ))
    }

    fn invoke_emitter_tx(events: Vec<ProgramEvent>) -> LeeTransaction {
        let message = lee::public_transaction::Message::try_new(
            test_methods::EVENT_EMITTER_ID,
            vec![AccountId::new([42; 32])],
            vec![],
            EmitterInstruction {
                events,
                chain: vec![],
            },
        )
        .expect("emitter instruction serializes");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    }

    // Chains genesis, a block deploying the emitter guest, and a block invoking it;
    // returns the invoking transaction's hash.
    async fn seed_emitted_events(store: &IndexerStore) -> common::HashType {
        let genesis = produce_dummy_block(1, None, vec![]);
        let mut prev_hash = genesis.header.hash;
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let deploy_block = produce_dummy_block(2, Some(prev_hash), vec![deploy_emitter_tx()]);
        prev_hash = deploy_block.header.hash;
        assert!(matches!(
            store
                .accept_block(&deploy_block, Slot::from(0))
                .await
                .unwrap(),
            AcceptOutcome::Applied
        ));

        let invoke = invoke_emitter_tx(vec![emitted(0), emitted(1)]);
        let invoke_hash = invoke.hash();
        let invoke_block = produce_dummy_block(3, Some(prev_hash), vec![invoke]);
        assert!(matches!(
            store
                .accept_block(&invoke_block, Slot::from(0))
                .await
                .unwrap(),
            AcceptOutcome::Applied
        ));

        invoke_hash
    }

    #[test]
    fn correct_startup() {
        let home = tempdir().unwrap();

        let storage = open_default(home.as_ref());

        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(final_id, None);
    }

    #[tokio::test]
    async fn accept_block_applies_transfers_and_advances_tip() {
        let home = tempdir().unwrap();
        let store = open_default(home.as_ref());

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        // Genesis (block 1): clock-only.
        let genesis = produce_dummy_block(1, None, vec![]);
        let mut prev_hash = genesis.header.hash;
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        // Blocks 2..=11: one native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            9900
        );
        assert_eq!(
            store.account_current_state(&to).await.unwrap().balance,
            20100
        );
        // Tip advanced to the last applied block; a clean run leaves no stall.
        assert_eq!(store.get_last_block_id().unwrap(), Some(11));
        assert!(store.get_stall_reason().unwrap().is_none());
    }

    #[tokio::test]
    async fn account_state_at_block_reflects_history() {
        let home = tempdir().unwrap();
        let store = open_default(home.as_ref());

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        let mut prev_hash = genesis.header.hash;
        store.accept_block(&genesis, Slot::from(0)).await.unwrap();

        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            store.accept_block(&block, Slot::from(0)).await.unwrap();
        }

        // State at block N is inclusive of block N.
        // Block 1 (genesis, clock-only): no transfers yet.
        assert_eq!(
            store.account_state_at_block(&from, 1).unwrap().balance,
            10000
        );
        assert_eq!(store.account_state_at_block(&to, 1).unwrap().balance, 20000);
        // Through block 5: 4 transfers applied (blocks 2..=5).
        assert_eq!(
            store.account_state_at_block(&from, 5).unwrap().balance,
            9960
        );
        assert_eq!(store.account_state_at_block(&to, 5).unwrap().balance, 20040);
        // Through block 9: 8 transfers applied (blocks 2..=9).
        assert_eq!(
            store.account_state_at_block(&from, 9).unwrap().balance,
            9920
        );
        assert_eq!(store.account_state_at_block(&to, 9).unwrap().balance, 20080);
    }

    #[tokio::test]
    async fn accept_block_captures_emitted_events() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);

        let invoke_hash = seed_emitted_events(&store).await;

        let groups = store
            .get_events_for_block(3)
            .unwrap()
            .expect("invoking block must have an events row");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].tx_index, 0);
        assert_eq!(groups[0].tx_hash, invoke_hash);

        let events = &groups[0].events;
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.program_id == test_methods::EVENT_EMITTER_ID)
        );
        assert_eq!(events[0].event, emitted(0));
        assert_eq!(events[1].event, emitted(1));

        // The deploying block and genesis emit nothing, so the range holds only block 3.
        assert_eq!(
            store.get_events_range(1, 3).unwrap(),
            vec![(3, groups.clone())]
        );

        let block_id = store
            .block_id_by_tx_hash(invoke_hash.0)
            .unwrap()
            .expect("the invoking tx must resolve its block");
        assert_eq!(block_id, 3);
        let group = store
            .get_events_for_block(block_id)
            .unwrap()
            .and_then(|rows| rows.into_iter().find(|row| row.tx_hash == invoke_hash))
            .expect("tx-hash lookup must find the group");
        assert_eq!(group, groups[0]);
    }

    #[tokio::test]
    async fn events_survive_store_reopen() {
        let home = tempdir().unwrap();
        let invoke_hash = {
            let store = open_with(home.as_ref(), EventFilter::Archival);
            seed_emitted_events(&store).await
        }; // drop releases the RocksDB lock

        // Reopening replays state from the breakpoints; the events rows must be untouched.
        let store = open_with(home.as_ref(), EventFilter::Archival);
        let groups = store
            .get_events_for_block(3)
            .unwrap()
            .expect("events must survive reopen");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].tx_hash, invoke_hash);
        assert_eq!(groups[0].events.len(), 2);
    }

    #[tokio::test]
    async fn reaccepting_applied_block_does_not_duplicate_events() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);

        seed_emitted_events(&store).await;
        let before = store.get_events_for_block(3).unwrap().unwrap();

        let replayed = store.get_block_at_id(3).unwrap().unwrap();
        assert!(matches!(
            store.accept_block(&replayed, Slot::from(0)).await.unwrap(),
            AcceptOutcome::AlreadyApplied
        ));

        assert_eq!(store.get_events_for_block(3).unwrap().unwrap(), before);
    }

    #[tokio::test]
    async fn default_filter_stores_no_events() {
        let home = tempdir().unwrap();
        let store = open_default(home.as_ref());

        let invoke_hash = seed_emitted_events(&store).await;

        // Nothing survives the filter, so block 3 gets no row at all — where the
        // archival run stores both emitted events.
        assert_eq!(store.get_events_for_block(3).unwrap(), None);
        assert!(store.get_events_range(1, 3).unwrap().is_empty());
        assert!(
            store
                .block_id_by_tx_hash(invoke_hash.0)
                .unwrap()
                .and_then(|block_id| store.get_events_for_block(block_id).unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn declared_source_filters_at_ingest() {
        let home = tempdir().unwrap();
        let filter = EventFilter::Sources(HashMap::from([(
            test_methods::EVENT_EMITTER_ID,
            SelectorFilter::Only(HashSet::from([emitted(1).selector])),
        )]));
        let store = open_with(home.as_ref(), filter);

        let invoke_hash = seed_emitted_events(&store).await;

        // The invoke emits `emitted(0)` and `emitted(1)`; only the declared selector lands.
        let groups = store
            .get_events_for_block(3)
            .unwrap()
            .expect("the retained event must still produce a row");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].tx_hash, invoke_hash);
        assert_eq!(groups[0].events.len(), 1);
        assert_eq!(
            groups[0].events[0].program_id,
            test_methods::EVENT_EMITTER_ID
        );
        assert_eq!(groups[0].events[0].event, emitted(1));
    }

    #[tokio::test]
    async fn blocks_without_events_have_no_row() {
        let home = tempdir().unwrap();
        let store = open_default(home.as_ref());

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        store.accept_block(&genesis, Slot::from(0)).await.unwrap();

        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        store.accept_block(&block, Slot::from(0)).await.unwrap();

        assert_eq!(store.get_events_for_block(1).unwrap(), None);
        assert_eq!(store.get_events_for_block(2).unwrap(), None);
        assert!(store.get_events_range(1, 2).unwrap().is_empty());
    }

    #[test]
    fn fresh_open_records_the_configured_filter_from_genesis() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);

        assert_eq!(store.filter_segments(), &[(EventFilter::Archival, 0)]);
    }

    #[tokio::test]
    async fn a_db_with_blocks_but_no_segments_seams_at_the_tip() {
        let home = tempdir().unwrap();
        let tip = {
            let store = open_with(home.as_ref(), EventFilter::Archival);
            seed_emitted_events(&store).await;
            store.get_last_block_id().unwrap().unwrap()
        };

        // What every upgrading deployment looks like: blocks already ingested, but no
        // segment history, because filtering did not exist when they were written.
        let initial_state = testnet_initial_state::initial_state();
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.del::<EventFilterSegmentsCellOwned>(()).unwrap();
        drop(dbio);

        let reopened = open_with(home.as_ref(), EventFilter::Archival);

        assert_eq!(
            reopened.filter_segments(),
            &[(EventFilter::Archival, tip.saturating_add(1))]
        );
        // Those blocks were never filtered, so no query may claim them as covered.
        assert!(!covered_over_range(
            reopened.filter_segments(),
            1,
            tip,
            None,
            None
        ));
    }

    #[tokio::test]
    async fn unchanged_filter_reopen_keeps_a_single_segment() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);
        seed_emitted_events(&store).await;
        assert_eq!(store.get_last_block_id().unwrap(), Some(3));
        drop(store);

        let reopened = open_with(home.as_ref(), EventFilter::Archival);

        assert_eq!(reopened.filter_segments(), &[(EventFilter::Archival, 0)]);
    }

    #[test]
    fn same_seam_filter_change_replaces_the_last_segment() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));
        let reopened = open_default(home.as_ref());

        assert_eq!(reopened.filter_segments(), &[(EventFilter::default(), 0)]);
    }

    #[tokio::test]
    async fn filter_change_after_ingest_appends_a_segment_at_the_seam() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);
        seed_emitted_events(&store).await;
        let tip = store.get_last_block_id().unwrap().unwrap();
        drop(store);

        let reopened = open_default(home.as_ref());

        assert_eq!(
            reopened.filter_segments(),
            &[
                (EventFilter::Archival, 0),
                (EventFilter::default(), tip.saturating_add(1)),
            ]
        );
    }

    #[tokio::test]
    async fn coverage_follows_the_segment_history_end_to_end() {
        let home = tempdir().unwrap();
        let tip = {
            let store = open_with(home.as_ref(), EventFilter::Archival);
            seed_emitted_events(&store).await;
            store.get_last_block_id().unwrap().unwrap()
        };

        let reopened = open_default(home.as_ref());
        let segments = reopened.filter_segments();

        assert!(covered_over_range(segments, 1, tip, None, None));
        assert!(!covered_over_range(
            segments,
            1,
            tip.saturating_add(1),
            None,
            None
        ));
        assert!(!covered_over_range(
            segments,
            tip.saturating_add(1),
            tip.saturating_add(1),
            None,
            None
        ));
    }

    #[tokio::test]
    async fn sources_segment_survives_reopen_regardless_of_insertion_order() {
        let filter = |entries: Vec<(ProgramId, SelectorFilter)>| {
            EventFilter::Sources(entries.into_iter().collect())
        };
        let a = ([1; 8], SelectorFilter::All);
        let b = (
            [2; 8],
            SelectorFilter::Only(HashSet::from([[3; 8], [4; 8]])),
        );

        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), filter(vec![a.clone(), b.clone()]));
        seed_emitted_events(&store).await;
        drop(store);

        let reopened = open_with(home.as_ref(), filter(vec![b.clone(), a.clone()]));

        assert_eq!(reopened.filter_segments(), &[(filter(vec![a, b]), 0)]);
    }

    #[tokio::test]
    async fn append_then_same_seam_change_replaces_only_the_appended_segment() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);
        seed_emitted_events(&store).await;
        let seam = store
            .get_last_block_id()
            .unwrap()
            .unwrap()
            .saturating_add(1);
        drop(store);

        let widened = EventFilter::Sources(HashMap::from([([1; 8], SelectorFilter::All)]));
        drop(open_with(home.as_ref(), widened));
        let reopened = open_default(home.as_ref());

        assert_eq!(
            reopened.filter_segments(),
            &[(EventFilter::Archival, 0), (EventFilter::default(), seam),]
        );
    }

    #[tokio::test]
    async fn wipe_resets_the_segment_history() {
        let home = tempdir().unwrap();
        let store = open_with(home.as_ref(), EventFilter::Archival);
        seed_emitted_events(&store).await;
        drop(store);

        RocksDBIO::destroy(home.as_ref()).unwrap();

        let reopened = open_with(home.as_ref(), EventFilter::Archival);

        assert_eq!(reopened.filter_segments(), &[(EventFilter::Archival, 0)]);
    }

    #[tokio::test]
    async fn reaccepted_block_after_filter_change_keeps_its_original_events() {
        let home = tempdir().unwrap();
        let before = {
            let store = open_with(home.as_ref(), EventFilter::Archival);
            seed_emitted_events(&store).await;
            store.get_events_for_block(3).unwrap().unwrap()
        };

        let reopened = open_default(home.as_ref());
        assert_eq!(
            reopened.filter_segments(),
            &[(EventFilter::Archival, 0), (EventFilter::default(), 4)]
        );

        let replayed = reopened.get_block_at_id(3).unwrap().unwrap();
        assert!(matches!(
            reopened
                .accept_block(&replayed, Slot::from(0))
                .await
                .unwrap(),
            AcceptOutcome::AlreadyApplied
        ));

        assert_eq!(reopened.get_events_for_block(3).unwrap().unwrap(), before);
    }

    #[test]
    fn tampered_segment_bytes_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let initial_state = testnet_initial_state::initial_state();
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(b"garbage").unwrap();
        drop(dbio);

        assert!(IndexerStore::open_db(home.as_ref(), EventFilter::Archival).is_err());
    }

    #[test]
    fn non_ascending_segments_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let bad: Vec<(EventFilter, BlockId)> =
            vec![(EventFilter::Archival, 5), (EventFilter::Archival, 0)];
        let initial_state = testnet_initial_state::initial_state();
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(&borsh::to_vec(&bad).unwrap())
            .unwrap();
        drop(dbio);

        assert!(IndexerStore::open_db(home.as_ref(), EventFilter::Archival).is_err());
    }

    #[test]
    fn segments_beyond_the_next_block_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let ahead: Vec<(EventFilter, BlockId)> = vec![(EventFilter::Archival, 1)];
        let initial_state = testnet_initial_state::initial_state();
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(&borsh::to_vec(&ahead).unwrap())
            .unwrap();
        drop(dbio);

        assert!(IndexerStore::open_db(home.as_ref(), EventFilter::Archival).is_err());
    }

    #[tokio::test]
    async fn filtered_out_tx_still_resolves_its_block() {
        let home = tempdir().unwrap();
        let store = open_default(home.as_ref());
        let invoke_hash = seed_emitted_events(&store).await;

        // The events row was dropped by the filter, but the height is still known —
        // which is what lets the query layer reject instead of serving `[]`.
        let block_id = store
            .block_id_by_tx_hash(invoke_hash.0)
            .unwrap()
            .expect("the filtered-out tx must still resolve its block");
        assert_eq!(store.get_events_for_block(block_id).unwrap(), None);
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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

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
        let store = open_default(dir.path());

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // Block 2: a single transfer of 10.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
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
        let store = open_default(dir.path());

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Build a short chain: genesis (1) -> block 2 -> block 3, so the tip is 3.
        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        let tx2 = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        assert!(matches!(
            store.accept_block(&block2, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let tx3 = common::test_utils::create_transaction_native_token_transfer(
            from, 1, to, 10, &sign_key,
        );
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
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
        let store = open_default(dir.path());

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        let mut prev_hash = genesis.header.hash;

        // Blocks 2..=101: one transfer of 1 each; block 100 crosses the interval.
        for i in 0..100_u64 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                i.into(),
                to,
                1,
                &sign_key,
            );
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        // Snapshot at block 100 = genesis + 99 transfers, written with the block.
        let bp1 = store.dbio.get_breakpoint(1).expect("breakpoint 1 present");
        assert_eq!(bp1.get_account_by_id(from).balance, 10000 - 99);

        // The #605 restart: reopening past the boundary must work.
        drop(store);
        let reopened = open_default(dir.path());
        assert_eq!(reopened.last_block().unwrap(), Some(101));
    }

    #[tokio::test]
    async fn transient_apply_failure_returns_retryable_failure_without_stall() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_default(dir.path());

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // Overdraft: rejected during execution → StateTransition → retryable.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            from,
            0,
            to,
            1_000_000_000,
            &sign_key,
        );
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
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
