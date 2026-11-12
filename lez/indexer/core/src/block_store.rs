use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result, ensure};
use chain_state::{BlockIngestError, StallReason, Tip, apply::validate_link, chain::SettledBlock};
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockHeader},
    transaction::{LeeTransaction, TxEvents},
};
use lee::{Account, AccountId, Actor, V03State};
use lee_core::BlockId;
use log::warn;
use logos_blockchain_core::{header::HeaderId, mantle::ops::channel::MsgId};
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

/// What storing a settlement did.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// The block was written.
    Written,
    /// The store already held the block, so nothing was written.
    Replayed,
}

/// Why the store did not take a settlement.
#[derive(Debug, thiserror::Error)]
pub enum PutSettledError {
    /// The store holds a different block at the settlement's id.
    #[error("the store holds block {block_id} as {stored}, not {settled}")]
    Identity {
        block_id: u64,
        stored: HashType,
        settled: HashType,
    },
    /// The block is not the next one on the stored tip.
    #[error("the block does not follow the stored tip: {0}")]
    Parent(BlockIngestError),
    /// Reading or writing the store failed.
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    pub fn open_db(
        location: &Path,
        cross_zone: bool,
        genesis_seed: Vec<(AccountId, Account)>,
        event_filter: EventFilter,
    ) -> Result<Self> {
        let initial_state =
            testnet_initial_state::initial_state(cross_zone).with_public_accounts(genesis_seed);

        // In production `genesis_seed` is empty: configs and holdings are
        // reconstructed by replaying the genesis block, so this state matches the
        // sequencer's by construction (fingerprint below is the diagnostic). Tests
        // seed the producer's reward account, which no genesis block of theirs
        // stakes.
        log::info!(
            "Genesis fingerprint: {}",
            hex::encode(initial_state.genesis_fingerprint())
        );
        let dbio = RocksDBIO::open_or_create(location, &initial_state)?;
        // Presence cannot change on a chain: an existing store keeps its seeded
        // genesis, so a disagreement here is an operator error.
        if let Some(stored) = dbio.get_breakpoint_opt(0)?
            && stored.genesis_fingerprint() != initial_state.genesis_fingerprint()
        {
            log::error!(
                "Stored genesis fingerprint {} does not match the configured one; the store keeps running on its own genesis. Did cross_zone presence change since this chain was created?",
                hex::encode(stored.genesis_fingerprint())
            );
        }

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

    /// The channel message whose block the store applied last, and its L1 slot.
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

    /// The L1 inscription slot of the validated tip, written atomically with it
    /// by [`Self::put_settled_block`]. `None` on a cold store or one written before
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

    pub async fn account_current_state(&self, account_id: &AccountId) -> Result<Option<Account>> {
        Ok(self
            .current_state
            .read()
            .await
            .get_account_by_id_ref(*account_id)
            .cloned())
    }

    pub fn account_state_at_block(
        &self,
        account_id: &AccountId,
        block_id: u64,
    ) -> Result<Option<Account>> {
        Ok(self
            .get_state_at_block(block_id)?
            .get_account_by_id_ref(*account_id)
            .cloned())
    }

    pub async fn account_current_view(&self, actor: Actor) -> Result<Option<Account>> {
        let state = self.current_state.read().await;
        Ok(project_account(&state, actor))
    }

    pub fn account_view_at_block(&self, actor: Actor, block_id: u64) -> Result<Option<Account>> {
        Ok(project_account(&self.get_state_at_block(block_id)?, actor))
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

    /// Persists a settled block with the state after it and its events, if it
    /// extends the stored tip. A block the store already holds is not rewritten.
    pub async fn put_settled_block(
        &self,
        settled: &SettledBlock,
    ) -> Result<Stored, PutSettledError> {
        let block = settled.block();
        let header = &block.header;
        let tip = match self.get_last_block_id()? {
            None => None,
            Some(tip_id) => {
                let id = tip_id.min(header.block_id);
                let held = self.get_block_at_id(id)?.with_context(|| {
                    format!("The store lacks block {id}, at or below its tip {tip_id}")
                })?;
                if id == header.block_id {
                    return if held.header.hash == header.hash {
                        Ok(Stored::Replayed)
                    } else {
                        Err(PutSettledError::Identity {
                            block_id: id,
                            stored: held.header.hash,
                            settled: header.hash,
                        })
                    };
                }
                Some(Tip::from(&held))
            }
        };
        validate_link(tip.as_ref(), header).map_err(PutSettledError::Parent)?;

        let l1_slot = settled
            .slot()
            .expect("the indexer folds only final entries");
        let events = self.live_filter().filter_block(settled.events().to_vec());

        let mut stored = block.clone();
        stored.bedrock_status = BedrockStatus::Finalized;
        self.dbio
            .put_block(
                &stored,
                [0_u8; 32],
                l1_slot.into_inner(),
                settled.state(),
                &events,
            )
            .context("Failed to persist accepted block")?;

        // Commit in-memory state (infallible) only after the DB write succeeded.
        *self.current_state.write().await = settled.state().clone();
        // Best-effort: the block is durably applied, so a failed stall clear must not
        // fail the apply. It self-heals on the next clear.
        if let Err(err) = self.clear_stall_if_present() {
            warn!("Failed to clear stall marker after applying block: {err:#}");
        }
        Ok(Stored::Written)
    }
}

fn project_account(state: &V03State, actor: Actor) -> Option<Account> {
    state
        .get_account_by_id_ref(actor.account_id)
        .map(|account| account.project([actor.program_account_id]))
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
    // Seed the producer's reward account as claimed, mirroring the stake a real
    // sequencer holds, so charged blocks can credit it on the accept path.
    IndexerStore::open_db(
        home,
        true,
        vec![common::test_utils::producer_seed()],
        filter,
    )
    .expect("open store")
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

/// A block whose forced fee transaction carries the summary its transactions
/// settle to against `state`, which is advanced past the block.
#[cfg(test)]
pub(crate) fn settled_test_block(
    state: &mut lee::V03State,
    id: u64,
    prev_hash: Option<common::HashType>,
    txs: Vec<common::transaction::LeeTransaction>,
) -> common::block::Block {
    use common::{
        block::HashableBlockData,
        test_utils::producer_account_for_testing,
        transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
    };
    let timestamp = id.saturating_mul(100);
    let (summary, payout, reverted) =
        chain_state::apply::derive_block_summary(state, &txs, id, timestamp)
            .expect("test transactions settle");
    let producer = producer_account_for_testing();
    let mut transactions = txs;
    transactions.push(LeeTransaction::Public(fee_invocation(
        summary,
        payout,
        FeePayee::Present(producer),
    )));
    transactions.push(LeeTransaction::Public(clock_invocation(id, timestamp)));
    let block = HashableBlockData {
        reverted,
        block_id: id,
        prev_block_hash: prev_hash.unwrap_or_default(),
        timestamp,
        transactions,
    }
    .into_pending_block();
    chain_state::apply::apply_block_to_state(&block, state).expect("settled block applies");
    block
}

/// Stores `block` as the fold hands it over: with the state after it and its events.
#[cfg(test)]
pub(crate) async fn store_block(store: &IndexerStore, block: &Block, l1_slot: Slot) {
    let mut state = store.current_state.read().await.clone();
    let events = chain_state::apply::apply_block_to_state(block, &mut state)
        .expect("the block applies on the stored state");
    store
        .put_settled_block(&SettledBlock::new(
            MsgId::root(),
            Some(l1_slot),
            block.clone(),
            state,
            events,
        ))
        .await
        .expect("the block is stored");
}

/// A mirror build-state seeded like the store's genesis (the producer's reward
/// account claimed), so `settled_test_block` can credit fees to it — crediting
/// an unclaimed account is rejected.
#[cfg(test)]
fn claimed_build_state() -> lee::V03State {
    testnet_initial_state::initial_state(true)
        .with_public_accounts([common::test_utils::producer_seed()])
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use common::test_utils::{create_transaction_native_token_transfer, produce_dummy_block};
    use lee::Actor;
    use lee_core::program::{ProgramEvent, Response};
    use storage::{DBIO as _, indexer::indexer_cells::EventFilterSegmentsCellOwned};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;
    use crate::event_filter::{SelectorFilter, covered_over_range};

    fn emitted(n: u8) -> ProgramEvent {
        ProgramEvent {
            selector: [n; 8],
            data: vec![n; 4],
        }
    }

    fn emitter_header_key() -> lee::PrivateKey {
        lee::PrivateKey::try_new([201; 32]).unwrap()
    }

    fn emitter_header_account_id() -> AccountId {
        AccountId::from(&lee::PublicKey::new_from_private_key(&emitter_header_key()))
    }

    // Deploys the `scripted` test guest through `program_loader`, chunked into `WriteSegment`s.
    // A funded genesis account co-signs every transaction as payer, since new accounts can't
    // self-pay.
    fn deploy_emitter_txs() -> Vec<LeeTransaction> {
        let payer = &initial_pub_accounts_private_keys()[0];
        let header_key = emitter_header_key();
        let header_id = emitter_header_account_id();
        let loader = lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;

        // Segments only ever hold `user_elf`.
        let user_elf = test_programs::scripted()
            .user_elf()
            .expect("scripted program has a valid user_elf");
        let chunks: Vec<&[u8]> = user_elf
            .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
            .collect();
        // Base 210 avoids colliding with `emitter_header_key`'s [201; 32].
        let segment_keys: Vec<lee::PrivateKey> = (0..chunks.len())
            .map(|i| {
                lee::PrivateKey::try_new([u8::try_from(i).unwrap().saturating_add(210); 32])
                    .unwrap()
            })
            .collect();
        let segment_ids: Vec<AccountId> = segment_keys
            .iter()
            .map(|key| AccountId::from(&lee::PublicKey::new_from_private_key(key)))
            .collect();

        let mut txs = Vec::with_capacity(chunks.len().saturating_add(1));
        let mut payer_nonce = 0_u128;
        for i in (0..chunks.len()).rev() {
            let to = Actor::new(segment_ids[i], loader);
            let segment_message = lee::public_transaction::Message::try_new_with_fees(
                to,
                vec![to],
                BTreeMap::from([
                    (segment_ids[i], lee_core::account::Nonce(0)),
                    (payer.account_id, lee_core::account::Nonce(payer_nonce)),
                ]),
                program_loader_core::Message::WriteSegment {
                    bytecode: chunks[i].to_vec(),
                    next_segment: segment_ids.get(i.saturating_add(1)).copied(),
                },
                common::test_utils::test_fee_declaration(payer.account_id),
            )
            .expect("WriteSegment message should always be serializable");
            let segment_witness_set = lee::public_transaction::WitnessSet::for_message(
                &segment_message,
                &[&segment_keys[i], &payer.pub_sign_key],
            );
            txs.push(LeeTransaction::Public(lee::PublicTransaction::new(
                segment_message,
                segment_witness_set,
            )));
            payer_nonce = payer_nonce.saturating_add(1);
        }

        let header_to = Actor::new(header_id, loader);
        let header_message = lee::public_transaction::Message::try_new_with_fees(
            header_to,
            vec![header_to],
            BTreeMap::from([
                (header_id, lee_core::account::Nonce(0)),
                (payer.account_id, lee_core::account::Nonce(payer_nonce)),
            ]),
            program_loader_core::Message::CreateHeader {
                first_segment: segment_ids[0],
                immutable: true,
            },
            common::test_utils::test_fee_declaration(payer.account_id),
        )
        .expect("CreateHeader message should always be serializable");
        let header_witness_set = lee::public_transaction::WitnessSet::for_message(
            &header_message,
            &[&header_key, &payer.pub_sign_key],
        );
        txs.push(LeeTransaction::Public(lee::PublicTransaction::new(
            header_message,
            header_witness_set,
        )));

        txs
    }

    fn invoke_emitter_tx(events: Vec<ProgramEvent>) -> LeeTransaction {
        // create message with payer so that it's not rejected due to missing fee declaration
        let payer = &initial_pub_accounts_private_keys()[0];
        // The payer's next nonce after `deploy_emitter_txs`'s chunked deploy.
        let user_elf = test_programs::scripted()
            .user_elf()
            .expect("scripted program has a valid user_elf");
        let chunk_count = user_elf
            .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
            .count();
        let payer_nonce = u128::try_from(chunk_count.saturating_add(1)).unwrap();
        let header_id = emitter_header_account_id();
        let to = Actor::new(header_id, header_id);
        let message = lee::public_transaction::Message::try_new_with_fees(
            to,
            vec![to],
            BTreeMap::from([(payer.account_id, payer_nonce.into())]),
            test_guest_core::Script {
                response: Response {
                    events,
                    ..Response::keep_state()
                },
                ..test_guest_core::Script::default()
            },
            common::test_utils::test_fee_declaration(payer.account_id),
        )
        .expect("script serializes");
        let witness_set =
            lee::public_transaction::WitnessSet::for_message(&message, &[&payer.pub_sign_key]);
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    }

    // Chains genesis, a block deploying the emitter guest, and a block invoking it;
    // returns the invoking transaction's hash.
    async fn seed_emitted_events(store: &IndexerStore) -> common::HashType {
        // The invoke is a charged transaction, so its block's forced fee tail
        // must carry the summary it settles to; `settled_test_block` derives it,
        // which needs a mirror `build_state` advanced past each block.
        let mut build_state = claimed_build_state();

        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        store_block(store, &genesis, Slot::from(0)).await;

        let deploy_block = settled_test_block(
            &mut build_state,
            2,
            Some(genesis.header.hash),
            deploy_emitter_txs(),
        );
        store_block(store, &deploy_block, Slot::from(0)).await;

        let invoke = invoke_emitter_tx(vec![emitted(0), emitted(1)]);
        let invoke_hash = invoke.hash();
        let invoke_block = settled_test_block(
            &mut build_state,
            3,
            Some(deploy_block.header.hash),
            vec![invoke],
        );
        store_block(store, &invoke_block, Slot::from(0)).await;

        invoke_hash
    }

    #[test]
    fn a_fresh_store_keeps_the_initial_states_pinned_recovery_bindings() {
        let home = tempdir().unwrap();
        let storage =
            IndexerStore::open_db(home.as_ref(), false, Vec::new(), EventFilter::default())
                .unwrap();
        let genesis = storage.dbio.get_breakpoint_opt(0).unwrap().unwrap();

        assert_eq!(
            genesis.genesis_fingerprint(),
            testnet_initial_state::initial_state(false).genesis_fingerprint()
        );
        for binding in testnet_initial_state::initial_recovery_bindings() {
            assert_eq!(
                genesis.recovery_binding(binding.address),
                Some(&binding.note)
            );
        }
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

        // Genesis (block 1): fee/clock only.
        let mut build_state = claimed_build_state();
        let initial_from = build_state
            .get_account_by_id(from)
            .data
            .native_balance()
            .unwrap();
        let initial_to = build_state
            .get_account_by_id(to)
            .data
            .native_balance()
            .unwrap();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        let mut prev_hash = genesis.header.hash;
        store_block(&store, &genesis, Slot::from(0)).await;

        // Blocks 2..=11: one charged native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = settled_test_block(&mut build_state, i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            store_block(&store, &block, Slot::from(0)).await;
        }

        // The recipient gains exactly the transfers; the sender also pays fees.
        assert!(
            store
                .account_current_state(&from)
                .await
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap()
                < initial_from - 100
        );
        assert_eq!(
            store
                .account_current_state(&to)
                .await
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap(),
            initial_to + 100
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

        let mut build_state = claimed_build_state();
        let initial_from = build_state
            .get_account_by_id(from)
            .data
            .native_balance()
            .unwrap();
        let initial_to = build_state
            .get_account_by_id(to)
            .data
            .native_balance()
            .unwrap();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        let mut prev_hash = genesis.header.hash;
        store_block(&store, &genesis, Slot::from(0)).await;

        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = settled_test_block(&mut build_state, i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            store_block(&store, &block, Slot::from(0)).await;
        }

        // State at block N is inclusive of block N.
        // Block 1 (genesis, clock-only): no transfers yet.
        assert_eq!(
            store
                .account_state_at_block(&from, 1)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap(),
            initial_from
        );
        assert_eq!(
            store
                .account_state_at_block(&to, 1)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap(),
            initial_to
        );
        // Through block 5: 4 transfers applied (blocks 2..=5); the sender also
        // pays a fee per charged transfer.
        assert!(
            store
                .account_state_at_block(&from, 5)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap()
                < initial_from - 40
        );
        assert_eq!(
            store
                .account_state_at_block(&to, 5)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap(),
            initial_to + 40
        );
        // Through block 9: 8 transfers applied (blocks 2..=9).
        assert!(
            store
                .account_state_at_block(&from, 9)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap()
                < initial_from - 80
        );
        assert_eq!(
            store
                .account_state_at_block(&to, 9)
                .unwrap()
                .unwrap()
                .data
                .native_balance()
                .unwrap(),
            initial_to + 80
        );
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
                .all(|event| event.account_id == emitter_header_account_id())
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
            emitter_header_account_id(),
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
        assert_eq!(groups[0].events[0].account_id, emitter_header_account_id());
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

        let mut build_state = claimed_build_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        store_block(&store, &genesis, Slot::from(0)).await;

        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block = settled_test_block(&mut build_state, 2, Some(genesis.header.hash), vec![tx]);
        store_block(&store, &block, Slot::from(0)).await;

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
        let initial_state = testnet_initial_state::initial_state(true);
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
        let filter = |entries: Vec<(AccountId, SelectorFilter)>| {
            EventFilter::Sources(entries.into_iter().collect())
        };
        let a = (AccountId::new([1; 32]), SelectorFilter::All);
        let b = (
            AccountId::new([2; 32]),
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

        let widened = EventFilter::Sources(HashMap::from([(
            AccountId::new([1; 32]),
            SelectorFilter::All,
        )]));
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

    #[test]
    fn tampered_segment_bytes_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let initial_state = testnet_initial_state::initial_state(true);
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(b"garbage").unwrap();
        drop(dbio);

        assert!(
            IndexerStore::open_db(home.as_ref(), true, Vec::new(), EventFilter::Archival).is_err()
        );
    }

    #[test]
    fn non_ascending_segments_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let bad: Vec<(EventFilter, BlockId)> =
            vec![(EventFilter::Archival, 5), (EventFilter::Archival, 0)];
        let initial_state = testnet_initial_state::initial_state(true);
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(&borsh::to_vec(&bad).unwrap())
            .unwrap();
        drop(dbio);

        assert!(
            IndexerStore::open_db(home.as_ref(), true, Vec::new(), EventFilter::Archival).is_err()
        );
    }

    #[test]
    fn segments_beyond_the_next_block_refuse_to_open() {
        let home = tempdir().unwrap();
        drop(open_with(home.as_ref(), EventFilter::Archival));

        let ahead: Vec<(EventFilter, BlockId)> = vec![(EventFilter::Archival, 1)];
        let initial_state = testnet_initial_state::initial_state(true);
        let dbio = RocksDBIO::open_or_create(home.as_ref(), &initial_state).unwrap();
        dbio.put_event_filter_segments_bytes(&borsh::to_vec(&ahead).unwrap())
            .unwrap();
        drop(dbio);

        assert!(
            IndexerStore::open_db(home.as_ref(), true, Vec::new(), EventFilter::Archival).is_err()
        );
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

    // A block with a correct hash but empty body.
    fn valid_hash_block(block_id: u64, prev: HashType) -> common::block::Block {
        HashableBlockData {
            block_id,
            prev_block_hash: prev,
            timestamp: 0,
            transactions: vec![],
            reverted: Vec::new(),
        }
        .into_pending_block()
    }

    #[tokio::test]
    async fn second_break_bumps_orphan_count_and_keeps_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_default(dir.path());

        let first = valid_hash_block(2, HashType([0_u8; 32]));
        store
            .record_stall(
                Some(&first.header),
                Slot::from(0),
                BlockIngestError::UnexpectedBlockId {
                    expected: 1,
                    got: 2,
                },
            )
            .expect("record");
        let second = valid_hash_block(3, HashType([0_u8; 32]));
        store
            .record_stall(
                Some(&second.header),
                Slot::from(0),
                BlockIngestError::UnexpectedBlockId {
                    expected: 1,
                    got: 3,
                },
            )
            .expect("record");

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
    async fn persisting_a_settlement_clears_a_recorded_stall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_default(dir.path());

        // Genesis (block 1, clock-only) applies and advances the tip.
        let genesis = produce_dummy_block(1, None, vec![]);
        store_block(&store, &genesis, Slot::from(0)).await;

        // A stall recorded for a block that skips ahead (id 3 while the tip is 1).
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        store
            .record_stall(
                Some(&bad.header),
                Slot::from(0),
                BlockIngestError::UnexpectedBlockId {
                    expected: 2,
                    got: 3,
                },
            )
            .expect("record");
        assert!(
            store.get_stall_reason().unwrap().is_some(),
            "the stall is recorded"
        );

        // Persisting the next settlement (block 2 chaining on genesis) clears it.
        let next = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        store_block(&store, &next, Slot::from(0)).await;
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "the persisted settlement clears the stall"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(2),
            "the tip advances to the persisted block"
        );
    }

    #[tokio::test]
    async fn accept_block_records_tip_inscription_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_default(dir.path());

        assert_eq!(store.get_tip_slot().expect("get"), None);

        let genesis = produce_dummy_block(1, None, vec![]);
        store_block(&store, &genesis, Slot::from(1_000)).await;
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_000)));

        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        store_block(&store, &block2, Slot::from(1_005)).await;
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));
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

        let mut build_state = claimed_build_state();
        let initial_from = build_state
            .get_account_by_id(from)
            .data
            .native_balance()
            .unwrap();
        let genesis = produce_dummy_block(1, None, vec![]);
        chain_state::apply::apply_block_to_state(&genesis, &mut build_state)
            .expect("genesis applies");
        store_block(&store, &genesis, Slot::from(0)).await;
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
            store_block(&store, &block, Slot::from(0)).await;
        }

        // Snapshot at block 100 = genesis + 99 transfers (plus their fees),
        // written with the block.
        let bp1 = store.dbio.get_breakpoint(1).expect("breakpoint 1 present");
        assert!(bp1.get_account_by_id(from).data.native_balance().unwrap() < initial_from - 99);

        // The #605 restart: reopening past the boundary must work.
        drop(store);
        let reopened = open_default(dir.path());
        assert_eq!(reopened.last_block().unwrap(), Some(101));
    }
}
