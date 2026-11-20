//! The chains a mocked store holds when an executor starts.

use std::{collections::BTreeSet, sync::Arc};

use chain_state::{ChainState, ChannelEntry, Tip};
use common::{
    HashType,
    block::{Block, BlockMeta, HashableBlockData},
    test_utils::{producer_account_for_testing, producer_seed},
    transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
};
use lee::V03State;
use sequencer_bedrock_actor::{mock::mock_msg_of, protocol::MsgId};
use sequencer_core::storage::{
    ChannelViewRecord, FinalSnapshotRecord, HeadStateRecord, ZoneAnchorRecord, blocks::BlockRecord,
    bridge::PendingDepositEventRecord,
};
use sequencer_storage_actor::{
    encoding::{BigEndian, BorshArc, SingletonKey},
    mock::{CannedStore, SharedStore, StoredValues},
};

/// Genesis stored but not finalized, as a fresh store seeds it.
pub(in crate::actor) fn fresh_store() -> CannedStore {
    let genesis = genesis();
    let head_state = applied(&testnet_initial_state::initial_state(), &genesis);
    let store = CannedStore::default();
    store_block(&store.values, genesis);
    store_head_state(&store.values, head_state);
    store
}

/// Genesis finalized, over a state where the test producer collects fees.
pub(in crate::actor) fn finalized_genesis_store() -> CannedStore {
    let state = applied(
        &testnet_initial_state::initial_state().with_public_accounts([producer_seed()]),
        &genesis(),
    );
    finalized_genesis_over(state)
}

/// Extends the head tier of `store` with `block`.
pub(in crate::actor) fn with_head(store: CannedStore, block: Block) -> CannedStore {
    let head_state = stored_head_state(&store.values).expect("the store holds a chain");
    store_head_state(&store.values, applied(&head_state, &block));
    store_block(&store.values, block);
    store
}

/// Extends the chain of `store` with `block` and finalizes through it. A finalized block is never
/// replayed, so its state is taken as is.
pub(in crate::actor) fn with_finalized(store: CannedStore, block: Block) -> CannedStore {
    let head_state = stored_head_state(&store.values).expect("the store holds a chain");
    store_final_snapshot(&store.values, head_state, BlockMeta::from(&block));
    store_block(&store.values, block);
    store
}

/// Records the blocks of `store` above its final tier as the channel view, each chained on the
/// one before, as publishing them leaves it.
pub(in crate::actor) fn with_view(store: CannedStore) -> CannedStore {
    let (final_state, final_tip) = stored_final_snapshot(&store.values).map_or_else(
        || (testnet_initial_state::initial_state(), None),
        |(state, meta)| (state, Some(Tip::from(meta))),
    );
    let boundary = final_tip.as_ref().map_or(0, |tip| tip.block_id);
    let mut chain = ChainState::from_final(final_state, final_tip);
    let mut parent = MsgId::root();
    let entries = stored_blocks(&store.values)
        .into_iter()
        .filter(|block| block.header.block_id > boundary)
        .map(|block| {
            let entry = ChannelEntry {
                msg: mock_msg_of(&block),
                parent,
                block: Some(block),
                finally_absent_keys: BTreeSet::new(),
                final_slot: None,
            };
            parent = entry.msg;
            entry
        })
        .collect();
    chain.apply_conflict(entries);
    store_view(&store, chain.encode_view());
    store
}

/// Records `anchor` in `store`.
pub(in crate::actor) fn with_anchor(store: CannedStore, anchor: ZoneAnchorRecord) -> CannedStore {
    store
        .values
        .store(&SingletonKey, &anchor)
        .expect("Failed to store the anchor");
    store
}

/// Records `record` as a pending deposit of `store`.
pub(in crate::actor) fn with_pending_deposit(
    store: CannedStore,
    record: &PendingDepositEventRecord,
) -> CannedStore {
    store
        .values
        .store(&record.deposit_op_id, record)
        .expect("Failed to store the pending deposit");
    store
}

pub(in crate::actor) fn stored_pending_deposits(
    values: &StoredValues,
) -> Vec<PendingDepositEventRecord> {
    values
        .range(None, None, usize::MAX)
        .expect("Failed to read the pending deposits")
}

/// Records `bytes` as the channel view of `store`.
pub(in crate::actor) fn store_view(store: &CannedStore, bytes: Vec<u8>) {
    store
        .values
        .store(&SingletonKey, &ChannelViewRecord { bytes })
        .expect("Failed to store the channel view");
}

pub(in crate::actor) fn stored_anchor(store: &SharedStore) -> Option<ZoneAnchorRecord> {
    store
        .values()
        .get(&SingletonKey)
        .expect("Failed to read the anchor")
}

pub(in crate::actor) fn stored_view(store: &SharedStore) -> Option<Vec<u8>> {
    store
        .values()
        .get::<ChannelViewRecord>(&SingletonKey)
        .expect("Failed to read the channel view")
        .map(|view| view.bytes)
}

pub(in crate::actor) fn store_block(values: &StoredValues, block: Block) {
    values
        .store(
            &BigEndian::new(&block.header.block_id),
            &BlockRecord { block },
        )
        .expect("Failed to store the block");
}

pub(in crate::actor) fn delete_block(values: &StoredValues, block_id: u64) {
    values.delete::<BlockRecord>(&BigEndian::new(&block_id));
}

pub(in crate::actor) fn stored_block(values: &StoredValues, block_id: u64) -> Option<Block> {
    values
        .get::<BlockRecord>(&BigEndian::new(&block_id))
        .expect("Failed to read the block")
        .map(|record| record.block)
}

/// Every stored block, lowest first.
pub(in crate::actor) fn stored_blocks(values: &StoredValues) -> Vec<Block> {
    values
        .range::<BlockRecord>(None, None, usize::MAX)
        .expect("Failed to read the blocks")
        .into_iter()
        .map(|record| record.block)
        .collect()
}

/// The last stored block.
pub(in crate::actor) fn stored_tip(values: &StoredValues) -> Option<BlockMeta> {
    stored_blocks(values).last().map(BlockMeta::from)
}

pub(in crate::actor) fn store_head_state(values: &StoredValues, state: V03State) {
    values
        .store(
            &SingletonKey,
            &HeadStateRecord {
                state: BorshArc(Arc::new(state)),
            },
        )
        .expect("Failed to store the head state");
}

pub(in crate::actor) fn stored_head_state(values: &StoredValues) -> Option<V03State> {
    values
        .get::<HeadStateRecord>(&SingletonKey)
        .expect("Failed to read the head state")
        .map(HeadStateRecord::into_state)
}

pub(in crate::actor) fn store_final_snapshot(
    values: &StoredValues,
    state: V03State,
    meta: BlockMeta,
) {
    values
        .store(
            &SingletonKey,
            &FinalSnapshotRecord {
                state: BorshArc(Arc::new(state)),
                meta,
            },
        )
        .expect("Failed to store the final snapshot");
}

pub(in crate::actor) fn stored_final_snapshot(
    values: &StoredValues,
) -> Option<(V03State, BlockMeta)> {
    values
        .get::<FinalSnapshotRecord>(&SingletonKey)
        .expect("Failed to read the final snapshot")
        .map(FinalSnapshotRecord::into_parts)
}

/// Genesis finalized with `state` after it.
fn finalized_genesis_over(state: V03State) -> CannedStore {
    let genesis = genesis();
    let store = fresh_store();
    store_final_snapshot(&store.values, state.clone(), BlockMeta::from(&genesis));
    store_head_state(&store.values, state);
    store
}

/// Genesis the way a stakeless node seeds it: only the fee and clock tail.
pub(in crate::actor) fn genesis() -> Block {
    block_at(1, HashType([0; 32]), 0)
}

/// A valid empty block, like [`produce_dummy_block`] but at `timestamp`.
pub(in crate::actor) fn block_at(id: u64, prev: HashType, timestamp: u64) -> Block {
    HashableBlockData {
        receipts: Vec::new(),
        block_id: id,
        prev_block_hash: prev,
        timestamp,
        transactions: vec![
            LeeTransaction::Public(fee_invocation(
                fee_core::BlockFeeSummary::default(),
                0,
                FeePayee::Present(producer_account_for_testing()),
            )),
            LeeTransaction::Public(clock_invocation(id, timestamp)),
        ],
    }
    .into_pending_block()
}

pub(in crate::actor) fn applied(state: &V03State, block: &Block) -> V03State {
    let mut next = state.clone();
    chain_state::apply_block_to_state(block, &mut next).expect("test block applies");
    next
}
