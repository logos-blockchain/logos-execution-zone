//! The chains a mocked store holds when an executor starts.

use std::collections::{BTreeMap, BTreeSet};

use chain_state::{ChainState, ChannelEntry, Tip};
use common::{
    HashType,
    block::{Block, BlockMeta, HashableBlockData},
    test_utils::{producer_account_for_testing, producer_seed},
    transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
};
use lee::V03State;
use sequencer_bedrock_actor::{
    mock::mock_msg_of,
    protocol::{Checkpoint, HeaderId, MsgId, SerializeOp as _, Slot},
};
use sequencer_storage_actor::mock::CannedStore;

/// Genesis stored but not finalized, as a fresh store seeds it.
pub(in crate::actor) fn fresh_store() -> CannedStore {
    let genesis = genesis();
    let head_state = applied(&testnet_initial_state::initial_state(), &genesis);
    CannedStore {
        blocks: BTreeMap::from([(genesis.header.block_id, genesis)]),
        head_state: Some(head_state),
        ..CannedStore::default()
    }
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
pub(in crate::actor) fn with_head(mut store: CannedStore, block: Block) -> CannedStore {
    let head_state = store.head_state.as_ref().expect("the store holds a chain");
    store.head_state = Some(applied(head_state, &block));
    store.blocks.insert(block.header.block_id, block);
    store
}

/// Extends the chain of `store` with `block` and finalizes through it. A finalized block is never
/// replayed, so its state is taken as is.
pub(in crate::actor) fn with_finalized(mut store: CannedStore, block: Block) -> CannedStore {
    let head_state = store.head_state.clone().expect("the store holds a chain");
    store.final_snapshot = Some((head_state, BlockMeta::from(&block)));
    store.blocks.insert(block.header.block_id, block);
    store
}

/// Records the blocks of `store` above its final tier as the channel view, each chained on the
/// one before, as publishing them leaves it.
pub(in crate::actor) fn with_view(mut store: CannedStore) -> CannedStore {
    let (final_state, final_tip) = store.final_snapshot.clone().map_or_else(
        || (testnet_initial_state::initial_state(), None),
        |(state, meta)| (state, Some(Tip::from(meta))),
    );
    let boundary = final_tip.as_ref().map_or(0, |tip| tip.block_id);
    let mut chain = ChainState::from_final(final_state, final_tip);
    let mut parent = MsgId::root();
    let entries = store
        .blocks
        .values()
        .filter(|block| block.header.block_id > boundary)
        .map(|block| {
            let entry = ChannelEntry {
                msg: mock_msg_of(block),
                parent,
                block: Some(block.clone()),
                finally_absent_keys: BTreeSet::new(),
                final_slot: None,
            };
            parent = entry.msg;
            entry
        })
        .collect();
    chain.apply_conflict(entries);
    store.channel_view = Some(chain.encode_view());
    store
}

/// Genesis finalized with `state` after it.
fn finalized_genesis_over(state: V03State) -> CannedStore {
    let genesis = genesis();
    CannedStore {
        final_snapshot: Some((state.clone(), BlockMeta::from(&genesis))),
        head_state: Some(state),
        ..fresh_store()
    }
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

/// The bytes of a checkpoint at the root of the channel.
pub(in crate::actor) fn checkpoint_bytes() -> Vec<u8> {
    Checkpoint {
        last_msg_id: MsgId::from([0; 32]),
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
        channel_notes: Vec::new(),
        finalized_config: MsgId::root(),
        funding: Vec::new(),
    }
    .to_bytes()
    .expect("checkpoint serializes")
    .into()
}
