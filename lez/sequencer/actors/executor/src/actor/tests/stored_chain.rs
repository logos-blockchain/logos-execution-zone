//! The chains a mocked store holds when an executor starts.

use std::collections::BTreeMap;

use chain_state::{ChainState, ChannelEntry, Tip};
use common::{
    HashType,
    block::{Block, BlockMeta, HashableBlockData},
    test_utils::{producer_account_for_testing, producer_seed, sequencer_sign_key_for_testing},
    transaction::{LeeTransaction, clock_invocation, fee_invocation},
};
use lee::V03State;
use sequencer_bedrock_actor::{
    mock::mock_msg_of,
    protocol::{Checkpoint, HeaderId, MsgId, SerializeOp as _, Slot},
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_storage_actor::{mock::CannedStore, protocol::ZoneCheckpointRecord};

/// The peer zone a delivery comes from.
pub(in crate::actor) const PEER_ZONE: [u8; 32] = [0xbe_u8; 32];

/// Genesis stored but not finalized, as a fresh store seeds it.
pub(in crate::actor) fn fresh_store() -> CannedStore {
    let genesis = genesis();
    let head_state = applied(&testnet_initial_state::initial_state(false), &genesis);
    CannedStore {
        blocks: BTreeMap::from([(genesis.header.block_id, genesis)]),
        head_state: Some(head_state),
        ..CannedStore::default()
    }
}

/// Genesis finalized, over a state where the test producer collects fees.
pub(in crate::actor) fn finalized_genesis_store() -> CannedStore {
    let state = applied(
        &testnet_initial_state::initial_state(false).with_public_accounts([producer_seed()]),
        &genesis(),
    );
    finalized_genesis_over(state)
}

/// Genesis finalized over a state whose cross-zone inbox accepts pings from
/// [`PEER_ZONE`], configured the way genesis configures it.
pub(in crate::actor) fn cross_zone_genesis_store() -> CannedStore {
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: PEER_ZONE,
            allowed_routes: vec![CrossZoneRoute {
                src_account_id: programs::ping_sender_account_id(),
                target_account_id: programs::ping_receiver_account_id(),
                mint_cap: None,
            }],
            min_committee_size: 0,
        }],
        source_authority: None,
        source_governance: None,
    };
    let mut state =
        testnet_initial_state::initial_state(true).with_public_accounts([producer_seed()]);
    for tx in [
        cross_zone::build_wrapped_token_init_config_tx(&cross_zone),
        cross_zone::build_ping_sender_init_config_tx(),
        cross_zone::build_ping_receiver_init_config_tx(&cross_zone),
        cross_zone::build_bridge_lock_init_config_tx(),
        cross_zone::build_inbox_init_config_tx([0; 32]),
    ] {
        state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("cross-zone config initializes");
    }
    finalized_genesis_over(applied(&state, &genesis()))
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
        || (testnet_initial_state::initial_state(false), None),
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
        block_id: id,
        prev_block_hash: prev,
        timestamp,
        transactions: vec![
            LeeTransaction::Public(fee_invocation(
                fee_core::BlockFeeSummary::default(),
                0,
                producer_account_for_testing(),
            )),
            LeeTransaction::Public(clock_invocation(id, timestamp)),
        ],
    }
    .into_pending_block(&sequencer_sign_key_for_testing())
}

pub(in crate::actor) fn applied(state: &V03State, block: &Block) -> V03State {
    let mut next = state.clone();
    chain_state::apply_block_to_state(block, &mut next).expect("test block applies");
    next
}

pub(in crate::actor) fn checkpoint_record() -> ZoneCheckpointRecord {
    let bytes = Checkpoint {
        last_msg_id: MsgId::from([0; 32]),
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
        channel_notes: Vec::new(),
        finalized_config: MsgId::root(),
    }
    .to_bytes()
    .expect("checkpoint serializes")
    .into();
    ZoneCheckpointRecord { bytes, seq: 0 }
}
