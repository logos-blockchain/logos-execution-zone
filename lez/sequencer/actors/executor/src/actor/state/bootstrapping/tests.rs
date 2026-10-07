//! A bootstrapping executor refusing a channel that serves a different chain.

use chain_state::{ChainMismatch, ingest_error::BlockIngestError};
use common::{HashType, test_utils::produce_dummy_block};
use sequencer_bedrock_actor::{mock::CannedChannel, protocol::FinalizedBlock};
use sequencer_storage_actor::{mock::CannedStore, protocol::ZoneAnchorRecord};
use tokio::test;

use crate::{
    actor::{
        state::State,
        tests::{
            finalized_at, initialize_state, sequencer_config,
            stored_chain::{
                block_at, checkpoint_record, finalized_genesis_store, fresh_store, genesis,
                with_finalized,
            },
        },
    },
    error::Error,
};

/// The error starting over `store` and following `history` refuses with. `history` is the
/// finalized channel entries the Bedrock actor streams from the stored anchor on; its last entry
/// is the channel tip, and an empty history means there is no channel.
async fn refusal(store: CannedStore, history: Vec<FinalizedBlock>) -> Error {
    let (config, _home) = sequencer_config();
    let channel = history
        .last()
        .map_or_else(CannedChannel::absent, |tip| CannedChannel {
            tip_slot: Some(tip.slot),
            tip: Some(tip.msg_id),
            ..CannedChannel::absent()
        })
        .share();
    let mut state = match initialize_state(config, &store.share(), &channel).await {
        Ok(state) => state,
        Err(err) => return err,
    };
    for finalized in history {
        let State::Bootstrapping(bootstrapping) = state else {
            panic!("the channel tip was reached without a refusal");
        };
        state = match Box::pin(bootstrapping.on_finalized_block(finalized)).await {
            Ok(next) => next,
            Err(err) => return err,
        };
    }
    panic!("bootstrapping must refuse this channel");
}

#[test]
async fn fails_when_channel_serves_a_divergent_block() {
    let genesis = genesis();
    let store = CannedStore {
        anchor: Some(ZoneAnchorRecord {
            slot: 100,
            block_id: 1,
            hash: genesis.header.hash,
        }),
        ..finalized_genesis_store()
    };

    // The channel serves a different block at the anchor id/slot.
    let mut tampered = genesis;
    tampered.header.hash = HashType([9_u8; 32]);

    let err = refusal(store, vec![finalized_at(&tampered, 100)]).await;
    assert!(
        matches!(
            err,
            Error::StoreAndChannelDivergence(ChainMismatch::Block { .. })
        ),
        "{err:?}"
    );
}

#[test]
async fn fails_when_channel_is_missing() {
    let genesis = genesis();
    let store = CannedStore {
        anchor: Some(ZoneAnchorRecord {
            slot: 100,
            block_id: 1,
            hash: genesis.header.hash,
        }),
        ..finalized_genesis_store()
    };

    // Anchor present, but the channel does not exist on the connected chain.
    let err = refusal(store, Vec::new()).await;
    assert!(
        matches!(
            err,
            Error::StoreAndChannelDivergence(ChainMismatch::ChannelMissing)
        ),
        "{err:?}"
    );
}

#[test]
async fn committed_local_against_missing_channel_fails_without_anchor() {
    // A sequencer that has committed blocks — a non-genesis tip plus a persisted
    // checkpoint — but only ever produced (so it never recorded a per-block
    // anchor). Restarting it against a wiped/missing channel must still fail,
    // driven by the committed-blocks invariant rather than an anchor probe.
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let store = CannedStore {
        checkpoint: Some(checkpoint_record()),
        ..with_finalized(finalized_genesis_store(), block2)
    };

    let err = refusal(store, Vec::new()).await;
    assert!(
        matches!(
            err,
            Error::StoreAndChannelDivergence(ChainMismatch::ChannelMissing)
        ),
        "{err:?}"
    );
}

// The following cases exercise a first finalized block that does not apply on
// our genesis state, reached with no recorded anchor, so the block's own
// validation fires rather than the up-front `AnchorConsistencyCheck`. Only the
// first is fatal: it is the channel's genesis, so one that is not ours means a
// different chain.

#[test]
async fn fails_when_channel_reinscribes_genesis_with_a_different_hash() {
    // Fresh store, no anchor. The channel serves a genesis at the same id but a
    // different hash — a foreign chain reinscribing genesis.
    let mut reinscribed = genesis();
    reinscribed.header.hash = HashType([0xAB_u8; 32]);

    let err = refusal(fresh_store(), vec![finalized_at(&reinscribed, 10)]).await;
    assert!(
        matches!(
            err,
            Error::BlockReconstructionFailed {
                block_id: 1,
                source: BlockIngestError::HashMismatch { .. },
            }
        ),
        "{err:?}"
    );
}

#[test]
async fn fails_when_a_channel_block_is_numbered_below_genesis() {
    // A block numbered below our genesis — a foreign chain with a lower
    // numbering. Nothing local sits at that id, so it goes straight to
    // validation and parks there.
    let foreign = block_at(0, HashType([0; 32]), 0);

    let err = refusal(fresh_store(), vec![finalized_at(&foreign, 10)]).await;
    assert!(
        matches!(
            err,
            Error::BlockReconstructionFailed {
                block_id: 0,
                source: BlockIngestError::UnexpectedBlockId { .. },
            }
        ),
        "{err:?}"
    );
}

#[test]
async fn fails_when_the_first_channel_block_is_not_genesis() {
    // A block claiming an id far past genesis, first on a channel the store has
    // seen nothing of.
    let orphan = block_at(6, genesis().header.hash, 0);

    let err = refusal(fresh_store(), vec![finalized_at(&orphan, 10)]).await;
    assert!(
        matches!(
            err,
            Error::BlockReconstructionFailed {
                block_id: 6,
                source: BlockIngestError::UnexpectedBlockId {
                    expected: lee::GENESIS_BLOCK_ID,
                    got: 6
                },
            }
        ),
        "{err:?}"
    );
}
