//! An executor coming online without channel history to bootstrap from.

use anyhow::Result;
use common::{block::BedrockStatus, test_utils::produce_dummy_block};
use sequencer_bedrock_actor::{
    mock::{CannedChannel, mock_msg_of},
    protocol::{Checkpoint, DeserializeOp as _},
};
use tokio::test;

use crate::{
    actor::tests::{
        initialize_state, sequencer_config,
        stored_chain::{fresh_store, genesis, with_head},
    },
    error::Error,
};

/// A store seeded offline holds a chain no channel has seen yet, so the channel is created from
/// it rather than from a new genesis.
#[test]
async fn a_seeded_store_creates_the_channel_from_its_chain() -> Result<()> {
    let (config, _home) = sequencer_config();
    let block2 = produce_dummy_block(2, Some(genesis().header.hash), vec![]);
    let store = with_head(fresh_store(), block2.clone()).share();
    let channel = CannedChannel::absent().share();

    let state = initialize_state(config, &store, &channel).await?;

    // The channel refuses a publish chained on anything but its tip, so landing on
    // block 2 means the chain was inscribed in order.
    assert_eq!(channel.lock().tip, Some(mock_msg_of(&block2)));
    let checkpoint = store
        .lock()
        .checkpoint
        .clone()
        .expect("the checkpoint of the last publish is persisted");
    assert_eq!(
        Checkpoint::from_bytes(&checkpoint)?.last_msg_id,
        mock_msg_of(&block2)
    );
    assert_eq!(state.online()?.sequencer().chain_height().await, 2);
    Ok(())
}

/// A channel without entries has nothing to bootstrap from, so a node holding a chain resumes on
/// it and publishes nothing.
#[test]
async fn a_stored_chain_resumes_on_a_channel_without_entries() -> Result<()> {
    let (config, _home) = sequencer_config();
    let block2 = produce_dummy_block(2, Some(genesis().header.hash), vec![]);
    let store = with_head(fresh_store(), block2).share();
    let channel = CannedChannel::empty().share();

    let state = initialize_state(config, &store, &channel).await?;

    assert_eq!(channel.lock().tip, None, "nothing is published");
    assert_eq!(state.online()?.sequencer().chain_height().await, 2);
    Ok(())
}

/// The channel is created from the pending blocks, genesis first, so pending blocks starting past
/// genesis cannot create it.
#[test]
async fn a_store_without_a_pending_genesis_cannot_create_the_channel() {
    let (config, _home) = sequencer_config();
    let block2 = produce_dummy_block(2, Some(genesis().header.hash), vec![]);
    let mut store = with_head(fresh_store(), block2);
    store
        .blocks
        .get_mut(&lee::GENESIS_BLOCK_ID)
        .expect("genesis is stored")
        .bedrock_status = BedrockStatus::Finalized;

    let Err(err) = initialize_state(config, &store.share(), &CannedChannel::absent().share()).await
    else {
        panic!("creating the channel must be refused");
    };
    assert!(matches!(err, Error::StorageInconsistency(_)), "{err:?}");
}
