//! An executor coming online without channel history to bootstrap from.

use anyhow::Result;
use common::test_utils::produce_dummy_block;
use sequencer_bedrock_actor::mock::{CannedChannel, mock_msg_of};
use tokio::test;

use crate::{
    actor::tests::{
        initialize_state, sequencer_config,
        stored_chain::{
            delete_block, fresh_store, genesis, stored_blocks, stored_view, with_head, with_view,
        },
    },
    error::Error,
};

/// A store seeded offline holds a chain no channel has seen yet, so the channel is created from
/// it rather than from a new genesis, however many pages of blocks it takes.
#[test]
async fn a_seeded_store_creates_the_channel_from_its_chain() -> Result<()> {
    let (config, _home) = sequencer_config();
    let mut store = fresh_store();
    let mut tip = genesis();
    for block_id in 2..=70 {
        tip = produce_dummy_block(block_id, Some(tip.header.hash), vec![]);
        store = with_head(store, tip.clone());
    }
    let store = store.share();
    let channel = CannedChannel::absent().share();

    let state = initialize_state(config, &store, &channel).await?;

    // The channel refuses a publish chained on anything but its tip, so landing on
    // the last block means the chain was inscribed in order.
    assert_eq!(channel.lock().tip, Some(mock_msg_of(&tip)));
    assert_eq!(state.online()?.sequencer().chain_height().await, 70);
    assert_eq!(
        stored_blocks(&store.values()).len(),
        70,
        "every block stays"
    );
    assert!(stored_view(&store).is_some());
    Ok(())
}

/// A channel without entries has nothing to bootstrap from, so a node holding a chain resumes on
/// the view it stored and publishes nothing.
#[test]
async fn a_stored_chain_resumes_on_a_channel_without_entries() -> Result<()> {
    let (config, _home) = sequencer_config();
    let block2 = produce_dummy_block(2, Some(genesis().header.hash), vec![]);
    let store = with_view(with_head(fresh_store(), block2)).share();
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
    let store = with_head(fresh_store(), block2);
    delete_block(&store.values, lee::GENESIS_BLOCK_ID);

    let Err(err) = initialize_state(config, &store.share(), &CannedChannel::absent().share()).await
    else {
        panic!("creating the channel must be refused");
    };
    assert!(matches!(err, Error::StorageInconsistency(_)), "{err:?}");
}
