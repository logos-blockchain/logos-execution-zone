//! A [`MockBedrockActor`] serving a canned channel.

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use common::block::Block;
use logos_blockchain_core::mantle::{
    ledger::{NoteId, Utxo},
    ops::channel::MsgId,
};
use logos_blockchain_zone_sdk::{Slot, ZoneMessage, sequencer::WithdrawArg};
use sequencer_bedrock_actor::{
    Result,
    error::Error,
    mock::MockBedrockActor,
    protocol::{
        AccreditedKeys, BoxStream, CreateChannel, PublishBlock, PublishOutcome, ReadChannel,
    },
};

use super::{checkpoint_at, mock_msg_of};

/// What the mocked channel holds. A running sequencer sees it change when its
/// mock is replaced with one built from a different [`CannedChannel`].
#[derive(Clone, Default)]
pub struct CannedChannel {
    /// Channel frontier; `None` means the channel does not exist.
    pub tip_slot: Option<Slot>,
    /// Finalized history served to reconstruction.
    pub messages: Vec<(ZoneMessage, Slot)>,
    /// Entry the last publish left the channel at. A publish chained on any
    /// other entry is refused, as L1 does.
    pub tip: Option<MsgId>,
    /// When set, the tip a read reports instead of [`Self::tip`].
    pub stale_tip_read: Option<MsgId>,
    /// Fails every publish.
    pub publish_fails: bool,
}

impl CannedChannel {
    /// An existing but empty channel.
    pub fn empty() -> Self {
        Self {
            tip_slot: Some(Slot::from(0)),
            ..Self::default()
        }
    }

    /// No channel yet, so startup creates it and publishes the stored blocks.
    pub fn absent() -> Self {
        Self::default()
    }

    pub fn into_mock(self) -> MockBedrockActor {
        let Self {
            tip_slot,
            messages,
            tip,
            stale_tip_read,
            publish_fails,
        } = self;
        let tip = Arc::new(Mutex::new(tip));

        let mut mock = MockBedrockActor::default();
        // This node is always the one bootstrapping the channel.
        mock.expect_handle_check_channel_exists()
            .returning(|_msg, _ctx| Ok(false));
        mock.expect_handle_check_is_our_turn()
            .returning(|_msg, _ctx| true);
        mock.expect_handle_get_channel_tip_slot()
            .returning(move |_msg, _ctx| Ok(tip_slot));
        // The config entry is the root, which `checkpoint_at` reports
        // finalized, so the committee reads as final.
        mock.expect_handle_get_accredited_keys()
            .returning(move |_msg, _ctx| {
                Ok(tip_slot.map(|_| AccreditedKeys {
                    keys: Vec::new(),
                    config_tip: MsgId::root(),
                    tip_sequencer: 0,
                }))
            });
        mock.expect_handle_change_channel_config()
            .returning(|_msg, _ctx| Ok(()));
        mock.expect_handle_read_channel()
            .returning(move |ReadChannel { after }, _ctx| Ok(history_after(&messages, after)));
        mock.expect_handle_get_channel_tip_message_id().returning({
            let tip = Arc::clone(&tip);
            move |_msg, _ctx| {
                Ok(stale_tip_read.or_else(|| *tip.lock().expect("channel tip lock poisoned")))
            }
        });
        mock.expect_handle_create_channel().returning({
            let tip = Arc::clone(&tip);
            move |CreateChannel { genesis, .. }, _ctx| {
                land(&tip, publish_fails, &genesis, Vec::new())
            }
        });
        mock.expect_handle_publish_block().returning(
            move |PublishBlock {
                      block,
                      withdrawals,
                      parent,
                  },
                  _ctx| {
                let current = *tip.lock().expect("channel tip lock poisoned");
                if let Some(parent) = parent
                    && current.is_some_and(|current| current != parent)
                {
                    return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                        "Block {} is chained on an entry that is no longer the channel tip",
                        block.header.block_id
                    )));
                }
                land(
                    &tip,
                    publish_fails,
                    &block,
                    mock_released_notes(&withdrawals),
                )
            },
        );
        mock
    }
}

/// The entries of `messages` past `after` (exclusive), as `ReadChannel` serves them.
fn history_after(
    messages: &[(ZoneMessage, Slot)],
    after: Option<Slot>,
) -> BoxStream<(ZoneMessage, Slot)> {
    let messages: Vec<_> = messages
        .iter()
        .filter(|(_, slot)| after.is_none_or(|after| *slot > after))
        .cloned()
        .collect();
    Box::pin(futures::stream::iter(messages))
}

/// Moves the channel tip to `block` and reports what its publish produced.
fn land(
    tip: &Mutex<Option<MsgId>>,
    publish_fails: bool,
    block: &Block,
    released_notes: Vec<NoteId>,
) -> Result<PublishOutcome> {
    if publish_fails {
        return Err(Error::SubmitSignedTransactionFailed(anyhow!(
            "Canned publish failure for block {}",
            block.header.block_id
        )));
    }
    let this_msg = mock_msg_of(block);
    *tip.lock().expect("channel tip lock poisoned") = Some(this_msg);
    Ok(PublishOutcome {
        this_msg,
        checkpoint: checkpoint_at(this_msg),
        released_notes,
    })
}

/// The notes the mock reports as released by `withdrawals`.
///
/// Zone-sdk picks the actual channel notes to release, so the mock invents one
/// per requested output, derived from the output itself so a test can
/// recompute the reconciliation keys of a block it produced.
fn mock_released_notes(withdrawals: &[WithdrawArg]) -> Vec<NoteId> {
    withdrawals
        .iter()
        .flat_map(|withdraw| withdraw.outputs.into_iter().enumerate())
        .map(|(output_index, note)| Utxo::new([0; 32], output_index, *note).id())
        .collect()
}
