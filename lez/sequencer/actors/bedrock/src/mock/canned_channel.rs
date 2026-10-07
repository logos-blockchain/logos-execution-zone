//! A [`MockBedrockActor`] serving a canned channel.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::anyhow;
use common::block::Block;
use logos_blockchain_core::mantle::ledger::{NoteId, Utxo};

use super::MockBedrockActor;
use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChannelSeq, CreateChannel, HeaderId, MsgId, PublishBlock,
        PublishOutcome, ReadChannel, SequencerCheckpoint, Slot, WithdrawArg, ZoneMessage,
    },
};

/// What a mocked channel holds.
#[derive(Clone, Default)]
pub struct CannedChannel {
    /// Channel frontier; `None` means the channel does not exist.
    pub tip_slot: Option<Slot>,
    /// Finalized history served to [`ReadChannel`].
    pub messages: Vec<(ZoneMessage, Slot)>,
    /// Entry the last publish left the channel at. A publish chained on any
    /// other entry is refused, as L1 does.
    pub tip: Option<MsgId>,
    /// When set, the tip a read reports instead of [`Self::tip`].
    pub stale_tip_read: Option<MsgId>,
    /// Fails every publish.
    pub publish_fails: bool,
    /// Channel sequence the last publish left the channel at.
    pub seq: u64,
}

impl CannedChannel {
    /// An existing but empty channel.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tip_slot: Some(Slot::from(0)),
            ..Self::default()
        }
    }

    /// No channel yet.
    #[must_use]
    pub fn absent() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn share(self) -> SharedChannel {
        SharedChannel(Arc::new(Mutex::new(self)))
    }
}

/// A [`CannedChannel`] every mock built from it serves, so a test can change the channel under a
/// running node and keep it across restarts.
#[derive(Clone)]
pub struct SharedChannel(Arc<Mutex<CannedChannel>>);

impl SharedChannel {
    /// Makes every mock serve `channel` from now on.
    pub fn serve(&self, channel: CannedChannel) {
        *self.lock() = channel;
    }

    /// A mock serving this channel, with this node always on turn.
    #[must_use]
    pub fn mock(&self) -> MockBedrockActor {
        let mut mock = MockBedrockActor::default();
        mock.expect_handle_initialize_channel_publisher()
            .returning(|_msg, _ctx| Ok(true));
        mock.expect_handle_check_channel_exists().returning({
            let channel = self.clone();
            move |_msg, _ctx| Ok(channel.lock().tip_slot.is_some())
        });
        mock.expect_handle_check_is_our_turn()
            .returning(|_msg, _ctx| Ok(true));
        mock.expect_handle_get_channel_tip_slot().returning({
            let channel = self.clone();
            move |_msg, _ctx| Ok(channel.lock().tip_slot)
        });
        // The config entry is the root, which `checkpoint_at` reports
        // finalized, so the committee reads as final.
        mock.expect_handle_get_accredited_keys().returning({
            let channel = self.clone();
            move |_msg, _ctx| {
                Ok(channel.lock().tip_slot.map(|tip_slot| AccreditedKeys {
                    keys: Vec::new(),
                    config_tip: MsgId::root(),
                    tip_sequencer: 0,
                    tip_slot,
                }))
            }
        });
        mock.expect_handle_change_channel_config()
            .returning(|_msg, _ctx| Ok(()));
        mock.expect_handle_read_channel().returning({
            let channel = self.clone();
            move |ReadChannel {
                      channel_id: _,
                      after,
                  },
                  _ctx| Ok(history_after(&channel.lock().messages, after))
        });
        mock.expect_handle_get_channel_tip_message_id().returning({
            let channel = self.clone();
            move |_msg, _ctx| {
                let channel = channel.lock();
                Ok(channel.stale_tip_read.or(channel.tip))
            }
        });
        mock.expect_handle_create_channel().returning({
            let channel = self.clone();
            move |CreateChannel { genesis, .. }, _ctx| channel.land(&genesis, None, Vec::new())
        });
        mock.expect_handle_publish_block().returning({
            let channel = self.clone();
            move |PublishBlock {
                      channel_id: _,
                      block,
                      withdrawals,
                      parent,
                      expected_seq: _,
                  },
                  _ctx| {
                let current = channel.lock().tip;
                if let Some(parent) = parent
                    && current.is_some_and(|current| current != parent)
                {
                    return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                        "Block {} is chained on an entry that is no longer the channel tip",
                        block.header.block_id
                    )));
                }
                channel.land(&block, parent, mock_released_notes(&withdrawals))
            }
        });
        mock
    }

    /// Moves the channel tip to `block`, inscribed on `parent` or else on the tip, and reports
    /// what its publish produced.
    fn land(
        &self,
        block: &Block,
        parent: Option<MsgId>,
        released_notes: Vec<NoteId>,
    ) -> Result<PublishOutcome> {
        let mut channel = self.lock();
        if channel.publish_fails {
            return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                "Canned publish failure for block {}",
                block.header.block_id
            )));
        }
        let this_msg = mock_msg_of(block);
        let tip = channel.tip.replace(this_msg);
        let parent = parent.or(tip).unwrap_or_else(MsgId::root);
        channel.seq = channel.seq.saturating_add(1);
        Ok(PublishOutcome {
            this_msg,
            parent,
            checkpoint: checkpoint_at(this_msg),
            seq: ChannelSeq::mocked(channel.seq),
            released_notes,
        })
    }

    /// # Panics
    ///
    /// If a mock panicked while holding the channel.
    pub fn lock(&self) -> MutexGuard<'_, CannedChannel> {
        self.0.lock().expect("canned channel lock poisoned")
    }
}

/// The message id a canned channel lands `block` under.
#[must_use]
pub fn mock_msg_of(block: &Block) -> MsgId {
    MsgId::from(block.header.hash.0)
}

/// A checkpoint whose channel tip is `tip`, with the root as its finalized config entry.
#[must_use]
pub fn checkpoint_at(tip: MsgId) -> SequencerCheckpoint {
    SequencerCheckpoint {
        last_msg_id: tip,
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
        channel_notes: Vec::new(),
        finalized_config: MsgId::root(),
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
