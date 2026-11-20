//! A [`MockBedrockActor`] serving a canned channel.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::anyhow;
use common::block::Block;
use sequencer_storage_actor::protocol::ZoneAnchorRecord;

use super::MockBedrockActor;
use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChannelReadStream, ChannelSeq, CreateChannel, FilterFinallyAbsent,
        HeaderId, InitializeChannelPublisher, MsgId, PublishBlock, PublishOutcome, ReadChannel,
        SequencerCheckpoint, SequencerKey, Slot, VaultMint, ZoneMessage,
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
    /// Reads of [`Self::tip_slot`] that fail, as with a node that is not ready yet, before they
    /// succeed.
    pub failed_tip_slot_reads: u32,
    /// Fails every publish.
    pub publish_fails: bool,
    /// Keys whose removal config is reported not yet final; every other key's is.
    pub pending_removals: BTreeSet<SequencerKey>,
    /// Channel sequence the last publish left the channel at.
    pub seq: u64,
    /// [`InitializeChannelPublisher::replayed_up_to`] of the last publisher initialized.
    pub replayed_up_to: Option<Slot>,
    /// [`FollowChannel::anchor`](crate::protocol::FollowChannel::anchor) of every follow, in
    /// order.
    pub follows: Vec<Option<ZoneAnchorRecord>>,
    /// The deposits the vault admits, by the bytes submitted; it refuses any other.
    pub admitted: Vec<(Vec<u8>, VaultMint)>,
    /// The deposits of every publish, in order.
    pub taken_in: Vec<Vec<u8>>,
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
            .returning({
                let channel = self.clone();
                move |msg: InitializeChannelPublisher, _ctx| {
                    let mut channel = channel.lock();
                    channel.replayed_up_to = msg.replayed_up_to;
                    Ok(Some(ChannelSeq::mocked(channel.seq)))
                }
            });
        mock.expect_handle_follow_channel().returning({
            let channel = self.clone();
            move |msg, _ctx| {
                channel.lock().follows.push(msg.anchor);
                Ok(())
            }
        });
        mock.expect_handle_check_channel_exists().returning({
            let channel = self.clone();
            move |_msg, _ctx| Ok(channel.lock().tip_slot.is_some())
        });
        mock.expect_handle_check_is_our_turn()
            .returning(|_msg, _ctx| Ok(true));
        mock.expect_handle_admit_deposit().returning({
            let channel = self.clone();
            move |msg, _ctx| {
                channel
                    .lock()
                    .admitted
                    .iter()
                    .find(|(deposit, _)| *deposit == msg.deposit)
                    .map(|(_, mint)| mint.clone())
                    .ok_or(Error::InvalidVaultDeposit(
                        "the canned vault does not know it",
                    ))
            }
        });
        mock.expect_handle_get_channel_tip_slot().returning({
            let channel = self.clone();
            move |_msg, _ctx| {
                let mut channel = channel.lock();
                if channel.failed_tip_slot_reads > 0 {
                    channel.failed_tip_slot_reads = channel.failed_tip_slot_reads.saturating_sub(1);
                    return Err(Error::NodeRequestFailed(anyhow!(
                        "the node is not ready yet"
                    )));
                }
                Ok(channel.tip_slot)
            }
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
        mock.expect_handle_filter_finally_absent().returning({
            let channel = self.clone();
            move |FilterFinallyAbsent { keys, .. }, _ctx| {
                Ok(keys
                    .difference(&channel.lock().pending_removals)
                    .copied()
                    .collect())
            }
        });
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
            move |CreateChannel { genesis, .. }, _ctx| channel.land(&genesis, None)
        });
        mock.expect_handle_publish_block().returning({
            let channel = self.clone();
            move |PublishBlock {
                      channel_id: _,
                      block,
                      parent,
                      expected_seq: _,
                      bridge,
                  },
                  _ctx| {
                let outcome = channel.publish(&block, parent)?;
                channel.lock().taken_in.extend(bridge.deposits);
                Ok(outcome)
            }
        });
        mock
    }

    /// Lands `block` unless it is chained on an entry that is no longer the tip, as L1 refuses
    /// it.
    fn publish(&self, block: &Block, parent: Option<MsgId>) -> Result<PublishOutcome> {
        let current = self.lock().tip;
        if let Some(parent) = parent
            && current.is_some_and(|current| current != parent)
        {
            return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                "Block {} is chained on an entry that is no longer the channel tip",
                block.header.block_id
            )));
        }
        self.land(block, parent)
    }

    /// Moves the channel tip to `block`, inscribed on `parent` or else on the tip, and reports
    /// what its publish produced.
    fn land(&self, block: &Block, parent: Option<MsgId>) -> Result<PublishOutcome> {
        let mut channel = self.lock();
        if channel.publish_fails {
            return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                "Canned publish failure for block {}",
                block.header.block_id
            )));
        }
        // The first publish creates the channel.
        channel.tip_slot.get_or_insert_with(|| Slot::from(0));
        let this_msg = mock_msg_of(block);
        let tip = channel.tip.replace(this_msg);
        let parent = parent.or(tip).unwrap_or_else(MsgId::root);
        channel.seq = channel.seq.saturating_add(1);
        Ok(PublishOutcome {
            this_msg,
            parent,
            checkpoint: checkpoint_at(this_msg),
            seq: ChannelSeq::mocked(channel.seq),
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
        finalized_config: MsgId::root(),
        funding: Vec::new(),
        program_notes: None,
    }
}

/// The entries of `messages` past `after` (exclusive), as `ReadChannel` serves them.
fn history_after(messages: &[(ZoneMessage, Slot)], after: Option<Slot>) -> ChannelReadStream {
    let messages: Vec<_> = messages
        .iter()
        .filter(|(_, slot)| after.is_none_or(|after| *slot > after))
        .cloned()
        .map(Ok)
        .collect();
    Box::pin(futures::stream::iter(messages))
}
