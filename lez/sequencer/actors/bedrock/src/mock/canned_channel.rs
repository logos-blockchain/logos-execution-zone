//! A [`MockBedrockActor`] serving a canned channel.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::anyhow;
use common::block::Block;
use logos_blockchain_core::mantle::ledger::{Inputs, NoteId, Utxo};

use super::MockBedrockActor;
use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChannelReadStream, ChannelSeq, CreateChannel, HeaderId, MsgId, PreparePin,
        PreparedPin, PublishBlock, PublishOutcome, PublishPin, ReadChannel, SequencerCheckpoint,
        Slot, WithdrawArg, ZoneMessage,
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
    /// Fails every pin before it is funded.
    pub prepare_pin_fails: bool,
    /// Fails every pin once it is signed.
    pub publish_pin_fails: bool,
    /// Channel notes on the current branch, the ones a publish may pin.
    pub channel_notes: HashSet<NoteId>,
    /// The deposit notes each publish pinned, in publish order.
    pub pins: Arc<Mutex<Vec<Vec<NoteId>>>>,
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
        mock.expect_handle_get_channel_notes().returning({
            let channel = self.clone();
            move |_msg, _ctx| Ok(channel.lock().channel_notes.clone())
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
                let outcome = channel.publish(&block, parent, mock_released_notes(&withdrawals))?;
                channel.record_pin(Vec::new());
                Ok(outcome)
            }
        });
        let prepared = Arc::new(Mutex::new(HashMap::new()));
        mock.expect_handle_prepare_pin().returning({
            let channel = self.clone();
            let prepared = Arc::clone(&prepared);
            move |PreparePin {
                      channel_id: _,
                      block,
                      parent,
                      notes,
                      expected_seq: _,
                  },
                  _ctx| {
                let (prepare_pin_fails, channel_notes) = {
                    let channel = channel.lock();
                    (channel.prepare_pin_fails, channel.channel_notes.clone())
                };
                if prepare_pin_fails {
                    return Err(Error::DepositPinAssemblyFailed(anyhow!(
                        "Canned pin failure for block {}",
                        block.header.block_id
                    )));
                }
                if let Some(missing) = notes.iter().find(|note| !channel_notes.contains(note)) {
                    return Err(Error::DepositNoteNotOnBranch(*missing));
                }
                // Bedrock's own bound on the transfer's inputs.
                Inputs::try_new(notes.clone())
                    .map_err(|err| Error::DepositPinAssemblyFailed(anyhow!("{err:?}")))?;
                let msg_id = mock_msg_of(&block);
                prepared
                    .lock()
                    .expect("prepared pins lock poisoned")
                    .insert(msg_id, (block, notes));
                Ok(PreparedPin::mocked(msg_id, parent))
            }
        });
        mock.expect_handle_publish_pin().returning({
            let channel = self.clone();
            move |PublishPin {
                      channel_id: _,
                      prepared: pin,
                      signatures: _,
                      expected_seq: _,
                  },
                  _ctx| {
                let (block, notes) = prepared
                    .lock()
                    .expect("prepared pins lock poisoned")
                    .remove(&pin.msg_id())
                    .expect("only a prepared pin is published");
                if channel.lock().publish_pin_fails {
                    return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                        "Canned pin publish failure for block {}",
                        block.header.block_id
                    )));
                }
                let outcome = channel.publish(&block, Some(pin.parent()), Vec::new())?;
                channel.record_pin(notes);
                Ok(outcome)
            }
        });
        mock
    }

    /// Lands `block` unless it is chained on an entry that is no longer the tip, as L1 refuses
    /// it.
    fn publish(
        &self,
        block: &Block,
        parent: Option<MsgId>,
        released_notes: Vec<NoteId>,
    ) -> Result<PublishOutcome> {
        let current = self.lock().tip;
        if let Some(parent) = parent
            && current.is_some_and(|current| current != parent)
        {
            return Err(Error::SubmitSignedTransactionFailed(anyhow!(
                "Block {} is chained on an entry that is no longer the channel tip",
                block.header.block_id
            )));
        }
        self.land(block, parent, released_notes)
    }

    /// Records the deposit notes a landed publish pinned.
    fn record_pin(&self, notes: Vec<NoteId>) {
        let pins = Arc::clone(&self.lock().pins);
        pins.lock().expect("pins lock poisoned").push(notes);
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
        funding: Vec::new(),
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
