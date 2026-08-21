use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use common::block::Block;
use futures::Stream;
use logos_blockchain_core::{
    header::HeaderId,
    mantle::{
        ledger::{NoteId, Utxo},
        ops::channel::{ChannelId, Ed25519PublicKey, MsgId},
    },
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{Slot, ZoneMessage, sequencer::WithdrawArg};
use tokio_util::sync::CancellationToken;

use crate::{
    block_publisher::{BlockPublisherTrait, OnFollowSink, PublishOutcome, SequencerCheckpoint},
    config::BedrockConfig,
};

pub type SequencerCoreWithMockClients = crate::SequencerCore<MockBlockPublisher>;

#[derive(Clone)]
pub struct MockBlockPublisher {
    channel_id: ChannelId,
    // Never cancelled: the mock driver never dies.
    driver_cancellation: CancellationToken,
    /// Canned channel frontier returned by [`Self::channel_tip_slot`].
    tip_slot: Option<Slot>,
    /// Canned finalized channel history returned by [`Self::read_channel_after`].
    messages: Vec<(ZoneMessage, Slot)>,
    /// Canned signer; `None` means nothing can be attributed.
    inscription_signer: Option<Ed25519PublicKey>,
    /// Last entry a publish left the channel at, for the pinned-parent check.
    channel_tip: Arc<Mutex<Option<MsgId>>>,
    /// When set, fails every publish, as zone-sdk does for an atomic withdraw
    /// at this revision.
    publish_fails: Arc<AtomicBool>,
}

impl MockBlockPublisher {
    /// Builds a mock publisher backed by a canned channel, for reconstruction
    /// and consistency tests. The default (via [`BlockPublisherTrait::new`])
    /// serves an empty channel.
    #[must_use]
    pub fn with_canned_channel(
        channel_id: ChannelId,
        tip_slot: Option<Slot>,
        messages: Vec<(ZoneMessage, Slot)>,
    ) -> Self {
        Self {
            channel_id,
            driver_cancellation: CancellationToken::new(),
            tip_slot,
            messages,
            inscription_signer: None,
            channel_tip: Arc::new(Mutex::new(None)),
            publish_fails: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Attributes every inscription to `signer`.
    #[must_use]
    pub const fn with_inscription_signer(mut self, signer: Ed25519PublicKey) -> Self {
        self.inscription_signer = Some(signer);
        self
    }

    /// Makes every later publish fail.
    pub fn fail_publishes(&self) {
        self.publish_fails.store(true, Ordering::Relaxed);
    }

    /// Moves the canned channel tip, as an L1 reorg dropping inscriptions does.
    pub fn set_channel_tip(&self, tip: Option<MsgId>) {
        *self.channel_tip.lock().expect("channel tip lock poisoned") = tip;
    }

    /// Records `block` as the channel tip and reports what its publish produced.
    fn landed(&self, block: &Block, released_notes: Vec<NoteId>) -> Result<PublishOutcome> {
        anyhow::ensure!(
            !self.publish_fails.load(Ordering::Relaxed),
            "Canned publish failure for block {}",
            block.header.block_id
        );
        let this_msg = mock_msg_of(block);
        *self.channel_tip.lock().expect("channel tip lock poisoned") = Some(this_msg);
        Ok(PublishOutcome {
            this_msg,
            checkpoint: checkpoint_at(this_msg),
            released_notes,
        })
    }
}

impl BlockPublisherTrait for MockBlockPublisher {
    // Tests assume this node is always the one bootstrapping the channel.
    async fn channel_exists(_config: &BedrockConfig) -> Result<bool> {
        Ok(false)
    }

    async fn new(
        config: &BedrockConfig,
        _bedrock_signing_key: Ed25519Key,
        _resubmit_interval: Duration,
        _initial_checkpoint: Option<SequencerCheckpoint>,
        _on_follow: OnFollowSink,
    ) -> Result<Self> {
        Ok(Self {
            channel_id: config.channel_id,
            driver_cancellation: CancellationToken::new(),
            // An existing but empty channel: `None` means *missing*, which the
            // startup guard reads as a wiped Bedrock. Tests that want that say
            // so via [`Self::with_canned_channel`].
            tip_slot: Some(Slot::from(0)),
            messages: Vec::new(),
            inscription_signer: None,
            channel_tip: Arc::new(Mutex::new(None)),
            publish_fails: Arc::new(AtomicBool::new(false)),
        })
    }

    async fn publish_block(
        &self,
        block: &Block,
        withdrawals: Vec<WithdrawArg>,
    ) -> Result<PublishOutcome> {
        // Deterministic per-block id so head dedup behaves in tests.
        //
        // TODO: should we allow more "mockability" here?
        self.landed(block, mock_released_notes(&withdrawals))
    }

    /// Mirrors L1: the inscription only lands while `parent` is still the tip.
    async fn publish_block_chained_on(
        &self,
        block: &Block,
        parent: MsgId,
    ) -> Result<PublishOutcome> {
        let tip = *self.channel_tip.lock().expect("channel tip lock poisoned");
        anyhow::ensure!(
            tip.is_none_or(|tip| tip == parent),
            "Block {} is chained on an entry that is no longer the channel tip",
            block.header.block_id
        );
        self.landed(block, Vec::new())
    }

    async fn publish_genesis_creating_channel(
        &self,
        block: &Block,
        _keys: Vec<Ed25519PublicKey>,
    ) -> Result<PublishOutcome> {
        self.publish_block(block, Vec::new()).await
    }

    async fn accredited_keys(&self) -> Result<Option<(Vec<Ed25519PublicKey>, Slot)>> {
        Ok(self.tip_slot.map(|slot| (Vec::new(), slot)))
    }

    async fn submit_channel_config(&self, _new_keys: Vec<Ed25519PublicKey>) -> Result<()> {
        Ok(())
    }

    /// Whatever [`Self::with_inscription_signer`] canned.
    async fn inscription_signer(
        &self,
        _slot: Slot,
        _msg_id: MsgId,
    ) -> Result<Option<Ed25519PublicKey>> {
        Ok(self.inscription_signer)
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        true
    }

    fn driver_cancellation(&self) -> CancellationToken {
        self.driver_cancellation.clone()
    }

    async fn channel_tip_slot(&self) -> Result<Option<Slot>> {
        Ok(self.tip_slot)
    }

    async fn channel_tip_message(&self) -> Result<Option<MsgId>> {
        Ok(*self.channel_tip.lock().expect("channel tip lock poisoned"))
    }

    async fn read_channel_after(
        &self,
        after_slot: Option<Slot>,
    ) -> Result<impl Stream<Item = (ZoneMessage, Slot)> + Send + '_> {
        // Mirror `next_messages`: `after_slot` is exclusive.
        let messages = self
            .messages
            .iter()
            .filter(move |(_, slot)| after_slot.is_none_or(|after| *slot > after))
            .cloned();
        Ok(futures::stream::iter(messages))
    }
}

/// The notes the mock reports as released by `withdrawals`.
///
/// Zone-sdk picks the actual channel notes to release, so a mock has to invent
/// them: one note id per requested output, derived from the output itself so
/// tests can recompute the reconciliation keys of a block they produced.
#[must_use]
pub(crate) fn mock_released_notes(withdrawals: &[WithdrawArg]) -> Vec<NoteId> {
    withdrawals
        .iter()
        .flat_map(|withdraw| withdraw.outputs.into_iter().enumerate())
        .map(|(output_index, note)| Utxo::new([0; 32], output_index, *note).id())
        .collect()
}

/// The `MsgId` the mock assigns a published block: its hash, so tests can
/// recompute it. Real ids hash the inscription op (parent, payload, signer)
/// and change on re-inscription — never derivable from the block.
#[must_use]
pub(crate) fn mock_msg_of(block: &Block) -> MsgId {
    MsgId::from(block.header.hash.0)
}

/// A checkpoint reporting `tip` as the channel tip, as the sdk builds one for
/// each publish outcome and follow update.
#[must_use]
pub(crate) fn checkpoint_at(tip: MsgId) -> SequencerCheckpoint {
    SequencerCheckpoint {
        last_msg_id: tip,
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
    }
}

/// [`checkpoint_at`] a zeroed tip, for follow updates whose tests never
/// publish pinned on what they leave behind.
#[cfg(test)]
#[must_use]
pub(crate) fn mock_checkpoint() -> SequencerCheckpoint {
    checkpoint_at(MsgId::from([0; 32]))
}
