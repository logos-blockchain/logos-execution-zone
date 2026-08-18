use std::time::Duration;

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
        }
    }

    /// Attributes every inscription to `signer`.
    #[must_use]
    pub const fn with_inscription_signer(mut self, signer: Ed25519PublicKey) -> Self {
        self.inscription_signer = Some(signer);
        self
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
        })
    }

    async fn publish_block<'blk, 'pbl: 'blk>(
        &'pbl self,
        block: &'blk Block,
        withdrawals: Vec<WithdrawArg>,
    ) -> Result<PublishOutcome> {
        // Deterministic per-block id so head dedup behaves in tests.
        //
        // TODO: should we allow more "mockability" here?
        Ok(PublishOutcome {
            this_msg: MsgId::from(block.header.hash.0),
            checkpoint: mock_checkpoint(),
            released_notes: mock_released_notes(&withdrawals),
        })
    }

    async fn publish_genesis_creating_channel(
        &self,
        block: &Block,
        _keys: Vec<Ed25519PublicKey>,
    ) -> Result<PublishOutcome> {
        self.publish_block(block, Vec::new()).await
    }

    async fn accredited_keys(&self) -> Result<Vec<Ed25519PublicKey>> {
        Ok(Vec::new())
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

    async fn read_channel_after(
        &self,
        after_slot: Option<Slot>,
    ) -> Result<impl Stream<Item = (ZoneMessage, Slot)> + '_> {
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

/// A zeroed checkpoint, for [`MockBlockPublisher::publish_block`] and for tests
/// building a [`crate::block_publisher::FollowUpdate`]. Tests only assert *that*
/// a checkpoint was persisted alongside its effects, never what is in it.
#[must_use]
pub(crate) fn mock_checkpoint() -> SequencerCheckpoint {
    SequencerCheckpoint {
        last_msg_id: MsgId::from([0; 32]),
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
    }
}
