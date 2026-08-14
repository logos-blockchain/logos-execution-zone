#![expect(
    clippy::elidable_lifetime_names,
    clippy::manual_async_fn,
    reason = "Explicit futures preserve the lifetime and Send bounds required by the actor runtime"
)]

use std::{future::Future, time::Duration};

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
        }
    }
}

impl BlockPublisherTrait for MockBlockPublisher {
    // Tests assume this node is always the one bootstrapping the channel.
    fn channel_exists<'config>(
        _config: &'config BedrockConfig,
    ) -> impl Future<Output = Result<bool>> + Send + 'config {
        async move { Ok(false) }
    }

    fn new<'config>(
        config: &'config BedrockConfig,
        _bedrock_signing_key: Ed25519Key,
        _resubmit_interval: Duration,
        _initial_checkpoint: Option<SequencerCheckpoint>,
        _on_follow: OnFollowSink,
    ) -> impl Future<Output = Result<Self>> + Send + 'config {
        async move {
            Ok(Self {
                channel_id: config.channel_id,
                driver_cancellation: CancellationToken::new(),
                // An existing but empty channel: `None` means *missing*, which the
                // startup guard reads as a wiped Bedrock. Tests that want that say
                // so via [`Self::with_canned_channel`].
                tip_slot: Some(Slot::from(0)),
                messages: Vec::new(),
            })
        }
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

    fn publish_genesis_creating_channel<'publisher>(
        &'publisher self,
        block: &'publisher Block,
        _keys: Vec<Ed25519PublicKey>,
    ) -> impl Future<Output = Result<PublishOutcome>> + Send + 'publisher {
        async move { self.publish_block(block, Vec::new()).await }
    }

    fn accredited_keys(&self) -> impl Future<Output = Result<Vec<Ed25519PublicKey>>> + Send {
        async { Ok(Vec::new()) }
    }

    fn submit_channel_config(
        &self,
        _new_keys: Vec<Ed25519PublicKey>,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
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

    fn channel_tip_slot<'publisher>(
        &'publisher self,
    ) -> impl Future<Output = Result<Option<Slot>>> + Send + 'publisher {
        async move { Ok(self.tip_slot) }
    }

    fn read_channel_after<'publisher>(
        &'publisher self,
        after_slot: Option<Slot>,
    ) -> impl Future<Output = Result<impl Stream<Item = (ZoneMessage, Slot)> + Send + 'publisher>>
    + Send
    + 'publisher {
        async move {
            // Mirror `next_messages`: `after_slot` is exclusive.
            let messages = self
                .messages
                .iter()
                .filter(move |(_, slot)| after_slot.is_none_or(|after| *slot > after))
                .cloned();
            Ok(futures::stream::iter(messages))
        }
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
