use std::time::Duration;

use anyhow::Result;
use common::block::Block;
use logos_blockchain_core::mantle::ops::channel::{ChannelId, MsgId};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::WithdrawArg;

use crate::{
    block_publisher::{
        BlockPublisherTrait, CheckpointSink, FinalizedBlockSink, OnDepositEventSink, OnFollowSink,
        OnWithdrawEventSink, SequencerCheckpoint,
    },
    config::BedrockConfig,
};

pub type SequencerCoreWithMockClients = crate::SequencerCore<MockBlockPublisher>;

#[derive(Clone)]
pub struct MockBlockPublisher {
    channel_id: ChannelId,
}

impl BlockPublisherTrait for MockBlockPublisher {
    async fn new(
        config: &BedrockConfig,
        _bedrock_signing_key: Ed25519Key,
        _resubmit_interval: Duration,
        _initial_checkpoint: Option<SequencerCheckpoint>,
        _on_checkpoint: CheckpointSink,
        _on_finalized_block: FinalizedBlockSink,
        _on_deposit_event: OnDepositEventSink,
        _on_withdraw_event: OnWithdrawEventSink,
        _on_follow: OnFollowSink,
    ) -> Result<Self> {
        Ok(Self {
            channel_id: config.channel_id,
        })
    }

    async fn publish_block(
        &self,
        block: &Block,
        _bridge_withdrawals: Vec<WithdrawArg>,
    ) -> Result<MsgId> {
        // Deterministic per-block id so head dedup behaves in tests.
        //
        // TODO: should we allow more "mockability" here?
        Ok(MsgId::from(block.header.hash.0))
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        true
    }
}
