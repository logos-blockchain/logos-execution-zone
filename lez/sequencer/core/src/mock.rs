use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use common::block::Block;
use logos_blockchain_core::mantle::ops::channel::{ChannelId, MsgId};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::WithdrawArg;

use crate::{
    block_publisher::{
        BlockPublisherTrait, CheckpointSink, Ed25519PublicKey, FinalizedBlockSink,
        OnDepositEventSink, OnFollowSink, OnWithdrawEventSink, SequencerCheckpoint,
    },
    config::BedrockConfig,
};

pub type SequencerCoreWithMockClients = crate::SequencerCore<MockBlockPublisher>;

/// One recorded `configure_channel` invocation.
#[derive(Clone)]
pub struct ConfigureChannelCall {
    pub keys: Vec<Ed25519PublicKey>,
    pub posting_timeframe: u32,
    pub posting_timeout: u32,
    pub configuration_threshold: u16,
    pub withdraw_threshold: u16,
}

#[derive(Clone)]
pub struct MockBlockPublisher {
    channel_id: ChannelId,
    configure_channel_calls: Arc<Mutex<Vec<ConfigureChannelCall>>>,
}

impl MockBlockPublisher {
    #[must_use]
    pub fn configure_channel_calls(&self) -> Vec<ConfigureChannelCall> {
        self.configure_channel_calls
            .lock()
            .expect("mock mutex poisoned")
            .clone()
    }
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
            configure_channel_calls: Arc::default(),
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

    async fn configure_channel(
        &self,
        keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: u16,
        withdraw_threshold: u16,
    ) -> Result<()> {
        self.configure_channel_calls
            .lock()
            .expect("mock mutex poisoned")
            .push(ConfigureChannelCall {
                keys,
                posting_timeframe,
                posting_timeout,
                configuration_threshold,
                withdraw_threshold,
            });
        Ok(())
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        true
    }
}
