#![expect(
    clippy::struct_field_names,
    reason = "`handle*` prefix is used for convenience with `Message` trait"
)]

use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
pub use sequencer_actors_common::mock::ReplaceReply;
use sharding_pool_actor::ShardingKey;

pub use self::canned_channel::{CannedChannel, SharedChannel, checkpoint_at, mock_msg_of};
use crate::{
    BedrockActorTrait, Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, ChannelId, ChannelSeq, CheckChannelExists,
        CheckIsOurTurn, CreateChannel, GetAccreditedKeys, GetChannelTipMessageId,
        GetChannelTipSlot, InitializeChannelPublisher, MsgId, PrepareConfig, PreparedConfig,
        PublishBlock, PublishOutcome, ReadChannel, Slot, ZoneMessage,
    },
};

mod canned_channel;

/// Special message to trigger mockall's checkpoint mechanism.
///
/// Carries `channel_id` to be routable through [`sharding_pool_actor::ShardingPoolActor`].
pub struct Checkpoint {
    pub channel_id: ChannelId,
}

impl ShardingKey for Checkpoint {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Special message to [`std::mem::replace()`] the mock serving `channel_id` with a new one,
/// returning the old one.
///
/// Carries `channel_id` to be routable through [`sharding_pool_actor::ShardingPoolActor`].
pub struct Replace {
    pub channel_id: ChannelId,
    pub mock: MockBedrockActor,
}

impl ShardingKey for Replace {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

mockall::mock! {
    pub BedrockActor {
        pub fn handle_initialize_channel_publisher(
            &mut self,
            msg: InitializeChannelPublisher,
            ctx: &mut Context<Self, Result<Option<ChannelSeq>>>
        ) -> Result<Option<ChannelSeq>>;

        pub fn handle_create_channel(
            &mut self,
            msg: CreateChannel,
            ctx: &mut Context<Self, Result<PublishOutcome>>
        ) -> Result<PublishOutcome>;

        pub fn handle_publish_block(
            &mut self,
            msg: PublishBlock,
            ctx: &mut Context<Self, Result<PublishOutcome>>
        ) -> Result<PublishOutcome>;

        pub fn handle_prepare_config(
            &mut self,
            msg: PrepareConfig,
            ctx: &mut Context<Self, Result<PreparedConfig>>
        ) -> Result<PreparedConfig>;

        pub fn handle_change_channel_config(
            &mut self,
            msg: ChangeChannelConfig,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_check_channel_exists(
            &mut self,
            msg: CheckChannelExists,
            ctx: &mut Context<Self, Result<bool>>
        ) -> Result<bool>;

        pub fn handle_check_is_our_turn(
            &mut self,
            msg: CheckIsOurTurn,
            ctx: &mut Context<Self, Result<bool>>
        ) -> Result<bool>;

        pub fn handle_get_accredited_keys(
            &mut self,
            msg: GetAccreditedKeys,
            ctx: &mut Context<Self, Result<Option<AccreditedKeys>>>
        ) -> Result<Option<AccreditedKeys>>;

        pub fn handle_get_channel_tip_slot(
            &mut self,
            msg: GetChannelTipSlot,
            ctx: &mut Context<Self, Result<Option<Slot>>>
        ) -> Result<Option<Slot>>;

        pub fn handle_get_channel_tip_message_id(
            &mut self,
            msg: GetChannelTipMessageId,
            ctx: &mut Context<Self, Result<Option<MsgId>>>
        ) -> Result<Option<MsgId>>;

        pub fn handle_read_channel(
            &mut self,
            msg: ReadChannel,
            ctx: &mut Context<Self, Result<BoxStream<(ZoneMessage, Slot)>>>
        ) -> Result<BoxStream<(ZoneMessage, Slot)>>;
    }
}

impl BedrockActorTrait for MockBedrockActor {}

impl Actor for MockBedrockActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }
}

impl Message<Checkpoint> for MockBedrockActor {
    type Reply = ();

    async fn handle(
        &mut self,
        Checkpoint { channel_id: _ }: Checkpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.checkpoint();
    }
}

impl Message<Replace> for MockBedrockActor {
    type Reply = ReplaceReply<Self>;

    async fn handle(
        &mut self,
        Replace {
            channel_id: _,
            mock,
        }: Replace,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
    }
}

impl Message<InitializeChannelPublisher> for MockBedrockActor {
    type Reply = Result<Option<ChannelSeq>>;

    async fn handle(
        &mut self,
        msg: InitializeChannelPublisher,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_initialize_channel_publisher(msg, ctx)
    }
}

impl Message<CreateChannel> for MockBedrockActor {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        msg: CreateChannel,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_create_channel(msg, ctx)
    }
}

impl Message<PublishBlock> for MockBedrockActor {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        msg: PublishBlock,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_publish_block(msg, ctx)
    }
}

impl Message<PrepareConfig> for MockBedrockActor {
    type Reply = Result<PreparedConfig>;

    async fn handle(
        &mut self,
        msg: PrepareConfig,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_prepare_config(msg, ctx)
    }
}

impl Message<ChangeChannelConfig> for MockBedrockActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: ChangeChannelConfig,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_change_channel_config(msg, ctx)
    }
}

impl Message<CheckChannelExists> for MockBedrockActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        msg: CheckChannelExists,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_check_channel_exists(msg, ctx)
    }
}

impl Message<CheckIsOurTurn> for MockBedrockActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        msg: CheckIsOurTurn,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_check_is_our_turn(msg, ctx)
    }
}

impl Message<GetAccreditedKeys> for MockBedrockActor {
    type Reply = Result<Option<AccreditedKeys>>;

    async fn handle(
        &mut self,
        msg: GetAccreditedKeys,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_accredited_keys(msg, ctx)
    }
}

impl Message<GetChannelTipSlot> for MockBedrockActor {
    type Reply = Result<Option<Slot>>;

    async fn handle(
        &mut self,
        msg: GetChannelTipSlot,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_tip_slot(msg, ctx)
    }
}

impl Message<GetChannelTipMessageId> for MockBedrockActor {
    type Reply = Result<Option<MsgId>>;

    async fn handle(
        &mut self,
        msg: GetChannelTipMessageId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_tip_message_id(msg, ctx)
    }
}

impl Message<ReadChannel> for MockBedrockActor {
    type Reply = Result<BoxStream<(ZoneMessage, Slot)>>;

    async fn handle(
        &mut self,
        msg: ReadChannel,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_read_channel(msg, ctx)
    }
}
