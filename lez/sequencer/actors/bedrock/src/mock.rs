#![expect(
    clippy::struct_field_names,
    reason = "`handle*` prefix is used for convenience with `Message` trait"
)]

use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
pub use sequencer_actors_common::mock::{Checkpoint, Replace, ReplaceReply};

use crate::{
    BedrockActorTrait, Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, GetAccreditedKeys, GetChannelId, GetChannelIdReply, GetChannelTipMessageId,
        GetChannelTipSlot, MsgId, PublishBlock, PublishOutcome, ReadChannel, Slot, ZoneMessage,
    },
};

mockall::mock! {
    pub BedrockActor {
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

        pub fn handle_get_channel_id(
            &mut self,
            msg: GetChannelId,
            ctx: &mut Context<Self, GetChannelIdReply>
        ) -> GetChannelIdReply;

        pub fn handle_check_is_our_turn(
            &mut self,
            msg: CheckIsOurTurn,
            ctx: &mut Context<Self, bool>
        ) -> bool;

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
        Checkpoint: Checkpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.checkpoint();
    }
}

impl Message<Replace<Self>> for MockBedrockActor {
    type Reply = ReplaceReply<Self>;

    async fn handle(
        &mut self,
        Replace { mock }: Replace<Self>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
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

impl Message<GetChannelId> for MockBedrockActor {
    type Reply = GetChannelIdReply;

    async fn handle(
        &mut self,
        msg: GetChannelId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_id(msg, ctx)
    }
}

impl Message<CheckIsOurTurn> for MockBedrockActor {
    type Reply = bool;

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
