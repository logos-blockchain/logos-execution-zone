use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, ChannelSeq, CheckChannelExists,
        CheckIsOurTurn, CreateChannel, GetAccreditedKeys, GetChannelTipMessageId,
        GetChannelTipSlot, InitializeChannelPublisher, MsgId, PrepareConfig, PreparedConfig,
        PublishBlock, PublishOutcome, ReadChannel, Slot, ZoneMessage,
    },
};

pub trait BedrockActorTrait:
    Actor<Error = Error>
    + Message<InitializeChannelPublisher, Reply = Result<Option<ChannelSeq>>>
    + Message<CreateChannel, Reply = Result<PublishOutcome>>
    + Message<PublishBlock, Reply = Result<PublishOutcome>>
    + Message<PrepareConfig, Reply = Result<PreparedConfig>>
    + Message<ChangeChannelConfig, Reply = Result<()>>
    + Message<CheckChannelExists, Reply = Result<bool>>
    + Message<CheckIsOurTurn, Reply = Result<bool>>
    + Message<GetAccreditedKeys, Reply = Result<Option<AccreditedKeys>>>
    + Message<GetChannelTipSlot, Reply = Result<Option<Slot>>>
    + Message<GetChannelTipMessageId, Reply = Result<Option<MsgId>>>
    + Message<ReadChannel, Reply = Result<BoxStream<(ZoneMessage, Slot)>>>
{
}
