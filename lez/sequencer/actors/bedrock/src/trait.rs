use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, GetAccreditedKeys, GetChannelTipMessageId, GetChannelTipSlot,
        InitializeChannelPublisher, MsgId, PublishBlock, PublishOutcome, ReadChannel, Slot,
        ZoneMessage,
    },
};

pub trait BedrockActorTrait:
    Actor<Error = Error>
    + Message<InitializeChannelPublisher, Reply = Result<bool>>
    + Message<CreateChannel, Reply = Result<PublishOutcome>>
    + Message<PublishBlock, Reply = Result<PublishOutcome>>
    + Message<ChangeChannelConfig, Reply = Result<()>>
    + Message<CheckChannelExists, Reply = Result<bool>>
    + Message<CheckIsOurTurn, Reply = Result<bool>>
    + Message<GetAccreditedKeys, Reply = Result<Option<AccreditedKeys>>>
    + Message<GetChannelTipSlot, Reply = Result<Option<Slot>>>
    + Message<GetChannelTipMessageId, Reply = Result<Option<MsgId>>>
    + Message<ReadChannel, Reply = Result<BoxStream<(ZoneMessage, Slot)>>>
{
}
