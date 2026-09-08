use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, BoxStream, ChangeChannelConfig, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, GetAccreditedKeys, GetChannelId, GetChannelIdReply, GetChannelTipMessageId,
        GetChannelTipSlot, MsgId, PublishBlock, PublishOutcome, ReadChannel, Slot, ZoneMessage,
    },
};

pub trait BedrockActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<CreateChannel, Reply = Result<PublishOutcome>>
    + Message<PublishBlock, Reply = Result<PublishOutcome>>
    + Message<ChangeChannelConfig, Reply = Result<()>>
    + Message<CheckChannelExists, Reply = Result<bool>>
    + Message<GetChannelId, Reply = GetChannelIdReply>
    + Message<CheckIsOurTurn, Reply = bool>
    + Message<GetAccreditedKeys, Reply = Result<Option<AccreditedKeys>>>
    + Message<GetChannelTipSlot, Reply = Result<Option<Slot>>>
    + Message<GetChannelTipMessageId, Reply = Result<Option<MsgId>>>
    + Message<ReadChannel, Reply = Result<BoxStream<(ZoneMessage, Slot)>>>
{
}
