use std::collections::HashSet;

use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, ChannelReadStream, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, GetAccreditedKeys, GetChannelId, GetChannelIdReply, GetChannelNotes,
        GetChannelTipMessageId, GetChannelTipSlot, MsgId, NoteId, PrepareConfig, PreparePin,
        PreparedChannelConfig, PreparedPin, PublishBlock, PublishOutcome, PublishPin, ReadChannel,
        Slot,
    },
};

pub trait BedrockActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<CreateChannel, Reply = Result<PublishOutcome>>
    + Message<PublishBlock, Reply = Result<PublishOutcome>>
    + Message<PreparePin, Reply = Result<PreparedPin>>
    + Message<PublishPin, Reply = Result<PublishOutcome>>
    + Message<PrepareConfig, Reply = Result<PreparedChannelConfig>>
    + Message<ChangeChannelConfig, Reply = Result<()>>
    + Message<CheckChannelExists, Reply = Result<bool>>
    + Message<GetChannelId, Reply = GetChannelIdReply>
    + Message<CheckIsOurTurn, Reply = bool>
    + Message<GetAccreditedKeys, Reply = Result<Option<AccreditedKeys>>>
    + Message<GetChannelNotes, Reply = HashSet<NoteId>>
    + Message<GetChannelTipSlot, Reply = Result<Option<Slot>>>
    + Message<GetChannelTipMessageId, Reply = Result<Option<MsgId>>>
    + Message<ReadChannel, Reply = Result<ChannelReadStream>>
{
}
