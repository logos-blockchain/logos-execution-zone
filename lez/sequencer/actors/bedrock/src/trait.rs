use std::collections::HashSet;

use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, ChannelReadStream, ChannelSeq, CheckChannelExists,
        CheckIsOurTurn, CreateChannel, GetAccreditedKeys, GetChannelNotes, GetChannelTipMessageId,
        GetChannelTipSlot, InitializeChannelPublisher, MsgId, NoteId, PrepareConfig, PreparePin,
        PreparedConfig, PreparedPin, PublishBlock, PublishOutcome, PublishPin, ReadChannel, Slot,
    },
};

pub trait BedrockActorTrait:
    Actor<Error = Error>
    + Message<InitializeChannelPublisher, Reply = Result<Option<ChannelSeq>>>
    + Message<CreateChannel, Reply = Result<PublishOutcome>>
    + Message<PublishBlock, Reply = Result<PublishOutcome>>
    + Message<PreparePin, Reply = Result<PreparedPin>>
    + Message<PublishPin, Reply = Result<PublishOutcome>>
    + Message<PrepareConfig, Reply = Result<PreparedConfig>>
    + Message<ChangeChannelConfig, Reply = Result<()>>
    + Message<CheckChannelExists, Reply = Result<bool>>
    + Message<CheckIsOurTurn, Reply = Result<bool>>
    + Message<GetAccreditedKeys, Reply = Result<Option<AccreditedKeys>>>
    + Message<GetChannelNotes, Reply = Result<HashSet<NoteId>>>
    + Message<GetChannelTipSlot, Reply = Result<Option<Slot>>>
    + Message<GetChannelTipMessageId, Reply = Result<Option<MsgId>>>
    + Message<ReadChannel, Reply = Result<ChannelReadStream>>
{
}
