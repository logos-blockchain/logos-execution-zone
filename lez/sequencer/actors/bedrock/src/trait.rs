use std::collections::{BTreeSet, HashSet};

use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, CheckChannelExists, CheckIsOurTurn, CreateChannel,
        FilterFinallyAbsent, FollowChannel, FollowStart, GetAccreditedKeys, GetChannelNotes,
        GetChannelTipMessageId, GetChannelTipSlot, InitializeChannelPublisher, MsgId, NoteId,
        PendingBlock, PrepareConfig, PreparePin, PreparedConfig, PreparedPin, PublishBlock,
        PublishOutcome, PublishPin, SequencerKey, Slot,
    },
};

pub trait BedrockActorTrait:
    Actor<Error = Error>
    + Message<FollowChannel, Reply = Result<FollowStart>>
    + Message<InitializeChannelPublisher, Reply = Result<Vec<PendingBlock>>>
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
    + Message<FilterFinallyAbsent, Reply = Result<BTreeSet<SequencerKey>>>
{
}
