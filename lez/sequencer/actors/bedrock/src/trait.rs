use std::collections::BTreeSet;

use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, ChannelReadStream, ChannelSeq, CheckChannelExists,
        CheckIsOurTurn, CreateChannel, FilterFinallyAbsent, FollowChannel, GetAccreditedKeys,
        GetChannelTipMessageId, GetChannelTipSlot, InitializeChannelPublisher, MsgId,
        PrepareConfig, PreparedConfig, PublishBlock, PublishOutcome, ReadChannel, SequencerKey,
        Slot,
    },
};

pub trait BedrockActorTrait:
    Actor<Error = Error>
    + Message<FollowChannel, Reply = Result<()>>
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
    + Message<ReadChannel, Reply = Result<ChannelReadStream>>
    + Message<FilterFinallyAbsent, Reply = Result<BTreeSet<SequencerKey>>>
{
}
