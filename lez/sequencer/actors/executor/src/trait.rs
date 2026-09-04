use common::{block::Block, transaction::LeeTransaction};
use kameo::{Actor, message::Message, reply::DelegatedReply};
use lee_core::{
    BlockId, CommitmentSetDigest, MembershipProof,
    account::{Balance, Nonce},
};

use crate::{
    Result,
    error::Error,
    protocol::{
        FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces, GetAccountReply, GetBlock,
        GetBlockRange, GetChannelId, GetChannelIdReply, GetCrossZoneDeadLetters,
        GetCrossZoneDeadLettersReply, GetFeeQuote, GetLastBlockId, GetProofsAndRoot,
        GetTransaction, ProduceBlock, RequeueCrossZoneDeadLetter, RequeueCrossZoneDeadLetterReply,
        Transaction,
    },
};

pub trait ExecutorActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<ProduceBlock, Reply = Result<()>>
    + Message<Transaction, Reply = Result<()>>
    + Message<GetBlock, Reply = Result<Option<Block>>>
    + Message<GetBlockRange, Reply = DelegatedReply<Result<Vec<Block>>>>
    + Message<GetLastBlockId, Reply = Result<BlockId>>
    + Message<GetAccountBalance, Reply = Balance>
    + Message<GetTransaction, Reply = Result<Option<(LeeTransaction, BlockId)>>>
    + Message<GetAccountNonces, Reply = Vec<Nonce>>
    + Message<GetProofsAndRoot, Reply = (Vec<Option<MembershipProof>>, CommitmentSetDigest)>
    + Message<GetAccount, Reply = GetAccountReply>
    + Message<GetChannelId, Reply = GetChannelIdReply>
    + Message<GetCrossZoneDeadLetters, Reply = Result<GetCrossZoneDeadLettersReply>>
    + Message<RequeueCrossZoneDeadLetter, Reply = Result<RequeueCrossZoneDeadLetterReply>>
    + Message<GetFeeQuote, Reply = FeeStateQuote>
{
}
