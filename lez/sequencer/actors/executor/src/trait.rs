use common::{block::Block, transaction::LeeTransaction};
use kameo::{Actor, message::Message, reply::DelegatedReply};
use lee::Account;
use lee_core::{
    BlockId, CommitmentSetDigest, MembershipProof,
    account::{Balance, Nonce},
};
use sequencer_actors_common::Reply;

use crate::{
    Result,
    error::Error,
    protocol::{
        ChannelId, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces, GetBlock,
        GetBlockRange, GetChannelId, GetCrossZoneDeadLetters, GetCrossZoneDeadLettersReply,
        GetFeeQuote, GetLastBlockId, GetProofsAndRoot, GetTransaction, ProduceBlock,
        RequeueCrossZoneDeadLetter, RequeueCrossZoneDeadLetterReply, Transaction,
    },
};

pub trait ExecutorActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<ProduceBlock, Reply = Result<()>>
    + Message<Transaction, Reply = Result<()>>
    + Message<GetBlock, Reply = Result<Option<Block>>>
    + Message<GetBlockRange, Reply = DelegatedReply<Result<Vec<Block>>>>
    + Message<GetLastBlockId, Reply = Result<BlockId>>
    + Message<GetAccountBalance, Reply = Result<Balance>>
    + Message<GetTransaction, Reply = Result<Option<(LeeTransaction, BlockId)>>>
    + Message<GetAccountNonces, Reply = Result<Vec<Nonce>>>
    + Message<GetProofsAndRoot, Reply = Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest)>>
    + Message<GetAccount, Reply = Result<Account>>
    + Message<GetChannelId, Reply = Reply<ChannelId>>
    + Message<GetCrossZoneDeadLetters, Reply = Result<GetCrossZoneDeadLettersReply>>
    + Message<RequeueCrossZoneDeadLetter, Reply = Result<RequeueCrossZoneDeadLetterReply>>
    + Message<GetFeeQuote, Reply = Result<FeeStateQuote>>
{
}
