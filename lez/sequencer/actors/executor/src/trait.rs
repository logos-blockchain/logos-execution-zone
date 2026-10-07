use common::{block::Block, transaction::LeeTransaction};
use kameo::{Actor, message::Message, reply::DelegatedReply};
use lee::Account;
use lee_core::{
    BlockId, CommitmentPosition, EncryptedNote, MembershipProof,
    account::{Balance, Nonce},
    program::Publication,
};
use sequencer_actors_common::Reply;

use crate::{
    Result,
    error::Error,
    protocol::{
        ChannelId, ExecutorStatus, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces,
        GetAccountView, GetBlock, GetBlockRange, GetChannelId, GetCrossZoneDeadLetters,
        GetCrossZoneDeadLettersReply, GetFeeQuote, GetLastBlockId, GetMessagePath,
        GetProofsAndRoot, GetProofsAndRootReply, GetPublications, GetRecoveryBinding, GetStatus,
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
    + Message<GetAccountBalance, Reply = Result<Balance>>
    + Message<GetTransaction, Reply = Result<Option<(LeeTransaction, BlockId)>>>
    + Message<GetAccountNonces, Reply = Result<Vec<Nonce>>>
    + Message<GetProofsAndRoot, Reply = Result<GetProofsAndRootReply>>
    + Message<GetAccount, Reply = Result<Option<Account>>>
    + Message<GetAccountView, Reply = Result<Option<Account>>>
    + Message<GetPublications, Reply = Result<Vec<(CommitmentPosition, Publication)>>>
    + Message<GetMessagePath, Reply = Result<Option<MembershipProof>>>
    + Message<GetRecoveryBinding, Reply = Result<Option<EncryptedNote>>>
    + Message<GetChannelId, Reply = Reply<ChannelId>>
    + Message<GetStatus, Reply = ExecutorStatus>
    + Message<GetCrossZoneDeadLetters, Reply = Result<GetCrossZoneDeadLettersReply>>
    + Message<RequeueCrossZoneDeadLetter, Reply = Result<RequeueCrossZoneDeadLetterReply>>
    + Message<GetFeeQuote, Reply = Result<FeeStateQuote>>
{
}
