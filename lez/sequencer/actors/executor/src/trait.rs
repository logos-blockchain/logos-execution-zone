use common::{block::Block, transaction::LeeTransaction};
use kameo::{Actor, message::Message, reply::DelegatedReply};
use lee_core::{
    BlockId, EncryptedNote, MembershipProof,
    account::{Balance, Nonce},
    program::Publication,
};

use crate::{
    Result,
    error::Error,
    protocol::{
        ChannelId, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces, GetAccountReply,
        GetAccountView, GetBlock, GetBlockRange, GetChannelId, GetCrossZoneDeadLetters,
        GetCrossZoneDeadLettersReply, GetFeeQuote, GetLastBlockId, GetMessagePath,
        GetProofsAndRoot, GetPublications, GetRecoveryBinding, GetTransaction, ProduceBlock,
        ProofsAndRoot, RequeueCrossZoneDeadLetter, RequeueCrossZoneDeadLetterReply, Transaction,
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
    + Message<GetProofsAndRoot, Reply = ProofsAndRoot>
    + Message<GetAccount, Reply = GetAccountReply>
    + Message<GetAccountView, Reply = GetAccountReply>
    + Message<GetPublications, Reply = Vec<(u64, Publication)>>
    + Message<GetMessagePath, Reply = Option<MembershipProof>>
    + Message<GetRecoveryBinding, Reply = Option<EncryptedNote>>
    + Message<GetChannelId, Reply = Result<ChannelId>>
    + Message<GetCrossZoneDeadLetters, Reply = Result<GetCrossZoneDeadLettersReply>>
    + Message<RequeueCrossZoneDeadLetter, Reply = Result<RequeueCrossZoneDeadLetterReply>>
    + Message<GetFeeQuote, Reply = FeeStateQuote>
{
}
