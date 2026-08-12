use std::ops::RangeInclusive;

use common::{HashType, transaction::LeeTransaction};
use kameo::Reply;
use lee_core::{
    BlockId, Commitment,
    account::{Account, AccountId},
};

#[derive(Copy, Clone)]
pub struct ProduceBlock;

pub struct Transaction {
    pub transaction: LeeTransaction,
}

pub struct GetBlock {
    pub block_id: BlockId,
}

pub struct GetBlockRange {
    pub range: RangeInclusive<BlockId>,
}

pub struct GetLastBlockId;

pub struct GetAccountBalance {
    pub account_id: AccountId,
}

pub struct GetTransaction {
    pub tx_hash: HashType,
}

pub struct GetAccountNonces {
    pub account_ids: Vec<AccountId>,
}

pub struct GetProofsAndRoot {
    pub commitments: Vec<Commitment>,
}

pub struct GetAccount {
    pub account_id: AccountId,
}

#[derive(Reply)]
pub struct GetAccountReply {
    pub account: Account,
}

pub struct GetChannelId;

#[derive(Reply)]
pub struct GetChannelIdReply {
    pub channel_id: [u8; 32],
}

pub struct GetCrossZoneDeadLetters;

#[derive(Reply)]
pub struct GetCrossZoneDeadLettersReply {
    pub total_retired: u64,
    pub retained: Vec<sequencer_storage_actor::protocol::DeadLetterDispatchRecord>,
}
