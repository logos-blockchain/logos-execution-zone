use std::ops::RangeInclusive;

use common::{HashType, transaction::LeeTransaction};
use kameo::Reply;
use lee_core::{
    BlockId, Commitment,
    account::{Account, AccountId},
};

/// The widest range a [`GetBlockRange`] may span.
pub const MAX_BLOCK_RANGE_LEN: usize = 1024;

#[derive(Copy, Clone)]
pub struct ProduceBlock;

pub struct Transaction {
    pub transaction: LeeTransaction,
}

pub struct GetBlock {
    pub block_id: BlockId,
}

pub struct GetBlockRange {
    pub range: BoundedRangeInclusive<{ MAX_BLOCK_RANGE_LEN }, BlockId>,
}

pub struct BoundedRangeInclusive<const N: usize, T>(RangeInclusive<T>);

#[derive(Debug, thiserror::Error)]
pub enum BoundedRangeInclusiveError<const N: usize, T> {
    #[error("Range goes backwards: start {start:?}, end {end:?}")]
    RangeGoesBackwards { start: T, end: T },

    #[error("Range is too large: max length is {N}")]
    RangeTooLarge,
}

impl<const N: usize, T> BoundedRangeInclusive<N, T> {
    pub fn into_inner(self) -> RangeInclusive<T> {
        self.0
    }
}

impl<const N: usize, T: Copy + num_traits::CheckedSub + TryInto<usize>> TryFrom<RangeInclusive<T>>
    for BoundedRangeInclusive<N, T>
{
    type Error = BoundedRangeInclusiveError<N, T>;

    fn try_from(range: RangeInclusive<T>) -> Result<Self, Self::Error> {
        let (start, end) = range.into_inner();

        let len = end
            .checked_sub(&start)
            .ok_or(BoundedRangeInclusiveError::RangeGoesBackwards { start, end })?
            .try_into()
            .map_err(|_err| BoundedRangeInclusiveError::RangeTooLarge)?;

        if len > N.saturating_sub(1) {
            return Err(BoundedRangeInclusiveError::RangeTooLarge);
        }

        Ok(Self(RangeInclusive::new(start, end)))
    }
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
