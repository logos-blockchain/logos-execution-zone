//! Reads of the stored chain that take more than one lookup.

use common::{HashType, block::Block, transaction::LeeTransaction};
use kameo::actor::ActorRef;
use lee::AccountId;
use lee_core::BlockId;
use sequencer_core::storage::{
    CoreStorage,
    blocks::{AccountBlockKey, AccountBlockRecord, BlockIdByTransactionRecord, BlockRecord},
};
use sequencer_storage_actor::{encoding::BigEndian, protocol::Get, utils::Pages};

use crate::{Result, error::Error};

/// How many blocks of an account one read of the store returns.
const ACCOUNT_BLOCKS_PAGE: usize = 64;
/// The stored block holding the transaction `hash`, and the position of the transaction in it.
pub async fn block_with_transaction<S: CoreStorage>(
    storage_ref: &ActorRef<S>,
    hash: HashType,
) -> Result<Option<(Block, usize)>> {
    let Some(index) = storage_ref
        .ask(Get::<BlockIdByTransactionRecord>::new(hash))
        .await?
    else {
        return Ok(None);
    };
    let block = stored_block(storage_ref, index.block_id).await?.block;
    Ok(block
        .body
        .transactions
        .iter()
        .position(|transaction| transaction.hash() == hash)
        .map(|position| (block, position)))
}

/// Up to `limit` of the stored transactions affecting `account_id`, oldest first, after skipping
/// `offset` of them. `None` when no stored block affects the account.
pub async fn account_transactions<S: CoreStorage>(
    storage_ref: &ActorRef<S>,
    account_id: AccountId,
    offset: u64,
    limit: u64,
) -> Result<Option<Vec<LeeTransaction>>> {
    let mut transactions = Vec::new();
    let mut taken = 0_u64;
    let mut to_skip = offset;
    let mut any_block = false;
    let mut pages = Pages::<_, AccountBlockRecord>::new(
        storage_ref,
        Some(AccountBlockKey::new(account_id, 0)),
        Some(AccountBlockKey::new(account_id, BlockId::MAX)),
        ACCOUNT_BLOCKS_PAGE,
    );
    while let Some(entries) = pages.next().await? {
        any_block = true;
        for (_key, entry) in entries {
            let block = stored_block(storage_ref, entry.block_id).await?.block;
            for transaction in block.body.transactions {
                if !transaction
                    .affected_public_account_ids()
                    .contains(&account_id)
                {
                    continue;
                }
                if to_skip > 0 {
                    to_skip = to_skip.saturating_sub(1);
                    continue;
                }
                if taken >= limit {
                    return Ok(Some(transactions));
                }
                transactions.push(transaction);
                taken = taken.saturating_add(1);
            }
        }
    }
    Ok(any_block.then_some(transactions))
}

async fn stored_block<S: CoreStorage>(
    storage_ref: &ActorRef<S>,
    block_id: u64,
) -> Result<BlockRecord> {
    storage_ref
        .ask(Get::<BlockRecord>::new(BigEndian::new(&block_id)))
        .await?
        .ok_or_else(|| {
            Error::StorageInconsistency(format!("Index points to the absent block {block_id}"))
        })
}
