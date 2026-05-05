use indexer_service_protocol::{AccountId, HashType};
use indexer_service_rpc::RpcClient as _;

use crate::{
    IndexerServiceFFI,
    api::{
        PointerResult,
        types::{
            FfiAccountId, FfiBlockId, FfiHashType, FfiOption, FfiVec,
            account::FfiAccount,
            block::{FfiBlock, FfiBlockOpt},
            transaction::FfiTransaction,
        },
    },
    errors::OperationStatus,
};

/// Query the last block id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
///
/// # Returns
///
/// A `PointerResult<u64, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_last_block(
    indexer: *const IndexerServiceFFI,
) -> PointerResult<u64, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_last_finalized_block_id())
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            PointerResult::from_value,
        )
}

/// Query the block by id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `block_id`: `u64` number of block id
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block(
    indexer: *const IndexerServiceFFI,
    block_id: FfiBlockId,
) -> PointerResult<FfiBlockOpt, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_block_by_id(block_id))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |block_opt| {
                let block_ffi = block_opt.map_or_else(FfiBlockOpt::from_none, |block| {
                    FfiBlockOpt::from_value(block.into())
                });

                PointerResult::from_value(block_ffi)
            },
        )
}

/// Query the block by id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `hash`: `FfiHashType` - hash of block
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block_by_hash(
    indexer: *const IndexerServiceFFI,
    hash: FfiHashType,
) -> PointerResult<FfiBlockOpt, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_block_by_hash(HashType(hash.data)))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |block_opt| {
                let block_ffi = block_opt.map_or_else(FfiBlockOpt::from_none, |block| {
                    FfiBlockOpt::from_value(block.into())
                });

                PointerResult::from_value(block_ffi)
            },
        )
}

/// Query the account by id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `account_id`: `FfiAccountId` - id of queried account
///
/// # Returns
///
/// A `PointerResult<FfiAccount, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_account(
    indexer: *const IndexerServiceFFI,
    account_id: FfiAccountId,
) -> PointerResult<FfiAccount, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_account(AccountId {
            value: account_id.data,
        }))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |acc| {
                let acc_nssa: nssa::Account =
                    acc.try_into().expect("Source is in blocks, must fit");
                PointerResult::from_value(acc_nssa.into())
            },
        )
}

/// Query the trasnaction by hash from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `hash`: `FfiHashType` - hash of transaction
///
/// # Returns
///
/// A `PointerResult<FfiOption<FfiTransaction>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_transaction(
    indexer: *const IndexerServiceFFI,
    hash: FfiHashType,
) -> PointerResult<FfiOption<FfiTransaction>, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_transaction(HashType(hash.data)))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |tx_opt| {
                let tx_ffi = tx_opt.map_or_else(FfiOption::<FfiTransaction>::from_none, |tx| {
                    FfiOption::<FfiTransaction>::from_value(tx.into())
                });

                PointerResult::from_value(tx_ffi)
            },
        )
}

/// Query the blocks by block range from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `before`: `FfiOption<u64>` - end block of query
/// - `limit`: `u64` - number of blocks to query before `before`
///
/// # Returns
///
/// A `PointerResult<FfiVec<FfiBlock>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block_vec(
    indexer: *const IndexerServiceFFI,
    before: FfiOption<u64>,
    limit: u64,
) -> PointerResult<FfiVec<FfiBlock>, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    let before_std = before.is_some.then(|| unsafe { *before.value });

    runtime
        .block_on(client.get_blocks(before_std, limit))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |block_vec| {
                PointerResult::from_value(
                    block_vec
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                        .into(),
                )
            },
        )
}

/// Query the transactions range by account id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be queried.
/// - `account_id`: `FfiAccountId` - id of queried account
/// - `offset`: `u64` - first tx id of query
/// - `limit`: `u64` - number of tx ids to query after `offset`
///
/// # Returns
///
/// A `PointerResult<FfiVec<FfiBlock>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_transactions_by_account(
    indexer: *const IndexerServiceFFI,
    account_id: FfiAccountId,
    offset: u64,
    limit: u64,
) -> PointerResult<FfiVec<FfiTransaction>, OperationStatus> {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    let client = unsafe { indexer.client() };
    let runtime = unsafe { indexer.runtime() };

    runtime
        .block_on(client.get_transactions_by_account(
            AccountId {
                value: account_id.data,
            },
            offset,
            limit,
        ))
        .map_or_else(
            |_| PointerResult::from_error(OperationStatus::ClientError),
            |tx_vec| {
                PointerResult::from_value(
                    tx_vec
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                        .into(),
                )
            },
        )
}
