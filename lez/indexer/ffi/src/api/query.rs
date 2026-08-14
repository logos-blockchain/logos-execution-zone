use std::ffi::{CString, c_char};

use indexer_service_protocol::AccountId;

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

/// Result of [`query_last_block`], returned **inline** (no heap allocation, so
/// there is no corresponding `free_*` to call).
///
/// `block_id` is only meaningful when `error` is `Ok` *and* `is_some` is
/// `true`. An `Ok` result with `is_some == false` means the indexer has no
/// finalized block yet (an empty chain) — which is distinct from an error.
#[repr(C)]
pub struct LastBlockIdResult {
    pub block_id: u64,
    pub is_some: bool,
    pub error: OperationStatus,
}

impl LastBlockIdResult {
    const fn error(error: OperationStatus) -> Self {
        Self {
            block_id: 0,
            is_some: false,
            error,
        }
    }

    const fn none() -> Self {
        Self {
            block_id: 0,
            is_some: false,
            error: OperationStatus::Ok,
        }
    }

    const fn some(block_id: u64) -> Self {
        Self {
            block_id,
            is_some: true,
            error: OperationStatus::Ok,
        }
    }
}

/// Query the last block id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
///
/// # Returns
///
/// A [`LastBlockIdResult`] indicating success or failure. The block id is
/// returned inline; nothing needs to be freed.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_last_block(indexer: *const IndexerServiceFFI) -> LastBlockIdResult {
    if indexer.is_null() {
        log::error!("Attempted to query a null indexer pointer. This is a bug. Aborting.");
        return LastBlockIdResult::error(OperationStatus::NullPointer);
    }

    let indexer = unsafe { &*indexer };

    indexer.core().store.get_last_block_id().map_or_else(
        |e| {
            log::error!("Failed to query last block id: {e:#}");
            LastBlockIdResult::error(OperationStatus::ClientError)
        },
        |opt| opt.map_or_else(LastBlockIdResult::none, LastBlockIdResult::some),
    )
}

/// Query the indexer's current sync status as a JSON C-string.
///
/// The JSON schema is owned by `indexer_core` (`IndexerStatus`): an object with
/// `state` (`Starting`/`Syncing`/`CaughtUp`/`Error`/`Stalled`/`Halted`),
/// `indexed_block_id`, `last_error`, `stall_reason`, `cross_zone_halt`, and
/// `cross_zone_peers`. Lets a client distinguish "still catching up" from
/// "something went wrong".
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
///
/// # Returns
///
/// A heap-allocated, null-terminated JSON string that the caller MUST free with
/// `free_cstring`. Returns null on error (null `indexer` pointer or a
/// serialization failure).
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_status(indexer: *const IndexerServiceFFI) -> *mut c_char {
    if indexer.is_null() {
        log::error!(
            "Attempted to query status on a null indexer pointer. This is a bug. Aborting."
        );
        return std::ptr::null_mut();
    }

    let indexer = unsafe { &*indexer };
    let status = indexer.core().status();

    let json = match serde_json::to_string(&status) {
        Ok(json) => json,
        Err(e) => {
            log::error!("Failed to serialize indexer status: {e}");
            return std::ptr::null_mut();
        }
    };

    CString::new(json).map_or_else(
        |e| {
            log::error!("Indexer status JSON contained an interior nul byte: {e}");
            std::ptr::null_mut()
        },
        CString::into_raw,
    )
}

/// Query the block by id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
/// - `block_id`: `u64` number of block id
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    indexer.core().store.get_block_at_id(block_id).map_or_else(
        |e| {
            log::error!("Failed to query block by id: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |block_opt| {
            let block_ffi = block_opt.map_or_else(FfiBlockOpt::from_none, |block| {
                let block: indexer_service_protocol::Block = block.into();
                FfiBlockOpt::from_value(block.into())
            });

            PointerResult::from_value(block_ffi)
        },
    )
}

/// Query the block by hash from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
/// - `hash`: `FfiHashType` - hash of block
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    indexer
        .core()
        .store
        .get_block_by_hash(hash.data)
        .map_or_else(
            |e| {
                log::error!("Failed to query block by hash: {e:#}");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |block_opt| {
                let block_ffi = block_opt.map_or_else(FfiBlockOpt::from_none, |block| {
                    let block: indexer_service_protocol::Block = block.into();
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
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
/// - `account_id`: `FfiAccountId` - id of queried account
///
/// # Returns
///
/// A `PointerResult<FfiAccount, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    // `account_current_state` is the only async store call; drive it on the
    // runtime the indexer was started on.
    let account_id = AccountId {
        value: account_id.data,
    };
    indexer
        .runtime()
        .block_on(
            indexer
                .core()
                .store
                .account_current_state(&account_id.into()),
        )
        .map_or_else(
            |e| {
                log::error!("Failed to query account: {e:#}");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |account| PointerResult::from_value(account.into()),
        )
}

/// Query the transaction by hash from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
/// - `hash`: `FfiHashType` - hash of transaction
///
/// # Returns
///
/// A `PointerResult<FfiOption<FfiTransaction>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    indexer
        .core()
        .store
        .get_transaction_by_hash(hash.data)
        .map_or_else(
            |e| {
                log::error!("Failed to query transaction: {e:#}");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |tx_opt| {
                let tx_ffi = tx_opt.map_or_else(FfiOption::<FfiTransaction>::from_none, |tx| {
                    let tx: indexer_service_protocol::Transaction = tx.into();
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
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
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
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    let before_std = before.is_some.then(|| unsafe { *before.value });

    indexer
        .core()
        .store
        .get_block_batch(before_std, limit)
        .map_or_else(
            |e| {
                log::error!("Failed to query block batch: {e:#}");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |block_vec| {
                PointerResult::from_value(
                    block_vec
                        .into_iter()
                        .map(|block| {
                            let block: indexer_service_protocol::Block = block.into();
                            block.into()
                        })
                        .collect::<Vec<FfiBlock>>()
                        .into(),
                )
            },
        )
}

/// Query the transactions range by account id from indexer.
///
/// # Arguments
///
/// - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
/// - `account_id`: `FfiAccountId` - id of queried account
/// - `offset`: `u64` - first tx id of query
/// - `limit`: `u64` - number of tx ids to query after `offset`
///
/// # Returns
///
/// A `PointerResult<FfiVec<FfiTransaction>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
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

    indexer
        .core()
        .store
        .get_transactions_by_account(account_id.data, offset, limit)
        .map_or_else(
            |e| {
                log::error!("Failed to query transactions by account: {e:#}");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |tx_vec| {
                PointerResult::from_value(
                    tx_vec
                        .into_iter()
                        .map(|tx| {
                            let tx: indexer_service_protocol::Transaction = tx.into();
                            tx.into()
                        })
                        .collect::<Vec<FfiTransaction>>()
                        .into(),
                )
            },
        )
}
