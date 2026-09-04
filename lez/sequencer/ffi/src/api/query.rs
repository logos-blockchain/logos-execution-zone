use std::ffi::{CString, c_char};

use sequencer_executor_actor::protocol::{
    BoundedRangeInclusive, GetAccount, GetBlock, GetBlockRange, GetLastBlockId, GetTransaction,
};

use crate::{
    SequencerServiceFFI,
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
/// `true`. An `Ok` result with `is_some == false` means the sequencer has no
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

    const fn some(block_id: u64) -> Self {
        Self {
            block_id,
            is_some: true,
            error: OperationStatus::Ok,
        }
    }
}

/// Query the last block id from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
///
/// # Returns
///
/// A [`LastBlockIdResult`] indicating success or failure. The block id is
/// returned inline; nothing needs to be freed.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_last_block(
    sequencer: *const SequencerServiceFFI,
) -> LastBlockIdResult {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return LastBlockIdResult::error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let last_block_id_resp = sequencer
        .runtime()
        .block_on(sequencer.executor_actor().ask(GetLastBlockId).send());

    last_block_id_resp.map_or_else(
        |e| {
            log::error!("Failed to query last block id: {e:#}");
            LastBlockIdResult::error(OperationStatus::ClientError)
        },
        |val| LastBlockIdResult::some(val),
    )
}

/// Query the sequencer's current sync status as a JSON C-string.
///
/// The JSON schema is owned by `sequencer_core` (`SequencerStatus`): an object with
/// `state` (`Starting`/`Syncing`/`CaughtUp`/`Error`/`Stalled`/`Halted`),
/// `indexed_block_id`, `last_error`, `stall_reason`, `cross_zone_halt`, and
/// `cross_zone_peers`. Each peer entry's `health` is one of
/// `Live`/`Lagging`/`Holed`/`Suspended`/`Halted`; treat a string you do not
/// know as not known healthy. Lets a client distinguish "still catching up"
/// from "something went wrong".
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
///
/// # Returns
///
/// A heap-allocated, null-terminated JSON string that the caller MUST free with
/// `free_cstring`. Returns null on error (null `sequencer` pointer or a
/// serialization failure).
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_status(sequencer: *const SequencerServiceFFI) -> *mut c_char {
    if sequencer.is_null() {
        log::error!(
            "Attempted to query status on a null sequencer pointer. This is a bug. Aborting."
        );
        return std::ptr::null_mut();
    }

    let json = match serde_json::to_string("Not yet supported") {
        Ok(json) => json,
        Err(e) => {
            log::error!("Failed to serialize sequencer status: {e}");
            return std::ptr::null_mut();
        }
    };

    CString::new(json).map_or_else(
        |e| {
            log::error!("Sequencer status JSON contained an interior nul byte: {e}");
            std::ptr::null_mut()
        },
        CString::into_raw,
    )
}

/// Query the block by id from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `block_id`: `u64` number of block id
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block(
    sequencer: *const SequencerServiceFFI,
    block_id: FfiBlockId,
) -> PointerResult<FfiBlockOpt, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let block_resp = sequencer
        .runtime()
        .block_on(sequencer.executor_actor().ask(GetBlock { block_id }).send());

    block_resp.map_or_else(
        |e| {
            log::error!("Failed to query block by id: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |block_opt| {
            let block_ffi = block_opt.map_or_else(FfiBlockOpt::from_none, |block| {
                FfiBlockOpt::from_value(block.into())
            });

            PointerResult::from_value(block_ffi)
        },
    )
}

/// Query the block by hash from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `hash`: `FfiHashType` - hash of block
///
/// # Returns
///
/// A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block_by_hash(
    sequencer: *const SequencerServiceFFI,
    _hash: FfiHashType,
) -> PointerResult<FfiBlockOpt, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    log::error!("Not supported yet");

    PointerResult::from_value(FfiBlockOpt::from_none())
}

/// Query the account by id from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `account_id`: `FfiAccountId` - id of queried account
///
/// # Returns
///
/// A `PointerResult<FfiAccount, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_account(
    sequencer: *const SequencerServiceFFI,
    account_id: FfiAccountId,
) -> PointerResult<FfiAccount, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let acc_resp = sequencer.runtime().block_on(
        sequencer
            .executor_actor()
            .ask(GetAccount {
                account_id: account_id.into(),
            })
            .send(),
    );

    acc_resp.map_or_else(
        |e| {
            log::error!("Failed to query account: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |account| PointerResult::from_value(account.account.into()),
    )
}

/// Query the transaction by hash from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `hash`: `FfiHashType` - hash of transaction
///
/// # Returns
///
/// A `PointerResult<FfiOption<FfiTransaction>, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_transaction(
    sequencer: *const SequencerServiceFFI,
    hash: FfiHashType,
) -> PointerResult<FfiOption<FfiTransaction>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let tx_resp = sequencer.runtime().block_on(
        sequencer
            .executor_actor()
            .ask(GetTransaction {
                tx_hash: hash.into(),
            })
            .send(),
    );

    tx_resp.map_or_else(
        |e| {
            log::error!("Failed to query transaction: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |tx_opt| {
            let tx_ffi = tx_opt.map_or_else(FfiOption::<FfiTransaction>::from_none, |(tx, _)| {
                FfiOption::<FfiTransaction>::from_value(tx.into())
            });

            PointerResult::from_value(tx_ffi)
        },
    )
}

/// Query the blocks by block range from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
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
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_block_vec(
    sequencer: *const SequencerServiceFFI,
    before: u64,
    limit: u64,
) -> PointerResult<FfiVec<FfiBlock>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let block_range_resp = sequencer.runtime().block_on(
        sequencer
            .executor_actor()
            .ask(GetBlockRange {
                range: BoundedRangeInclusive::try_from(before..=(before + limit)).unwrap(),
            })
            .send(),
    );

    block_range_resp.map_or_else(
        |e| {
            log::error!("Failed to query block batch: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |block_vec| {
            PointerResult::from_value(
                block_vec
                    .into_iter()
                    .map(|block| block.into())
                    .collect::<Vec<FfiBlock>>()
                    .into(),
            )
        },
    )
}

/// Query the transactions range by account id from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
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
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn query_transactions_by_account(
    sequencer: *const SequencerServiceFFI,
    _account_id: FfiAccountId,
    _offset: u64,
    _limit: u64,
) -> PointerResult<FfiVec<FfiTransaction>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    log::error!("Not supported yet");

    PointerResult::from_value(FfiVec::from(vec![]))
}

// ToDo: Current sequecner does not know about events yet

// #[unsafe(no_mangle)]
// pub unsafe extern "C" fn query_events(
//     sequencer: *const SequencerServiceFFI,
//     from_block: u64,
//     to_block: FfiOption<u64>,
//     tx_hash: *const FfiHashType,
//     program_id: *const FfiProgramId,
//     selector: *const FfiSelector,
// ) -> PointerResult<FfiVec<FfiEventRecord>, OperationStatus> {
//     if sequencer.is_null() {
//         log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
//         return PointerResult::from_error(OperationStatus::NullPointer);
//     }

//     let sequencer = unsafe { &*sequencer };
//     let program_id =
//         unsafe { program_id.as_ref() }.map(|id| sequencer_service_protocol::ProgramId(id.data));
//     let selector =
//         unsafe { selector.as_ref() }.map(|s| sequencer_service_protocol::Selector(s.data));

//     let records = if let Some(tx_hash) = unsafe { tx_hash.as_ref() } {
//         // Coverage is judged at the transaction's height, resolved BEFORE the events
//         // read: a filtered-out tx has no events row, and gating on the row's presence
//         // would serve an empty result for exactly the dropped domains.
//         match sequencer.core().store.block_id_by_tx_hash(tx_hash.data) {
//             Err(e) => Err(e),
//             Ok(None) => {
//                 log::error!("query_events: no indexed transaction has the requested hash");
//                 return PointerResult::from_error(OperationStatus::InvalidArgument);
//             }
//             Ok(Some(block_id)) => {
//                 if !sequencer_core::event_filter::covered_over_range(
//                     sequencer.core().store.filter_segments(),
//                     block_id,
//                     block_id,
//                     program_id.map(|id| id.0),
//                     selector.map(|s| s.0),
//                 ) {
//                     log::error!(
//                         "query_events: the requested events at block {block_id} are outside this
// \                          sequencer's event-filter history"
//                     );
//                     return PointerResult::from_error(OperationStatus::InvalidArgument);
//                 }
//                 sequencer
//                     .core()
//                     .store
//                     .get_events_for_block(block_id)
//                     .map(|row| {
//                         row.and_then(|groups| {
//                             groups
//                                 .into_iter()
//                                 .find(|group| group.tx_hash.0 == tx_hash.data)
//                         })
//                         .map(|group| EventRecord::from_tx_events(block_id, group))
//                         .unwrap_or_default()
//                     })
//             }
//         }
//     } else {
//         let tip = match sequencer.core().store.get_last_block_id() {
//             Ok(tip) => tip.unwrap_or(0),
//             Err(e) => {
//                 log::error!("Failed to read the indexed tip for query_events: {e:#}");
//                 return PointerResult::from_error(OperationStatus::ClientError);
//             }
//         };
//         if to_block.is_some && to_block.value.is_null() {
//             log::error!("query_events to_block is flagged present but its value pointer is
// null");             return PointerResult::from_error(OperationStatus::InvalidArgument);
//         }
//         let to_block = to_block.is_some.then(|| unsafe { *to_block.value });
//         let (from_block, to_block) = match sequencer_service_protocol::resolve_event_block_range(
//             from_block, to_block, tip,
//         ) {
//             Ok(range) => range,
//             Err(err) => {
//                 log::error!("query_events: {err}");
//                 return PointerResult::from_error(OperationStatus::InvalidArgument);
//             }
//         };
//         if !sequencer_core::event_filter::covered_over_range(
//             sequencer.core().store.filter_segments(),
//             from_block,
//             to_block,
//             program_id.map(|id| id.0),
//             selector.map(|s| s.0),
//         ) {
//             log::error!(
//                 "query_events: the requested events over blocks {from_block}..={to_block} are \
//                  outside this sequencer's event-filter history"
//             );
//             return PointerResult::from_error(OperationStatus::InvalidArgument);
//         }
//         sequencer
//             .core()
//             .store
//             .get_events_range(from_block, to_block)
//             .map(|groups| {
//                 groups
//                     .into_iter()
//                     .flat_map(|(block_id, groups)| {
//                         groups
//                             .into_iter()
//                             .flat_map(move |group| EventRecord::from_tx_events(block_id, group))
//                     })
//                     .collect::<Vec<_>>()
//             })
//     };

//     records.map_or_else(
//         |e| {
//             log::error!("Failed to query events: {e:#}");
//             PointerResult::from_error(OperationStatus::ClientError)
//         },
//         |records| {
//             PointerResult::from_value(
//                 records
//                     .into_iter()
//                     .filter(|record| record.matches_fields(program_id, selector))
//                     .map(Into::into)
//                     .collect::<Vec<FfiEventRecord>>()
//                     .into(),
//             )
//         },
//     )
// }
