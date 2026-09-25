use sequencer_executor_actor::protocol::{
    BoundedRangeInclusive, GetAccount, GetAccountTransactions, GetBlock, GetBlockByHash,
    GetBlockRange, GetLastBlockId, GetStatus, GetTransaction, MAX_BLOCK_RANGE_LEN, Transaction,
    TransactionOrigin,
};
use sequencer_storage_actor::{
    actor::event_filter::{EventRecord, MAX_EVENT_QUERY_RESPONSE_BYTES, Selector, record_charge},
    protocol::{GetBlockEvents, GetEventFilter, GetTxHashToBlockIdMapItem},
};

use crate::{
    SequencerServiceFFI,
    api::{
        PointerResult,
        types::{
            FfiAccountId, FfiBlockId, FfiHashType, FfiOption, FfiSelector, FfiSequencerStatus,
            FfiVec,
            account::FfiAccount,
            block::{FfiBlock, FfiBlockOpt},
            event::FfiEventRecord,
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
pub unsafe extern "C" fn sequencer_ffi_query_last_block(
    sequencer: *const SequencerServiceFFI,
) -> LastBlockIdResult {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return LastBlockIdResult::error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let last_block_id_resp = sequencer
        .runtime()
        .block_on(sequencer.executor_ref().ask(GetLastBlockId).send());

    last_block_id_resp.map_or_else(
        |e| {
            log::error!("Failed to query last block id: {e:#}");
            LastBlockIdResult::error(OperationStatus::ClientError)
        },
        |val| {
            if val == 0 {
                LastBlockIdResult::none()
            } else {
                LastBlockIdResult::some(val)
            }
        },
    )
}

/// Query the sequencer's current sync status.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
///
/// # Returns
///
/// A `PointerResult<FfiSequencerStatus, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_query_status(
    sequencer: *const SequencerServiceFFI,
) -> PointerResult<FfiSequencerStatus, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let status_reply = sequencer
        .runtime()
        .block_on(sequencer.executor_ref().ask(GetStatus).send());

    status_reply.map_or_else(
        |e| {
            log::error!("Failed to get status from sequencer: {e:?}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |reply| {
            let reply_res = reply.try_into();
            reply_res.map_or_else(
                |_| PointerResult::from_error(OperationStatus::ClientError),
                PointerResult::from_value,
            )
        },
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
pub unsafe extern "C" fn sequencer_ffi_query_block(
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
        .block_on(sequencer.executor_ref().ask(GetBlock { block_id }).send());

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
pub unsafe extern "C" fn sequencer_ffi_query_block_by_hash(
    sequencer: *const SequencerServiceFFI,
    hash: FfiHashType,
) -> PointerResult<FfiBlockOpt, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let map_resp = sequencer
        .runtime()
        .block_on(
            sequencer
                .executor_ref()
                .ask(GetBlockByHash {
                    block_hash: hash.into(),
                })
                .send(),
        )
        .inspect_err(|e| {
            log::error!("Failed to query block by id: {e:#}");
        });

    let block_id = if let Ok(map_opt) = map_resp {
        if let Some(block_id) = map_opt {
            block_id
        } else {
            return PointerResult::from_value(FfiBlockOpt::from_none());
        }
    } else {
        return PointerResult::from_error(OperationStatus::ClientError);
    };

    unsafe { sequencer_ffi_query_block(sequencer, block_id) }
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
pub unsafe extern "C" fn sequencer_ffi_query_account(
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
            .executor_ref()
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

/// Send transaction into sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `tx`: `FfiTransaction` object
///
/// # Returns
///
/// A `PointerResult<u8, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_send_transaction(
    sequencer: *const SequencerServiceFFI,
    transaction: FfiTransaction,
) -> PointerResult<u8, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let lee_tx_res = transaction.try_into();
    if lee_tx_res.is_err() {
        return PointerResult::from_error(lee_tx_res.err().unwrap());
    }
    let lee_tx = lee_tx_res.unwrap();

    let tx_resp = sequencer.runtime().block_on(
        sequencer
            .executor_ref()
            .ask(Transaction {
                transaction: lee_tx,
                origin: TransactionOrigin::User,
            })
            .send(),
    );

    tx_resp.map_or_else(
        |e| {
            log::error!("Failed to query transaction: {e:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        // Not really the most intuitive example of an FFI.
        // Written this way to satisfy `PointerResult` semantics,
        // it is assumed, that `PointerResult::from_value` must produce a valid pointer to
        // somewhere. The issue is that there is no natural representation for ZSTs(in this
        // case `()`) in C. Any FFI type will take as much place as u8, so there is no
        // point in hiding anything here. ToDo: Update, if `Transaction` message for
        // `ExecutorActor` will get non-`()` response.
        |()| PointerResult::from_value(0_u8),
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
pub unsafe extern "C" fn sequencer_ffi_query_transaction(
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
            .executor_ref()
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
pub unsafe extern "C" fn sequencer_ffi_query_block_vec(
    sequencer: *const SequencerServiceFFI,
    before: FfiOption<u64>,
    limit: u64,
) -> PointerResult<FfiVec<FfiBlock>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let before_opt = before.is_some.then(|| unsafe { before.value.read() });

    let before_limit = if let Some(before_val) = before_opt {
        before_val
    } else {
        let last_block_res = unsafe { sequencer_ffi_query_last_block(sequencer) };
        if last_block_res.error.is_ok() && last_block_res.is_some {
            last_block_res.block_id
        } else {
            log::error!("Failed to get last block in block_vec query. Aborting");
            return PointerResult::from_error(OperationStatus::ClientError);
        }
    };

    if limit > u64::try_from(MAX_BLOCK_RANGE_LEN).expect("1024 must fit into u64") {
        log::error!("Limit is too big in block_vec query. Aborting");
        return PointerResult::from_error(OperationStatus::ClientError);
    }

    let left_bound = if before_limit.saturating_sub(limit) != 0 {
        before_limit.saturating_sub(limit)
    } else {
        1
    };

    let block_range_resp = sequencer.runtime().block_on(
        sequencer
            .executor_ref()
            .ask(GetBlockRange {
                range: BoundedRangeInclusive::try_from(left_bound..=before_limit)
                    .expect("Previous checks ensure that range fits the limit"),
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
                    .map(Into::into)
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
pub unsafe extern "C" fn sequencer_ffi_query_transactions_by_account(
    sequencer: *const SequencerServiceFFI,
    account_id: FfiAccountId,
    offset: u64,
    limit: u64,
) -> PointerResult<FfiVec<FfiTransaction>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let tx_range_resp = sequencer.runtime().block_on(
        sequencer
            .executor_ref()
            .ask(GetAccountTransactions {
                account_id: account_id.into(),
                offset,
                limit,
            })
            .send(),
    );

    match tx_range_resp {
        Ok(tx_range_opt) => tx_range_opt.map_or_else(
            || {
                log::error!("Account not found for account to block id map");
                PointerResult::from_error(OperationStatus::ClientError)
            },
            |tx_range| {
                PointerResult::from_value(
                    tx_range
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                        .into(),
                )
            },
        ),
        Err(err) => {
            log::error!("Failed to query account to block map: {err:#}");
            PointerResult::from_error(OperationStatus::ClientError)
        }
    }
}

/// Query the block id by transaction hash from sequencer.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `hash`: `FfiHashType` - hash of a transaction
///
/// # Returns
///
/// A `PointerResult<u64, OperationStatus>` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_query_block_by_tx_hash(
    sequencer: *const SequencerServiceFFI,
    tx_hash: FfiHashType,
) -> PointerResult<u64, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };

    let map_resp = sequencer
        .runtime()
        .block_on(
            sequencer
                .storage_ref()
                .ask(GetTxHashToBlockIdMapItem {
                    tx_hash: tx_hash.into(),
                })
                .send(),
        )
        .inspect_err(|e| {
            log::error!("Failed to query block by id: {e:#}");
        });

    map_resp.map_or_else(
        |_| {
            log::error!("query_block_by_tx_hash: db failure");
            PointerResult::from_error(OperationStatus::ClientError)
        },
        |map_opt| {
            map_opt.map_or_else(
                || {
                    log::error!("query_block_by_tx_hash: block for this block id does not exist");
                    PointerResult::from_error(OperationStatus::InvalidArgument)
                },
                PointerResult::from_value,
            )
        },
    )
}

/// Frees the resources associated with the query for block id by transaction hash.
///
/// # Arguments
///
/// - `val`: Valid pointer into `u64`, received from `sequencer_ffi_query_block_by_tx_hash` as a
///   `PointerResult.value`
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid pointer into `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_free_query_block_id_by_transaction(val: *mut u64) {
    if val.is_null() {
        log::error!("Attempted to free a null pointer. This is a bug. Aborting.");
        return;
    }

    let boxed_val = unsafe { Box::from_raw(val) };
    drop(boxed_val);
}

/// Query events emitted by programs, optionally filtered.
///
/// Resolution mirrors the `getEvents` RPC: a non-null `tx_hash` makes this a point
/// lookup and the block range is ignored; otherwise the range from `from_block` to
/// `to_block` (defaulting to the current tip when none) is read, capped at
/// `MAX_EVENT_QUERY_BLOCK_SPAN` blocks, returning `InvalidArgument` when the span is
/// exceeded or a bound is past the sequencer's tip.
/// `program_account_id` and `selector` are exact-match filters applied to the result.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
/// - `from_block`: Inclusive range start, ignored when `tx_hash` is non-null.
/// - `to_block`: `FfiOption<u64>` - inclusive range end; none means the current tip. Ignored when
///   `tx_hash` is non-null.
/// - `tx_hash`: Optional transaction hash; null means absent.
/// - `program_account_id`: Optional emitting-program filter; null means absent.
/// - `selector`: Optional event-selector filter; null means absent.
///
/// # Returns
///
/// A [`PointerResult`] holding an `FfiVec<FfiEventRecord>` that the caller MUST free
/// with `free_ffi_event_record_vec`, or an error status.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
/// - if `to_block.is_some`, its `value` points to a valid `u64`.
/// - each of `tx_hash`, `program_account_id` and `selector` is either null or a valid pointer to
///   its respective type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_query_events(
    sequencer: *const SequencerServiceFFI,
    from_block: u64,
    to_block: FfiOption<u64>,
    tx_hash: *const FfiHashType,
    program_account_id: *const FfiAccountId,
    selector: *const FfiSelector,
) -> PointerResult<FfiVec<FfiEventRecord>, OperationStatus> {
    if sequencer.is_null() {
        log::error!("Attempted to query a null sequencer pointer. This is a bug. Aborting.");
        return PointerResult::from_error(OperationStatus::NullPointer);
    }

    let sequencer = unsafe { &*sequencer };
    let program_account_id = unsafe { program_account_id.as_ref() }.map(|id| id.data);
    let selector = unsafe { selector.as_ref() }.map(|s| Selector(s.data));

    let event_filter_res = sequencer
        .runtime()
        .block_on(sequencer.storage_ref().ask(GetEventFilter).send())
        .inspect_err(|e| {
            log::error!("Failed to query block by id: {e:#}");
        });

    let Ok(event_filter) = event_filter_res else {
        log::error!("GetEventFilter: query failed");
        return PointerResult::from_error(OperationStatus::ClientError);
    };

    let records = if let Some(tx_hash) = unsafe { tx_hash.as_ref() } {
        // Coverage is judged at the transaction's height, resolved BEFORE the events
        // read: a filtered-out tx has no events row, and gating on the row's presence
        // would serve an empty result for exactly the dropped domains.
        let block_id_res = unsafe { sequencer_ffi_query_block_by_tx_hash(sequencer, *tx_hash) };
        if block_id_res.error.is_error() {
            log::error!("query_events: no indexed transaction has the requested hash");
            return PointerResult::from_error(OperationStatus::ClientError);
        }
        let block_id = unsafe { block_id_res.value.read() };

        if !sequencer_storage_actor::actor::event_filter::covered_over_range(
            &[(event_filter, block_id)],
            block_id,
            block_id,
            program_account_id.map(lee::AccountId::new),
            selector.map(|s| s.0),
        ) {
            log::error!(
                "query_events: the requested events over blocks {block_id} are outside this \
                 sequencer's event-filter history"
            );
            return PointerResult::from_error(OperationStatus::InvalidArgument);
        }

        if let Ok(block_events) = sequencer
            .runtime()
            .block_on(
                sequencer
                    .storage_ref()
                    .ask(GetBlockEvents { block_id })
                    .send(),
            )
            .inspect_err(|e| {
                log::error!("Failed to query block by id: {e:#}");
            })
            .map(|row| {
                row.and_then(|groups| {
                    groups
                        .into_iter()
                        .find(|group| group.tx_hash.0 == tx_hash.data)
                })
                .map(|group| EventRecord::from_tx_events(block_id, group))
                .unwrap_or_default()
            })
        {
            block_events
        } else {
            return PointerResult::from_error(OperationStatus::ClientError);
        }
    } else {
        let tip_res = unsafe { sequencer_ffi_query_last_block(sequencer) };

        let tip = if tip_res.is_some && tip_res.error.is_ok() {
            tip_res.block_id
        } else {
            log::error!("Failed to read the indexed tip for query_events");
            return PointerResult::from_error(OperationStatus::ClientError);
        };

        if to_block.is_some && to_block.value.is_null() {
            log::error!("query_events to_block is flagged present but its value pointer is null");
            return PointerResult::from_error(OperationStatus::InvalidArgument);
        }
        let to_block = to_block.is_some.then(|| unsafe { *to_block.value });
        let (from_block, to_block) =
            match sequencer_storage_actor::actor::event_filter::resolve_event_block_range(
                from_block, to_block, tip,
            ) {
                Ok(range) => range,
                Err(err) => {
                    log::error!("query_events: {err:?}");
                    return PointerResult::from_error(OperationStatus::InvalidArgument);
                }
            };
        if !sequencer_storage_actor::actor::event_filter::covered_over_range(
            (from_block..=to_block)
                .map(|block_id| (event_filter.clone(), block_id))
                .collect::<Vec<_>>()
                .as_slice(),
            from_block,
            to_block,
            program_account_id.map(lee::AccountId::new),
            selector.map(|s| s.0),
        ) {
            log::error!(
                "query_events: the requested events over blocks {from_block}..={to_block} are \
                 outside this sequencer's event-filter history"
            );
            return PointerResult::from_error(OperationStatus::InvalidArgument);
        }

        let mut events_range = vec![];
        let mut cumulative_events_size: usize = 0;

        for block_id in from_block..=to_block {
            let Ok(block_events) = sequencer
                .runtime()
                .block_on(
                    sequencer
                        .storage_ref()
                        .ask(GetBlockEvents { block_id })
                        .send(),
                )
                .inspect_err(|e| {
                    log::error!("Failed to query events by block id: {e:#}");
                })
                .map(|row| {
                    row.unwrap_or_default()
                        .into_iter()
                        .flat_map(|group_events| {
                            EventRecord::from_tx_events(block_id, group_events)
                        })
                        .collect::<Vec<_>>()
                })
            else {
                return PointerResult::from_error(OperationStatus::ClientError);
            };

            cumulative_events_size = cumulative_events_size.saturating_add(
                block_events
                    .iter()
                    .fold(0, |acc, x| acc.saturating_add(record_charge(x))),
            );

            if cumulative_events_size > MAX_EVENT_QUERY_RESPONSE_BYTES {
                return PointerResult::from_error(OperationStatus::ResponseTooBig);
            }

            events_range.extend(block_events);
        }

        events_range
    };

    PointerResult::from_value(
        records
            .into_iter()
            .filter(|record| {
                record.matches_fields(program_account_id.map(lee::AccountId::new), selector)
            })
            .map(Into::into)
            .collect::<Vec<FfiEventRecord>>()
            .into(),
    )
}
