#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * FFI-owned sequencer.
 *
 * - `handle`: a [`SequencerHandle`] owning every actor the sequencer runs.
 * - `runtime`: the [`Runtime`] used to run async queries against the node (either owned or
 *   borrowed), already FFI-safe.
 */
typedef struct SequencerServiceFFI {
  void *handle;
  Runtime runtime;
} SequencerServiceFFI;

typedef PointerResult<SequencerServiceFFI, OperationStatus> InitializedSequencerServiceFFIResult;

/**
 * Result of [`query_last_block`], returned **inline** (no heap allocation, so
 * there is no corresponding `free_*` to call).
 *
 * `block_id` is only meaningful when `error` is `Ok` *and* `is_some` is
 * `true`. An `Ok` result with `is_some == false` means the sequencer has no
 * finalized block yet (an empty chain) — which is distinct from an error.
 */
typedef struct LastBlockIdResult {
  uint64_t block_id;
  bool is_some;
  OperationStatus error;
} LastBlockIdResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Creates and starts an sequencer based on the provided
 * configuration file path.
 *
 * # Arguments
 *
 * - `runtime`: A runtime for the sequencer to run on, or null to have the sequencer create and own
 *   one.
 * - `config_path`: A pointer to a string representing the path to the configuration file.
 *
 * # Returns
 *
 * An `InitializedSequencerServiceFFIResult` containing either a pointer to the
 * initialized `SequencerServiceFFI` or an error code.
 *
 * # Safety
 * The caller must ensure that:
 * - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
 * - `config_path` is a valid pointer to a null-terminated C string.
 */
InitializedSequencerServiceFFIResult sequencer_ffi_start_sequencer(const Runtime *runtime,
                                                                   const char *config_path);

/**
 * Stops and frees the resources associated with the given sequencer service.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the `SequencerServiceFFI` instance to be stopped.
 *
 * # Returns
 *
 * An `OperationStatus` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a `SequencerServiceFFI` instance
 * - The `SequencerServiceFFI` instance was created by this library
 * - The pointer will not be used after this function returns
 */
OperationStatus sequencer_ffi_stop_sequencer(struct SequencerServiceFFI *sequencer);

/**
 * Initializes logging for the sequencer at `level`.
 *
 * - `level` is a null-terminated string (`off`/`error`/`warn`/`info`/`debug`/ `trace`,
 *   case-insensitive); null or unparseable falls back to `info`.
 *
 * Only the `sequencer_ffi` and `sequencer_core` targets are enabled!
 *
 * # Safety
 * - `level` must be a valid null-terminated C string, or null.
 * - First call to this function wins; subsequent calls are no-ops.
 */
void sequencer_ffi_init_logger(const char *level);

/**
 * Query the last block id from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 *
 * # Returns
 *
 * A [`LastBlockIdResult`] indicating success or failure. The block id is
 * returned inline; nothing needs to be freed.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
struct LastBlockIdResult sequencer_ffi_query_last_block(const struct SequencerServiceFFI *sequencer);

/**
 * Query the sequencer's current sync status as a JSON C-string.
 *
 * The JSON schema is owned by `sequencer_core` (`SequencerStatus`): an object with
 * `state` (`Starting`/`Syncing`/`CaughtUp`/`Error`/`Stalled`/`Halted`),
 * `indexed_block_id`, `last_error`, `stall_reason`, `cross_zone_halt`, and
 * `cross_zone_peers`. Each peer entry's `health` is one of
 * `Live`/`Lagging`/`Holed`/`Suspended`/`Halted`; treat a string you do not
 * know as not known healthy. Lets a client distinguish "still catching up"
 * from "something went wrong".
 *
 * Not supporded yet.
 *
 * TODO: Add support. Needs database modifications.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 *
 * # Returns
 *
 * A heap-allocated, null-terminated JSON string that the caller MUST free with
 * `free_cstring`. Returns null on error (null `sequencer` pointer or a
 * serialization failure).
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
char *sequencer_ffi_query_status(const struct SequencerServiceFFI *sequencer);

/**
 * Query the block by id from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `block_id`: `u64` number of block id
 *
 * # Returns
 *
 * A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiBlockOpt, OperationStatus> sequencer_ffi_query_block(const struct SequencerServiceFFI *sequencer,
                                                                      FfiBlockId block_id);

/**
 * Query the block by hash from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `hash`: `FfiHashType` - hash of block
 *
 * # Returns
 *
 * A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiBlockOpt, OperationStatus> sequencer_ffi_query_block_by_hash(const struct SequencerServiceFFI *sequencer,
                                                                              FfiHashType hash);

/**
 * Query the account by id from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `account_id`: `FfiAccountId` - id of queried account
 *
 * # Returns
 *
 * A `PointerResult<FfiAccount, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiAccount, OperationStatus> sequencer_ffi_query_account(const struct SequencerServiceFFI *sequencer,
                                                                       FfiAccountId account_id);

/**
 * Send transaction into sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `tx`: `FfiTransaction` object
 *
 * # Returns
 *
 * A `PointerResult<u8, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<uint8_t, OperationStatus> sequencer_ffi_send_transaction(const struct SequencerServiceFFI *sequencer,
                                                                       FfiTransaction transaction);

/**
 * Query the transaction by hash from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `hash`: `FfiHashType` - hash of transaction
 *
 * # Returns
 *
 * A `PointerResult<FfiOption<FfiTransaction>, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiOption<FfiTransaction>, OperationStatus> sequencer_ffi_query_transaction(const struct SequencerServiceFFI *sequencer,
                                                                                          FfiHashType hash);

/**
 * Query the blocks by block range from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `before`: `FfiOption<u64>` - end block of query
 * - `limit`: `u64` - number of blocks to query before `before`
 *
 * # Returns
 *
 * A `PointerResult<FfiVec<FfiBlock>, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiVec<FfiBlock>, OperationStatus> sequencer_ffi_query_block_vec(const struct SequencerServiceFFI *sequencer,
                                                                               FfiOption<uint64_t> before,
                                                                               uint64_t limit);

/**
 * Query the transactions range by account id from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `account_id`: `FfiAccountId` - id of queried account
 * - `offset`: `u64` - first tx id of query
 * - `limit`: `u64` - number of tx ids to query after `offset`
 *
 * # Returns
 *
 * A `PointerResult<FfiVec<FfiTransaction>, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<FfiVec<FfiTransaction>, OperationStatus> sequencer_ffi_query_transactions_by_account(const struct SequencerServiceFFI *sequencer,
                                                                                                   FfiAccountId account_id,
                                                                                                   uint64_t offset,
                                                                                                   uint64_t limit);

/**
 * Query the block id by transaction hash from sequencer.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `hash`: `FfiHashType` - hash of a transaction
 *
 * # Returns
 *
 * A `PointerResult<u64, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 */
PointerResult<uint64_t, OperationStatus> sequencer_ffi_query_block_by_tx_hash(const struct SequencerServiceFFI *sequencer,
                                                                              FfiHashType tx_hash);

/**
 * Frees the resources associated with the query for block id by transaction hash.
 *
 * # Arguments
 *
 * - `val`: Valid pointer into `u64`, received from `sequencer_ffi_query_block_by_tx_hash` as a
 *   `PointerResult.value`
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a valid pointer into `u64`.
 */
void sequencer_ffi_free_query_block_id_by_transaction(uint64_t *val);

/**
 * Query events emitted by programs, optionally filtered.
 *
 * Resolution mirrors the `getEvents` RPC: a non-null `tx_hash` makes this a point
 * lookup and the block range is ignored; otherwise the range from `from_block` to
 * `to_block` (defaulting to the current tip when none) is read, capped at
 * `MAX_EVENT_QUERY_BLOCK_SPAN` blocks, returning `InvalidArgument` when the span is
 * exceeded or a bound is past the sequencer's tip.
 * `program_account_id` and `selector` are exact-match filters applied to the result.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the [`SequencerServiceFFI`] instance to be queried.
 * - `from_block`: Inclusive range start, ignored when `tx_hash` is non-null.
 * - `to_block`: `FfiOption<u64>` - inclusive range end; none means the current tip. Ignored when
 *   `tx_hash` is non-null.
 * - `tx_hash`: Optional transaction hash; null means absent.
 * - `program_account_id`: Optional emitting-program filter; null means absent.
 * - `selector`: Optional event-selector filter; null means absent.
 *
 * # Returns
 *
 * A [`PointerResult`] holding an `FfiVec<FfiEventRecord>` that the caller MUST free
 * with `free_ffi_event_record_vec`, or an error status.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a [`SequencerServiceFFI`] instance.
 * - if `to_block.is_some`, its `value` points to a valid `u64`.
 * - each of `tx_hash`, `program_account_id` and `selector` is either null or a valid pointer to
 *   its respective type.
 */
PointerResult<FfiVec<FfiEventRecord>, OperationStatus> sequencer_ffi_query_events(const struct SequencerServiceFFI *sequencer,
                                                                                  uint64_t from_block,
                                                                                  FfiOption<uint64_t> to_block,
                                                                                  const FfiHashType *tx_hash,
                                                                                  const FfiAccountId *program_account_id,
                                                                                  const FfiSelector *selector);

/**
 * # Safety
 * It's up to the caller to pass a proper pointer, if somehow from c/c++ side
 * this is called with a type which doesn't come from a returned `CString` it
 * will cause a segfault.
 */
void primitives_ffi_free_cstring(char *block);

/**
 * Frees the resources associated with the given ffi account.
 *
 * Takes ownership of the whole allocation produced by a `query_*` call: the
 * outer `Box<FfiAccount>` (the `PointerResult.value` pointer) *and* its inner
 * data buffer. Passing the struct by value previously freed only the inner
 * buffer and leaked the outer box.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiAccount` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiAccount` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_account(FfiAccount *val);

/**
 * Frees the resources owned by an `FfiBlock` value.
 *
 * This frees the block's transaction bodies (the only heap-owning field); the
 * header/status fields are `Copy`. It operates on the struct by value because
 * it is an element-level helper, used both for the vector path
 * ([`free_ffi_block_vec`]) and the optional path ([`free_ffi_block_opt`]) — in
 * neither case is an `FfiBlock` itself wrapped in its own outer box.
 *
 * # Arguments
 *
 * - `val`: An instance of `FfiBlock`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a valid instance of `FfiBlock` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_block(FfiBlock val);

/**
 * Frees the resources associated with the given ffi block option.
 *
 * Takes ownership of the whole allocation produced by a `query_*` call: the
 * outer `Box<FfiBlockOpt>` (the `PointerResult.value` pointer), the inner
 * `Box<FfiBlock>` (when present), and that block's transaction bodies.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiBlockOpt` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiBlockOpt` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_block_opt(FfiBlockOpt *val);

/**
 * Frees the resources associated with the given ffi block vector.
 *
 * Takes ownership of the whole allocation produced by a `query_*` call: the
 * outer `Box<FfiVec<FfiBlock>>` (the `PointerResult.value` pointer), the
 * vector's backing buffer, and every block within it.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiVec<FfiBlock>` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiVec<FfiBlock>` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_block_vec(FfiVec<FfiBlock> *val);

/**
 * Frees the resources associated with the given vector of ffi event records.
 *
 * Takes ownership of the whole allocation produced by `query_events`: the outer
 * `Box<FfiVec<FfiEventRecord>>` (the `PointerResult.value` pointer), the vector's
 * backing buffer, and every record's payload within it.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiVec<FfiEventRecord>` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiVec<FfiEventRecord>` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_event_record_vec(FfiVec<FfiEventRecord> *val);

/**
 * Frees the resources associated with the given ffi transaction.
 *
 * # Arguments
 *
 * - `val`: An instance of `FfiTransaction`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a valid instance of `FfiTransaction`.
 */
void primitives_ffi_free_ffi_transaction(FfiTransaction val);

/**
 * Frees the resources associated with the given ffi transaction option.
 *
 * Takes ownership of the whole allocation produced by a `query_*` call: the
 * outer `Box<FfiOption<FfiTransaction>>` (the `PointerResult.value` pointer),
 * the inner `Box<FfiTransaction>` (when present), and its body.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiOption<FfiTransaction>` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiOption<FfiTransaction>` produced by this library and not yet
 *   freed.
 */
void primitives_ffi_free_ffi_transaction_opt(FfiOption<FfiTransaction> *val);

/**
 * Frees the resources associated with the given vector of ffi transactions.
 *
 * Takes ownership of the whole allocation produced by a `query_*` call: the
 * outer `Box<FfiVec<FfiTransaction>>` (the `PointerResult.value` pointer), the
 * vector's backing buffer, and every transaction within it.
 *
 * # Arguments
 *
 * - `val`: The `*mut FfiVec<FfiTransaction>` returned in `PointerResult.value`.
 *
 * # Returns
 *
 * void.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `val` is a pointer to an `FfiVec<FfiTransaction>` produced by this library and not yet freed.
 */
void primitives_ffi_free_ffi_transaction_vec(FfiVec<FfiTransaction> *val);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
