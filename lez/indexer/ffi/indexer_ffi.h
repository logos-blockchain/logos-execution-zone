#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum OperationStatus {
  Ok = 0,
  NullPointer = 1,
  InitializationError = 2,
  ClientError = 3,
} OperationStatus;

typedef enum FfiBedrockStatus {
  Pending = 0,
  Safe,
  Finalized,
} FfiBedrockStatus;

typedef enum PointerKind_Tag {
  Owned,
  Borrowed,
  Null,
} PointerKind_Tag;

typedef struct PointerKind {
  PointerKind_Tag tag;
  union {
    struct {
      void *owned;
    };
    struct {
      const void *borrowed;
    };
  };
} PointerKind;

typedef struct Pointer_Runtime {
  struct PointerKind kind;
} Pointer_Runtime;

/**
 * Wrapper around [`tokio::runtime::Runtime`] that can be safely passed across the FFI boundary.
 */
typedef struct Runtime {
  struct Pointer_Runtime inner;
} Runtime;

/**
 * FFI-owned indexer.
 *
 * - An [`IndexerCore`] used to answer queries
 * - The background task [`JoinHandle`] that drives ingestion (consuming the block stream so the
 *   store stays populated)
 * - The [`Runtime`] used to run async queries against the store (either owned or borrowed),
 *   already FFI-safe.
 */
typedef struct IndexerServiceFFI {
  void *core;
  void *ingest_handle;
  struct Runtime runtime;
} IndexerServiceFFI;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_IndexerServiceFFI__OperationStatus {
  struct IndexerServiceFFI *value;
  enum OperationStatus error;
} PointerResult_IndexerServiceFFI__OperationStatus;

typedef struct PointerResult_IndexerServiceFFI__OperationStatus InitializedIndexerServiceFFIResult;

/**
 * Result of [`query_last_block`], returned **inline** (no heap allocation, so
 * there is no corresponding `free_*` to call).
 *
 * `block_id` is only meaningful when `error` is `Ok` *and* `is_some` is
 * `true`. An `Ok` result with `is_some == false` means the indexer has no
 * finalized block yet (an empty chain) — which is distinct from an error.
 */
typedef struct LastBlockIdResult {
  uint64_t block_id;
  bool is_some;
  enum OperationStatus error;
} LastBlockIdResult;

typedef struct FfiBlockHeader {
  FfiBlockId block_id;
  FfiHashType prev_block_hash;
  FfiHashType hash;
  FfiTimestamp timestamp;
  FfiSignature signature;
} FfiBlockHeader;

typedef FfiVec<FfiTransaction> FfiBlockBody;

typedef struct FfiBlock {
  struct FfiBlockHeader header;
  FfiBlockBody body;
  enum FfiBedrockStatus bedrock_status;
} FfiBlock;

typedef FfiOption<FfiBlock> FfiBlockOpt;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiBlockOpt__OperationStatus {
  FfiBlockOpt *value;
  enum OperationStatus error;
} PointerResult_FfiBlockOpt__OperationStatus;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiAccount__OperationStatus {
  FfiAccount *value;
  enum OperationStatus error;
} PointerResult_FfiAccount__OperationStatus;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiOption_FfiTransaction_____OperationStatus {
  FfiOption<FfiTransaction> *value;
  enum OperationStatus error;
} PointerResult_FfiOption_FfiTransaction_____OperationStatus;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiVec_FfiBlock_____OperationStatus {
  FfiVec<FfiBlock> *value;
  enum OperationStatus error;
} PointerResult_FfiVec_FfiBlock_____OperationStatus;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiVec_FfiTransaction_____OperationStatus {
  FfiVec<FfiTransaction> *value;
  enum OperationStatus error;
} PointerResult_FfiVec_FfiTransaction_____OperationStatus;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Creates and starts an indexer based on the provided
 * configuration file path.
 *
 * # Arguments
 *
 * - `runtime`: A runtime for the indexer to run on, or null to have the indexer create and own
 *   one.
 * - `config_path`: A pointer to a string representing the path to the configuration file.
 * - `storage_dir`: A pointer to a string naming the directory under which the indexer stores its
 *   state (`RocksDB`), or null/empty to use the current directory. The host (e.g. a Logos module's
 *   instance persistence path) owns this location.
 *
 * # Returns
 *
 * An `InitializedIndexerServiceFFIResult` containing either a pointer to the
 * initialized `IndexerServiceFFI` or an error code.
 *
 * # Safety
 * The caller must ensure that:
 * - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the indexer.
 * - `config_path` is a valid pointer to a null-terminated C string.
 * - `storage_dir` is either null or a valid pointer to a null-terminated C string.
 */
InitializedIndexerServiceFFIResult start_indexer(const struct Runtime *runtime,
                                                 const char *config_path,
                                                 const char *storage_dir);

/**
 * Stops and frees the resources associated with the given indexer service.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the `IndexerServiceFFI` instance to be stopped.
 *
 * # Returns
 *
 * An `OperationStatus` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
 * - The `IndexerServiceFFI` instance was created by this library
 * - The pointer will not be used after this function returns
 */
enum OperationStatus stop_indexer(struct IndexerServiceFFI *indexer);

/**
 * Initializes logging for the indexer at `level`.
 *
 * - `level` is a null-terminated string (`off`/`error`/`warn`/`info`/`debug`/ `trace`,
 *   case-insensitive); null or unparseable falls back to `info`.
 *
 * Only the `indexer_ffi` and `indexer_core` targets are enabled!
 *
 * # Safety
 * - `level` must be a valid null-terminated C string, or null.
 * - First call to this function wins; subsequent calls are no-ops.
 */
void init_logger(const char *level);

/**
 * # Safety
 * It's up to the caller to pass a proper pointer, if somehow from c/c++ side
 * this is called with a type which doesn't come from a returned `CString` it
 * will cause a segfault.
 */
void free_cstring(char *block);

/**
 * Query the last block id from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 *
 * # Returns
 *
 * A [`LastBlockIdResult`] indicating success or failure. The block id is
 * returned inline; nothing needs to be freed.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct LastBlockIdResult query_last_block(const struct IndexerServiceFFI *indexer);

/**
 * Query the indexer's current sync status as a JSON C-string.
 *
 * The JSON schema is owned by `indexer_core` (`IndexerStatus`): an object with
 * `state` (`Starting`/`Syncing`/`CaughtUp`/`Error`/`Stalled`),
 * `indexed_block_id`, `last_error`, and `stall_reason`. Lets a client
 * distinguish "still catching up" from "something went wrong".
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 *
 * # Returns
 *
 * A heap-allocated, null-terminated JSON string that the caller MUST free with
 * `free_cstring`. Returns null on error (null `indexer` pointer or a
 * serialization failure).
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
char *query_status(const struct IndexerServiceFFI *indexer);

/**
 * Query the block by id from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 * - `block_id`: `u64` number of block id
 *
 * # Returns
 *
 * A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiBlockOpt__OperationStatus query_block(const struct IndexerServiceFFI *indexer,
                                                              FfiBlockId block_id);

/**
 * Query the block by hash from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 * - `hash`: `FfiHashType` - hash of block
 *
 * # Returns
 *
 * A `PointerResult<FfiBlockOpt, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiBlockOpt__OperationStatus query_block_by_hash(const struct IndexerServiceFFI *indexer,
                                                                      FfiHashType hash);

/**
 * Query the account by id from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 * - `account_id`: `FfiAccountId` - id of queried account
 *
 * # Returns
 *
 * A `PointerResult<FfiAccount, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiAccount__OperationStatus query_account(const struct IndexerServiceFFI *indexer,
                                                               FfiAccountId account_id);

/**
 * Query the transaction by hash from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
 * - `hash`: `FfiHashType` - hash of transaction
 *
 * # Returns
 *
 * A `PointerResult<FfiOption<FfiTransaction>, OperationStatus>` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiOption_FfiTransaction_____OperationStatus query_transaction(const struct IndexerServiceFFI *indexer,
                                                                                    FfiHashType hash);

/**
 * Query the blocks by block range from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
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
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiVec_FfiBlock_____OperationStatus query_block_vec(const struct IndexerServiceFFI *indexer,
                                                                         FfiOption<uint64_t> before,
                                                                         uint64_t limit);

/**
 * Query the transactions range by account id from indexer.
 *
 * # Arguments
 *
 * - `indexer`: A pointer to the [`IndexerServiceFFI`] instance to be queried.
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
 * - `indexer` is a valid pointer to a [`IndexerServiceFFI`] instance.
 */
struct PointerResult_FfiVec_FfiTransaction_____OperationStatus query_transactions_by_account(const struct IndexerServiceFFI *indexer,
                                                                                             FfiAccountId account_id,
                                                                                             uint64_t offset,
                                                                                             uint64_t limit);

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
void free_ffi_account(FfiAccount *val);

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
void free_ffi_block(struct FfiBlock val);

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
void free_ffi_block_opt(FfiBlockOpt *val);

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
void free_ffi_block_vec(FfiVec<FfiBlock> *val);

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
void free_ffi_transaction(FfiTransaction val);

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
void free_ffi_transaction_opt(FfiOption<FfiTransaction> *val);

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
void free_ffi_transaction_vec(FfiVec<FfiTransaction> *val);

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
