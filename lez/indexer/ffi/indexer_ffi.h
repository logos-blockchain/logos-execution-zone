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

typedef enum FfiTransactionKind {
  Public = 0,
  Private,
  ProgramDeploy,
} FfiTransactionKind;

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

typedef uint64_t FfiBlockId;

/**
 * 32-byte array type for `AccountId`, keys, hashes, etc.
 */
typedef struct FfiBytes32 {
  uint8_t data[32];
} FfiBytes32;

typedef struct FfiBytes32 FfiHashType;

typedef uint64_t FfiTimestamp;

/**
 * 64-byte array type for signatures, etc.
 */
typedef struct FfiBytes64 {
  uint8_t data[64];
} FfiBytes64;

typedef struct FfiBytes64 FfiSignature;

typedef struct FfiBlockHeader {
  FfiBlockId block_id;
  FfiHashType prev_block_hash;
  FfiHashType hash;
  FfiTimestamp timestamp;
  FfiSignature signature;
} FfiBlockHeader;

/**
 * Program ID - 8 u32 values (32 bytes total).
 */
typedef struct FfiProgramId {
  uint32_t data[8];
} FfiProgramId;

typedef struct FfiBytes32 FfiAccountId;

typedef struct FfiVec_FfiAccountId {
  FfiAccountId *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiAccountId;

typedef struct FfiVec_FfiAccountId FfiAccountIdList;

/**
 * U128 - 16 bytes little endian.
 */
typedef struct FfiU128 {
  uint8_t data[16];
} FfiU128;

typedef struct FfiU128 FfiNonce;

typedef struct FfiVec_FfiNonce {
  FfiNonce *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiNonce;

typedef struct FfiVec_FfiNonce FfiNonceList;

typedef struct FfiVec_u8 {
  uint8_t *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_u8;

typedef struct FfiVec_u8 FfiInstructionDataList;

typedef struct FfiPublicMessage {
  struct FfiProgramId program_id;
  FfiAccountIdList account_ids;
  FfiNonceList nonces;
  FfiInstructionDataList instruction_data;
} FfiPublicMessage;

typedef struct FfiBytes32 FfiPublicKey;

typedef struct FfiSignaturePubKeyEntry {
  FfiSignature signature;
  FfiPublicKey public_key;
} FfiSignaturePubKeyEntry;

typedef struct FfiVec_FfiSignaturePubKeyEntry {
  struct FfiSignaturePubKeyEntry *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiSignaturePubKeyEntry;

typedef struct FfiVec_FfiSignaturePubKeyEntry FfiSignaturePubKeyList;

typedef struct FfiPublicTransactionBody {
  FfiHashType hash;
  struct FfiPublicMessage message;
  FfiSignaturePubKeyList witness_set;
} FfiPublicTransactionBody;

/**
 * Account data structure - C-compatible version of lee Account.
 *
 * Note: `balance` and `nonce` are u128 values represented as little-endian
 * byte arrays since C doesn't have native u128 support.
 */
typedef struct FfiAccount {
  struct FfiBytes32 program_owner;
  /**
   * Balance as little-endian [u8; 16].
   */
  struct FfiU128 balance;
  /**
   * Pointer to account data bytes.
   */
  uint8_t *data;
  /**
   * Length of account data.
   */
  uintptr_t data_len;
  /**
   * Capacity of account data.
   */
  uintptr_t data_cap;
  /**
   * Nonce as little-endian [u8; 16].
   */
  struct FfiU128 nonce;
} FfiAccount;

typedef struct FfiPublicAction {
  FfiAccountId account_id;
  struct FfiAccount post_state;
} FfiPublicAction;

typedef struct FfiVec_FfiPublicAction {
  struct FfiPublicAction *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiPublicAction;

typedef struct FfiVec_FfiPublicAction FfiPublicActionList;

typedef struct FfiVec_u8 FfiVecU8;

typedef struct FfiEncryptedAccountData {
  FfiVecU8 ciphertext;
  FfiVecU8 epk;
  uint8_t view_tag;
} FfiEncryptedAccountData;

typedef struct FfiPrivateAction {
  struct FfiBytes32 nullifier;
  struct FfiBytes32 root;
  struct FfiBytes32 commitment;
  struct FfiEncryptedAccountData encrypted_post_state;
} FfiPrivateAction;

typedef struct FfiVec_FfiPrivateAction {
  struct FfiPrivateAction *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiPrivateAction;

typedef struct FfiVec_FfiPrivateAction FfiPrivateActionList;

typedef struct FfiPrivacyPreservingMessage {
  FfiPublicActionList public_actions;
  FfiNonceList nonces;
  FfiPrivateActionList private_actions;
  uint64_t block_validity_window[2];
  uint64_t timestamp_validity_window[2];
} FfiPrivacyPreservingMessage;

typedef FfiVecU8 FfiProof;

typedef struct FfiPrivateTransactionBody {
  FfiHashType hash;
  struct FfiPrivacyPreservingMessage message;
  FfiSignaturePubKeyList witness_set;
  FfiProof proof;
} FfiPrivateTransactionBody;

typedef FfiVecU8 FfiProgramDeploymentMessage;

typedef struct FfiProgramDeploymentTransactionBody {
  FfiHashType hash;
  FfiProgramDeploymentMessage message;
} FfiProgramDeploymentTransactionBody;

typedef struct FfiTransactionBody {
  struct FfiPublicTransactionBody *public_body;
  struct FfiPrivateTransactionBody *private_body;
  struct FfiProgramDeploymentTransactionBody *program_deployment_body;
} FfiTransactionBody;

typedef struct FfiTransaction {
  struct FfiTransactionBody body;
  enum FfiTransactionKind kind;
} FfiTransaction;

typedef struct FfiVec_FfiTransaction {
  struct FfiTransaction *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiTransaction;

typedef struct FfiVec_FfiTransaction FfiBlockBody;

typedef struct FfiBlock {
  struct FfiBlockHeader header;
  FfiBlockBody body;
  enum FfiBedrockStatus bedrock_status;
} FfiBlock;

typedef struct FfiOption_FfiBlock {
  struct FfiBlock *value;
  bool is_some;
} FfiOption_FfiBlock;

typedef struct FfiOption_FfiBlock FfiBlockOpt;

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
  struct FfiAccount *value;
  enum OperationStatus error;
} PointerResult_FfiAccount__OperationStatus;

typedef struct FfiOption_FfiTransaction {
  struct FfiTransaction *value;
  bool is_some;
} FfiOption_FfiTransaction;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiOption_FfiTransaction_____OperationStatus {
  struct FfiOption_FfiTransaction *value;
  enum OperationStatus error;
} PointerResult_FfiOption_FfiTransaction_____OperationStatus;

typedef struct FfiVec_FfiBlock {
  struct FfiBlock *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiBlock;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiVec_FfiBlock_____OperationStatus {
  struct FfiVec_FfiBlock *value;
  enum OperationStatus error;
} PointerResult_FfiVec_FfiBlock_____OperationStatus;

typedef struct FfiOption_u64 {
  uint64_t *value;
  bool is_some;
} FfiOption_u64;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_FfiVec_FfiTransaction_____OperationStatus {
  struct FfiVec_FfiTransaction *value;
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
 * `state` (`Starting`/`Syncing`/`CaughtUp`/`Error`/`Stalled`/`Halted`),
 * `indexed_block_id`, `last_error`, `stall_reason`, `cross_zone_halt`, and
 * `cross_zone_peers`. Lets a client distinguish "still catching up" from
 * "something went wrong".
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
                                                                         struct FfiOption_u64 before,
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
void free_ffi_account(struct FfiAccount *val);

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
void free_ffi_block_vec(struct FfiVec_FfiBlock *val);

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
void free_ffi_transaction(struct FfiTransaction val);

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
void free_ffi_transaction_opt(struct FfiOption_FfiTransaction *val);

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
void free_ffi_transaction_vec(struct FfiVec_FfiTransaction *val);

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
