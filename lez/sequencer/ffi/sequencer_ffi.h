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
 * FFI-owned sequencer.
 *
 * - A [`StorageActor`] used to get acess to db.
 * - An [`ExecutorActor`] used to query the node.
 * - A [`GossipNetwork`] right now is unused and exists only to pin gossip.
 * - The [`Runtime`] used to run async queries against the store (either owned or borrowed),
 *   already FFI-safe.
 */
typedef struct SequencerServiceFFI {
  void *storage_actor;
  void *executor_actor;
  void *gossip;
  struct Runtime runtime;
} SequencerServiceFFI;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_SequencerServiceFFI__OperationStatus {
  struct SequencerServiceFFI *value;
  enum OperationStatus error;
} PointerResult_SequencerServiceFFI__OperationStatus;

typedef struct PointerResult_SequencerServiceFFI__OperationStatus InitializedSequencerServiceFFIResult;

/**
 * 32-byte array type for `AccountId`, keys, hashes, etc.
 */
typedef struct FfiBytes32 {
  uint8_t data[32];
} FfiBytes32;

/**
 * U128 - 16 bytes little endian.
 */
typedef struct FfiU128 {
  uint8_t data[16];
} FfiU128;

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

typedef uint64_t FfiBlockId;

typedef struct FfiBytes32 FfiHashType;

typedef uint64_t FfiTimestamp;

typedef struct FfiBytes32 FfiPublicKey;

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
  FfiPublicKey producer;
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

/**
 * Fee declaration of a public transaction. Held inline (not behind a
 * pointer): a fee-exempt transaction carries `has_fee == false` and a zeroed
 * declaration.
 */
typedef struct FfiFeeDeclaration {
  FfiAccountId payer;
  uint64_t gas_limit;
  uint64_t tip;
  struct FfiU128 max_fee;
} FfiFeeDeclaration;

typedef struct FfiPublicMessage {
  struct FfiProgramId program_id;
  FfiAccountIdList account_ids;
  FfiNonceList nonces;
  FfiInstructionDataList instruction_data;
  bool has_fee;
  struct FfiFeeDeclaration fee;
} FfiPublicMessage;

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

typedef struct FfiVec_FfiBlock {
  struct FfiBlock *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiBlock;

/**
 * 8-byte array type for event selectors.
 */
typedef struct FfiBytes8 {
  uint8_t data[8];
} FfiBytes8;

typedef struct FfiBytes8 FfiSelector;

typedef struct FfiEventRecord {
  FfiBlockId block_id;
  uint32_t tx_index;
  FfiHashType tx_hash;
  struct FfiProgramId program_id;
  FfiSelector selector;
  FfiVecU8 data;
} FfiEventRecord;

typedef struct FfiVec_FfiEventRecord {
  struct FfiEventRecord *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiEventRecord;

typedef struct FfiOption_FfiTransaction {
  struct FfiTransaction *value;
  bool is_some;
} FfiOption_FfiTransaction;

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
InitializedSequencerServiceFFIResult start_sequencer(const struct Runtime *runtime,
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
enum OperationStatus stop_sequencer(struct SequencerServiceFFI *sequencer);

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
void init_logger(const char *level);

/**
 * # Safety
 * It's up to the caller to pass a proper pointer, if somehow from c/c++ side
 * this is called with a type which doesn't come from a returned `CString` it
 * will cause a segfault.
 */
void free_cstring(char *block);

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
void free_ffi_event_record_vec(struct FfiVec_FfiEventRecord *val);

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
