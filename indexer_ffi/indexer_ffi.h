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

typedef struct IndexerServiceFFI {
  void *indexer_handle;
  void *runtime;
  void *indexer_client;
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
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_u64__OperationStatus {
  uint64_t *value;
  enum OperationStatus error;
} PointerResult_u64__OperationStatus;

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

typedef struct FfiVec_u32 {
  uint32_t *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_u32;

typedef struct FfiVec_u32 FfiInstructionDataList;

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
 * Account data structure - C-compatible version of nssa Account.
 *
 * Note: `balance` and `nonce` are u128 values represented as little-endian
 * byte arrays since C doesn't have native u128 support.
 */
typedef struct FfiAccount {
  struct FfiProgramId program_owner;
  /**
   * Balance as little-endian [u8; 16].
   */
  struct FfiU128 balance;
  /**
   * Pointer to account data bytes.
   */
  const uint8_t *data;
  /**
   * Length of account data.
   */
  uintptr_t data_len;
  /**
   * Nonce as little-endian [u8; 16].
   */
  struct FfiU128 nonce;
} FfiAccount;

typedef struct FfiVec_FfiAccount {
  struct FfiAccount *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiAccount;

typedef struct FfiVec_FfiAccount FfiAccountList;

typedef struct FfiVec_u8 {
  uint8_t *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_u8;

typedef struct FfiVec_u8 FfiVecU8;

typedef struct FfiEncryptedAccountData {
  FfiVecU8 ciphertext;
  FfiVecU8 epk;
  uint8_t view_tag;
} FfiEncryptedAccountData;

typedef struct FfiVec_FfiEncryptedAccountData {
  struct FfiEncryptedAccountData *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiEncryptedAccountData;

typedef struct FfiVec_FfiEncryptedAccountData FfiEncryptedAccountDataList;

typedef struct FfiVec_FfiBytes32 {
  struct FfiBytes32 *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiBytes32;

typedef struct FfiVec_FfiBytes32 FfiVecBytes32;

typedef struct FfiNullifierCommitmentSet {
  struct FfiBytes32 nullifier;
  struct FfiBytes32 commitment_set_digest;
} FfiNullifierCommitmentSet;

typedef struct FfiVec_FfiNullifierCommitmentSet {
  struct FfiNullifierCommitmentSet *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiNullifierCommitmentSet;

typedef struct FfiVec_FfiNullifierCommitmentSet FfiNullifierCommitmentSetList;

typedef struct FfiPrivacyPreservingMessage {
  FfiAccountIdList public_account_ids;
  FfiNonceList nonces;
  FfiAccountList public_post_states;
  FfiEncryptedAccountDataList encrypted_private_post_states;
  FfiVecBytes32 new_commitments;
  FfiNullifierCommitmentSetList new_nullifiers;
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

typedef struct FfiBytes32 FfiMsgId;

typedef struct FfiBlock {
  struct FfiBlockHeader header;
  FfiBlockBody body;
  enum FfiBedrockStatus bedrock_status;
  FfiMsgId bedrock_parent_id;
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
 * Creates and starts an indexer based on the provided
 * configuration file path.
 *
 * # Arguments
 *
 * - `config_path`: A pointer to a string representing the path to the configuration file.
 * - `port`: Number representing a port, on which indexers RPC will start.
 *
 * # Returns
 *
 * An `InitializedIndexerServiceFFIResult` containing either a pointer to the
 * initialized `IndexerServiceFFI` or an error code.
 */
InitializedIndexerServiceFFIResult start_indexer(const char *config_path, uint16_t port);

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
 * # Safety
 * It's up to the caller to pass a proper pointer, if somehow from c/c++ side
 * this is called with a type which doesn't come from a returned `CString` it
 * will cause a segfault.
 */
void free_cstring(char *block);

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
struct PointerResult_u64__OperationStatus query_last_block(const struct IndexerServiceFFI *indexer);

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
struct PointerResult_FfiBlockOpt__OperationStatus query_block(const struct IndexerServiceFFI *indexer,
                                                              FfiBlockId block_id);

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);
