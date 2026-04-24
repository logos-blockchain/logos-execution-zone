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

typedef enum TransactionKind {
  Public = 0,
  Private,
  ProgramDeploy,
} TransactionKind;

typedef enum BedrockStatus {
  Pending = 0,
  Safe,
  Finalized,
} BedrockStatus;

typedef struct Vec_AccountId Vec_AccountId;

typedef struct Vec_Nonce Vec_Nonce;

typedef struct Vec_u32 Vec_u32;

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

typedef uint64_t BlockId;

typedef uint8_t HashType[32];

typedef uint64_t Timestamp;

typedef uint8_t Signature[64];

typedef struct BlockHeader {
  BlockId block_id;
  HashType prev_block_hash;
  HashType hash;
  Timestamp timestamp;
  Signature signature;
} BlockHeader;

typedef uint32_t ProgramId[8];

typedef struct PublicMessage {
  ProgramId program_id;
  struct Vec_AccountId account_ids;
  struct Vec_Nonce nonces;
  struct Vec_u32 instruction_data;
} PublicMessage;

typedef struct WitnessSet {

} WitnessSet;

typedef struct PublicTransactionBody {
  HashType hash;
  struct PublicMessage message;
  struct WitnessSet witness_set;
} PublicTransactionBody;

typedef struct TransactionBody {
  struct PublicTransactionBody *public_body;
} TransactionBody;

typedef struct Transaction {
  struct TransactionBody body;
  enum TransactionKind kind;
} Transaction;

typedef struct BlockBody {
  struct Transaction *txs;
  uintptr_t len;
} BlockBody;

typedef uint8_t MsgId[32];

typedef struct Block {
  struct BlockHeader header;
  struct BlockBody body;
  enum BedrockStatus bedrock_status;
  MsgId bedrock_parent_id;
} Block;

typedef struct BlockOpt {
  struct Block *block;
  bool is_ok;
} BlockOpt;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_BlockOpt__OperationStatus {
  struct BlockOpt *value;
  enum OperationStatus error;
} PointerResult_BlockOpt__OperationStatus;

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
struct PointerResult_BlockOpt__OperationStatus query_block(const struct IndexerServiceFFI *indexer,
                                                           BlockId block_id);

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);
