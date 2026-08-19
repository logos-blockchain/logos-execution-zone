/**
 * LEE Wallet FFI Bindings
 *
 * Thread Safety: All functions are thread-safe. The wallet handle can be
 * shared across threads, but operations are serialized internally.
 *
 * Memory Management:
 * - Functions returning pointers allocate memory that must be freed
 * - Use the corresponding wallet_ffi_free_* function to free memory
 * - Never free memory returned by FFI using standard C free()
 *
 * Error Handling:
 * - Functions return WalletFfiError codes
 * - On error, call wallet_ffi_get_last_error() for detailed message
 * - The error string must be freed with wallet_ffi_free_error_string()
 *
 * Initialization:
 * 1. Call wallet_ffi_init_runtime() before any other function
 * 2. Create wallet with wallet_ffi_create_new() or wallet_ffi_open()
 * 3. Destroy wallet with wallet_ffi_destroy() when done
 */


#ifndef WALLET_FFI_H
#define WALLET_FFI_H

/* Generated with cbindgen:0.29.3 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Error codes returned by FFI functions.
 */
typedef enum WalletFfiError {
  /**
   * Operation completed successfully.
   */
  SUCCESS = 0,
  /**
   * A null pointer was passed where a valid pointer was expected.
   */
  NULL_POINTER = 1,
  /**
   * Invalid UTF-8 string.
   */
  INVALID_UTF8 = 2,
  /**
   * Wallet handle is not initialized.
   */
  WALLET_NOT_INITIALIZED = 3,
  /**
   * Configuration error.
   */
  CONFIG_ERROR = 4,
  /**
   * Storage/persistence error.
   */
  STORAGE_ERROR = 5,
  /**
   * Network/RPC error.
   */
  NETWORK_ERROR = 6,
  /**
   * Account not found.
   */
  ACCOUNT_NOT_FOUND = 7,
  /**
   * Key not found for account.
   */
  KEY_NOT_FOUND = 8,
  /**
   * Insufficient funds for operation.
   */
  INSUFFICIENT_FUNDS = 9,
  /**
   * Invalid account ID format.
   */
  INVALID_ACCOUNT_ID = 10,
  /**
   * Tokio runtime error.
   */
  RUNTIME_ERROR = 11,
  /**
   * Password required but not provided.
   */
  PASSWORD_REQUIRED = 12,
  /**
   * Block synchronization error.
   */
  SYNC_ERROR = 13,
  /**
   * Serialization/deserialization error.
   */
  SERIALIZATION_ERROR = 14,
  /**
   * Invalid conversion from FFI types to LEE types.
   */
  INVALID_TYPE_CONVERSION = 15,
  /**
   * Invalid Key value.
   */
  INVALID_KEY_VALUE = 16,
  /**
   * Invalid program bytecode.
   */
  INVALID_BYTECODE = 17,
  /**
   * Internal error (catch-all).
   */
  INTERNAL_ERROR = 99,
} WalletFfiError;

/**
 * Enumeration to represent kinds of `FfiAccountIdentity`.
 */
typedef enum FfiAccountIdentityKind {
  PUBLIC = 0,
  PUBLIC_NO_SIGN = 1,
  PUBLIC_KEYCARD = 2,
  PRIVATE_OWNED = 3,
  PRIVATE_FOREIGN = 4,
  PRIVATE_PDA_OWNED = 5,
  PRIVATE_PDA_FOREIGN = 6,
  PRIVATE_SHARED = 7,
  PRIVATE_PDA_SHARED = 8,
} FfiAccountIdentityKind;

/**
 * Opaque pointer to the Wallet instance.
 *
 * This type is never instantiated directly - it's used as an opaque handle
 * to hide the internal wallet structure from C code.
 */
typedef struct WalletHandle {
  uint8_t _private[0];
} WalletHandle;

/**
 * 32-byte array type for `AccountId`, keys, hashes, etc.
 */
typedef struct FfiBytes32 {
  uint8_t data[32];
} FfiBytes32;

/**
 * Public keys for a private account (safe to expose).
 */
typedef struct FfiPrivateAccountKeys {
  /**
   * Nullifier public key (32 bytes).
   */
  struct FfiBytes32 nullifier_public_key;
  /**
   * Viewing public key (ML-KEM-768 encapsulation key, 1184 bytes).
   */
  const uint8_t *viewing_public_key;
  /**
   * Length of viewing public key (always 1184 bytes for ML-KEM-768).
   */
  uintptr_t viewing_public_key_len;
} FfiPrivateAccountKeys;

/**
 * Single entry in the account list.
 */
typedef struct FfiAccountListEntry {
  struct FfiBytes32 account_id;
  bool is_public;
} FfiAccountListEntry;

/**
 * List of accounts returned by `wallet_ffi_list_accounts`.
 */
typedef struct FfiAccountList {
  struct FfiAccountListEntry *entries;
  uintptr_t count;
} FfiAccountList;

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

/**
 * Result of a transfer operation.
 */
typedef struct FfiTransferResult {
  /**
   * Transaction hash (null-terminated string, or null on failure).
   */
  char *tx_hash;
  /**
   * Whether the transfer succeeded.
   */
  bool success;
} FfiTransferResult;

/**
 * Struct representing an account identity, given to `AccountManager` at intialization.
 */
typedef struct FfiAccountIdentity {
  enum FfiAccountIdentityKind kind;
  struct FfiBytes32 account_id;
  /**
   * C-compatible string.
   */
  char *key_path;
  struct FfiBytes32 authorization_secret_key;
  struct FfiBytes32 nullifier_secret_key;
  struct FfiBytes32 nullifier_public_key;
  const uint8_t *viewing_public_key;
  uintptr_t viewing_public_key_len;
  struct FfiU128 identifier;
} FfiAccountIdentity;

/**
 * Program ID - 8 u32 values (32 bytes total).
 */
typedef struct FfiProgramId {
  uint32_t data[8];
} FfiProgramId;

/**
 * Result of a generic transaction operation.
 */
typedef struct FfiTransactionResult {
  /**
   * Transaction hash (null-terminated string, or null on failure).
   */
  char *tx_hash;
  /**
   * Whether the transaction succeeded.
   */
  bool success;
  const struct FfiBytes32 *secrets_data;
  /**
   * Public transactions have 0 secrets.
   */
  uintptr_t secrets_size;
} FfiTransactionResult;

/**
 * Intended to be created manually.
 */
typedef struct FfiProgram {
  const uint8_t *elf_data;
  uintptr_t elf_size;
} FfiProgram;

/**
 * Intended to be created manually.
 */
typedef struct FfiProgramWithDependencies {
  struct FfiProgram program;
  const struct FfiProgram *deps;
  uintptr_t deps_size;
} FfiProgramWithDependencies;

/**
 * Public key info for a public account.
 */
typedef struct FfiPublicAccountKey {
  struct FfiBytes32 public_key;
} FfiPublicAccountKey;

typedef struct LabelAvailability {
  bool is_available;
  enum WalletFfiError error;
} LabelAvailability;

typedef struct FfiAccountIdWithPrivacy {
  struct FfiBytes32 account_id;
  bool is_private;
} FfiAccountIdWithPrivacy;

typedef struct AccountIdResolvedFromLabel {
  struct FfiAccountIdWithPrivacy account_id;
  enum WalletFfiError error;
} AccountIdResolvedFromLabel;

typedef struct LabelList {
  const char **labels_data;
  uintptr_t labels_size;
  enum WalletFfiError error;
} LabelList;

typedef struct FfiBytes32 FfiPdaSeed;

typedef struct FfiBytes32 FfiNullifierPublicKey;

typedef struct FfiCreateWalletOutput {
  struct WalletHandle *wallet;
  /**
   * C compatible(null terminated) string.
   */
  char *mnemonic;
} FfiCreateWalletOutput;

/**
 * Create a new public account.
 *
 * Public accounts use standard transaction signing and are suitable for
 * non-private operations.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_account_id`: Output pointer for the new account ID (32 bytes)
 *
 * # Returns
 * - `Success` on successful creation
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
 */
enum WalletFfiError wallet_ffi_create_account_public(struct WalletHandle *handle,
                                                     struct FfiBytes32 *out_account_id);

/**
 * Create a new private account, storing a default account entry in local storage.
 *
 * This is the private-account equivalent of `wallet_ffi_create_account_public`.
 * It generates a key node, assigns a random identifier, and inserts a default
 * account record so the account can immediately be used with
 * `wallet_ffi_register_private_account`.
 *
 * The identifier is chosen at random and is not encoded in the mnemonic seed.
 * Once the account is initialized, the identifier is embedded in the encrypted
 * transaction payload and can be recovered by running `sync-private` from the
 * same mnemonic. An account that was created locally but has never been initialized
 * cannot be recovered from the seed alone.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_account_id`: Output pointer for the new account ID (32 bytes)
 *
 * # Returns
 * - `Success` on successful creation
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
 */
enum WalletFfiError wallet_ffi_create_account_private(struct WalletHandle *handle,
                                                      struct FfiBytes32 *out_account_id);

/**
 * Create a new private key node.
 *
 * Returns the nullifier public key (npk) and viewing public key (vpk) to share with
 * senders. Account IDs are discovered later via sync when senders initialize accounts
 * under this key.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_keys`: Output pointer for the key data (npk + vpk)
 *
 * # Returns
 * - `Success` on successful creation
 * - Error code on failure
 *
 * # Memory
 * The keys structure must be freed with `wallet_ffi_free_private_account_keys()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
 */
enum WalletFfiError wallet_ffi_create_private_accounts_key(struct WalletHandle *handle,
                                                           struct FfiPrivateAccountKeys *out_keys);

/**
 * List all accounts in the wallet.
 *
 * Returns both public and private accounts managed by this wallet.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_list`: Output pointer for the account list
 *
 * # Returns
 * - `Success` on successful listing
 * - Error code on failure
 *
 * # Memory
 * The returned list must be freed with `wallet_ffi_free_account_list()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_list` must be a valid pointer to a `FfiAccountList` struct
 */
enum WalletFfiError wallet_ffi_list_accounts(struct WalletHandle *handle,
                                             struct FfiAccountList *out_list);

/**
 * Free an account list returned by `wallet_ffi_list_accounts`.
 *
 * # Safety
 * The list must be either null or a valid list returned by `wallet_ffi_list_accounts`.
 */
void wallet_ffi_free_account_list(struct FfiAccountList *list);

/**
 * Get account balance.
 *
 * For public accounts, this fetches the balance from the network.
 * For private accounts, this returns the locally cached balance.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: The account ID (32 bytes)
 * - `is_public`: Whether this is a public account
 * - `out_balance`: Output for balance as little-endian [u8; 16]
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_balance` must be a valid pointer to a `[u8; 16]` array
 */
enum WalletFfiError wallet_ffi_get_balance(struct WalletHandle *handle,
                                           const struct FfiBytes32 *account_id,
                                           bool is_public,
                                           uint8_t (*out_balance)[16]);

/**
 * Get full public account data from the network.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: The account ID (32 bytes)
 * - `out_account`: Output pointer for account data
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Memory
 * The account data must be freed with `wallet_ffi_free_account_data()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_account` must be a valid pointer to a `FfiAccount` struct
 */
enum WalletFfiError wallet_ffi_get_account_public(struct WalletHandle *handle,
                                                  const struct FfiBytes32 *account_id,
                                                  struct FfiAccount *out_account);

/**
 * Get full private account data from the local storage.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: The account ID (32 bytes)
 * - `out_account`: Output pointer for account data
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Memory
 * The account data must be freed with `wallet_ffi_free_account_data()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_account` must be a valid pointer to a `FfiAccount` struct
 */
enum WalletFfiError wallet_ffi_get_account_private(struct WalletHandle *handle,
                                                   const struct FfiBytes32 *account_id,
                                                   struct FfiAccount *out_account);

/**
 * Free account data returned by `wallet_ffi_get_account_public`.
 *
 * # Safety
 * The account must be either null or a valid account returned by
 * `wallet_ffi_get_account_public`.
 */
void wallet_ffi_free_account_data(struct FfiAccount *account);

/**
 * Import a public account private key into wallet storage.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `private_key_hex`: Hex-encoded private key string
 *
 * # Returns
 * - `Success` on successful import
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `private_key_hex` must be a valid pointer to a null-terminated C string
 */
enum WalletFfiError wallet_ffi_import_public_account(struct WalletHandle *handle,
                                                     const char *private_key_hex);

/**
 * Import a private account keychain and account state into wallet storage.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `key_chain_json`: JSON-encoded `key_protocol::key_management::KeyChain`
 * - `chain_index`: Optional chain index string (for example `/0/1`, `NULL` if unknown)
 * - `identifier`: Identifier for this private account as little-endian u128 bytes
 * - `account_state_json`: JSON-encoded `wallet::account::HumanReadableAccount`
 *
 * # Returns
 * - `Success` on successful import
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `key_chain_json` must be a valid pointer to a null-terminated C string
 * - `identifier` must be a valid pointer to a `FfiU128` struct
 * - `account_state_json` must be a valid pointer to a null-terminated C string
 */
enum WalletFfiError wallet_ffi_import_private_account(struct WalletHandle *handle,
                                                      const char *key_chain_json,
                                                      const char *chain_index,
                                                      const struct FfiU128 *identifier,
                                                      const char *account_state_json);

/**
 * Withdraw native tokens from a public account to Bedrock (L1) through the bridge.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source public account ID (must be owned by this wallet). Bridge withdrawals only
 *   support public sender accounts.
 * - `amount`: Amount of native tokens to withdraw
 * - `bedrock_account_pk`: Recipient's Bedrock (L1) public key, 32 bytes
 * - `out_result`: Output pointer for the withdraw result
 *
 * # Returns
 * - `Success` if the withdraw transaction was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if the source account's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `bedrock_account_pk` must be a valid pointer to a `FfiBytes32` struct
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_bridge_withdraw(struct WalletHandle *handle,
                                               const struct FfiBytes32 *from,
                                               uint64_t amount,
                                               const struct FfiBytes32 *bedrock_account_pk,
                                               struct FfiTransferResult *out_result);

/**
 * Send generic public transaction.
 *
 * # Parameters
 * - `handle`: Valid pointer to wallet handle
 * - `account_identities`: Valid pointer to list of `FfiAccountIdentity`
 * - `instruction_data`: Valid pointer to instruction words
 * - `out_result`: Valid pointer to `FfiTransactionResult`
 *
 * # Returns
 * - `Success` on successful creation
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid pointer
 * - `account_identities` must be a valid pointer
 * - `instruction_data` must be a valid pointer
 * - `out_result` must be a valid pointer
 */
enum WalletFfiError wallet_ffi_send_generic_public_transaction(struct WalletHandle *handle,
                                                               const struct FfiAccountIdentity *account_identities,
                                                               uintptr_t account_identities_size,
                                                               const uint8_t *instruction_data,
                                                               uintptr_t instruction_data_size,
                                                               struct FfiProgramId program_id,
                                                               struct FfiTransactionResult *out_result);

/**
 * Send generic private transaction.
 *
 * # Parameters
 * - `handle`: Valid pointer to wallet handle
 * - `account_identities`: Valid pointer to list of `FfiAccountIdentity`
 * - `instruction_data`: Valid pointer to instruction words
 * - `out_result`: Valid pointer to `FfiTransactionResult`
 *
 * # Returns
 * - `Success` on successful creation
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid pointer
 * - `account_identities` must be a valid pointer
 * - `instruction_data` must be a valid pointer
 * - `out_result` must be a valid pointer
 */
enum WalletFfiError wallet_ffi_send_generic_private_transaction(struct WalletHandle *handle,
                                                                const struct FfiAccountIdentity *account_identities,
                                                                uintptr_t account_identities_size,
                                                                const uint8_t *instruction_data,
                                                                uintptr_t instruction_data_size,
                                                                const struct FfiProgramWithDependencies *program_with_dependencies,
                                                                struct FfiTransactionResult *out_result);

/**
 * Poll transaction for its status.
 *
 * # Parameters
 * - `handle`: Valid pointer to wallet handle.
 * - `tx_hash`: Bytes of a transaction hash,
 * - `transaction_status`: Valid pointer into `bool`.
 *
 * # Returns
 * - `true` if seen included, `false` othervise.
 *
 * # Safety
 * - `handle` must be a valid pointer.
 */
enum WalletFfiError wallet_ffi_poll_transaction_status(struct WalletHandle *handle,
                                                       struct FfiBytes32 tx_hash,
                                                       bool *transaction_status);

/**
 * Free a transaction result returned by `wallet_ffi_send_generic_public_transaction` or
 * `wallet_ffi_send_generic_private_transaction`.
 *
 * # Safety
 * The result must be either null or a valid result from a transaction function.
 */
void wallet_ffi_free_transaction_result(struct FfiTransactionResult *result);

/**
 * Get the public key for a public account.
 *
 * This returns the public key derived from the account's signing key.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: The account ID (32 bytes)
 * - `out_public_key`: Output pointer for the public key
 *
 * # Returns
 * - `Success` on successful retrieval
 * - `KeyNotFound` if the account's key is not in this wallet
 * - Error code on other failures
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_public_key` must be a valid pointer to a `FfiPublicAccountKey` struct
 */
enum WalletFfiError wallet_ffi_get_public_account_key(struct WalletHandle *handle,
                                                      const struct FfiBytes32 *account_id,
                                                      struct FfiPublicAccountKey *out_public_key);

/**
 * Get keys for a private account.
 *
 * Returns the nullifier public key (NPK) and viewing public key (VPK)
 * for the specified private account. These keys are safe to share publicly.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: The account ID (32 bytes)
 * - `out_keys`: Output pointer for the key data
 *
 * # Returns
 * - `Success` on successful retrieval
 * - `AccountNotFound` if the private account is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The keys structure must be freed with `wallet_ffi_free_private_account_keys()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
 */
enum WalletFfiError wallet_ffi_get_private_account_keys(struct WalletHandle *handle,
                                                        const struct FfiBytes32 *account_id,
                                                        struct FfiPrivateAccountKeys *out_keys);

/**
 * Free private account keys returned by `wallet_ffi_get_private_account_keys`.
 *
 * # Safety
 * The keys must be either null or valid keys returned by
 * `wallet_ffi_get_private_account_keys`.
 */
void wallet_ffi_free_private_account_keys(struct FfiPrivateAccountKeys *keys);

/**
 * Convert an account ID to a Base58 string.
 *
 * # Parameters
 * - `account_id`: The account ID (32 bytes)
 *
 * # Returns
 * - Pointer to null-terminated Base58 string on success
 * - Null pointer on error
 *
 * # Memory
 * The returned string must be freed with `wallet_ffi_free_string()`.
 *
 * # Safety
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 */
char *wallet_ffi_account_id_to_base58(const struct FfiBytes32 *account_id);

/**
 * Parse a Base58 string into an account ID.
 *
 * # Parameters
 * - `base58_str`: Null-terminated Base58 string
 * - `out_account_id`: Output pointer for the account ID (32 bytes)
 *
 * # Returns
 * - `Success` on successful parsing
 * - `InvalidAccountId` if the string is not valid Base58
 * - Error code on other failures
 *
 * # Safety
 * - `base58_str` must be a valid pointer to a null-terminated C string
 * - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
 */
enum WalletFfiError wallet_ffi_account_id_from_base58(const char *base58_str,
                                                      struct FfiBytes32 *out_account_id);

/**
 * Resolve public account.
 *
 * # Parameters
 * - `account_id`: 32 bytes of the public account ID
 * - `needs_sign`: whether the account needs signing
 * - `out_account_identity`: valid pointer, where output will be written
 *
 * # Returns
 * - `Success` on successful retrieval
 *
 * # Safety
 * - `out_account_identity` must be a valid pointer to a `FfiAccountIdentity` struct
 */
enum WalletFfiError wallet_ffi_resolve_public_account(struct FfiBytes32 account_id,
                                                      bool needs_sign,
                                                      struct FfiAccountIdentity *out_account_identity);

/**
 * Resolve private account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: 32 bytes of the public account ID
 * - `out_account_identity`: valid pointer, where output will be written
 *
 * # Returns
 * - `Success` on successful retrieval
 * - `InternalError` if failed to lock wallet
 * - `AccountNotFound` if the account is not found
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_account_identity` must be a valid pointer to a `FfiAccountIdentity` struct
 */
enum WalletFfiError wallet_ffi_resolve_private_account(struct WalletHandle *handle,
                                                       struct FfiBytes32 account_id,
                                                       struct FfiAccountIdentity *out_account_identity);

/**
 * Free account identity returned by `wallet_ffi_resolve_private_account` or
 * `wallet_ffi_resolve_public_account`.
 *
 * # Safety
 * The account must be either null or a valid account returned by
 * `wallet_ffi_resolve_private_account` or `wallet_ffi_resolve_public_account`.
 */
void wallet_ffi_free_account_identity(struct FfiAccountIdentity *account_identity);

/**
 * Check if label is available.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `label`: Input null terminated C string for a label
 *
 * # Returns
 * - `LabelAvailability` struct
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `label` must be a valid pointer to a null-terminated C string
 */
struct LabelAvailability wallet_ffi_check_label_available(struct WalletHandle *handle,
                                                          const char *label);

/**
 * Add new label.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `label`: Input null terminated C string for a label
 * - `account_id_with_privacy`: The account ID (32 bytes) and its privacy.
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `label` must be a valid pointer to a null-terminated C string
 */
enum WalletFfiError wallet_ffi_add_label(struct WalletHandle *handle,
                                         const char *label,
                                         struct FfiAccountIdWithPrivacy account_id_with_privacy);

/**
 * Resolve a label.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `label`: Input null terminated C string for a label
 *
 * # Returns
 * - `AccountIdResolvedFromLabel` struct
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `label` must be a valid pointer to a null-terminated C string
 */
struct AccountIdResolvedFromLabel wallet_ffi_resolve_label(struct WalletHandle *handle,
                                                           const char *label);

/**
 * Get all labels for account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id_with_privacy`: The account ID (32 bytes) and its privacy.
 *
 * # Returns
 * - `LabelList` struct
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 */
struct LabelList wallet_ffi_get_all_labels_for_account(struct WalletHandle *handle,
                                                       struct FfiAccountIdWithPrivacy account_id_with_privacy);

/**
 * Free label list.
 *
 * # Parameters
 * - `label_list`: Input list of labels
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Safety
 * - `label_list` must be a valid pointer to `LabelList`, received from
 *   `wallet_ffi_get_all_labels_for_account`
 */
enum WalletFfiError wallet_ffi_free_label_list(struct LabelList *label_list);

/**
 * Produce account id for public PDA.
 *
 * # Parameters
 * - `program_id`: Id of the owner program
 * - `pda_seed`: 32 byte seed
 *
 * # Returns
 * - `FfiBytes32` representing account id bytes
 */
struct FfiBytes32 wallet_ffi_account_id_for_public_pda(struct FfiProgramId program_id,
                                                       FfiPdaSeed pda_seed);

/**
 * Produce account id for private PDA.
 *
 * # Parameters
 * - `program_id`: Id of the owner program
 * - `pda_seed`: 32 byte seed
 * - `npk`: 32 byte nullifier public key (can be obtained from
 *   `wallet_ffi_get_private_account_keys`)
 * - `viewing_public_key`: pointer to u8 (can be obtained from
 *   `wallet_ffi_get_private_account_keys`)
 * - `viewing_public_key_len`: length of a `viewing_public_key` (can be obtained from
 *   `wallet_ffi_get_private_account_keys`), must be `1184`
 * - `identifier`: little endian encoded `u128`
 * - `account_id`: valid pointer to `FfiBytes32`
 *
 * # Returns
 * - `Success` on successful parsing
 * - Error code on failure
 *
 * # Safety
 * - `viewing_public_key` must be a valid pointer to a `u8`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 */
enum WalletFfiError wallet_ffi_account_id_for_private_pda(struct FfiProgramId program_id,
                                                          FfiPdaSeed pda_seed,
                                                          FfiNullifierPublicKey npk,
                                                          const uint8_t *viewing_public_key,
                                                          uintptr_t viewing_public_key_len,
                                                          struct FfiU128 identifier,
                                                          struct FfiBytes32 *account_id);

/**
 * Claim a pinata reward using a public transaction.
 *
 * Sends a public claim transaction to the pinata program.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `pinata_account_id`: The pinata program account ID
 * - `winner_account_id`: The recipient account ID
 * - `solution`: The solution value as little-endian [u8; 16]
 * - `out_result`: Output pointer for the transaction result
 *
 * # Returns
 * - `Success` if the claim transaction was submitted successfully
 * - Error code on failure
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `solution` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_claim_pinata(struct WalletHandle *handle,
                                            const struct FfiBytes32 *pinata_account_id,
                                            const struct FfiBytes32 *winner_account_id,
                                            const uint8_t (*solution)[16],
                                            struct FfiTransferResult *out_result);

/**
 * Claim a pinata reward using a private transaction for an already-initialized owned account.
 *
 * Sends a privacy-preserving claim transaction for a winner account that already has
 * an on-chain commitment (i.e. was previously initialized).
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `pinata_account_id`: The pinata program account ID
 * - `winner_account_id`: The recipient private account ID (must be owned by this wallet)
 * - `solution`: The solution value as little-endian [u8; 16]
 * - `winner_proof_index`: Leaf index in the commitment tree for the membership proof
 * - `winner_proof_siblings`: Pointer to an array of 32-byte sibling hashes
 * - `winner_proof_siblings_len`: Number of sibling hashes in the array
 * - `out_result`: Output pointer for the transaction result
 *
 * # Returns
 * - `Success` if the claim transaction was submitted successfully
 * - Error code on failure
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `solution` must be a valid pointer to a `[u8; 16]` array
 * - `winner_proof_siblings` must be a valid pointer to an array of `winner_proof_siblings_len`
 *   elements of `[u8; 32]`, or null if `winner_proof_siblings_len` is 0
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_claim_pinata_private_owned_already_initialized(struct WalletHandle *handle,
                                                                              const struct FfiBytes32 *pinata_account_id,
                                                                              const struct FfiBytes32 *winner_account_id,
                                                                              const uint8_t (*solution)[16],
                                                                              uintptr_t winner_proof_index,
                                                                              const uint8_t (*winner_proof_siblings)[32],
                                                                              uintptr_t winner_proof_siblings_len,
                                                                              struct FfiTransferResult *out_result);

/**
 * Claim a pinata reward using a private transaction for a not-yet-initialized owned account.
 *
 * Sends a privacy-preserving claim transaction for a winner account that has not yet
 * been committed on-chain (i.e. is being initialized as part of this claim).
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `pinata_account_id`: The pinata program account ID
 * - `winner_account_id`: The recipient private account ID (must be owned by this wallet)
 * - `solution`: The solution value as little-endian [u8; 16]
 * - `out_result`: Output pointer for the transaction result
 *
 * # Returns
 * - `Success` if the claim transaction was submitted successfully
 * - Error code on failure
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `solution` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_claim_pinata_private_owned_not_initialized(struct WalletHandle *handle,
                                                                          const struct FfiBytes32 *pinata_account_id,
                                                                          const struct FfiBytes32 *winner_account_id,
                                                                          const uint8_t (*solution)[16],
                                                                          struct FfiTransferResult *out_result);

/**
 * Send a program deployment transaction.
 *
 * Publishes program for future use.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `elf_data`: Valid pointer to elf data in bytes
 * - `elf_size`: Size of elf data
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if deployment was submitted successfully
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transaction_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `elf_data` must be a valid pointer to elf data
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_program_deployment(struct WalletHandle *handle,
                                                  const uint8_t *elf_data,
                                                  uintptr_t elf_size,
                                                  struct FfiTransactionResult *out_result);

/**
 * Writes elf data of authenticated transfer program into buffer.
 *
 * WARNING: Result is not consisent and change between versions, use for testing purposes only.
 *
 * # Parameters
 * - `ffi_program`: Valid pointer to `FfiProgram`
 *
 * # Returns
 * - `Success` if deployment was submitted successfully
 * - Error code on other failures
 *
 * # Memory
 * - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
 *
 * # Safety
 * - `ffi_program` must be a non-null pointer
 */
enum WalletFfiError wallet_ffi_transfer_elf(struct FfiProgram *ffi_program);

/**
 * Writes elf data of authenticated token program into buffer.
 *
 * WARNING: Result is not consisent and change between versions, use for testing purposes only.
 *
 * # Parameters
 * - `ffi_program`: Valid pointer to `FfiProgram`
 *
 * # Returns
 * - `Success` if deployment was submitted successfully
 * - Error code on other failures
 *
 * # Memory
 * - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
 *
 * # Safety
 * - `ffi_program` must be a non-null pointer
 */
enum WalletFfiError wallet_ffi_token_elf(struct FfiProgram *ffi_program);

/**
 * Writes elf data of amm into buffer.
 *
 * WARNING: Result is not consisent and change between versions, use for testing purposes only.
 *
 * # Parameters
 * - `ffi_program`: Valid pointer to `FfiProgram`
 *
 * # Returns
 * - `Success` if deployment was submitted successfully
 * - Error code on other failures
 *
 * # Memory
 * - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
 *
 * # Safety
 * - `ffi_program` must be a non-null pointer
 */
enum WalletFfiError wallet_ffi_amm_elf(struct FfiProgram *ffi_program);

/**
 * Writes elf data of ata into buffer.
 *
 * WARNING: Result is not consisent and change between versions, use for testing purposes only.
 *
 * # Parameters
 * - `ffi_program`: Valid pointer to `FfiProgram`
 *
 * # Returns
 * - `Success` if deployment was submitted successfully
 * - Error code on other failures
 *
 * # Memory
 * - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
 *
 * # Safety
 * - `ffi_program` must be a non-null pointer
 */
enum WalletFfiError wallet_ffi_ata_elf(struct FfiProgram *ffi_program);

/**
 * Free a ffi program returned by functions `wallet_ffi_*_elf`.
 *
 * # Safety
 * The result must be either null or a valid result from a elf getter function.
 */
void wallet_ffi_free_ffi_program(struct FfiProgram *ffi_program);

/**
 * Synchronize private accounts to a specific block.
 *
 * This scans the blockchain from the last synced block to the specified block,
 * updating private account balances based on any relevant transactions.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `block_id`: Target block number to sync to
 *
 * # Returns
 * - `Success` if synchronization completed
 * - `SyncError` if synchronization failed
 * - Error code on other failures
 *
 * # Note
 * This operation can take a while for large block ranges. The wallet
 * internally uses a progress bar which may output to stdout.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 */
enum WalletFfiError wallet_ffi_sync_to_block(struct WalletHandle *handle, uint64_t block_id);

/**
 * Get the last synced block number.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_block_id`: Output pointer for the block number
 *
 * # Returns
 * - `Success` on success
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_block_id` must be a valid pointer to a `u64`
 */
enum WalletFfiError wallet_ffi_get_last_synced_block(struct WalletHandle *handle,
                                                     uint64_t *out_block_id);

/**
 * Get the current block height from the sequencer.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `out_block_height`: Output pointer for the current block height
 *
 * # Returns
 * - `Success` on success
 * - `NetworkError` if the sequencer is unreachable
 * - Error code on other failures
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `out_block_height` must be a valid pointer to a `u64`
 */
enum WalletFfiError wallet_ffi_get_current_block_height(struct WalletHandle *handle,
                                                        uint64_t *out_block_height);

/**
 * Send a public token transfer.
 *
 * Transfers tokens from one public account to another on the network.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source account ID (must be owned by this wallet)
 * - `to`: Destination account ID
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if the source account's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_public(struct WalletHandle *handle,
                                               const struct FfiBytes32 *from,
                                               const struct FfiBytes32 *to,
                                               const uint8_t (*amount)[16],
                                               struct FfiTransferResult *out_result);

/**
 * Send a shielded token transfer.
 *
 * Transfers tokens from a public account to a private account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source account ID (must be owned by this wallet)
 * - `to_keys`: Destination account keys
 * - `to_identifier`: Identifier for the recipient's private account
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if the source account's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_shielded(struct WalletHandle *handle,
                                                 const struct FfiBytes32 *from,
                                                 const struct FfiPrivateAccountKeys *to_keys,
                                                 const struct FfiU128 *to_identifier,
                                                 const uint8_t (*amount)[16],
                                                 const char *key_path,
                                                 struct FfiTransferResult *out_result);

/**
 * Send a deshielded token transfer.
 *
 * Transfers tokens from a private account to a public account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source account ID (must be owned by this wallet)
 * - `to`: Destination account ID
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if the source account's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_deshielded(struct WalletHandle *handle,
                                                   const struct FfiBytes32 *from,
                                                   const struct FfiBytes32 *to,
                                                   const uint8_t (*amount)[16],
                                                   struct FfiTransferResult *out_result);

/**
 * Send a private token transfer.
 *
 * Transfers tokens from a private account to another private account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source account ID (must be owned by this wallet)
 * - `to_keys`: Destination account keys
 * - `to_identifier`: Identifier for the recipient's private account
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if the source account's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_private(struct WalletHandle *handle,
                                                const struct FfiBytes32 *from,
                                                const struct FfiPrivateAccountKeys *to_keys,
                                                const struct FfiU128 *to_identifier,
                                                const uint8_t (*amount)[16],
                                                struct FfiTransferResult *out_result);

/**
 * Send a shielded token transfer to an owned private account.
 *
 * Transfers tokens from a public account to a private account that is owned
 * by this wallet. Unlike `wallet_ffi_transfer_shielded` which sends to a
 * foreign account using NPK/VPK keys, this variant takes a destination
 * account ID that must belong to this wallet.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source public account ID (must be owned by this wallet)
 * - `to`: Destination private account ID (must be owned by this wallet)
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if either account's keys are not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_shielded_owned(struct WalletHandle *handle,
                                                       const struct FfiBytes32 *from,
                                                       const struct FfiBytes32 *to,
                                                       const uint8_t (*amount)[16],
                                                       const char *key_path,
                                                       struct FfiTransferResult *out_result);

/**
 * Send a private token transfer to an owned private account.
 *
 * Transfers tokens from a private account to another private account that is
 * owned by this wallet. Unlike `wallet_ffi_transfer_private` which sends to a
 * foreign account using NPK/VPK keys, this variant takes a destination
 * account ID that must belong to this wallet.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `from`: Source private account ID (must be owned by this wallet)
 * - `to`: Destination private account ID (must be owned by this wallet)
 * - `amount`: Amount to transfer as little-endian [u8; 16]
 * - `out_result`: Output pointer for transfer result
 *
 * # Returns
 * - `Success` if the transfer was submitted successfully
 * - `InsufficientFunds` if the source account doesn't have enough balance
 * - `KeyNotFound` if either account's keys are not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `from` must be a valid pointer to a `FfiBytes32` struct
 * - `to` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_transfer_private_owned(struct WalletHandle *handle,
                                                      const struct FfiBytes32 *from,
                                                      const struct FfiBytes32 *to,
                                                      const uint8_t (*amount)[16],
                                                      struct FfiTransferResult *out_result);

/**
 * Register a public account on the network.
 *
 * This initializes a public account on the blockchain. The account must be
 * owned by this wallet.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: Account ID to register
 * - `out_result`: Output pointer for registration result
 *
 * # Returns
 * - `Success` if the registration was submitted successfully
 * - Error code on failure
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_register_public_account(struct WalletHandle *handle,
                                                       const struct FfiBytes32 *account_id,
                                                       struct FfiTransferResult *out_result);

/**
 * Register a private account on the network.
 *
 * This initializes a private account. The account must be
 * owned by this wallet.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `account_id`: Account ID to register
 * - `out_result`: Output pointer for registration result
 *
 * # Returns
 * - `Success` if the registration was submitted successfully
 * - Error code on failure
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `account_id` must be a valid pointer to a `FfiBytes32` struct
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_register_private_account(struct WalletHandle *handle,
                                                        const struct FfiBytes32 *account_id,
                                                        struct FfiTransferResult *out_result);

/**
 * Free a transfer result returned by `wallet_ffi_transfer_public` or
 * `wallet_ffi_register_public_account`.
 *
 * # Safety
 * The result must be either null or a valid result from a transfer function.
 */
void wallet_ffi_free_transfer_result(struct FfiTransferResult *result);

/**
 * Get the claimable balance held in an account's bridge vault.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `owner`: The account ID whose vault balance to query
 * - `out_balance`: Output for balance as little-endian [u8; 16]
 *
 * # Returns
 * - `Success` on successful query
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `owner` must be a valid pointer to a `FfiBytes32` struct
 * - `out_balance` must be a valid pointer to a `[u8; 16]` array
 */
enum WalletFfiError wallet_ffi_get_vault_balance(struct WalletHandle *handle,
                                                 const struct FfiBytes32 *owner,
                                                 uint8_t (*out_balance)[16]);

/**
 * Claim native tokens from a public owner's vault into their account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `owner`: Owner account ID (must be owned by this wallet, public)
 * - `amount`: Amount to claim as little-endian [u8; 16]
 * - `out_result`: Output pointer for the claim result
 *
 * # Returns
 * - `Success` if the claim was submitted successfully
 * - `InsufficientFunds` if the vault doesn't have enough balance
 * - `KeyNotFound` if the owner's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `owner` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_vault_claim(struct WalletHandle *handle,
                                           const struct FfiBytes32 *owner,
                                           const uint8_t (*amount)[16],
                                           struct FfiTransferResult *out_result);

/**
 * Claim native tokens from a private owner's vault into their account.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `owner`: Owner account ID (must be owned by this wallet, private)
 * - `amount`: Amount to claim as little-endian [u8; 16]
 * - `out_result`: Output pointer for the claim result
 *
 * # Returns
 * - `Success` if the claim was submitted successfully
 * - `InsufficientFunds` if the vault doesn't have enough balance
 * - `KeyNotFound` if the owner's signing key is not in this wallet
 * - Error code on other failures
 *
 * # Memory
 * The result must be freed with `wallet_ffi_free_transfer_result()`.
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `owner` must be a valid pointer to a `FfiBytes32` struct
 * - `amount` must be a valid pointer to a `[u8; 16]` array
 * - `out_result` must be a valid pointer to a `FfiTransferResult` struct
 */
enum WalletFfiError wallet_ffi_vault_claim_private(struct WalletHandle *handle,
                                                   const struct FfiBytes32 *owner,
                                                   const uint8_t (*amount)[16],
                                                   struct FfiTransferResult *out_result);

/**
 * Create a new wallet with fresh storage.
 *
 * This initializes a new wallet with a new seed derived from the password.
 * Use this for first-time wallet creation.
 *
 * # Parameters
 * - `config_path`: Path to the wallet configuration file (JSON)
 * - `storage_path`: Path where wallet data will be stored
 * - `statistics_path`: Path to the wallet statistics file (JSON)
 * - `password`: Password for encrypting the wallet seed
 *
 * # Returns
 * - Result, which contains opaque wallet handle and mnemonic words on success
 * - Result with null pointers on error (call `wallet_ffi_get_last_error()` for details)
 *
 * # Safety
 * All string parameters must be valid null-terminated UTF-8 strings.
 */
struct FfiCreateWalletOutput wallet_ffi_create_new(const char *config_path,
                                                   const char *storage_path,
                                                   const char *statistics_path,
                                                   const char *password);

/**
 * Open an existing wallet from storage.
 *
 * This loads a wallet that was previously created with `wallet_ffi_create_new()`.
 *
 * # Parameters
 * - `config_path`: Path to the wallet configuration file (JSON)
 * - `storage_path`: Path to the wallet storage (JSON)
 * - `statistics_path`: Path to the wallet statistics file (JSON)
 *
 * # Returns
 * - Opaque wallet handle on success
 * - Null pointer on error (call `wallet_ffi_get_last_error()` for details)
 *
 * # Safety
 * All string parameters must be valid null-terminated UTF-8 strings.
 */
struct WalletHandle *wallet_ffi_open(const char *config_path,
                                     const char *storage_path,
                                     const char *statistics_path);

/**
 * Destroy a wallet handle and free its resources.
 *
 * After calling this function, the handle is invalid and must not be used.
 *
 * # Safety
 * - The handle must be either null or a valid handle from `wallet_ffi_create_new()` or
 *   `wallet_ffi_open()`.
 * - The handle must not be used after this call.
 */
void wallet_ffi_destroy(struct WalletHandle *handle);

/**
 * Save wallet state to persistent storage.
 *
 * This should be called periodically or after important operations to ensure
 * wallet data is persisted to disk.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 *
 * # Returns
 * - `Success` on successful save
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 */
enum WalletFfiError wallet_ffi_save(struct WalletHandle *handle);

/**
 * Restore wallet data from mnemonic and password.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 * - `mnemonic`: Valid pointer to instance of `* char`, provided by `wallet_ffi_create_new`
 * - `password`: Valid pointer to C string.
 * - `depth`: Depth of a reconstructed tree
 *
 * # Returns
 * - `Success` on successful restoration
 * - Error code on failure
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 * - `mnemonic` must be a valid pointer to instance of `* char`, provided by
 *   `wallet_ffi_create_new`
 * - `password` must be a valid pointer to C string.
 * - `depth` parameter induces exponential growth in execution time, be aware of it.
 */
enum WalletFfiError wallet_ffi_restore_data(struct WalletHandle *handle,
                                            const char *mnemonic,
                                            const char *password,
                                            uint32_t depth);

/**
 * Get the sequencer address from the wallet configuration.
 *
 * # Parameters
 * - `handle`: Valid wallet handle
 *
 * # Returns
 * - Pointer to null-terminated string on success (caller must free with
 *   `wallet_ffi_free_string()`)
 * - Null pointer on error
 *
 * # Safety
 * - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
 */
char *wallet_ffi_get_sequencer_addr(struct WalletHandle *handle);

/**
 * Free a string returned by wallet FFI functions.
 *
 * # Safety
 * The pointer must be either null or a valid string returned by an FFI function.
 */
void wallet_ffi_free_string(char *ptr);

#endif  /* WALLET_FFI_H */
