#ifndef FFI_TYPES_H
#define FFI_TYPES_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum FfiBoundaryStepKind {
  PrivateToPublic = 0,
  PublicToPrivate,
  EndPrivateSubtree,
  EndPublicSubtree,
} FfiBoundaryStepKind;

typedef enum FfiPublicAccountEvidenceKind {
  Key = 0,
  Pda,
} FfiPublicAccountEvidenceKind;

/**
 * 32-byte array type for `AccountId`, keys, hashes, etc.
 */
typedef struct FfiBytes32 {
  uint8_t data[32];
} FfiBytes32;

typedef struct FfiBytes32 FfiAccountId;

typedef struct FfiVec_FfiAccountId {
  FfiAccountId *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiAccountId;

typedef struct FfiVec_FfiAccountId FfiAccountIdList;

/**
 * Identifies one of an account's program actor states.
 */
typedef struct FfiActor {
  FfiAccountId account_id;
  FfiAccountId program_account_id;
} FfiActor;

typedef struct FfiVec_FfiActor {
  struct FfiActor *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiActor;

typedef struct FfiVec_FfiActor FfiActorList;

typedef struct FfiVec_u8 {
  uint8_t *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_u8;

typedef struct FfiVec_u8 FfiMessageDataList;

typedef struct FfiVec_FfiBytes32 {
  struct FfiBytes32 *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiBytes32;

typedef struct FfiVec_FfiBytes32 FfiPdaSeedList;

typedef struct FfiDelivery {
  struct FfiActor from;
  struct FfiActor to;
  FfiMessageDataList message;
  FfiAccountIdList inherited_authorizations;
  bool inherits_entry_authorizations;
  FfiPdaSeedList pda_seeds;
} FfiDelivery;

/**
 * One step of a proof's boundary trace (`delivery`, meaningful only for `PrivateToPublic` and
 * `PublicToPrivate`).
 */
typedef struct FfiBoundaryStep {
  enum FfiBoundaryStepKind kind;
  struct FfiDelivery delivery;
} FfiBoundaryStep;

typedef struct FfiVec_FfiBoundaryStep {
  struct FfiBoundaryStep *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiBoundaryStep;

typedef struct FfiVec_FfiBoundaryStep FfiBoundaryStepList;

/**
 * 64-byte array type for signatures, etc.
 */
typedef struct FfiBytes64 {
  uint8_t data[64];
} FfiBytes64;

typedef struct FfiVec_u64 {
  uint64_t *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_u64;

typedef struct FfiVec_u64 FfiCastPromotionList;

typedef struct FfiVec_u8 FfiVecU8;

typedef struct FfiEncryptedAccountData {
  FfiVecU8 ciphertext;
  FfiVecU8 epk;
} FfiEncryptedAccountData;

/**
 * U128 - 16 bytes little endian.
 */
typedef struct FfiU128 {
  uint8_t data[16];
} FfiU128;

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

typedef struct FfiU128 FfiNonce;

/**
 * One signer's replay nonce.
 */
typedef struct FfiNonceEntry {
  FfiAccountId account_id;
  FfiNonce nonce;
} FfiNonceEntry;

typedef struct FfiVec_FfiNonceEntry {
  struct FfiNonceEntry *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiNonceEntry;

typedef struct FfiVec_FfiNonceEntry FfiNonceList;

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

typedef struct FfiPublicExecutionContext {
  FfiActorList actors;
  FfiAccountIdList authorized_accounts;
  FfiCastPromotionList cast_promotions;
} FfiPublicExecutionContext;

typedef struct FfiBytes32 FfiPublicKey;

typedef struct FfiPublicAccountEvidence {
  enum FfiPublicAccountEvidenceKind kind;
  FfiPublicKey key;
  FfiAccountId program;
  struct FfiBytes32 seed;
} FfiPublicAccountEvidence;

typedef struct FfiVec_FfiPublicAccountEvidence {
  struct FfiPublicAccountEvidence *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiPublicAccountEvidence;

typedef struct FfiVec_FfiPublicAccountEvidence FfiPublicAccountEvidenceList;

typedef struct FfiRecoveryBinding {
  FfiAccountId address;
  FfiVecU8 epk;
  FfiVecU8 ciphertext;
} FfiRecoveryBinding;

typedef struct FfiVec_FfiRecoveryBinding {
  struct FfiRecoveryBinding *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiRecoveryBinding;

typedef struct FfiVec_FfiRecoveryBinding FfiRecoveryBindingList;

/**
 * How a proven transaction starts, as far as its proof discloses: a Call to a public actor.
 */
typedef struct FfiRootCall {
  struct FfiActor to;
  FfiMessageDataList message;
} FfiRootCall;

/**
 * One Cast a proof publishes.
 */
typedef struct FfiSealedCast {
  struct FfiBytes32 commitment;
  FfiVecU8 epk;
  FfiVecU8 ciphertext;
} FfiSealedCast;

typedef struct FfiVec_FfiSealedCast {
  struct FfiSealedCast *entries;
  uintptr_t len;
  uintptr_t capacity;
} FfiVec_FfiSealedCast;

typedef struct FfiVec_FfiSealedCast FfiSealedCastList;

typedef struct FfiBytes64 FfiSignature;

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

#endif  /* FFI_TYPES_H */
