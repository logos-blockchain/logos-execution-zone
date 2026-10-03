use indexer_service_protocol::{
    AccountId, Actor, BoundaryStep, Ciphertext, Commitment, CommitmentSetDigest, Delivery,
    EncryptedAccountData, EphemeralPublicKey, FeeDeclaration, HashType, MessageBody, MessageDigest,
    MessageEnvelope, MessageRef, Nullifier, PdaSeed, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, PrivateAction, Proof, PublicExecutionContext, PublicIdentity,
    PublicKey, PublicMessage, PublicTransaction, Signature, Transaction, TransactionEntry,
    ValidityWindow, WitnessSet,
};

use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiPublicKey, FfiSignature, FfiU128, FfiVec,
    vectors::{
        FfiAccountIdList, FfiActorList, FfiBoundaryStepList, FfiMessageBodyList,
        FfiMessageDataList, FfiNonceList, FfiPdaSeedList, FfiPrivateActionList, FfiProof,
        FfiPublicIdentityList, FfiSignaturePubKeyList, FfiVecU8,
    },
};

#[repr(C)]
pub struct FfiPublicTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPublicMessage,
    pub witness_set: FfiSignaturePubKeyList,
}

impl From<PublicTransaction> for FfiPublicTransactionBody {
    fn from(value: PublicTransaction) -> Self {
        let PublicTransaction {
            hash,
            message,
            witness_set,
        } = value;

        Self {
            hash: hash.into(),
            message: message.into(),
            witness_set: witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<Box<FfiPublicTransactionBody>> for PublicTransaction {
    fn from(value: Box<FfiPublicTransactionBody>) -> Self {
        Self {
            hash: HashType(value.hash.data),
            message: PublicMessage {
                root: value.message.root.into(),
                public_actors: {
                    let std_vec: Vec<_> = value.message.public_actors.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                fee: value.message.has_fee.then(|| value.message.fee.into()),
                identities: {
                    let std_vec: Vec<_> = value.message.identities.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: {
                    let std_vec: Vec<_> = value.witness_set.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Signature(ffi_val.signature.data),
                                PublicKey(ffi_val.public_key.data),
                            )
                        })
                        .collect()
                },
                proof: None,
            },
        }
    }
}

/// Fee declaration of a public transaction. Held inline (not behind a
/// pointer): a fee-exempt transaction carries `has_fee == false` and a zeroed
/// declaration.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiFeeDeclaration {
    pub payer: FfiAccountId,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: FfiU128,
}

impl From<FeeDeclaration> for FfiFeeDeclaration {
    fn from(value: FeeDeclaration) -> Self {
        let FeeDeclaration {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;

        Self {
            payer: payer.into(),
            gas_limit,
            tip,
            max_fee: max_fee.into(),
        }
    }
}

impl From<FfiFeeDeclaration> for FeeDeclaration {
    fn from(value: FfiFeeDeclaration) -> Self {
        Self {
            payer: AccountId {
                value: value.payer.data,
            },
            gas_limit: value.gas_limit,
            tip: value.tip,
            max_fee: value.max_fee.into(),
        }
    }
}

/// Identifies one of an account's program shards.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiActor {
    pub account_id: FfiAccountId,
    pub program_account_id: FfiAccountId,
}

impl From<Actor> for FfiActor {
    fn from(value: Actor) -> Self {
        let Actor {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.into(),
        }
    }
}

impl From<FfiActor> for Actor {
    fn from(value: FfiActor) -> Self {
        Self {
            account_id: AccountId {
                value: value.account_id.data,
            },
            program_account_id: AccountId {
                value: value.program_account_id.data,
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiMessageRef {
    pub sequence: FfiU128,
    pub digest: FfiBytes32,
}

impl From<MessageRef> for FfiMessageRef {
    fn from(value: MessageRef) -> Self {
        Self {
            sequence: value.sequence.into(),
            digest: FfiBytes32 {
                data: value.digest.0,
            },
        }
    }
}

impl From<FfiMessageRef> for MessageRef {
    fn from(value: FfiMessageRef) -> Self {
        Self {
            sequence: value.sequence.into(),
            digest: MessageDigest(value.digest.data),
        }
    }
}

#[repr(C)]
pub enum FfiTransactionEntryKind {
    Call = 0x0,
    Cast,
}

#[repr(C)]
pub struct FfiTransactionEntry {
    pub kind: FfiTransactionEntryKind,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub message_ref: FfiMessageRef,
}

impl From<TransactionEntry> for FfiTransactionEntry {
    fn from(value: TransactionEntry) -> Self {
        match value {
            TransactionEntry::Call { to, message } => Self {
                kind: FfiTransactionEntryKind::Call,
                to: to.into(),
                message: message.into(),
                message_ref: FfiMessageRef::default(),
            },
            TransactionEntry::Cast(reference) => Self {
                kind: FfiTransactionEntryKind::Cast,
                to: FfiActor::default(),
                message: Vec::new().into(),
                message_ref: reference.into(),
            },
        }
    }
}

impl From<FfiTransactionEntry> for TransactionEntry {
    fn from(value: FfiTransactionEntry) -> Self {
        match value.kind {
            FfiTransactionEntryKind::Call => Self::Call {
                to: value.to.into(),
                message: value.message.into(),
            },
            FfiTransactionEntryKind::Cast => Self::Cast(value.message_ref.into()),
        }
    }
}

#[repr(C)]
pub enum FfiPublicIdentityKind {
    Key = 0x0,
    Pda,
}

#[repr(C)]
pub struct FfiPublicIdentity {
    pub kind: FfiPublicIdentityKind,
    pub key: FfiPublicKey,
    pub program: FfiAccountId,
    pub seed: FfiBytes32,
}

impl From<PublicIdentity> for FfiPublicIdentity {
    fn from(value: PublicIdentity) -> Self {
        match value {
            PublicIdentity::Key(key) => Self {
                kind: FfiPublicIdentityKind::Key,
                key: key.into(),
                program: FfiAccountId::default(),
                seed: FfiBytes32::default(),
            },
            PublicIdentity::Pda { program, seed } => Self {
                kind: FfiPublicIdentityKind::Pda,
                key: FfiPublicKey::default(),
                program: program.into(),
                seed: pda_seed_to_ffi(seed),
            },
        }
    }
}

impl From<FfiPublicIdentity> for PublicIdentity {
    fn from(value: FfiPublicIdentity) -> Self {
        match value.kind {
            FfiPublicIdentityKind::Key => Self::Key(PublicKey(value.key.data)),
            FfiPublicIdentityKind::Pda => Self::Pda {
                program: AccountId {
                    value: value.program.data,
                },
                seed: ffi_to_pda_seed(value.seed),
            },
        }
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub root: FfiTransactionEntry,
    pub public_actors: FfiActorList,
    pub nonces: FfiNonceList,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
    pub identities: FfiPublicIdentityList,
}

impl From<PublicMessage> for FfiPublicMessage {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            root,
            public_actors,
            nonces,
            fee,
            identities,
        } = value;

        Self {
            root: root.into(),
            public_actors: public_actors
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            has_fee: fee.is_some(),
            fee: fee.map(Into::into).unwrap_or_default(),
            identities: identities
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivateTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPrivacyPreservingMessage,
    pub witness_set: FfiSignaturePubKeyList,
    pub proof: FfiProof,
}

impl From<PrivacyPreservingTransaction> for FfiPrivateTransactionBody {
    fn from(value: PrivacyPreservingTransaction) -> Self {
        let PrivacyPreservingTransaction {
            hash,
            message,
            witness_set,
        } = value;

        Self {
            hash: hash.into(),
            message: message.into(),
            witness_set: witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            proof: witness_set
                .proof
                .expect("Private execution: proof must be present")
                .0
                .into(),
        }
    }
}

impl From<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    fn from(value: Box<FfiPrivateTransactionBody>) -> Self {
        let entry = value.message.entry;
        Self {
            hash: HashType(value.hash.data),
            message: PrivacyPreservingMessage {
                context: value.message.context.into(),
                boundary: {
                    let std_vec: Vec<FfiBoundaryStep> = value.message.boundary.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                casts: {
                    let std_vec: Vec<FfiMessageBody> = value.message.casts.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                entry: value.message.has_entry.then(|| entry.into()),
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                private_actions: {
                    let std_vec: Vec<_> = value.message.private_actions.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| PrivateAction {
                            nullifier: Nullifier(ffi_val.nullifier.data),
                            root: CommitmentSetDigest(ffi_val.root.data),
                            commitment: Commitment(ffi_val.commitment.data),
                            encrypted_post_state: EncryptedAccountData {
                                ciphertext: Ciphertext(
                                    ffi_val.encrypted_post_state.ciphertext.into(),
                                ),
                                epk: EphemeralPublicKey(ffi_val.encrypted_post_state.epk.into()),
                                view_tag: ffi_val.encrypted_post_state.view_tag,
                            },
                        })
                        .collect()
                },
                block_validity_window: cast_ffi_validity_window(
                    value.message.block_validity_window,
                ),
                timestamp_validity_window: cast_ffi_validity_window(
                    value.message.timestamp_validity_window,
                ),
                identities: {
                    let std_vec: Vec<_> = value.message.identities.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: {
                    let std_vec: Vec<_> = value.witness_set.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Signature(ffi_val.signature.data),
                                PublicKey(ffi_val.public_key.data),
                            )
                        })
                        .collect()
                },
                proof: Some(Proof(value.proof.into())),
            },
        }
    }
}

#[repr(C)]
pub struct FfiDelivery<S> {
    pub source: S,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl<S: Into<T>, T> From<Delivery<S>> for FfiDelivery<T> {
    fn from(value: Delivery<S>) -> Self {
        let Delivery {
            envelope:
                MessageEnvelope {
                    source,
                    to,
                    message,
                },
            grants,
            pda_seeds,
        } = value;

        Self {
            source: source.into(),
            to: to.into(),
            message: message.into(),
            grants: grants_to_ffi(grants),
            pda_seeds: pda_seeds
                .into_iter()
                .map(pda_seed_to_ffi)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl<S: Into<T>, T> From<FfiDelivery<S>> for Delivery<T> {
    fn from(value: FfiDelivery<S>) -> Self {
        Self {
            envelope: MessageEnvelope {
                source: value.source.into(),
                to: value.to.into(),
                message: value.message.into(),
            },
            grants: grants_from_ffi(value.grants),
            pda_seeds: {
                let std_vec: Vec<_> = value.pda_seeds.into();
                std_vec.into_iter().map(ffi_to_pda_seed).collect()
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum FfiBoundaryStepKind {
    EnterPublic = 0,
    EnterPrivate,
    ExitPrivate,
    ExitPublic,
}

/// One step of a proof's boundary trace (`public_delivery`, meaningful only for `EnterPublic`, and
/// `private_delivery`, meaningful only for `EnterPrivate`).
#[repr(C)]
pub struct FfiBoundaryStep {
    pub kind: FfiBoundaryStepKind,
    pub public_delivery: FfiDelivery<FfiAccountId>,
    pub private_delivery: FfiDelivery<FfiActor>,
}

impl From<BoundaryStep> for FfiBoundaryStep {
    fn from(value: BoundaryStep) -> Self {
        match value {
            BoundaryStep::EnterPublic(delivery) => Self {
                kind: FfiBoundaryStepKind::EnterPublic,
                public_delivery: delivery.into(),
                private_delivery: empty_delivery(),
            },
            BoundaryStep::EnterPrivate(delivery) => Self {
                kind: FfiBoundaryStepKind::EnterPrivate,
                public_delivery: empty_delivery(),
                private_delivery: delivery.into(),
            },
            BoundaryStep::ExitPrivate => Self {
                kind: FfiBoundaryStepKind::ExitPrivate,
                public_delivery: empty_delivery(),
                private_delivery: empty_delivery(),
            },
            BoundaryStep::ExitPublic => Self {
                kind: FfiBoundaryStepKind::ExitPublic,
                public_delivery: empty_delivery(),
                private_delivery: empty_delivery(),
            },
        }
    }
}

impl From<FfiBoundaryStep> for BoundaryStep {
    fn from(value: FfiBoundaryStep) -> Self {
        match value.kind {
            FfiBoundaryStepKind::EnterPublic => Self::EnterPublic(value.public_delivery.into()),
            FfiBoundaryStepKind::EnterPrivate => Self::EnterPrivate(value.private_delivery.into()),
            FfiBoundaryStepKind::ExitPrivate => Self::ExitPrivate,
            FfiBoundaryStepKind::ExitPublic => Self::ExitPublic,
        }
    }
}

#[repr(C)]
pub struct FfiMessageBody {
    pub source: FfiAccountId,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
}

impl From<MessageBody> for FfiMessageBody {
    fn from(value: MessageBody) -> Self {
        let MessageBody {
            source,
            to,
            message,
        } = value;

        Self {
            source: source.into(),
            to: to.into(),
            message: message.into(),
        }
    }
}

impl From<FfiMessageBody> for MessageBody {
    fn from(value: FfiMessageBody) -> Self {
        Self {
            source: AccountId {
                value: value.source.data,
            },
            to: value.to.into(),
            message: value.message.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPublicExecutionContext {
    pub actors: FfiActorList,
    pub authorized_accounts: FfiAccountIdList,
}

impl From<PublicExecutionContext> for FfiPublicExecutionContext {
    fn from(value: PublicExecutionContext) -> Self {
        let PublicExecutionContext {
            actors,
            authorized_accounts,
        } = value;

        Self {
            actors: actors
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            authorized_accounts: authorized_accounts
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiPublicExecutionContext> for PublicExecutionContext {
    fn from(value: FfiPublicExecutionContext) -> Self {
        let actors: Vec<FfiActor> = value.actors.into();
        let authorized_accounts: Vec<FfiAccountId> = value.authorized_accounts.into();

        Self {
            actors: actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts
                .into_iter()
                .map(|id| AccountId { value: id.data })
                .collect(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivateAction {
    pub nullifier: FfiBytes32,
    pub root: FfiBytes32,
    pub commitment: FfiBytes32,
    pub encrypted_post_state: FfiEncryptedAccountData,
}

impl From<PrivateAction> for FfiPrivateAction {
    fn from(value: PrivateAction) -> Self {
        Self {
            nullifier: FfiBytes32 {
                data: value.nullifier.0,
            },
            root: FfiBytes32 { data: value.root.0 },
            commitment: FfiBytes32 {
                data: value.commitment.0,
            },
            encrypted_post_state: value.encrypted_post_state.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub context: FfiPublicExecutionContext,
    pub boundary: FfiBoundaryStepList,
    pub casts: FfiMessageBodyList,
    pub has_entry: bool,
    pub entry: FfiTransactionEntry,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
    pub identities: FfiPublicIdentityList,
}

impl From<PrivacyPreservingMessage> for FfiPrivacyPreservingMessage {
    fn from(value: PrivacyPreservingMessage) -> Self {
        let PrivacyPreservingMessage {
            context,
            boundary,
            casts,
            entry,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            identities,
        } = value;

        Self {
            context: context.into(),
            boundary: boundary
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            casts: casts.into_iter().map(Into::into).collect::<Vec<_>>().into(),
            has_entry: entry.is_some(),
            entry: entry.map_or_else(empty_transaction_entry, Into::into),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            private_actions: private_actions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            block_validity_window: cast_validity_window(block_validity_window),
            timestamp_validity_window: cast_validity_window(timestamp_validity_window),
            identities: identities
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[repr(C)]
pub struct FfiEncryptedAccountData {
    pub ciphertext: FfiVecU8,
    pub epk: FfiVecU8,
    pub view_tag: u8,
}

impl From<EncryptedAccountData> for FfiEncryptedAccountData {
    fn from(value: EncryptedAccountData) -> Self {
        let EncryptedAccountData {
            ciphertext,
            epk,
            view_tag,
        } = value;

        Self {
            ciphertext: ciphertext.0.into(),
            epk: epk.0.into(),
            view_tag,
        }
    }
}

#[repr(C)]
pub struct FfiSignaturePubKeyEntry {
    pub signature: FfiSignature,
    pub public_key: FfiPublicKey,
}

impl From<(Signature, PublicKey)> for FfiSignaturePubKeyEntry {
    fn from(value: (Signature, PublicKey)) -> Self {
        Self {
            signature: value.0.into(),
            public_key: value.1.into(),
        }
    }
}

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *mut FfiPublicTransactionBody,
    pub private_body: *mut FfiPrivateTransactionBody,
}

#[repr(C)]
pub struct FfiTransaction {
    pub body: FfiTransactionBody,
    pub kind: FfiTransactionKind,
}

impl From<Transaction> for FfiTransaction {
    fn from(value: Transaction) -> Self {
        match value {
            Transaction::Public(pub_tx) => Self {
                body: FfiTransactionBody {
                    public_body: Box::into_raw(Box::new(pub_tx.into())),
                    private_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            Transaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                },
                kind: FfiTransactionKind::Private,
            },
        }
    }
}

#[repr(C)]
pub enum FfiTransactionKind {
    Public = 0x0,
    Private,
}

/// Frees the resources associated with the given ffi transaction.
///
/// # Arguments
///
/// - `val`: An instance of `FfiTransaction`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiTransaction`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction(val: FfiTransaction) {
    match val.kind {
        FfiTransactionKind::Public => {
            let body = unsafe { Box::from_raw(val.body.public_body) };
            let std_body: PublicTransaction = body.into();
            drop(std_body);
        }
        FfiTransactionKind::Private => {
            let body = unsafe { Box::from_raw(val.body.private_body) };
            let std_body: PrivacyPreservingTransaction = body.into();
            drop(std_body);
        }
    }
}

/// Frees the resources associated with the given ffi transaction option.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiOption<FfiTransaction>>` (the `PointerResult.value` pointer),
/// the inner `Box<FfiTransaction>` (when present), and its body.
///
/// # Arguments
///
/// - `val`: The `*mut FfiOption<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiOption<FfiTransaction>` produced by this library and not yet
///   freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_opt(val: *mut FfiOption<FfiTransaction>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner transaction box (if any).
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let tx = unsafe { Box::from_raw(opt.value) };
        unsafe {
            free_ffi_transaction(*tx);
        }
    }
}

/// Frees the resources owned by an `FfiVec<FfiTransaction>` value (the backing
/// buffer and each transaction), without owning an outer box.
///
/// This is the element-level helper shared by the block free path
/// ([`crate::api::types::block::free_ffi_block`], whose body is a transaction
/// vector held by value) and the public [`free_ffi_transaction_vec`] entry
/// point (which first reclaims the outer box).
pub(crate) fn free_transaction_vec_value(val: FfiVec<FfiTransaction>) {
    let ffi_tx_std_vec: Vec<_> = val.into();
    for tx in ffi_tx_std_vec {
        unsafe {
            free_ffi_transaction(tx);
        }
    }
}

/// Frees the resources associated with the given vector of ffi transactions.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiVec<FfiTransaction>>` (the `PointerResult.value` pointer), the
/// vector's backing buffer, and every transaction within it.
///
/// # Arguments
///
/// - `val`: The `*mut FfiVec<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiVec<FfiTransaction>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_vec(val: *mut FfiVec<FfiTransaction>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the backing buffer and each transaction.
    let boxed = unsafe { Box::from_raw(val) };
    free_transaction_vec_value(*boxed);
}

fn empty_transaction_entry() -> FfiTransactionEntry {
    FfiTransactionEntry {
        kind: FfiTransactionEntryKind::Call,
        to: FfiActor::default(),
        message: Vec::new().into(),
        message_ref: FfiMessageRef::default(),
    }
}

fn empty_delivery<S: Default>() -> FfiDelivery<S> {
    FfiDelivery {
        source: S::default(),
        to: FfiActor::default(),
        message: Vec::new().into(),
        grants: Vec::new().into(),
        pda_seeds: Vec::new().into(),
    }
}

fn grants_to_ffi(grants: Vec<AccountId>) -> FfiAccountIdList {
    grants
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>()
        .into()
}

fn grants_from_ffi(grants: FfiAccountIdList) -> Vec<AccountId> {
    let std_vec: Vec<FfiAccountId> = grants.into();
    std_vec
        .into_iter()
        .map(|id| AccountId { value: id.data })
        .collect()
}

const fn pda_seed_to_ffi(seed: PdaSeed) -> FfiBytes32 {
    FfiBytes32 { data: seed.0 }
}

const fn ffi_to_pda_seed(ffi: FfiBytes32) -> PdaSeed {
    PdaSeed(ffi.data)
}

fn cast_validity_window(window: ValidityWindow) -> [u64; 2] {
    [
        window.0.0.unwrap_or_default(),
        window.0.1.unwrap_or(u64::MAX),
    ]
}

const fn cast_ffi_validity_window(ffi_window: [u64; 2]) -> ValidityWindow {
    let left = if ffi_window[0] == 0 {
        None
    } else {
        Some(ffi_window[0])
    };

    let right = if ffi_window[1] == u64::MAX {
        None
    } else {
        Some(ffi_window[1])
    };

    ValidityWindow((left, right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_transaction_fee_roundtrips_over_the_ffi() {
        let tx = |fee| PublicTransaction {
            hash: HashType([1; 32]),
            message: PublicMessage {
                root: TransactionEntry::Call {
                    to: Actor {
                        account_id: AccountId { value: [3; 32] },
                        program_account_id:
                            indexer_service_protocol::AccountId::native_token_program(),
                    },
                    message: vec![9, 9],
                },
                public_actors: vec![Actor {
                    account_id: AccountId { value: [3; 32] },
                    program_account_id: indexer_service_protocol::AccountId::native_token_program(),
                }],
                nonces: vec![],
                fee,
                identities: vec![],
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: None,
            },
        };

        for fee in [
            None,
            Some(FeeDeclaration {
                payer: AccountId { value: [3; 32] },
                gas_limit: 5,
                tip: 1,
                max_fee: 42,
            }),
        ] {
            let original = tx(fee);
            let ffi: FfiPublicTransactionBody = original.clone().into();
            let back: PublicTransaction = Box::new(ffi).into();
            assert_eq!(back.message.fee, original.message.fee);
        }
    }

    fn account_id(tag: u8) -> AccountId {
        AccountId { value: [tag; 32] }
    }

    fn actor(account_tag: u8, program_tag: u8) -> Actor {
        Actor {
            account_id: account_id(account_tag),
            program_account_id: account_id(program_tag),
        }
    }

    fn identities() -> Vec<PublicIdentity> {
        vec![
            PublicIdentity::Key(PublicKey([1; 32])),
            PublicIdentity::Pda {
                program: account_id(2),
                seed: PdaSeed([3; 32]),
            },
        ]
    }

    #[test]
    fn public_transaction_receipt_root_and_identities_roundtrip_over_the_ffi() {
        let original = PublicTransaction {
            hash: HashType([4; 32]),
            message: PublicMessage {
                root: TransactionEntry::Cast(MessageRef {
                    sequence: u128::MAX,
                    digest: MessageDigest([5; 32]),
                }),
                public_actors: vec![actor(6, 7)],
                nonces: vec![],
                fee: None,
                identities: identities(),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: None,
            },
        };

        let ffi: FfiPublicTransactionBody = original.clone().into();
        let back: PublicTransaction = Box::new(ffi).into();

        assert_eq!(back.message, original.message);
    }

    #[test]
    fn private_transaction_boundary_entry_and_identities_roundtrip_over_the_ffi() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let repeated = Delivery {
            envelope: MessageEnvelope {
                source: account_id(3),
                to: actor(5, 6),
                message: vec![7],
            },
            grants: vec![],
            pda_seeds: vec![],
        };
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                context: PublicExecutionContext::default(),
                boundary: vec![
                    BoundaryStep::EnterPublic(repeated.clone()),
                    BoundaryStep::EnterPublic(Delivery {
                        envelope: MessageEnvelope {
                            source: account_id(12),
                            to: actor(9, 10),
                            message: vec![11],
                        },
                        grants: vec![account_id(15)],
                        pda_seeds: vec![PdaSeed([16; 32])],
                    }),
                    BoundaryStep::EnterPublic(Delivery {
                        envelope: MessageEnvelope {
                            source: account_id(40),
                            to: actor(41, 42),
                            message: vec![43],
                        },
                        grants: vec![],
                        pda_seeds: vec![],
                    }),
                    BoundaryStep::EnterPublic(repeated),
                    BoundaryStep::EnterPrivate(Delivery {
                        envelope: MessageEnvelope {
                            source: actor(17, 18),
                            to: actor(19, 20),
                            message: vec![21],
                        },
                        grants: vec![],
                        pda_seeds: vec![],
                    }),
                    BoundaryStep::ExitPrivate,
                    BoundaryStep::ExitPublic,
                ],
                casts: vec![
                    MessageBody {
                        source: account_id(23),
                        to: actor(24, 25),
                        message: vec![26],
                    };
                    2
                ],
                entry: Some(TransactionEntry::Cast(MessageRef {
                    sequence: u128::MAX - 1,
                    digest: MessageDigest([27; 32]),
                })),
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: ValidityWindow((None, None)),
                timestamp_validity_window: ValidityWindow((None, None)),
                identities: identities(),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: Some(Proof(vec![])),
            },
        };

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).into();

        assert_eq!(back.message, original.message);
    }

    #[test]
    fn boundary_steps_decode_only_the_payload_their_kind_selects() {
        let delivery = Delivery {
            envelope: MessageEnvelope {
                source: account_id(1),
                to: actor(2, 3),
                message: vec![4],
            },
            grants: vec![account_id(5)],
            pda_seeds: vec![PdaSeed([6; 32])],
        };
        let cross_message = Delivery {
            envelope: MessageEnvelope {
                source: actor(7, 8),
                to: actor(9, 10),
                message: vec![11],
            },
            grants: vec![account_id(12)],
            pda_seeds: vec![PdaSeed([13; 32])],
        };
        let zeroed = || unsafe { std::mem::zeroed::<FfiBoundaryStep>() };
        let steps = [
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::EnterPublic,
                public_delivery: delivery.clone().into(),
                ..zeroed()
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::EnterPrivate,
                private_delivery: cross_message.clone().into(),
                ..zeroed()
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::ExitPrivate,
                ..zeroed()
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::ExitPublic,
                ..zeroed()
            },
        ];

        assert_eq!(
            steps.map(BoundaryStep::from),
            [
                BoundaryStep::EnterPublic(delivery),
                BoundaryStep::EnterPrivate(cross_message),
                BoundaryStep::ExitPrivate,
                BoundaryStep::ExitPublic,
            ]
        );
    }

    #[test]
    fn a_cast_transaction_entry_decodes_only_its_message_reference() {
        let reference = MessageRef {
            sequence: 7,
            digest: MessageDigest([8; 32]),
        };
        let entry = FfiTransactionEntry {
            kind: FfiTransactionEntryKind::Cast,
            message_ref: reference.into(),
            ..unsafe { std::mem::zeroed::<FfiTransactionEntry>() }
        };

        assert_eq!(
            TransactionEntry::from(entry),
            TransactionEntry::Cast(reference)
        );
    }
}
