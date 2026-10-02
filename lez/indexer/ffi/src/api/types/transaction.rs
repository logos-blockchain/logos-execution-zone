use indexer_service_protocol::{
    AccountId, Actor, Assumption, BoundaryStep, Ciphertext, Commitment, CommitmentSetDigest,
    DeliverySource, EncryptedAccountData, EphemeralPublicKey, FeeDeclaration, HashType,
    MessageBody, MessageEnvelope, MessageId, Nullifier, PdaSeed, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, PrivateAction, Proof, PublicDelivery, PublicExecutionContext,
    PublicIdentity, PublicKey, PublicMessage, PublicTransaction, Signature, Transaction,
    TransactionEntry, ValidityWindow, WitnessSet,
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
pub enum FfiTransactionEntryKind {
    Call = 0x0,
    Receive,
}

#[repr(C)]
pub struct FfiTransactionEntry {
    pub kind: FfiTransactionEntryKind,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub message_id: FfiBytes32,
}

impl From<TransactionEntry> for FfiTransactionEntry {
    fn from(value: TransactionEntry) -> Self {
        match value {
            TransactionEntry::Call { to, message } => Self {
                kind: FfiTransactionEntryKind::Call,
                to: to.into(),
                message: message.into(),
                message_id: FfiBytes32::default(),
            },
            TransactionEntry::Receive(id) => Self {
                kind: FfiTransactionEntryKind::Receive,
                to: FfiActor::default(),
                message: Vec::new().into(),
                message_id: message_id_to_ffi(id),
            },
        }
    }
}

impl From<FfiTransactionEntry> for TransactionEntry {
    fn from(value: FfiTransactionEntry) -> Self {
        let message: Vec<u8> = value.message.into();

        match value.kind {
            FfiTransactionEntryKind::Call => Self::Call {
                to: value.to.into(),
                message,
            },
            FfiTransactionEntryKind::Receive => Self::Receive(ffi_to_message_id(value.message_id)),
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
                consumed_message: value
                    .message
                    .has_consumed_message
                    .then(|| ffi_to_message_id(value.message.consumed_message)),
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
pub enum FfiDeliverySourceKind {
    RootSource = 0x0,
    CallSource,
    CastSource,
}

/// Where a delivery came from: the root, or the program that called or cast it
/// (`program`, meaningful unless `kind` is `RootSource`).
#[repr(C)]
pub struct FfiDeliverySource {
    pub kind: FfiDeliverySourceKind,
    pub program: FfiAccountId,
}

impl From<DeliverySource> for FfiDeliverySource {
    fn from(value: DeliverySource) -> Self {
        match value {
            DeliverySource::Root => Self {
                kind: FfiDeliverySourceKind::RootSource,
                program: FfiAccountId::default(),
            },
            DeliverySource::Call(program) => Self {
                kind: FfiDeliverySourceKind::CallSource,
                program: program.into(),
            },
            DeliverySource::Cast(program) => Self {
                kind: FfiDeliverySourceKind::CastSource,
                program: program.into(),
            },
        }
    }
}

impl From<FfiDeliverySource> for DeliverySource {
    fn from(value: FfiDeliverySource) -> Self {
        let program = AccountId {
            value: value.program.data,
        };
        match value.kind {
            FfiDeliverySourceKind::RootSource => Self::Root,
            FfiDeliverySourceKind::CallSource => Self::Call(program),
            FfiDeliverySourceKind::CastSource => Self::Cast(program),
        }
    }
}

#[repr(C)]
pub struct FfiPublicDelivery {
    pub source: FfiDeliverySource,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<PublicDelivery> for FfiPublicDelivery {
    fn from(value: PublicDelivery) -> Self {
        let PublicDelivery {
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

impl From<FfiPublicDelivery> for PublicDelivery {
    fn from(value: FfiPublicDelivery) -> Self {
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
pub struct FfiAssumption {
    pub source: FfiActor,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Assumption> for FfiAssumption {
    fn from(value: Assumption) -> Self {
        let Assumption {
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

impl From<FfiAssumption> for Assumption {
    fn from(value: FfiAssumption) -> Self {
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
    CallPublic = 0,
    EnterPrivate,
    LeavePrivate,
    ReturnPublic,
}

/// One step of a proof's boundary trace (`public_delivery`, meaningful only for `CallPublic`, and
/// `assumption`, meaningful only for `EnterPrivate`).
#[repr(C)]
pub struct FfiBoundaryStep {
    pub kind: FfiBoundaryStepKind,
    pub public_delivery: FfiPublicDelivery,
    pub assumption: FfiAssumption,
}

impl From<BoundaryStep> for FfiBoundaryStep {
    fn from(value: BoundaryStep) -> Self {
        match value {
            BoundaryStep::CallPublic(delivery) => Self {
                kind: FfiBoundaryStepKind::CallPublic,
                public_delivery: delivery.into(),
                assumption: empty_assumption(),
            },
            BoundaryStep::EnterPrivate(assumption) => Self {
                kind: FfiBoundaryStepKind::EnterPrivate,
                public_delivery: empty_public_delivery(),
                assumption: assumption.into(),
            },
            BoundaryStep::LeavePrivate => Self {
                kind: FfiBoundaryStepKind::LeavePrivate,
                public_delivery: empty_public_delivery(),
                assumption: empty_assumption(),
            },
            BoundaryStep::ReturnPublic => Self {
                kind: FfiBoundaryStepKind::ReturnPublic,
                public_delivery: empty_public_delivery(),
                assumption: empty_assumption(),
            },
        }
    }
}

impl From<FfiBoundaryStep> for BoundaryStep {
    fn from(value: FfiBoundaryStep) -> Self {
        let public_delivery = PublicDelivery::from(value.public_delivery);
        let assumption = Assumption::from(value.assumption);
        match value.kind {
            FfiBoundaryStepKind::CallPublic => Self::CallPublic(public_delivery),
            FfiBoundaryStepKind::EnterPrivate => Self::EnterPrivate(assumption),
            FfiBoundaryStepKind::LeavePrivate => Self::LeavePrivate,
            FfiBoundaryStepKind::ReturnPublic => Self::ReturnPublic,
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
    pub has_consumed_message: bool,
    pub consumed_message: FfiBytes32,
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
            consumed_message,
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
            has_consumed_message: consumed_message.is_some(),
            consumed_message: consumed_message.map(message_id_to_ffi).unwrap_or_default(),
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

fn empty_public_delivery() -> FfiPublicDelivery {
    FfiPublicDelivery {
        source: FfiDeliverySource {
            kind: FfiDeliverySourceKind::RootSource,
            program: FfiAccountId::default(),
        },
        to: FfiActor::default(),
        message: Vec::new().into(),
        grants: Vec::new().into(),
        pda_seeds: Vec::new().into(),
    }
}

fn empty_assumption() -> FfiAssumption {
    FfiAssumption {
        source: FfiActor::default(),
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

const fn message_id_to_ffi(id: MessageId) -> FfiBytes32 {
    FfiBytes32 { data: id.0 }
}

const fn ffi_to_message_id(ffi: FfiBytes32) -> MessageId {
    MessageId(ffi.data)
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
    fn boundary_public_deliveries_keep_their_order_over_the_ffi() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let delivery = |data: u8| PublicDelivery {
            envelope: MessageEnvelope {
                source: DeliverySource::Root,
                to: Actor {
                    account_id: AccountId { value: [1; 32] },
                    program_account_id: AccountId { value: [2; 32] },
                },
                message: vec![data],
            },
            grants: vec![],
            pda_seeds: vec![],
        };
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                context: PublicExecutionContext::default(),
                boundary: vec![
                    BoundaryStep::CallPublic(delivery(7)),
                    BoundaryStep::CallPublic(delivery(8)),
                    BoundaryStep::CallPublic(delivery(9)),
                    BoundaryStep::CallPublic(delivery(7)),
                ],
                casts: vec![],
                consumed_message: None,
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: ValidityWindow((None, None)),
                timestamp_validity_window: ValidityWindow((None, None)),
                identities: vec![],
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: Some(Proof(vec![])),
            },
        };

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).into();

        assert_eq!(back.message.boundary, original.message.boundary);
    }

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
                root: TransactionEntry::Receive(MessageId([5; 32])),
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
    fn private_transaction_boundary_consumed_message_and_identities_roundtrip_over_the_ffi() {
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                context: PublicExecutionContext::default(),
                boundary: vec![
                    BoundaryStep::CallPublic(PublicDelivery {
                        envelope: MessageEnvelope {
                            source: DeliverySource::Root,
                            to: actor(5, 6),
                            message: vec![7],
                        },
                        grants: vec![],
                        pda_seeds: vec![],
                    }),
                    BoundaryStep::CallPublic(PublicDelivery {
                        envelope: MessageEnvelope {
                            source: DeliverySource::Call(account_id(12)),
                            to: actor(9, 10),
                            message: vec![11],
                        },
                        grants: vec![account_id(15)],
                        pda_seeds: vec![PdaSeed([16; 32])],
                    }),
                    BoundaryStep::CallPublic(PublicDelivery {
                        envelope: MessageEnvelope {
                            source: DeliverySource::Cast(account_id(40)),
                            to: actor(41, 42),
                            message: vec![43],
                        },
                        grants: vec![],
                        pda_seeds: vec![],
                    }),
                    BoundaryStep::EnterPrivate(Assumption {
                        envelope: MessageEnvelope {
                            source: actor(17, 18),
                            to: actor(19, 20),
                            message: vec![21],
                        },
                        grants: vec![],
                        pda_seeds: vec![],
                    }),
                    BoundaryStep::LeavePrivate,
                    BoundaryStep::ReturnPublic,
                ],
                casts: vec![MessageBody {
                    source: account_id(23),
                    to: actor(24, 25),
                    message: vec![26],
                }],
                consumed_message: Some(MessageId([27; 32])),
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
    fn identical_casts_keep_their_multiplicity_over_the_ffi() {
        let cast = MessageBody {
            source: account_id(1),
            to: actor(2, 3),
            message: vec![4],
        };
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                context: PublicExecutionContext::default(),
                boundary: vec![],
                casts: vec![cast.clone(), cast],
                consumed_message: None,
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: ValidityWindow((None, None)),
                timestamp_validity_window: ValidityWindow((None, None)),
                identities: vec![],
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
}
