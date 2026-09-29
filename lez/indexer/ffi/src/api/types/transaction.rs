use indexer_service_protocol::{
    AccountId, Actor, Assumption, Boundary, Ciphertext, Commitment, CommitmentSetDigest, Declared,
    EncryptedAccountData, EphemeralPublicKey, FeeDeclaration, HashType, Nullifier, Origin, Output,
    PdaSeed, PrivacyPreservingMessage, PrivacyPreservingTransaction, PrivateAction, Proof,
    PublicKey, PublicMessage, PublicTransaction, ScheduleOp, Signature, Transaction,
    ValidityWindow, WitnessSet,
};

use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiPublicKey, FfiSignature, FfiU128, FfiVec,
    vectors::{
        FfiAccountIdList, FfiActorList, FfiAssumptionList, FfiMessageDataList, FfiNonceList,
        FfiOutputList, FfiPdaSeedList, FfiPrivateActionList, FfiProof, FfiScheduleOpList,
        FfiSignaturePubKeyList, FfiVecU8,
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
                to: value.message.to.into(),
                message: value.message.message.into(),
                public_actors: {
                    let std_vec: Vec<_> = value.message.public_actors.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                fee: value.message.has_fee.then(|| value.message.fee.into()),
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
pub struct FfiPublicMessage {
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub public_actors: FfiActorList,
    pub nonces: FfiNonceList,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
}

impl From<PublicMessage> for FfiPublicMessage {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            to,
            message,
            public_actors,
            nonces,
            fee,
        } = value;

        Self {
            to: to.into(),
            message: message.into(),
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
                declared: value.message.declared.into(),
                boundary: value.message.boundary.into(),
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

/// Where a delivery came from: the root, or the program that sent it
/// (`program_account_id`, meaningful when `is_root` is false).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiOrigin {
    pub is_root: bool,
    pub program_account_id: FfiAccountId,
}

impl From<Origin> for FfiOrigin {
    fn from(value: Origin) -> Self {
        match value {
            Origin::Root => Self {
                is_root: true,
                program_account_id: FfiAccountId::default(),
            },
            Origin::Program(program) => Self {
                is_root: false,
                program_account_id: program.into(),
            },
        }
    }
}

impl From<FfiOrigin> for Origin {
    fn from(value: FfiOrigin) -> Self {
        if value.is_root {
            Self::Root
        } else {
            Self::Program(AccountId {
                value: value.program_account_id.data,
            })
        }
    }
}

#[repr(C)]
pub struct FfiOutput {
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub origin: FfiOrigin,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Output> for FfiOutput {
    fn from(value: Output) -> Self {
        let Output {
            to,
            message,
            origin,
            grants,
            pda_seeds,
        } = value;

        Self {
            to: to.into(),
            message: message.into(),
            origin: origin.into(),
            grants: grants_to_ffi(grants),
            pda_seeds: pda_seeds
                .into_iter()
                .map(pda_seed_to_ffi)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiOutput> for Output {
    fn from(value: FfiOutput) -> Self {
        Self {
            to: value.to.into(),
            message: value.message.into(),
            origin: value.origin.into(),
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
    pub from: FfiActor,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Assumption> for FfiAssumption {
    fn from(value: Assumption) -> Self {
        let Assumption {
            from,
            to,
            message,
            grants,
            pda_seeds,
        } = value;

        Self {
            from: from.into(),
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
            from: value.from.into(),
            to: value.to.into(),
            message: value.message.into(),
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
pub enum FfiScheduleOp {
    CallPublic = 0,
    EnterPrivate,
    LeavePrivate,
    ReturnPublic,
}

impl From<ScheduleOp> for FfiScheduleOp {
    fn from(value: ScheduleOp) -> Self {
        match value {
            ScheduleOp::CallPublic => Self::CallPublic,
            ScheduleOp::EnterPrivate => Self::EnterPrivate,
            ScheduleOp::LeavePrivate => Self::LeavePrivate,
            ScheduleOp::ReturnPublic => Self::ReturnPublic,
        }
    }
}

impl From<FfiScheduleOp> for ScheduleOp {
    fn from(value: FfiScheduleOp) -> Self {
        match value {
            FfiScheduleOp::CallPublic => Self::CallPublic,
            FfiScheduleOp::EnterPrivate => Self::EnterPrivate,
            FfiScheduleOp::LeavePrivate => Self::LeavePrivate,
            FfiScheduleOp::ReturnPublic => Self::ReturnPublic,
        }
    }
}

#[repr(C)]
pub struct FfiBoundary {
    pub outputs: FfiOutputList,
    pub assumptions: FfiAssumptionList,
    pub schedule: FfiScheduleOpList,
}

impl From<Boundary> for FfiBoundary {
    fn from(value: Boundary) -> Self {
        let Boundary {
            outputs,
            assumptions,
            schedule,
        } = value;

        Self {
            outputs: outputs
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            assumptions: assumptions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            schedule: schedule
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiBoundary> for Boundary {
    fn from(value: FfiBoundary) -> Self {
        let outputs: Vec<FfiOutput> = value.outputs.into();
        let assumptions: Vec<FfiAssumption> = value.assumptions.into();
        let schedule: Vec<FfiScheduleOp> = value.schedule.into();

        Self {
            outputs: outputs.into_iter().map(Into::into).collect(),
            assumptions: assumptions.into_iter().map(Into::into).collect(),
            schedule: schedule.into_iter().map(Into::into).collect(),
        }
    }
}

#[repr(C)]
pub struct FfiDeclared {
    pub public_actors: FfiActorList,
    pub authorized_accounts: FfiAccountIdList,
}

impl From<Declared> for FfiDeclared {
    fn from(value: Declared) -> Self {
        let Declared {
            public_actors,
            authorized_accounts,
        } = value;

        Self {
            public_actors: public_actors
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

impl From<FfiDeclared> for Declared {
    fn from(value: FfiDeclared) -> Self {
        let public_actors: Vec<FfiActor> = value.public_actors.into();
        let authorized_accounts: Vec<FfiAccountId> = value.authorized_accounts.into();

        Self {
            public_actors: public_actors.into_iter().map(Into::into).collect(),
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
    pub declared: FfiDeclared,
    pub boundary: FfiBoundary,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
}

impl From<PrivacyPreservingMessage> for FfiPrivacyPreservingMessage {
    fn from(value: PrivacyPreservingMessage) -> Self {
        let PrivacyPreservingMessage {
            declared,
            boundary,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
        } = value;

        Self {
            declared: declared.into(),
            boundary: boundary.into(),
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
    fn boundary_outputs_keep_their_order_over_the_ffi() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let output = |data: u8| Output {
            to: Actor {
                account_id: AccountId { value: [1; 32] },
                program_account_id: AccountId { value: [2; 32] },
            },
            message: vec![data],
            origin: Origin::Root,
            grants: vec![],
            pda_seeds: vec![],
        };
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                declared: Declared::default(),
                boundary: Boundary {
                    outputs: vec![output(7), output(8), output(9), output(7)],
                    assumptions: vec![],
                    schedule: vec![
                        ScheduleOp::CallPublic,
                        ScheduleOp::CallPublic,
                        ScheduleOp::CallPublic,
                        ScheduleOp::CallPublic,
                    ],
                },
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: ValidityWindow((None, None)),
                timestamp_validity_window: ValidityWindow((None, None)),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: Some(Proof(vec![])),
            },
        };

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).into();

        assert_eq!(
            back.message.boundary.outputs,
            original.message.boundary.outputs
        );
    }

    #[test]
    fn public_transaction_fee_roundtrips_over_the_ffi() {
        let tx = |fee| PublicTransaction {
            hash: HashType([1; 32]),
            message: PublicMessage {
                to: Actor {
                    account_id: AccountId { value: [3; 32] },
                    program_account_id: indexer_service_protocol::AccountId::native_token_program(),
                },
                message: vec![9, 9],
                public_actors: vec![Actor {
                    account_id: AccountId { value: [3; 32] },
                    program_account_id: indexer_service_protocol::AccountId::native_token_program(),
                }],
                nonces: vec![],
                fee,
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
}
