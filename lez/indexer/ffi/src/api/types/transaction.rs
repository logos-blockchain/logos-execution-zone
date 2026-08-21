use indexer_service_protocol::{
    AccountDiff, AccountDiffOutput, AccountId, BalanceDiff, Ciphertext, Claim, Commitment,
    CommitmentSetDigest, EncryptedAccountData, EphemeralPublicKey, HashType, Nullifier, PdaSeed,
    PrivacyPreservingMessage, PrivacyPreservingTransaction, PrivateAction,
    ProgramDeploymentMessage, ProgramDeploymentTransaction, ProgramId, Proof, PublicDiff,
    PublicKey, PublicMessage, PublicTransaction, Signature, Transaction, ValidityWindow,
    WitnessSet,
};

use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiProgramId, FfiPublicKey, FfiSignature,
    FfiU128, FfiVec,
    vectors::{
        FfiAccountIdList, FfiInstructionDataList, FfiNonceList, FfiPrivateActionList,
        FfiProgramDeploymentMessage, FfiProof, FfiPublicDiffList, FfiSignaturePubKeyList, FfiVecU8,
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
                program_id: ProgramId(value.message.program_id.data),
                account_ids: {
                    let std_vec: Vec<_> = value.message.account_ids.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| AccountId {
                            value: ffi_val.data,
                        })
                        .collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                instruction_data: value.message.instruction_data.into(),
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

#[repr(C)]
pub struct FfiPublicMessage {
    pub program_id: FfiProgramId,
    pub account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub instruction_data: FfiInstructionDataList,
}

impl From<PublicMessage> for FfiPublicMessage {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        } = value;

        Self {
            program_id: program_id.into(),
            account_ids: account_ids
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            instruction_data: instruction_data.into(),
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
                public_diffs: {
                    let std_vec: Vec<_> = value.message.public_diffs.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
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
                signer_account_ids: {
                    let std_vec: Vec<_> = value.message.signer_account_ids.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| AccountId {
                            value: ffi_val.data,
                        })
                        .collect()
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

/// C-compatible tagged `BalanceDiff`: `is_sub` selects `Sub` over `Add`.
#[repr(C)]
pub struct FfiBalanceDiff {
    pub is_sub: bool,
    pub amount: FfiU128,
}

impl From<BalanceDiff> for FfiBalanceDiff {
    fn from(value: BalanceDiff) -> Self {
        match value {
            BalanceDiff::Add(amount) => Self {
                is_sub: false,
                amount: amount.into(),
            },
            BalanceDiff::Sub(amount) => Self {
                is_sub: true,
                amount: amount.into(),
            },
        }
    }
}

impl From<FfiBalanceDiff> for BalanceDiff {
    fn from(value: FfiBalanceDiff) -> Self {
        let amount: u128 = value.amount.into();
        if value.is_sub {
            Self::Sub(amount)
        } else {
            Self::Add(amount)
        }
    }
}

/// C-compatible tagged `Claim`: `is_pda` selects `Pda(seed)` over `Authorized`, in which case
/// `pda_seed` is meaningless.
#[repr(C)]
pub struct FfiClaim {
    pub is_pda: bool,
    pub pda_seed: FfiBytes32,
}

impl From<Claim> for FfiClaim {
    fn from(value: Claim) -> Self {
        match value {
            Claim::Authorized => Self {
                is_pda: false,
                pda_seed: FfiBytes32::default(),
            },
            Claim::Pda(seed) => Self {
                is_pda: true,
                pda_seed: FfiBytes32 { data: seed.0 },
            },
        }
    }
}

impl From<FfiClaim> for Claim {
    fn from(value: FfiClaim) -> Self {
        if value.is_pda {
            Self::Pda(PdaSeed(value.pda_seed.data))
        } else {
            Self::Authorized
        }
    }
}

#[repr(C)]
pub struct FfiAccountDiff {
    pub id: FfiAccountId,
    pub diff_balance: FfiBalanceDiff,
    pub diff_data: FfiOption<FfiVecU8>,
}

impl From<AccountDiff> for FfiAccountDiff {
    fn from(value: AccountDiff) -> Self {
        let AccountDiff {
            id,
            diff_balance,
            diff_data,
        } = value;
        Self {
            id: id.into(),
            diff_balance: diff_balance.into(),
            diff_data: diff_data.map_or_else(FfiOption::from_none, |bytes| {
                FfiOption::from_value(bytes.into())
            }),
        }
    }
}

impl From<FfiAccountDiff> for AccountDiff {
    fn from(value: FfiAccountDiff) -> Self {
        let FfiAccountDiff {
            id,
            diff_balance,
            diff_data,
        } = value;
        let diff_data = diff_data.is_some.then(|| {
            let boxed = unsafe { Box::from_raw(diff_data.value) };
            let bytes: Vec<u8> = (*boxed).into();
            bytes
        });
        Self {
            id: AccountId { value: id.data },
            diff_balance: diff_balance.into(),
            diff_data,
        }
    }
}

#[repr(C)]
pub struct FfiAccountDiffOutput {
    pub diff: FfiAccountDiff,
    pub claim: FfiOption<FfiClaim>,
}

impl From<AccountDiffOutput> for FfiAccountDiffOutput {
    fn from(value: AccountDiffOutput) -> Self {
        let AccountDiffOutput { diff, claim } = value;
        Self {
            diff: diff.into(),
            claim: claim.map_or_else(FfiOption::from_none, |claim| {
                FfiOption::from_value(claim.into())
            }),
        }
    }
}

impl From<FfiAccountDiffOutput> for AccountDiffOutput {
    fn from(value: FfiAccountDiffOutput) -> Self {
        let FfiAccountDiffOutput { diff, claim } = value;
        let claim = claim.is_some.then(|| {
            let boxed = unsafe { Box::from_raw(claim.value) };
            (*boxed).into()
        });
        Self {
            diff: diff.into(),
            claim,
        }
    }
}

#[repr(C)]
pub struct FfiPublicDiff {
    pub account_id: FfiAccountId,
    pub executing_program_id: FfiProgramId,
    pub diff: FfiAccountDiffOutput,
}

impl From<PublicDiff> for FfiPublicDiff {
    fn from(value: PublicDiff) -> Self {
        let PublicDiff {
            account_id,
            executing_program_id,
            diff,
        } = value;
        Self {
            account_id: account_id.into(),
            executing_program_id: executing_program_id.into(),
            diff: diff.into(),
        }
    }
}

impl From<FfiPublicDiff> for PublicDiff {
    fn from(value: FfiPublicDiff) -> Self {
        let FfiPublicDiff {
            account_id,
            executing_program_id,
            diff,
        } = value;
        Self {
            account_id: AccountId {
                value: account_id.data,
            },
            executing_program_id: ProgramId(executing_program_id.data),
            diff: diff.into(),
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
    pub public_diffs: FfiPublicDiffList,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
    pub signer_account_ids: FfiAccountIdList,
}

impl From<PrivacyPreservingMessage> for FfiPrivacyPreservingMessage {
    fn from(value: PrivacyPreservingMessage) -> Self {
        let PrivacyPreservingMessage {
            public_diffs,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            signer_account_ids,
        } = value;

        Self {
            public_diffs: public_diffs
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
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
            signer_account_ids: signer_account_ids
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
pub struct FfiProgramDeploymentTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiProgramDeploymentMessage,
}

impl From<Box<FfiProgramDeploymentTransactionBody>> for ProgramDeploymentTransaction {
    fn from(value: Box<FfiProgramDeploymentTransactionBody>) -> Self {
        Self {
            hash: HashType(value.hash.data),
            message: ProgramDeploymentMessage {
                bytecode: value.message.into(),
            },
        }
    }
}

impl From<ProgramDeploymentTransaction> for FfiProgramDeploymentTransactionBody {
    fn from(value: ProgramDeploymentTransaction) -> Self {
        let ProgramDeploymentTransaction { hash, message } = value;

        Self {
            hash: hash.into(),
            message: message.bytecode.into(),
        }
    }
}

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *mut FfiPublicTransactionBody,
    pub private_body: *mut FfiPrivateTransactionBody,
    pub program_deployment_body: *mut FfiProgramDeploymentTransactionBody,
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
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            Transaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Private,
            },
            Transaction::ProgramDeployment(pr_dep_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: std::ptr::null_mut(),
                    program_deployment_body: Box::into_raw(Box::new(pr_dep_tx.into())),
                },
                kind: FfiTransactionKind::ProgramDeploy,
            },
        }
    }
}

#[repr(C)]
pub enum FfiTransactionKind {
    Public = 0x0,
    Private,
    ProgramDeploy,
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
        FfiTransactionKind::ProgramDeploy => {
            let body = unsafe { Box::from_raw(val.body.program_deployment_body) };
            let std_body: ProgramDeploymentTransaction = body.into();
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
