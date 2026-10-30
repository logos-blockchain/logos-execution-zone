use std::{
    collections::HashMap,
    ffi::{CString, c_char},
};

use common::HashType;
use lee::{
    AccountId, ProgramId,
    privacy_preserving_transaction::circuit::{Dependency, ProgramCatalog, ProgramKind},
    program::Program,
};
use lee_core::{MembershipProof, program::ProgramHeader};
use wallet::AccountMention;

use crate::{
    error::{FfiOperationError, print_error},
    wallet::{
        FfiAccountMention, FfiBytes32, WalletHandle, block_on, c_string_or_null, fees::FfiSendFee,
        lifecycle::get_wallet, map_execution_error, read_optional_account_id,
    },
};

#[repr(C)]
/// Intended to be created manually.
pub struct FfiProgram {
    pub elf_data: *const u8,
    pub elf_size: usize,
}

impl TryFrom<&FfiProgram> for Program {
    type Error = FfiOperationError;

    fn try_from(value: &FfiProgram) -> Result<Self, Self::Error> {
        let mut elf = Vec::with_capacity(value.elf_size);

        // Alignment will be different, we need to read elements one-by-one
        for i in 0..value.elf_size {
            elf.push(unsafe { *value.elf_data.add(i) });
        }

        Self::new(elf.into()).map_err(|err| {
            print_error(format!("Invalid program bytecode, err: {err}"));
            FfiOperationError::InvalidBytecode
        })
    }
}

impl From<Program> for FfiProgram {
    fn from(value: Program) -> Self {
        let elf_clone = value.elf().to_vec();
        let elf_size = elf_clone.len();
        let elf_data = Box::into_raw(elf_clone.into_boxed_slice()) as *const u8;

        Self { elf_data, elf_size }
    }
}

/// Which of `Disclosed`/`Shadow`/`Undisclosed` a program (or dependency) is resolved as.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiProgramKind {
    ProgramDisclosed = 0,
    ProgramShadow = 1,
    ProgramUndisclosed = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiProgramHeader {
    pub image_id: FfiBytes32,
    pub program_first_segment: FfiBytes32,
    pub immutable: bool,
}

impl From<&FfiProgramHeader> for ProgramHeader {
    fn from(value: &FfiProgramHeader) -> Self {
        Self {
            image_id: bytes_to_program_id(value.image_id.data),
            program_first_segment: value.program_first_segment.into(),
            immutable: value.immutable,
        }
    }
}

impl From<ProgramHeader> for FfiProgramHeader {
    fn from(value: ProgramHeader) -> Self {
        Self {
            image_id: FfiBytes32::from_bytes(program_id_to_bytes(value.image_id)),
            program_first_segment: value.program_first_segment.into(),
            immutable: value.immutable,
        }
    }
}

#[repr(C)]
/// Intended to be created manually.
pub struct FfiMembershipProof {
    pub index: usize,
    pub path: *const FfiBytes32,
    pub path_len: usize,
}

impl Default for FfiMembershipProof {
    fn default() -> Self {
        Self {
            index: 0,
            path: std::ptr::null(),
            path_len: 0,
        }
    }
}

impl TryFrom<&FfiMembershipProof> for MembershipProof {
    type Error = FfiOperationError;

    fn try_from(value: &FfiMembershipProof) -> Result<Self, Self::Error> {
        let mut path = Vec::with_capacity(value.path_len);
        for i in 0..value.path_len {
            let hash =
                unsafe { value.path.add(i).as_ref() }.ok_or(FfiOperationError::NullPointer)?;
            path.push(hash.data);
        }
        let index =
            u64::try_from(value.index).map_err(|_err| FfiOperationError::InvalidTypeConversion)?;
        Ok((index, path))
    }
}

impl TryFrom<MembershipProof> for FfiMembershipProof {
    type Error = FfiOperationError;

    fn try_from(value: MembershipProof) -> Result<Self, Self::Error> {
        let (index, path) = value;
        let index =
            usize::try_from(index).map_err(|_err| FfiOperationError::InvalidTypeConversion)?;
        let ffi_path: Vec<FfiBytes32> = path.into_iter().map(FfiBytes32::from).collect();
        let path_len = ffi_path.len();
        let path_ptr = Box::into_raw(ffi_path.into_boxed_slice()) as *const FfiBytes32;

        Ok(Self {
            index,
            path: path_ptr,
            path_len,
        })
    }
}

#[repr(C)]
/// Intended to be created manually.
pub struct FfiDependency {
    pub program: FfiProgram,
    /// Where `program` is actually deployed. Ignored for `ProgramShadow`, whose account id is
    /// always derived from `program` instead — never a real header's address.
    pub account_id: FfiBytes32,
    pub kind: FfiProgramKind,
    pub program_header: FfiProgramHeader,
    pub membership_proof: FfiMembershipProof,
}

#[repr(C)]
/// Every program an execution may dispatch, each paired with the account it is deployed at.
/// `programs` is empty for native execution, which has no bytecode to supply.
///
/// Intended to be created manually.
pub struct FfiProgramCatalog {
    pub programs: *const FfiDependency,
    pub programs_size: usize,
}

impl TryFrom<&FfiProgramCatalog> for ProgramCatalog {
    type Error = FfiOperationError;

    fn try_from(value: &FfiProgramCatalog) -> Result<Self, Self::Error> {
        let mut programs = HashMap::new();

        // Alignment will be different, we need to read elements one-by-one
        for i in 0..value.programs_size {
            let entry =
                unsafe { value.programs.add(i).as_ref() }.ok_or(FfiOperationError::NullPointer)?;
            let program: Program = (&entry.program).try_into()?;
            let account_id = ffi_account_id(&program, entry.kind, entry.account_id);
            let kind = match entry.kind {
                FfiProgramKind::ProgramDisclosed => ProgramKind::Disclosed,
                FfiProgramKind::ProgramShadow => ProgramKind::Shadow,
                FfiProgramKind::ProgramUndisclosed => ProgramKind::Undisclosed {
                    program_header: (&entry.program_header).into(),
                    membership_proof: (&entry.membership_proof).try_into()?,
                },
            };

            programs.insert(account_id, Dependency { program, kind });
        }

        Ok(Self { programs })
    }
}

/// Result of a generic transaction operation.
#[repr(C)]
pub struct FfiTransactionResult {
    // TODO: Replace with HashType FFI representation
    /// Transaction hash (null-terminated string, or null on failure).
    pub tx_hash: *mut c_char,
    /// Whether the transaction succeeded.
    pub success: bool,
    pub secrets_data: *const FfiBytes32,
    /// Public transactions have 0 secrets.
    pub secrets_size: usize,
    /// The fee the transaction declared, or the report of a dry run, which leaves `tx_hash`
    /// null.
    pub fee: FfiSendFee,
}

impl Default for FfiTransactionResult {
    fn default() -> Self {
        Self {
            tx_hash: std::ptr::null_mut(),
            success: false,
            secrets_data: std::ptr::null(),
            secrets_size: 0,
            fee: FfiSendFee::default(),
        }
    }
}

/// Same little-endian word packing `AccountId::from_builtin_program` uses, so a header's
/// `image_id` round-trips identically whichever type it's read back through.
fn program_id_to_bytes(program_id: ProgramId) -> [u8; 32] {
    let bytes: Vec<u8> = program_id
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    bytes.try_into().expect("8 u32 words are exactly 32 bytes")
}

fn bytes_to_program_id(bytes: [u8; 32]) -> ProgramId {
    let mut program_id = [0_u32; 8];
    for (word, chunk) in program_id.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    program_id
}

/// For `ProgramShadow`, the account id is definitional — there's no real header to consult, so
/// it's derived from `program` the same way the circuit itself derives it. For
/// `ProgramDisclosed`/`ProgramUndisclosed`, the account id is wherever the caller's header
/// actually lives — never assumed to be `program`'s bytecode-bijection address, since the same
/// bytecode may be deployed more than once at different addresses — so `supplied` is used as-is.
fn ffi_account_id(program: &Program, kind: FfiProgramKind, supplied: FfiBytes32) -> AccountId {
    match kind {
        FfiProgramKind::ProgramShadow => AccountId::for_shadow_program(&program.id()),
        FfiProgramKind::ProgramDisclosed | FfiProgramKind::ProgramUndisclosed => supplied.into(),
    }
}

/// Send generic public transaction.
///
/// # Parameters
/// - `handle`: Valid pointer to wallet handle
/// - `account_mentions`: Valid pointer to list of `FfiAccountMention`
/// - `root_mention`: Index into `account_mentions` of the actor the message is delivered to
/// - `message`: Valid pointer to the message bytes
/// - `payer`: Fee payer, or null to self-pay from the first funded signing account in
///   `account_mentions` (the first signing account if none is funded). May be one of those signing
///   accounts, or any other public account whose signing key the wallet holds (it co-signs without
///   joining the account list).
/// - `out_result`: Valid pointer to `FfiTransactionResult`
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid pointer
/// - `account_mentions` must point to `account_mentions_size` mentions, each with
///   `address_openings` pointing to `address_openings_size` openings, or null if that is 0
/// - `message` must be a valid pointer
/// - `payer` must be null or a valid pointer to a `FfiBytes32`
/// - `out_result` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_send_generic_public_transaction(
    handle: *mut WalletHandle,
    account_mentions: *const FfiAccountMention,
    account_mentions_size: usize,
    root_mention: usize,
    message: *const u8,
    message_size: usize,
    payer: *const FfiBytes32,
    out_result: *mut FfiTransactionResult,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_mentions.is_null() {
        print_error("Null input pointer for account mentions list");
        return FfiOperationError::NullPointer;
    }

    if message.is_null() {
        print_error("Null input pointer for message");
        return FfiOperationError::NullPointer;
    }

    if out_result.is_null() {
        print_error("Null output pointer return hash");
        return FfiOperationError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    let message = unsafe { std::slice::from_raw_parts(message, message_size).to_vec() };
    let accounts = match mentions(unsafe {
        std::slice::from_raw_parts(account_mentions, account_mentions_size)
    }) {
        Ok(v) => v,
        Err(err) => return err,
    };

    let payer = unsafe { read_optional_account_id(payer) };

    let sent = block_on(wallet.send_pub_tx_paid_by(accounts, root_mention, message, payer));
    match unsafe { (*out_result).fee.record(&wallet, sent) } {
        Ok(tx_hash) => {
            let tx_hash = c_string_or_null(tx_hash);

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Public send failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = std::ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}

/// Send generic private transaction.
///
/// # Parameters
/// - `handle`: Valid pointer to wallet handle
/// - `account_mentions`: Valid pointer to list of `FfiAccountMention`
/// - `root_mention`: Index into `account_mentions` of the actor the message is delivered to
/// - `message`: Valid pointer to the message bytes
/// - `programs`: Valid pointer to the catalog of programs the transaction may run
/// - `out_result`: Valid pointer to `FfiTransactionResult`
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid pointer
/// - `account_mentions` must point to `account_mentions_size` mentions, each with
///   `address_openings` pointing to `address_openings_size` openings, or null if that is 0
/// - `message` must be a valid pointer
/// - `programs` must be a valid pointer
/// - `out_result` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_send_generic_private_transaction(
    handle: *mut WalletHandle,
    account_mentions: *const FfiAccountMention,
    account_mentions_size: usize,
    root_mention: usize,
    message: *const u8,
    message_size: usize,
    programs: *const FfiProgramCatalog,
    out_result: *mut FfiTransactionResult,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_mentions.is_null() {
        print_error("Null input pointer for account mentions list");
        return FfiOperationError::NullPointer;
    }

    if message.is_null() {
        print_error("Null input pointer for message");
        return FfiOperationError::NullPointer;
    }

    if programs.is_null() {
        print_error("Null input pointer for the program catalog");
        return FfiOperationError::NullPointer;
    }

    if out_result.is_null() {
        print_error("Null output pointer return hash");
        return FfiOperationError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    let message = unsafe { std::slice::from_raw_parts(message, message_size) }.to_vec();
    let accounts = match mentions(unsafe {
        std::slice::from_raw_parts(account_mentions, account_mentions_size)
    }) {
        Ok(v) => v,
        Err(err) => return err,
    };

    let programs = match unsafe { &*programs }.try_into() {
        Ok(v) => v,
        Err(err) => return err,
    };

    let sent =
        block_on(wallet.send_privacy_preserving_tx(accounts, root_mention, message, &programs));
    match unsafe { (*out_result).fee.record(&wallet, sent) } {
        Ok(sent) => {
            let (tx_hash, secrets) = sent.unzip();
            let secrets = secrets.unwrap_or_default();
            let tx_hash = c_string_or_null(tx_hash);

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;

                let secrets_size = secrets.len();
                let boxed_slice = secrets
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<FfiBytes32>>()
                    .into_boxed_slice();
                let secrets_data = Box::into_raw(boxed_slice) as *const FfiBytes32;

                (*out_result).secrets_size = secrets_size;
                (*out_result).secrets_data = secrets_data;
            }
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Private send failed: {e:?}"));
            unsafe {
                *out_result = FfiTransactionResult::default();
            }
            map_execution_error(e)
        }
    }
}

pub(crate) fn mentions(
    mentions: &[FfiAccountMention],
) -> Result<Vec<AccountMention>, FfiOperationError> {
    mentions
        .iter()
        .map(AccountMention::try_from)
        .collect::<Result<Vec<_>, _>>()
        .inspect_err(|_| print_error("Failed to convert FfiAccountMention into AccountMention"))
}

/// Poll transaction for its status.
///
/// # Parameters
/// - `handle`: Valid pointer to wallet handle.
/// - `tx_hash`: Bytes of a transaction hash,
/// - `transaction_status`: Valid pointer into `bool`.
///
/// # Returns
/// - `true` if seen included, `false` othervise.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_poll_transaction_status(
    handle: *mut WalletHandle,
    tx_hash: FfiBytes32,
    // ToDo: Replace with status enum.
    transaction_status: *mut bool,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    unsafe {
        *transaction_status = block_on(wallet.poll_transaction(HashType(tx_hash.data))).is_ok();
    }

    FfiOperationError::Success
}

/// Free a transaction result returned by `wallet_ffi_send_generic_public_transaction` or
/// `wallet_ffi_send_generic_private_transaction`.
///
/// # Safety
/// The result must be either null or a valid result from a transaction function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_free_transaction_result(result: *mut FfiTransactionResult) {
    if result.is_null() {
        return;
    }

    unsafe {
        let result = &mut *result;
        if !result.tx_hash.is_null() {
            drop(CString::from_raw(result.tx_hash));
        }
        result.fee.free();

        if !result.secrets_data.is_null() {
            let secrets =
                std::slice::from_raw_parts_mut(result.secrets_data.cast_mut(), result.secrets_size);
            drop(Box::from_raw(std::ptr::from_mut::<[FfiBytes32]>(secrets)));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::generic_transaction::FfiProgram;

    #[test]
    fn program_cast_consistency() {
        let prog = programs::clock();

        let first_5_bytes = prog.elf()[..5].to_vec();

        let ffi_prog: FfiProgram = prog.into();

        assert!(!ffi_prog.elf_data.is_null());

        let mut ffi_first_5_bytes = vec![];
        for i in 0..5 {
            ffi_first_5_bytes.push(unsafe { *ffi_prog.elf_data.add(i) });
        }

        assert_eq!(ffi_first_5_bytes, first_5_bytes);
    }
}
