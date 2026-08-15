use std::{
    collections::HashMap,
    ffi::{c_char, CString},
};

use common::HashType;
use lee::{privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program};

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    map_execution_error,
    wallet::get_wallet,
    FfiAccountIdentity, FfiBytes32, FfiProgramId, WalletHandle,
};

#[repr(C)]
/// Intended to be created manually.
pub struct FfiProgram {
    pub elf_data: *const u8,
    pub elf_size: usize,
}

impl TryFrom<&FfiProgram> for Program {
    type Error = WalletFfiError;

    fn try_from(value: &FfiProgram) -> Result<Self, Self::Error> {
        let mut elf = Vec::with_capacity(value.elf_size);

        // Alignment will be different, we need to read elements one-by-one
        for i in 0..value.elf_size {
            elf.push(unsafe { *value.elf_data.add(i) });
        }

        Self::new(elf.into()).map_err(|err| {
            print_error(format!("Invalid program bytecode, err: {err}"));
            WalletFfiError::InvalidBytecode
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

#[repr(C)]
/// Intended to be created manually.
pub struct FfiProgramWithDependencies {
    pub program: FfiProgram,
    pub deps: *const FfiProgram,
    pub deps_size: usize,
}

impl TryFrom<&FfiProgramWithDependencies> for ProgramWithDependencies {
    type Error = WalletFfiError;

    fn try_from(value: &FfiProgramWithDependencies) -> Result<Self, Self::Error> {
        let mut program_map = HashMap::new();

        let orig_program: Program = (&value.program).try_into()?;
        let orig_program_id = orig_program.id();

        // Alignment will be different, we need to read elements one-by-one
        for i in 0..value.deps_size {
            let program_dep: Program = unsafe { value.deps.add(i).as_ref() }
                .ok_or(WalletFfiError::NullPointer)?
                .try_into()?;

            program_map.insert(
                program_loader_core::immutable_deploy_account_id(program_dep.id()),
                program_dep,
            );
        }

        Ok(Self::new(orig_program, program_map)
            .with_program_account_id(program_loader_core::immutable_deploy_account_id(orig_program_id)))
    }
}

impl From<ProgramWithDependencies> for FfiProgramWithDependencies {
    fn from(value: ProgramWithDependencies) -> Self {
        let ffi_program = value.program.into();

        let ffi_deps: Vec<FfiProgram> = value
            .dependencies
            .into_values()
            .map(Into::into)
            .collect::<Vec<_>>();

        let deps_size = ffi_deps.len();
        let deps = Box::into_raw(ffi_deps.into_boxed_slice()) as *const FfiProgram;

        Self {
            program: ffi_program,
            deps,
            deps_size,
        }
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
}

impl Default for FfiTransactionResult {
    fn default() -> Self {
        Self {
            tx_hash: std::ptr::null_mut(),
            success: false,
            secrets_data: std::ptr::null(),
            secrets_size: 0,
        }
    }
}

/// Send generic public transaction.
///
/// # Parameters
/// - `handle`: Valid pointer to wallet handle
/// - `account_identities`: Valid pointer to list of `FfiAccountIdentity`
/// - `instruction_data`: Valid pointer to instruction data bytes
/// - `out_result`: Valid pointer to `FfiTransactionResult`
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid pointer
/// - `account_identities` must be a valid pointer
/// - `instruction_data` must be a valid pointer
/// - `out_result` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_send_generic_public_transaction(
    handle: *mut WalletHandle,
    account_identities: *const FfiAccountIdentity,
    account_identities_size: usize,
    instruction_data: *const u8,
    instruction_data_size: usize,
    program_id: FfiProgramId,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_identities.is_null() {
        print_error("Null input pointer for account identities list");
        return WalletFfiError::NullPointer;
    }

    if instruction_data.is_null() {
        print_error("Null input pointer for instruction data");
        return WalletFfiError::NullPointer;
    }

    if out_result.is_null() {
        print_error("Null output pointer return hash");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let accounts_ffi = std::slice::from_raw_parts(account_identities, account_identities_size);
    let instruction_data = std::slice::from_raw_parts(instruction_data, instruction_data_size);

    let mut accounts = Vec::with_capacity(account_identities_size);

    for ffi_acc in accounts_ffi {
        match ffi_acc.try_into() {
            Ok(v) => accounts.push(v),
            Err(err) => {
                print_error("Failed to convert FfiAccountIdentity into AccountIdentity");
                return err;
            }
        }
    }

    match block_on(wallet.send_pub_tx(accounts, instruction_data.to_vec(), program_id.into())) {
        Ok(tx_hash) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map_or(std::ptr::null_mut(), std::ffi::CString::into_raw);

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
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
/// - `account_identities`: Valid pointer to list of `FfiAccountIdentity`
/// - `instruction_data`: Valid pointer to instruction data bytes
/// - `out_result`: Valid pointer to `FfiTransactionResult`
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid pointer
/// - `account_identities` must be a valid pointer
/// - `instruction_data` must be a valid pointer
/// - `out_result` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_send_generic_private_transaction(
    handle: *mut WalletHandle,
    account_identities: *const FfiAccountIdentity,
    account_identities_size: usize,
    instruction_data: *const u8,
    instruction_data_size: usize,
    program_with_dependencies: *const FfiProgramWithDependencies,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_identities.is_null() {
        print_error("Null input pointer for account identities list");
        return WalletFfiError::NullPointer;
    }

    if instruction_data.is_null() {
        print_error("Null input pointer for instruction data");
        return WalletFfiError::NullPointer;
    }

    if out_result.is_null() {
        print_error("Null output pointer return hash");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let accounts_ffi = std::slice::from_raw_parts(account_identities, account_identities_size);
    let instruction_data = std::slice::from_raw_parts(instruction_data, instruction_data_size);

    let mut accounts = Vec::with_capacity(account_identities_size);

    for ffi_acc in accounts_ffi {
        match ffi_acc.try_into() {
            Ok(v) => accounts.push(v),
            Err(err) => {
                print_error("Failed to convert FfiAccountIdentity into AccountIdentity");
                return err;
            }
        }
    }

    let program = match unsafe { &*program_with_dependencies }.try_into() {
        Ok(v) => v,
        Err(err) => return err,
    };

    match block_on(wallet.send_privacy_preserving_tx(accounts, instruction_data.to_vec(), &program))
    {
        Ok((tx_hash, secrets)) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map_or(std::ptr::null_mut(), std::ffi::CString::into_raw);

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
            WalletFfiError::Success
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
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_poll_transaction_status(
    handle: *mut WalletHandle,
    tx_hash: FfiBytes32,
    // ToDo: Replace with status enum.
    transaction_status: *mut bool,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    *transaction_status = block_on(wallet.poll_transaction(HashType(tx_hash.data))).is_ok();

    WalletFfiError::Success
}

/// Free a transaction result returned by `wallet_ffi_send_generic_public_transaction` or
/// `wallet_ffi_send_generic_private_transaction`.
///
/// # Safety
/// The result must be either null or a valid result from a transaction function.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_transaction_result(result: *mut FfiTransactionResult) {
    if result.is_null() {
        return;
    }

    unsafe {
        let result = &*result;
        if !result.tx_hash.is_null() {
            drop(CString::from_raw(result.tx_hash));
        }

        if !result.secrets_data.is_null() {
            let secrets =
                std::slice::from_raw_parts_mut(result.secrets_data.cast_mut(), result.secrets_size);
            drop(Box::from_raw(std::ptr::from_mut::<[FfiBytes32]>(secrets)));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::generic_transaction::FfiProgram;

    #[test]
    fn program_cast_consistency() {
        let prog = programs::amm();

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
