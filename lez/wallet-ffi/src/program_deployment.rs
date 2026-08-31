use std::{ffi::CString, ptr, slice};

use lee::AccountId;
use wallet::program_facades::program_loader::ProgramLoader;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    generic_transaction::{FfiProgram, FfiTransactionResult},
    types::FfiBytes32,
    wallet::get_wallet,
    WalletHandle,
};

/// Reads a bytecode buffer from an FFI pointer/length pair.
unsafe fn read_bytes(data: *const u8, size: usize) -> Vec<u8> {
    unsafe { slice::from_raw_parts(data, size) }.to_vec()
}

/// Reads a `FfiBytes32` array from an FFI pointer/length pair into `AccountId`s.
unsafe fn read_account_ids(data: *const FfiBytes32, len: usize) -> Vec<AccountId> {
    unsafe { slice::from_raw_parts(data, len) }
        .iter()
        .map(|bytes| AccountId::from(*bytes))
        .collect()
}

fn write_result(out_result: *mut FfiTransactionResult, tx_hash: common::HashType) {
    let tx_hash = CString::new(tx_hash.to_string()).map_or(ptr::null_mut(), CString::into_raw);
    unsafe {
        (*out_result).tx_hash = tx_hash;
        (*out_result).success = true;
    }
}

fn write_failure(out_result: *mut FfiTransactionResult) {
    unsafe {
        (*out_result).tx_hash = ptr::null_mut();
        (*out_result).success = false;
    }
}

/// Writes one `program_loader` bytecode segment.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `target` must be a valid pointer to a `FfiBytes32`; the wallet must hold its signing key
/// - `bytecode_data` must be a valid pointer to `bytecode_size` bytes
/// - `next_segment` may be null (meaning this is the chain's last segment), otherwise a valid
///   pointer to a `FfiBytes32` for an already-uploaded segment
/// - `out_result` must be a valid pointer to a `FfiTransactionResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_program_loader_new_segment(
    handle: *mut WalletHandle,
    target: *const FfiBytes32,
    bytecode_data: *const u8,
    bytecode_size: usize,
    next_segment: *const FfiBytes32,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if target.is_null() || bytecode_data.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }
    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let target = AccountId::from(unsafe { *target });
    let bytecode = unsafe { read_bytes(bytecode_data, bytecode_size) };
    let next_segment = if next_segment.is_null() {
        None
    } else {
        Some(AccountId::from(unsafe { *next_segment }))
    };

    match block_on(ProgramLoader(&wallet).new_segment(target, bytecode, next_segment)) {
        Ok(tx_hash) => {
            write_result(out_result, tx_hash);
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("NewSegment failed: {e:?}"));
            write_failure(out_result);
            WalletFfiError::NetworkError
        }
    }
}

/// Creates a new `program_loader` header pointing at an already-uploaded segment chain.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `target` must be a valid pointer to a `FfiBytes32`; the wallet must hold its signing key
/// - `first_segment` must be a valid pointer to a `FfiBytes32` for an already-uploaded segment
/// - `out_result` must be a valid pointer to a `FfiTransactionResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_program_loader_upload_header(
    handle: *mut WalletHandle,
    target: *const FfiBytes32,
    first_segment: *const FfiBytes32,
    immutable: bool,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if target.is_null() || first_segment.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }
    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let target = AccountId::from(unsafe { *target });
    let first_segment = AccountId::from(unsafe { *first_segment });

    let loader = ProgramLoader(&wallet);
    let chain = match block_on(loader.resolve_chain(first_segment)) {
        Ok(chain) => chain,
        Err(e) => {
            print_error(format!("Failed to resolve segment chain: {e:?}"));
            write_failure(out_result);
            return WalletFfiError::NetworkError;
        }
    };

    match block_on(loader.upload_header(target, first_segment, &chain, immutable)) {
        Ok(tx_hash) => {
            write_result(out_result, tx_hash);
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("UploadHeader failed: {e:?}"));
            write_failure(out_result);
            WalletFfiError::NetworkError
        }
    }
}

/// Rewrites an existing `program_loader` header to point at a different (already-uploaded)
/// segment chain.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `header` must be a valid pointer to a `FfiBytes32` for an existing header the wallet is
///   still authorized over
/// - `first_segment` must be a valid pointer to a `FfiBytes32` for an already-uploaded segment
/// - `out_result` must be a valid pointer to a `FfiTransactionResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_program_loader_update_header(
    handle: *mut WalletHandle,
    header: *const FfiBytes32,
    first_segment: *const FfiBytes32,
    immutable: bool,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if header.is_null() || first_segment.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }
    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let header = AccountId::from(unsafe { *header });
    let first_segment = AccountId::from(unsafe { *first_segment });

    let loader = ProgramLoader(&wallet);
    let chain = match block_on(loader.resolve_chain(first_segment)) {
        Ok(chain) => chain,
        Err(e) => {
            print_error(format!("Failed to resolve segment chain: {e:?}"));
            write_failure(out_result);
            return WalletFfiError::NetworkError;
        }
    };

    match block_on(loader.update_header(header, first_segment, &chain, immutable)) {
        Ok(tx_hash) => {
            write_result(out_result, tx_hash);
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("UpdateHeader failed: {e:?}"));
            write_failure(out_result);
            WalletFfiError::NetworkError
        }
    }
}

/// Deploys a new program from `elf_data`.
///
/// Chunks `elf_data`, uploads one segment per account in `segments`, then creates `header`
/// pointing at the resulting chain. `segments_len` must exactly match the number of chunks
/// `elf_data` splits into.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `header` must be a valid pointer to a `FfiBytes32`; the wallet must hold its signing key
/// - `segments` must be a valid pointer to `segments_len` contiguous `FfiBytes32`s, in chain
///   order (first chunk first); the wallet must hold every segment's signing key
/// - `elf_data` must be a valid pointer to `elf_size` bytes
/// - `out_result` must be a valid pointer to a `FfiTransactionResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_program_loader_deploy(
    handle: *mut WalletHandle,
    header: *const FfiBytes32,
    segments: *const FfiBytes32,
    segments_len: usize,
    elf_data: *const u8,
    elf_size: usize,
    immutable: bool,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if header.is_null() || segments.is_null() || elf_data.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }
    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let header = AccountId::from(unsafe { *header });
    let segment_ids = unsafe { read_account_ids(segments, segments_len) };
    let elf = unsafe { read_bytes(elf_data, elf_size) };

    match block_on(ProgramLoader(&wallet).deploy(header, &segment_ids, elf, immutable)) {
        Ok(header_account_id) => {
            let tx_hash_str = header_account_id.to_string();
            let tx_hash = CString::new(tx_hash_str).map_or(ptr::null_mut(), CString::into_raw);
            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Deploy failed: {e:?}"));
            write_failure(out_result);
            WalletFfiError::NetworkError
        }
    }
}

/// Updates an existing program in place with `elf_data`.
///
/// Chunks `elf_data`, uploads a fresh set of segments (segments are write-once), then rewrites
/// `header` to point at them. `segments_len` must exactly match the number of chunks `elf_data`
/// splits into.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `header` must be a valid pointer to a `FfiBytes32` for an existing header the wallet is
///   still authorized over
/// - `segments` must be a valid pointer to `segments_len` contiguous `FfiBytes32`s, in chain
///   order; the wallet must hold every segment's signing key
/// - `elf_data` must be a valid pointer to `elf_size` bytes
/// - `out_result` must be a valid pointer to a `FfiTransactionResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_program_loader_update(
    handle: *mut WalletHandle,
    header: *const FfiBytes32,
    segments: *const FfiBytes32,
    segments_len: usize,
    elf_data: *const u8,
    elf_size: usize,
    immutable: bool,
    out_result: *mut FfiTransactionResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if header.is_null() || segments.is_null() || elf_data.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }
    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let header = AccountId::from(unsafe { *header });
    let segment_ids = unsafe { read_account_ids(segments, segments_len) };
    let elf = unsafe { read_bytes(elf_data, elf_size) };

    match block_on(ProgramLoader(&wallet).update(header, &segment_ids, elf, immutable)) {
        Ok(()) => {
            let tx_hash = CString::new(header.to_string()).map_or(ptr::null_mut(), CString::into_raw);
            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Update failed: {e:?}"));
            write_failure(out_result);
            WalletFfiError::NetworkError
        }
    }
}

/// Writes elf data of authenticated transfer program into buffer.
///
/// WARNING: Result is not consisent and change between versions, use for testing purposes only.
///
/// # Parameters
/// - `ffi_program`: Valid pointer to `FfiProgram`
///
/// # Returns
/// - `Success` if deployment was submitted successfully
/// - Error code on other failures
///
/// # Memory
/// - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
///
/// # Safety
/// - `ffi_program` must be a non-null pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_transfer_elf(ffi_program: *mut FfiProgram) -> WalletFfiError {
    if ffi_program.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let elf = programs::authenticated_transfer().elf().to_vec();

    let (raw_elf_data, raw_elf_size, _) = elf.into_raw_parts();

    unsafe {
        (*ffi_program).elf_data = raw_elf_data;
        (*ffi_program).elf_size = raw_elf_size;
    };

    WalletFfiError::Success
}

/// Writes elf data of authenticated token program into buffer.
///
/// WARNING: Result is not consisent and change between versions, use for testing purposes only.
///
/// # Parameters
/// - `ffi_program`: Valid pointer to `FfiProgram`
///
/// # Returns
/// - `Success` if deployment was submitted successfully
/// - Error code on other failures
///
/// # Memory
/// - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
///
/// # Safety
/// - `ffi_program` must be a non-null pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_token_elf(ffi_program: *mut FfiProgram) -> WalletFfiError {
    if ffi_program.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let elf = programs::token().elf().to_vec();

    let (raw_elf_data, raw_elf_size, _) = elf.into_raw_parts();

    unsafe {
        (*ffi_program).elf_data = raw_elf_data;
        (*ffi_program).elf_size = raw_elf_size;
    };

    WalletFfiError::Success
}

/// Writes elf data of amm into buffer.
///
/// WARNING: Result is not consisent and change between versions, use for testing purposes only.
///
/// # Parameters
/// - `ffi_program`: Valid pointer to `FfiProgram`
///
/// # Returns
/// - `Success` if deployment was submitted successfully
/// - Error code on other failures
///
/// # Memory
/// - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
///
/// # Safety
/// - `ffi_program` must be a non-null pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_amm_elf(ffi_program: *mut FfiProgram) -> WalletFfiError {
    if ffi_program.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let elf = programs::amm().elf().to_vec();

    let (raw_elf_data, raw_elf_size, _) = elf.into_raw_parts();

    unsafe {
        (*ffi_program).elf_data = raw_elf_data;
        (*ffi_program).elf_size = raw_elf_size;
    };

    WalletFfiError::Success
}

/// Writes elf data of ata into buffer.
///
/// WARNING: Result is not consisent and change between versions, use for testing purposes only.
///
/// # Parameters
/// - `ffi_program`: Valid pointer to `FfiProgram`
///
/// # Returns
/// - `Success` if deployment was submitted successfully
/// - Error code on other failures
///
/// # Memory
/// - `FfiProgram` can be freed with corresponding `wallet_ffi_free_ffi_program` function
///
/// # Safety
/// - `ffi_program` must be a non-null pointer
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_ata_elf(ffi_program: *mut FfiProgram) -> WalletFfiError {
    if ffi_program.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let elf = programs::ata().elf().to_vec();

    let (raw_elf_data, raw_elf_size, _) = elf.into_raw_parts();

    unsafe {
        (*ffi_program).elf_data = raw_elf_data;
        (*ffi_program).elf_size = raw_elf_size;
    };

    WalletFfiError::Success
}

/// Free a ffi program returned by functions `wallet_ffi_*_elf`.
///
/// # Safety
/// The result must be either null or a valid result from a elf getter function.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_ffi_program(ffi_program: *mut FfiProgram) {
    if ffi_program.is_null() {
        return;
    }

    unsafe {
        let ffi_program = &*ffi_program;

        if !ffi_program.elf_data.is_null() {
            let elf = std::slice::from_raw_parts_mut(
                ffi_program.elf_data.cast_mut(),
                ffi_program.elf_size,
            );
            drop(Box::from_raw(std::ptr::from_mut::<[u8]>(elf)));
        }
    }
}
