//! Pinata program interaction functions.

use std::{ffi::CString, ptr, slice};

use nssa::AccountId;
use nssa_core::MembershipProof;
use wallet::program_facades::pinata::Pinata;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    map_execution_error,
    types::{FfiBytes32, FfiTransferResult, WalletHandle},
    wallet::get_wallet,
};

/// Claim a pinata reward using a public transaction.
///
/// Sends a public claim transaction to the pinata program.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `pinata_account_id`: The pinata program account ID
/// - `winner_account_id`: The recipient account ID
/// - `solution`: The solution value as little-endian [u8; 16]
/// - `out_result`: Output pointer for the transaction result
///
/// # Returns
/// - `Success` if the claim transaction was submitted successfully
/// - Error code on failure
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `solution` must be a valid pointer to a `[u8; 16]` array
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_claim_pinata(
    handle: *mut WalletHandle,
    pinata_account_id: *const FfiBytes32,
    winner_account_id: *const FfiBytes32,
    solution: *const [u8; 16],
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if pinata_account_id.is_null()
        || winner_account_id.is_null()
        || solution.is_null()
        || out_result.is_null()
    {
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

    let pinata_id = AccountId::new(unsafe { (*pinata_account_id).data });
    let winner_id = AccountId::new(unsafe { (*winner_account_id).data });
    let solution = u128::from_le_bytes(unsafe { *solution });

    let pinata = Pinata(&wallet);

    match block_on(pinata.claim(pinata_id, winner_id, solution)) {
        Ok(tx_hash) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map(std::ffi::CString::into_raw)
                .unwrap_or(ptr::null_mut());

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Pinata claim failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}

/// Claim a pinata reward using a private transaction for an already-initialized owned account.
///
/// Sends a privacy-preserving claim transaction for a winner account that already has
/// an on-chain commitment (i.e. was previously initialized).
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `pinata_account_id`: The pinata program account ID
/// - `winner_account_id`: The recipient private account ID (must be owned by this wallet)
/// - `solution`: The solution value as little-endian [u8; 16]
/// - `winner_proof_index`: Leaf index in the commitment tree for the membership proof
/// - `winner_proof_siblings`: Pointer to an array of 32-byte sibling hashes
/// - `winner_proof_siblings_len`: Number of sibling hashes in the array
/// - `out_result`: Output pointer for the transaction result
///
/// # Returns
/// - `Success` if the claim transaction was submitted successfully
/// - Error code on failure
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `solution` must be a valid pointer to a `[u8; 16]` array
/// - `winner_proof_siblings` must be a valid pointer to an array of `winner_proof_siblings_len`
///   elements of `[u8; 32]`, or null if `winner_proof_siblings_len` is 0
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_claim_pinata_private_owned_already_initialized(
    handle: *mut WalletHandle,
    pinata_account_id: *const FfiBytes32,
    winner_account_id: *const FfiBytes32,
    solution: *const [u8; 16],
    winner_proof_index: usize,
    winner_proof_siblings: *const [u8; 32],
    winner_proof_siblings_len: usize,
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if pinata_account_id.is_null()
        || winner_account_id.is_null()
        || solution.is_null()
        || out_result.is_null()
    {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    if winner_proof_siblings_len > 0 && winner_proof_siblings.is_null() {
        print_error("Null proof siblings pointer with non-zero length");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let pinata_id = AccountId::new(unsafe { (*pinata_account_id).data });
    let winner_id = AccountId::new(unsafe { (*winner_account_id).data });
    let solution = u128::from_le_bytes(unsafe { *solution });

    let siblings = if winner_proof_siblings_len > 0 {
        unsafe { slice::from_raw_parts(winner_proof_siblings, winner_proof_siblings_len).to_vec() }
    } else {
        vec![]
    };
    let proof: MembershipProof = (winner_proof_index, siblings);

    let pinata = Pinata(&wallet);

    match block_on(
        pinata
            .claim_private_owned_account_already_initialized(pinata_id, winner_id, solution, proof),
    ) {
        Ok((tx_hash, _shared_key)) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map(std::ffi::CString::into_raw)
                .unwrap_or(ptr::null_mut());

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!(
                "Pinata private claim (already initialized) failed: {e:?}"
            ));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}

/// Claim a pinata reward using a private transaction for a not-yet-initialized owned account.
///
/// Sends a privacy-preserving claim transaction for a winner account that has not yet
/// been committed on-chain (i.e. is being initialized as part of this claim).
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `pinata_account_id`: The pinata program account ID
/// - `winner_account_id`: The recipient private account ID (must be owned by this wallet)
/// - `solution`: The solution value as little-endian [u8; 16]
/// - `out_result`: Output pointer for the transaction result
///
/// # Returns
/// - `Success` if the claim transaction was submitted successfully
/// - Error code on failure
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `pinata_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `winner_account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `solution` must be a valid pointer to a `[u8; 16]` array
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_claim_pinata_private_owned_not_initialized(
    handle: *mut WalletHandle,
    pinata_account_id: *const FfiBytes32,
    winner_account_id: *const FfiBytes32,
    solution: *const [u8; 16],
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if pinata_account_id.is_null()
        || winner_account_id.is_null()
        || solution.is_null()
        || out_result.is_null()
    {
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

    let pinata_id = AccountId::new(unsafe { (*pinata_account_id).data });
    let winner_id = AccountId::new(unsafe { (*winner_account_id).data });
    let solution = u128::from_le_bytes(unsafe { *solution });

    let pinata = Pinata(&wallet);

    match block_on(pinata.claim_private_owned_account(pinata_id, winner_id, solution)) {
        Ok((tx_hash, _shared_key)) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map(std::ffi::CString::into_raw)
                .unwrap_or(ptr::null_mut());

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!(
                "Pinata private claim (not initialized) failed: {e:?}"
            ));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}
