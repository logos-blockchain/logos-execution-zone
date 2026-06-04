//! Key retrieval functions.

use std::ptr;

use nssa::{AccountId, PublicKey};

use crate::{
    error::{print_error, WalletFfiError},
    types::{FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey, WalletHandle},
    wallet::get_wallet,
};

/// Get the public key for a public account.
///
/// This returns the public key derived from the account's signing key.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_public_key`: Output pointer for the public key
///
/// # Returns
/// - `Success` on successful retrieval
/// - `KeyNotFound` if the account's key is not in this wallet
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_public_key` must be a valid pointer to a `FfiPublicAccountKey` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_public_account_key(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_public_key: *mut FfiPublicAccountKey,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_public_key.is_null() {
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

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let Some(private_key) = wallet.get_account_public_signing_key(account_id) else {
        print_error("Public account key not found in wallet");
        return WalletFfiError::KeyNotFound;
    };

    let public_key = PublicKey::new_from_private_key(private_key);

    unsafe {
        *out_public_key = public_key.into();
    }

    WalletFfiError::Success
}

/// Get keys for a private account.
///
/// Returns the nullifier public key (NPK) and viewing public key (VPK)
/// for the specified private account. These keys are safe to share publicly.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_keys`: Output pointer for the key data
///
/// # Returns
/// - `Success` on successful retrieval
/// - `AccountNotFound` if the private account is not in this wallet
/// - Error code on other failures
///
/// # Memory
/// The keys structure must be freed with `wallet_ffi_free_private_account_keys()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_private_account_keys(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_keys: *mut FfiPrivateAccountKeys,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_keys.is_null() {
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

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let Some(acc) = wallet.storage().key_chain().private_account(account_id) else {
        print_error("Private account not found in wallet");
        return WalletFfiError::AccountNotFound;
    };
    let key_chain = acc.key_chain;

    // NPK is a 32-byte array
    let npk_bytes = key_chain.nullifier_public_key.0;

    // VPK is a compressed secp256k1 point (33 bytes)
    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    let vpk_vec = vpk_bytes.to_vec();
    let vpk_boxed = vpk_vec.into_boxed_slice();
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert the boxed slice into a raw pointer for FFI"
    )]
    let vpk_ptr = Box::into_raw(vpk_boxed) as *const u8;

    unsafe {
        (*out_keys).nullifier_public_key.data = npk_bytes;
        (*out_keys).viewing_public_key = vpk_ptr;
        (*out_keys).viewing_public_key_len = vpk_len;
    }

    WalletFfiError::Success
}

/// Return the keys of the first private accounts key chain in the wallet.
///
/// The first chain is determined by BTreeMap ordering over chain indices,
/// which is deterministic — calling this function on a wallet persisted to
/// disk and reopened later returns the same NPK as long as no preceding
/// chain index was inserted in between.
///
/// Intended for clients (e.g. agent runtimes) that need a stable
/// cryptographic identity derived from the wallet seed without rotating
/// it at every call to `wallet_ffi_create_private_accounts_key`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_keys`: Output pointer for the key material
///
/// # Returns
/// - `Success` on success
/// - `AccountNotFound` if the wallet has no private accounts key yet
/// - Error code on other failures
///
/// # Memory
/// The keys must be freed with `wallet_ffi_free_private_account_keys()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_first_private_accounts_key(
    handle: *mut WalletHandle,
    out_keys: *mut FfiPrivateAccountKeys,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_keys.is_null() {
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

    let Some(key_chain) = wallet.first_private_accounts_key_chain() else {
        print_error("Wallet has no private accounts key");
        return WalletFfiError::AccountNotFound;
    };

    let npk_bytes = key_chain.nullifier_public_key.0;

    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    let vpk_vec = vpk_bytes.to_vec();
    let vpk_boxed = vpk_vec.into_boxed_slice();
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert the boxed slice into a raw pointer for FFI"
    )]
    let vpk_ptr = Box::into_raw(vpk_boxed) as *const u8;

    unsafe {
        (*out_keys).nullifier_public_key.data = npk_bytes;
        (*out_keys).viewing_public_key = vpk_ptr;
        (*out_keys).viewing_public_key_len = vpk_len;
    }

    WalletFfiError::Success
}

/// Return the keys of the private accounts key node at a specific chain
/// index. The chain index is given as the wallet-CLI string format,
/// e.g. "/" for the root node, "/0" for the first child, "/0/1" for a
/// nested node, etc.
///
/// Intended for clients that need a stable cryptographic identity
/// anchored on a known position in the key tree. Combined with the root
/// node "/" seeded automatically by `WalletCore::new_init_storage`, this
/// gives a deterministic agent identity that survives wallet reopen
/// without any side-car cache.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `chain_index_str`: Null-terminated UTF-8 chain index path
/// - `out_keys`: Output pointer for the key material
///
/// # Returns
/// - `Success` on success
/// - `InvalidUtf8` if `chain_index_str` is malformed
/// - `AccountNotFound` if no node exists at the given chain index
/// - Error code on other failures
///
/// # Memory
/// The keys must be freed with `wallet_ffi_free_private_account_keys()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `chain_index_str` must be a valid null-terminated UTF-8 string
/// - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_private_accounts_key_by_chain_index(
    handle: *mut WalletHandle,
    chain_index_str: *const std::ffi::c_char,
    out_keys: *mut FfiPrivateAccountKeys,
) -> WalletFfiError {
    use key_protocol::key_management::key_tree::chain_index::ChainIndex;
    use std::str::FromStr;

    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if chain_index_str.is_null() || out_keys.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let Ok(chain_index_str) = crate::c_str_to_string(chain_index_str, "chain_index_str") else {
        return WalletFfiError::InvalidUtf8;
    };

    let Ok(chain_index) = ChainIndex::from_str(&chain_index_str) else {
        print_error(format!("Failed to parse chain index: {chain_index_str}"));
        return WalletFfiError::InvalidKeyValue;
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let Some(key_chain) = wallet.private_accounts_key_chain_by_index(&chain_index) else {
        print_error(format!("No private accounts key at chain index {chain_index_str}"));
        return WalletFfiError::AccountNotFound;
    };

    let npk_bytes = key_chain.nullifier_public_key.0;

    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    let vpk_vec = vpk_bytes.to_vec();
    let vpk_boxed = vpk_vec.into_boxed_slice();
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert the boxed slice into a raw pointer for FFI"
    )]
    let vpk_ptr = Box::into_raw(vpk_boxed) as *const u8;

    unsafe {
        (*out_keys).nullifier_public_key.data = npk_bytes;
        (*out_keys).viewing_public_key = vpk_ptr;
        (*out_keys).viewing_public_key_len = vpk_len;
    }

    WalletFfiError::Success
}

/// FFI signature shape produced by `wallet_ffi_sign_message_at_chain_index`.
///
/// `signature` is a 64-byte BIP-340 Schnorr-over-secp256k1 signature.
/// `verifying_public_key` is the 32-byte x-only public key matching the
/// signing key derived at the specified chain index. Both arrays are
/// inlined by value — no allocation, no free function needed.
#[repr(C)]
pub struct FfiCardSignature {
    pub signature: [u8; 64],
    pub verifying_public_key: [u8; 32],
}

/// Sign an arbitrary message with the private accounts key at the
/// specified chain index. Uses BIP-340 Schnorr over secp256k1 with the
/// secret_spending_key as the signing scalar. The message is SHA-256
/// prehashed (matching the existing nssa::Signature::new convention).
///
/// Designed for clients that need to sign application-level material
/// (e.g. an A2A AgentCard or a JWS) with the same key tree the wallet
/// uses, without surfacing the private scalar to the host.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `chain_index_str`: Null-terminated UTF-8 chain index path (e.g. "/" for the root)
/// - `message`: Pointer to the message bytes to sign
/// - `message_len`: Length of the message in bytes
/// - `out_sig`: Output pointer for the {signature, verifying public key} pair
///
/// # Returns
/// - `Success` on success
/// - `InvalidUtf8` if `chain_index_str` is malformed
/// - `AccountNotFound` if no node exists at the given chain index
/// - `InternalError` if the signing scalar is not a valid k256 secret key
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle
/// - `chain_index_str` must be a valid null-terminated UTF-8 string
/// - `message` must be a valid pointer to at least `message_len` bytes
/// - `out_sig` must be a valid pointer to an `FfiCardSignature` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_sign_message_at_chain_index(
    handle: *mut WalletHandle,
    chain_index_str: *const std::ffi::c_char,
    message: *const u8,
    message_len: usize,
    out_sig: *mut FfiCardSignature,
) -> WalletFfiError {
    use key_protocol::key_management::key_tree::chain_index::ChainIndex;
    use sha2::{Digest as _, Sha256};
    use std::str::FromStr as _;

    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if chain_index_str.is_null() || message.is_null() || out_sig.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let Ok(chain_index_str) = crate::c_str_to_string(chain_index_str, "chain_index_str") else {
        return WalletFfiError::InvalidUtf8;
    };
    let Ok(chain_index) = ChainIndex::from_str(&chain_index_str) else {
        print_error(format!("Failed to parse chain index: {chain_index_str}"));
        return WalletFfiError::InvalidKeyValue;
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let Some(key_chain) = wallet.private_accounts_key_chain_by_index(&chain_index) else {
        print_error(format!("No private accounts key at chain index {chain_index_str}"));
        return WalletFfiError::AccountNotFound;
    };

    let secret_scalar = key_chain.secret_spending_key.0;
    let Ok(signing_key) = k256::schnorr::SigningKey::from_bytes(&secret_scalar) else {
        print_error("secret_spending_key is not a valid Schnorr signing scalar");
        return WalletFfiError::InternalError;
    };

    // Prehash with SHA-256 to fit the 32-byte BIP-340 message input.
    let msg_slice = unsafe { std::slice::from_raw_parts(message, message_len) };
    let mut hasher = Sha256::new();
    hasher.update(msg_slice);
    let prehash: [u8; 32] = hasher.finalize().into();

    let mut aux_random = [0_u8; 32];
    use k256::elliptic_curve::rand_core::{OsRng, RngCore as _};
    OsRng.fill_bytes(&mut aux_random);

    let signature = match signing_key.sign_prehash_with_aux_rand(&prehash, &aux_random) {
        Ok(s) => s,
        Err(e) => {
            print_error(format!("Schnorr signing failed: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let verifying_key = signing_key.verifying_key();
    let verifying_bytes = verifying_key.to_bytes();

    unsafe {
        (*out_sig).signature = signature.to_bytes();
        (*out_sig).verifying_public_key = verifying_bytes.into();
    }

    WalletFfiError::Success
}

/// Free private account keys returned by `wallet_ffi_get_private_account_keys`.
///
/// # Safety
/// The keys must be either null or valid keys returned by
/// `wallet_ffi_get_private_account_keys`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys) {
    if keys.is_null() {
        return;
    }

    unsafe {
        let keys = &*keys;
        if !keys.viewing_public_key.is_null() && keys.viewing_public_key_len > 0 {
            let slice = std::slice::from_raw_parts_mut(
                keys.viewing_public_key.cast_mut(),
                keys.viewing_public_key_len,
            );
            drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
        }
    }
}

/// Convert an account ID to a Base58 string.
///
/// # Parameters
/// - `account_id`: The account ID (32 bytes)
///
/// # Returns
/// - Pointer to null-terminated Base58 string on success
/// - Null pointer on error
///
/// # Memory
/// The returned string must be freed with `wallet_ffi_free_string()`.
///
/// # Safety
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_account_id_to_base58(
    account_id: *const FfiBytes32,
) -> *mut std::ffi::c_char {
    if account_id.is_null() {
        print_error("Null account_id pointer");
        return ptr::null_mut();
    }

    let account_id = AccountId::new(unsafe { (*account_id).data });
    let base58_str = account_id.to_string();

    match std::ffi::CString::new(base58_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            print_error(format!("Failed to create C string: {e}"));
            ptr::null_mut()
        }
    }
}

/// Parse a Base58 string into an account ID.
///
/// # Parameters
/// - `base58_str`: Null-terminated Base58 string
/// - `out_account_id`: Output pointer for the account ID (32 bytes)
///
/// # Returns
/// - `Success` on successful parsing
/// - `InvalidAccountId` if the string is not valid Base58
/// - Error code on other failures
///
/// # Safety
/// - `base58_str` must be a valid pointer to a null-terminated C string
/// - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_account_id_from_base58(
    base58_str: *const std::ffi::c_char,
    out_account_id: *mut FfiBytes32,
) -> WalletFfiError {
    if base58_str.is_null() || out_account_id.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(base58_str) };
    let str_slice = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            print_error(format!("Invalid UTF-8: {e}"));
            return WalletFfiError::InvalidUtf8;
        }
    };

    let account_id: AccountId = match str_slice.parse() {
        Ok(id) => id,
        Err(e) => {
            print_error(format!("Invalid Base58 account ID: {e}"));
            return WalletFfiError::InvalidAccountId;
        }
    };

    unsafe {
        (*out_account_id).data = *account_id.value();
    }

    WalletFfiError::Success
}
