use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use crate::clients::member::MemberClient;
use crate::clients::moderator::ModeratorClient;
use crate::clients::aggregator::SlashAggregator;
use crate::types::{EncryptedSharePerPost, ModerationCertificate};

pub struct FfiMemberClient {
    inner: MemberClient,
}

pub struct FfiModeratorClient {
    inner: ModeratorClient,
}

pub struct FfiSlashAggregator {
    inner: SlashAggregator,
}

// Helper: return a JSON string to C. Caller must free with ffi_free_string.
fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn error_json(msg: &str) -> *mut c_char {
    to_c_string(&format!("{{\"error\":\"{}\"}}", msg))
}

#[no_mangle]
pub extern "C" fn ffi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)); }
    }
}

/// MemberClient FFI
#[no_mangle]
pub unsafe extern "C" fn ffi_member_new(
    nsk_ptr: *const u8,
    k_strikes: u32,
) -> *mut FfiMemberClient {
    if nsk_ptr.is_null() { return ptr::null_mut(); }
    let nsk_slice = slice::from_raw_parts(nsk_ptr, 32);
    let mut nsk = [0u8; 32];
    nsk.copy_from_slice(nsk_slice);

    Box::into_raw(Box::new(FfiMemberClient {
        inner: MemberClient::new(nsk, k_strikes),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ffi_member_free(ptr: *mut FfiMemberClient) {
    if !ptr.is_null() { drop(Box::from_raw(ptr)); }
}

/// Prepare a post. Returns JSON string with PostPayload.
#[no_mangle]
pub unsafe extern "C" fn ffi_member_prepare_post(
    handle: *mut FfiMemberClient,
    message_ptr: *const u8,
    message_len: u32,
    post_salt_ptr: *const u8,
    mod_pubkeys_ptr: *const u8,
    mod_count: u32,
    n_threshold: u32,
) -> *mut c_char {
    if handle.is_null() || message_ptr.is_null() || post_salt_ptr.is_null() || mod_pubkeys_ptr.is_null() {
        return error_json("null pointer");
    }

    let client = &mut (*handle).inner;
    let message = slice::from_raw_parts(message_ptr, message_len as usize);

    let mut post_salt = [0u8; 32];
    post_salt.copy_from_slice(slice::from_raw_parts(post_salt_ptr, 32));

    let all_keys = slice::from_raw_parts(mod_pubkeys_ptr, (mod_count * 32) as usize);
    let mod_pubkeys: Vec<[u8; 32]> = all_keys
        .chunks_exact(32)
        .map(|chunk| {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            key
        })
        .collect();

    match client.prepare_post(message, &post_salt, &mod_pubkeys, n_threshold) {
        Ok(payload) => {
            match serde_json::to_string(&payload) {
                Ok(json) => to_c_string(&json),
                Err(e) => error_json(&format!("serialize: {}", e)),
            }
        }
        Err(e) => error_json(e),
    }
}

/// ModeratorClient FFI
#[no_mangle]
pub unsafe extern "C" fn ffi_moderator_new(
    privkey_ptr: *const u8,
) -> *mut FfiModeratorClient {
    if privkey_ptr.is_null() { return ptr::null_mut(); }
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(slice::from_raw_parts(privkey_ptr, 32));

    Box::into_raw(Box::new(FfiModeratorClient {
        inner: ModeratorClient::new(privkey),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ffi_moderator_free(ptr: *mut FfiModeratorClient) {
    if !ptr.is_null() { drop(Box::from_raw(ptr)); }
}

#[no_mangle]
pub unsafe extern "C" fn ffi_moderator_public_key(
    handle: *const FfiModeratorClient,
    out_ptr: *mut u8,
) {
    if handle.is_null() || out_ptr.is_null() { return; }
    let pk = (*handle).inner.public_key();
    ptr::copy_nonoverlapping(pk.as_ptr(), out_ptr, 32);
}

#[no_mangle]
pub unsafe extern "C" fn ffi_moderator_issue_strike(
    handle: *const FfiModeratorClient,
    tracing_tag_ptr: *const u8,
    encrypted_share_json: *const c_char,
    moderator_index: u32,
) -> *mut c_char {
    if handle.is_null() || tracing_tag_ptr.is_null() || encrypted_share_json.is_null() {
        return error_json("null pointer");
    }

    let mut tracing_tag = [0u8; 32];
    tracing_tag.copy_from_slice(slice::from_raw_parts(tracing_tag_ptr, 32));

    let json_str = match CStr::from_ptr(encrypted_share_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8 in encrypted_share_json"),
    };

    let share: EncryptedSharePerPost = match serde_json::from_str(json_str) {
        Ok(s) => s,
        Err(e) => return error_json(&format!("parse share: {}", e)),
    };

    match (*handle).inner.issue_strike(tracing_tag, &share, moderator_index) {
        Ok(cert) => match serde_json::to_string(&cert) {
            Ok(json) => to_c_string(&json),
            Err(e) => error_json(&format!("serialize: {}", e)),
        },
        Err(e) => error_json(e),
    }
}

/// SlashAggregator FFI
#[no_mangle]
pub unsafe extern "C" fn ffi_aggregator_new(
    n_threshold: u32,
    k_strikes: u32,
    mod_pubkeys_ptr: *const u8,
    mod_count: u32,
) -> *mut FfiSlashAggregator {
    if mod_pubkeys_ptr.is_null() { return ptr::null_mut(); }

    let all_keys = slice::from_raw_parts(mod_pubkeys_ptr, (mod_count * 32) as usize);
    let mod_pubkeys: Vec<[u8; 32]> = all_keys
        .chunks_exact(32)
        .map(|chunk| {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            key
        })
        .collect();

    Box::into_raw(Box::new(FfiSlashAggregator {
        inner: SlashAggregator::new(n_threshold, k_strikes, &mod_pubkeys),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ffi_aggregator_free(ptr: *mut FfiSlashAggregator) {
    if !ptr.is_null() { drop(Box::from_raw(ptr)); }
}

/// Reconstruct a per-post strike from N certificates.
#[no_mangle]
pub unsafe extern "C" fn ffi_aggregator_reconstruct_strike(
    handle: *const FfiSlashAggregator,
    tracing_tag_ptr: *const u8,
    certificates_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || tracing_tag_ptr.is_null() || certificates_json.is_null() {
        return error_json("null pointer");
    }

    let mut tracing_tag = [0u8; 32];
    tracing_tag.copy_from_slice(slice::from_raw_parts(tracing_tag_ptr, 32));

    let json_str = match CStr::from_ptr(certificates_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8"),
    };

    let certs: Vec<ModerationCertificate> = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(e) => return error_json(&format!("parse certs: {}", e)),
    };

    match (*handle).inner.reconstruct_strike(&tracing_tag, &certs) {
        Ok(s_post) => {
            let hex = hex::encode(s_post);
            to_c_string(&format!("{{\"s_post\":\"{}\"}}", hex))
        }
        Err(e) => error_json(e),
    }
}

/// Reconstruct the NSK from K accumulated strikes.
#[no_mangle]
pub unsafe extern "C" fn ffi_aggregator_reconstruct_nsk(
    handle: *const FfiSlashAggregator,
    strikes_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || strikes_json.is_null() {
        return error_json("null pointer");
    }

    let json_str = match CStr::from_ptr(strikes_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_json("invalid UTF-8"),
    };

    let raw: Vec<(u8, String)> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return error_json(&format!("parse strikes: {}", e)),
    };

    let mut strikes = Vec::new();
    for (x, hex_s) in &raw {
        match hex::decode(hex_s) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&bytes);
                strikes.push((*x, s));
            }
            _ => return error_json("invalid strike hex"),
        }
    }

    match (*handle).inner.reconstruct_nsk(&strikes) {
        Ok(nsk) => {
            let hex = hex::encode(nsk);
            to_c_string(&format!("{{\"nsk\":\"{}\"}}", hex))
        }
        Err(e) => error_json(e),
    }
}