//! C-compatible type definitions for the FFI layer.

use std::ptr;

use indexer_service_protocol::ProgramId;

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
}

/// 64-byte array type for signatures, etc.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiBytes64 {
    pub data: [u8; 64],
}

impl Default for FfiBytes64 {
    fn default() -> Self {
        Self { data: [0; 64] }
    }
}

/// Program ID - 8 u32 values (32 bytes total).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiProgramId {
    pub data: [u32; 8],
}

impl From<ProgramId> for FfiProgramId {
    fn from(value: ProgramId) -> Self {
        Self { data: value.0 }
    }
}

/// U128 - 16 bytes little endian.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiU128 {
    pub data: [u8; 16],
}

/// Account data structure - C-compatible version of nssa Account.
///
/// Note: `balance` and `nonce` are u128 values represented as little-endian
/// byte arrays since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    pub program_owner: FfiProgramId,
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Pointer to account data bytes.
    pub data: *const u8,
    /// Length of account data.
    pub data_len: usize,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
}

impl Default for FfiAccount {
    fn default() -> Self {
        Self {
            program_owner: FfiProgramId::default(),
            balance: FfiU128::default(),
            data: std::ptr::null(),
            data_len: 0,
            nonce: FfiU128::default(),
        }
    }
}

/// Public keys for a private account (safe to expose).
#[repr(C)]
pub struct FfiPrivateAccountKeys {
    /// Nullifier public key (32 bytes).
    pub nullifier_public_key: FfiBytes32,
    /// viewing public key (compressed secp256k1 point).
    pub viewing_public_key: *const u8,
    /// Length of viewing public key (typically 33 bytes).
    pub viewing_public_key_len: usize,
}

impl Default for FfiPrivateAccountKeys {
    fn default() -> Self {
        Self {
            nullifier_public_key: FfiBytes32::default(),
            viewing_public_key: std::ptr::null(),
            viewing_public_key_len: 0,
        }
    }
}

/// Public key info for a public account.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiPublicAccountKey {
    pub public_key: FfiBytes32,
}

// Helper functions to convert between Rust and FFI types

impl FfiBytes32 {
    /// Create from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// Create from an `AccountId`.
    #[must_use]
    pub const fn from_account_id(id: &nssa::AccountId) -> Self {
        Self { data: *id.value() }
    }
}

impl From<u128> for FfiU128 {
    fn from(value: u128) -> Self {
        Self {
            data: value.to_le_bytes(),
        }
    }
}

impl From<&nssa::AccountId> for FfiBytes32 {
    fn from(id: &nssa::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<nssa::Account> for FfiAccount {
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert to byte arrays for FFI"
    )]
    fn from(value: nssa::Account) -> Self {
        // Convert account data to FFI type
        let data_vec: Vec<u8> = value.data.into();
        let data_len = data_vec.len();
        let data = if data_len > 0 {
            let data_boxed = data_vec.into_boxed_slice();
            Box::into_raw(data_boxed) as *const u8
        } else {
            ptr::null()
        };

        let program_owner = FfiProgramId {
            data: value.program_owner,
        };
        Self {
            program_owner,
            balance: value.balance.into(),
            data,
            data_len,
            nonce: value.nonce.0.into(),
        }
    }
}

impl From<nssa::PublicKey> for FfiPublicAccountKey {
    fn from(value: nssa::PublicKey) -> Self {
        Self {
            public_key: FfiBytes32::from_bytes(*value.value()),
        }
    }
}
