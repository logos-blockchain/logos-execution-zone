//! C-compatible type definitions for the FFI layer.

use core::slice;
use std::{
    ffi::{c_char, CString},
    ptr,
    str::FromStr as _,
};

use common::HashType;
use lee::{Data, ProgramId, SharedSecretKey};
use lee_core::{
    encryption::MlKem768EncapsulationKey, program::PdaSeed, AuthorizationSecretKey,
    NullifierPublicKey, NullifierSecretKey,
};
use wallet::{account::AccountIdWithPrivacy, AccountIdentity};

use crate::error::WalletFfiError;

/// Opaque pointer to the Wallet instance.
///
/// This type is never instantiated directly - it's used as an opaque handle
/// to hide the internal wallet structure from C code.
#[repr(C)]
pub struct WalletHandle {
    _private: [u8; 0],
}

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
}

pub type FfiPdaSeed = FfiBytes32;

impl From<FfiPdaSeed> for PdaSeed {
    fn from(value: FfiPdaSeed) -> Self {
        Self::new(value.data)
    }
}

impl From<PdaSeed> for FfiPdaSeed {
    fn from(value: PdaSeed) -> Self {
        Self {
            data: *value.as_bytes(),
        }
    }
}

pub type FfiNullifierPublicKey = FfiBytes32;

impl From<FfiNullifierPublicKey> for NullifierPublicKey {
    fn from(value: FfiNullifierPublicKey) -> Self {
        Self(value.data)
    }
}

impl From<NullifierPublicKey> for FfiNullifierPublicKey {
    fn from(value: NullifierPublicKey) -> Self {
        Self { data: value.0 }
    }
}

/// Program ID - 8 u32 values (32 bytes total).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiProgramId {
    pub data: [u32; 8],
}

/// U128 - 16 bytes little endian.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiU128 {
    pub data: [u8; 16],
}

/// A single program's slot inside an account.
///
/// Note: `balance` is a u128 value represented as a little-endian byte array
/// since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccountSlot {
    pub program_id: FfiProgramId,
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Pointer to slot data bytes.
    pub data: *const u8,
    /// Length of slot data.
    pub data_len: usize,
}

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `nonce` is a u128 value represented as a little-endian byte array
/// since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    /// Pointer to the account's occupied slots, one entry per program.
    pub slots: *const FfiAccountSlot,
    /// Number of slots.
    pub slots_len: usize,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
}

impl Default for FfiAccount {
    fn default() -> Self {
        Self {
            slots: std::ptr::null(),
            slots_len: 0,
            nonce: FfiU128::default(),
        }
    }
}

/// Public keys for a private account (safe to expose).
#[repr(C)]
pub struct FfiPrivateAccountKeys {
    /// Nullifier public key (32 bytes).
    pub nullifier_public_key: FfiBytes32,
    /// Viewing public key (ML-KEM-768 encapsulation key, 1184 bytes).
    pub viewing_public_key: *const u8,
    /// Length of viewing public key (always 1184 bytes for ML-KEM-768).
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

/// Single entry in the account list.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiAccountListEntry {
    pub account_id: FfiBytes32,
    pub is_public: bool,
}

/// List of accounts returned by `wallet_ffi_list_accounts`.
#[repr(C)]
pub struct FfiAccountList {
    pub entries: *mut FfiAccountListEntry,
    pub count: usize,
}

impl Default for FfiAccountList {
    fn default() -> Self {
        Self {
            entries: std::ptr::null_mut(),
            count: 0,
        }
    }
}

/// Result of a transfer operation.
#[repr(C)]
#[derive(Debug)]
pub struct FfiTransferResult {
    // TODO: Replace with HashType FFI representation
    /// Transaction hash (null-terminated string, or null on failure).
    pub tx_hash: *mut c_char,
    /// Whether the transfer succeeded.
    pub success: bool,
}

impl Default for FfiTransferResult {
    fn default() -> Self {
        Self {
            tx_hash: std::ptr::null_mut(),
            success: false,
        }
    }
}

impl FfiTransferResult {
    #[must_use]
    /// Casting valid results hash into bytes. Effectively frees `FfiTransferResult`.
    ///
    /// # Safety
    /// Field `tx_hash` must be a valid pointer into transaction hash.
    pub unsafe fn tx_hash_bytes(self) -> FfiBytes32 {
        let cstring = unsafe { CString::from_raw(self.tx_hash) };
        let rstring = cstring.into_string().expect("Must be a valid Rust string");

        let hash_val = HashType::from_str(&rstring).expect("Must be a valid hex string");

        FfiBytes32 { data: hash_val.0 }
    }
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
    pub const fn from_account_id(id: lee::AccountId) -> Self {
        Self { data: *id.value() }
    }
}

impl From<SharedSecretKey> for FfiBytes32 {
    fn from(value: SharedSecretKey) -> Self {
        Self { data: value.0 }
    }
}

impl FfiPrivateAccountKeys {
    #[must_use]
    pub const fn npk(&self) -> lee_core::NullifierPublicKey {
        lee_core::NullifierPublicKey(self.nullifier_public_key.data)
    }

    pub fn vpk(&self) -> Result<lee_core::encryption::ViewingPublicKey, WalletFfiError> {
        if self.viewing_public_key_len == 1184 {
            let slice = unsafe {
                slice::from_raw_parts(self.viewing_public_key, self.viewing_public_key_len)
            };
            Ok(
                lee_core::encryption::ViewingPublicKey::from_bytes(slice.to_vec())
                    .expect("wallet_ffi: length already validated to 1184 bytes"),
            )
        } else {
            Err(WalletFfiError::InvalidKeyValue)
        }
    }
}

/// Enumeration to represent kinds of `FfiAccountIdentity`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiAccountIdentityKind {
    Public = 0,
    PublicNoSign = 1,
    PublicKeycard = 2,
    PrivateOwned = 3,
    PrivateForeign = 4,
    PrivatePdaOwned = 5,
    PrivatePdaForeign = 6,
    PrivateShared = 7,
    PrivatePdaShared = 8,
}

/// Struct representing an account identity, given to `AccountManager` at intialization.
#[repr(C)]
pub struct FfiAccountIdentity {
    pub kind: FfiAccountIdentityKind,
    pub account_id: FfiBytes32,
    /// C-compatible string.
    pub key_path: *mut c_char,
    pub authorization_secret_key: FfiBytes32,
    pub nullifier_secret_key: FfiBytes32,
    pub nullifier_public_key: FfiBytes32,
    pub viewing_public_key: *const u8,
    pub viewing_public_key_len: usize,
    pub identifier: FfiU128,
    /// Private-PDA binding: the authority program and the seed its address derives from.
    pub authority_program_id: FfiBytes32,
    pub pda_seed: FfiBytes32,
}

impl Default for FfiAccountIdentity {
    fn default() -> Self {
        Self {
            kind: FfiAccountIdentityKind::Public,
            account_id: FfiBytes32::default(),
            authority_program_id: FfiBytes32::default(),
            pda_seed: FfiBytes32::default(),
            key_path: std::ptr::null_mut(),
            authorization_secret_key: FfiBytes32::default(),
            nullifier_secret_key: FfiBytes32::default(),
            nullifier_public_key: FfiBytes32::default(),
            viewing_public_key: std::ptr::null(),
            viewing_public_key_len: 0,
            identifier: FfiU128::default(),
        }
    }
}

impl From<u128> for FfiU128 {
    fn from(value: u128) -> Self {
        Self {
            data: value.to_le_bytes(),
        }
    }
}

impl From<FfiU128> for u128 {
    fn from(value: FfiU128) -> Self {
        Self::from_le_bytes(value.data)
    }
}

impl From<lee::AccountId> for FfiBytes32 {
    fn from(id: lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<[u8; 32]> for FfiBytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self { data: value }
    }
}

impl From<FfiBytes32> for lee::AccountId {
    fn from(bytes: FfiBytes32) -> Self {
        Self::new(bytes.data)
    }
}

impl From<lee::Account> for FfiAccount {
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert to byte arrays for FFI"
    )]
    fn from(value: lee::Account) -> Self {
        let slots: Vec<FfiAccountSlot> = value
            .slots
            .into_iter()
            .map(|(program_id, slot)| {
                // Convert slot data to FFI type
                let data_vec: Vec<u8> = slot.data.into();
                let data_len = data_vec.len();
                let data = if data_len > 0 {
                    let data_boxed = data_vec.into_boxed_slice();
                    Box::into_raw(data_boxed) as *const u8
                } else {
                    ptr::null()
                };

                FfiAccountSlot {
                    program_id: FfiProgramId { data: program_id },
                    balance: slot.balance.into(),
                    data,
                    data_len,
                }
            })
            .collect();

        let slots_len = slots.len();
        let slots = if slots_len > 0 {
            Box::into_raw(slots.into_boxed_slice()) as *const FfiAccountSlot
        } else {
            ptr::null()
        };

        Self {
            slots,
            slots_len,
            nonce: value.nonce.0.into(),
        }
    }
}

impl TryFrom<&FfiAccount> for lee::Account {
    type Error = WalletFfiError;

    fn try_from(value: &FfiAccount) -> Result<Self, Self::Error> {
        let slots: &[FfiAccountSlot] = if value.slots.is_null() || value.slots_len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(value.slots, value.slots_len) }
        };

        Ok(Self {
            nonce: lee_core::account::Nonce(value.nonce.into()),
            slots: slots
                .iter()
                .map(|slot| {
                    let data = if slot.data_len > 0 {
                        let bytes = unsafe { slice::from_raw_parts(slot.data, slot.data_len) };
                        Data::try_from(bytes.to_vec())
                            .map_err(|_err| WalletFfiError::InvalidTypeConversion)?
                    } else {
                        Data::default()
                    };

                    Ok((
                        slot.program_id.data,
                        lee_core::account::Slot {
                            balance: slot.balance.into(),
                            data,
                        },
                    ))
                })
                .collect::<Result<_, Self::Error>>()?,
        })
    }
}

impl From<lee::PublicKey> for FfiPublicAccountKey {
    fn from(value: lee::PublicKey) -> Self {
        Self {
            public_key: FfiBytes32::from_bytes(*value.value()),
        }
    }
}

impl TryFrom<&FfiPublicAccountKey> for lee::PublicKey {
    type Error = WalletFfiError;

    fn try_from(value: &FfiPublicAccountKey) -> Result<Self, Self::Error> {
        let public_key = Self::try_new(value.public_key.data)
            .map_err(|_err| WalletFfiError::InvalidTypeConversion)?;
        Ok(public_key)
    }
}

impl From<AccountIdentity> for FfiAccountIdentity {
    fn from(value: AccountIdentity) -> Self {
        match value {
            AccountIdentity::Public(account_id) => Self {
                kind: FfiAccountIdentityKind::Public,
                account_id: account_id.into(),
                ..Default::default()
            },
            AccountIdentity::PublicNoSign(account_id) => Self {
                kind: FfiAccountIdentityKind::PublicNoSign,
                account_id: account_id.into(),
                ..Default::default()
            },
            AccountIdentity::PublicKeycard {
                account_id,
                key_path,
            } => Self {
                kind: FfiAccountIdentityKind::PublicKeycard,
                account_id: account_id.into(),
                key_path: CString::into_raw(
                    CString::from_str(&key_path).expect("key_path should be a valid string"),
                ),
                ..Default::default()
            },
            AccountIdentity::PrivateOwned(account_id) => Self {
                kind: FfiAccountIdentityKind::PrivateOwned,
                account_id: account_id.into(),
                ..Default::default()
            },
            AccountIdentity::PrivateForeign {
                npk,
                vpk,
                identifier,
            } => {
                let vpk_vec = vpk.to_bytes().to_vec();
                let vpk_len = vpk_vec.len();
                let vpk_data = if vpk_len > 0 {
                    let vpk_data_boxed = vpk_vec.into_boxed_slice();
                    Box::into_raw(vpk_data_boxed) as *const u8
                } else {
                    ptr::null()
                };

                Self {
                    kind: FfiAccountIdentityKind::PrivateForeign,
                    nullifier_public_key: npk.0.into(),
                    viewing_public_key: vpk_data,
                    viewing_public_key_len: vpk_len,
                    identifier: identifier.into(),
                    ..Default::default()
                }
            }
            AccountIdentity::PrivatePdaOwned(account_id) => Self {
                kind: FfiAccountIdentityKind::PrivatePdaOwned,
                account_id: account_id.into(),
                ..Default::default()
            },
            AccountIdentity::PrivatePdaForeign {
                binding,
                npk,
                vpk,
                identifier,
            } => {
                let vpk_vec = vpk.to_bytes().to_vec();
                let vpk_len = vpk_vec.len();
                let vpk_data = if vpk_len > 0 {
                    let vpk_data_boxed = vpk_vec.into_boxed_slice();
                    Box::into_raw(vpk_data_boxed) as *const u8
                } else {
                    ptr::null()
                };

                Self {
                    kind: FfiAccountIdentityKind::PrivatePdaForeign,
                    authority_program_id: lee::AccountId::from(binding.0).into(),
                    pda_seed: FfiBytes32 {
                        data: *binding.1.as_ref().first_chunk::<32>().expect("seed is 32 bytes"),
                    },
                    nullifier_public_key: npk.0.into(),
                    viewing_public_key: vpk_data,
                    viewing_public_key_len: vpk_len,
                    identifier: identifier.into(),
                    ..Default::default()
                }
            }
            AccountIdentity::PrivateShared {
                ask,
                vpk,
                identifier,
            } => {
                let vpk_vec = vpk.to_bytes().to_vec();
                let vpk_len = vpk_vec.len();
                let vpk_data = if vpk_len > 0 {
                    let vpk_data_boxed = vpk_vec.into_boxed_slice();
                    Box::into_raw(vpk_data_boxed) as *const u8
                } else {
                    ptr::null()
                };

                let nsk = NullifierSecretKey::from(&ask);

                Self {
                    kind: FfiAccountIdentityKind::PrivateShared,
                    authorization_secret_key: ask.0.into(),
                    nullifier_secret_key: nsk.into(),
                    nullifier_public_key: NullifierPublicKey::from(&nsk).0.into(),
                    viewing_public_key: vpk_data,
                    viewing_public_key_len: vpk_len,
                    identifier: identifier.into(),
                    ..Default::default()
                }
            }
            AccountIdentity::PrivatePdaShared {
                binding,
                nsk,
                vpk,
                identifier,
            } => {
                let vpk_vec = vpk.to_bytes().to_vec();
                let vpk_len = vpk_vec.len();
                let vpk_data = if vpk_len > 0 {
                    let vpk_data_boxed = vpk_vec.into_boxed_slice();
                    Box::into_raw(vpk_data_boxed) as *const u8
                } else {
                    ptr::null()
                };

                Self {
                    kind: FfiAccountIdentityKind::PrivatePdaShared,
                    authority_program_id: lee::AccountId::from(binding.0).into(),
                    pda_seed: FfiBytes32 {
                        data: *binding.1.as_ref().first_chunk::<32>().expect("seed is 32 bytes"),
                    },
                    nullifier_secret_key: nsk.into(),
                    nullifier_public_key: NullifierPublicKey::from(&nsk).0.into(),
                    viewing_public_key: vpk_data,
                    viewing_public_key_len: vpk_len,
                    identifier: identifier.into(),
                    ..Default::default()
                }
            }
        }
    }
}

impl TryFrom<&FfiAccountIdentity> for AccountIdentity {
    type Error = WalletFfiError;

    #[expect(
        clippy::map_err_ignore,
        reason = "`WalletFfiError` must be a trivial enum for FFI"
    )]
    fn try_from(value: &FfiAccountIdentity) -> Result<Self, Self::Error> {
        match value.kind {
            FfiAccountIdentityKind::Public => Ok(Self::Public(value.account_id.into())),
            FfiAccountIdentityKind::PublicNoSign => Ok(Self::PublicNoSign(value.account_id.into())),
            FfiAccountIdentityKind::PublicKeycard => {
                let key_path = unsafe { CString::from_raw(value.key_path) }
                    .to_str()?
                    .to_owned();
                Ok(Self::PublicKeycard {
                    account_id: value.account_id.into(),
                    key_path,
                })
            }
            FfiAccountIdentityKind::PrivateOwned => Ok(Self::PrivateOwned(value.account_id.into())),
            FfiAccountIdentityKind::PrivateForeign => {
                let vpk = if value.viewing_public_key_len == 1184 {
                    let slice = unsafe {
                        slice::from_raw_parts(
                            value.viewing_public_key,
                            value.viewing_public_key_len,
                        )
                    };
                    Ok(MlKem768EncapsulationKey::from_bytes(slice.to_vec())
                        .map_err(|_| WalletFfiError::InvalidKeyValue)?)
                } else {
                    Err(WalletFfiError::InvalidKeyValue)
                }?;

                Ok(Self::PrivateForeign {
                    npk: NullifierPublicKey(value.nullifier_public_key.data),
                    vpk,
                    identifier: value.identifier.into(),
                })
            }
            FfiAccountIdentityKind::PrivatePdaOwned => {
                Ok(Self::PrivatePdaOwned(value.account_id.into()))
            }
            FfiAccountIdentityKind::PrivatePdaForeign => {
                let vpk = if value.viewing_public_key_len == 1184 {
                    let slice = unsafe {
                        slice::from_raw_parts(
                            value.viewing_public_key,
                            value.viewing_public_key_len,
                        )
                    };
                    Ok(MlKem768EncapsulationKey::from_bytes(slice.to_vec())
                        .map_err(|_| WalletFfiError::InvalidKeyValue)?)
                } else {
                    Err(WalletFfiError::InvalidKeyValue)
                }?;

                Ok(Self::PrivatePdaForeign {
                    binding: (
                        lee::AccountId::new(value.authority_program_id.data).into(),
                        lee_core::program::PdaSeed::new(value.pda_seed.data),
                    ),
                    npk: NullifierPublicKey(value.nullifier_public_key.data),
                    vpk,
                    identifier: value.identifier.into(),
                })
            }
            FfiAccountIdentityKind::PrivateShared => {
                let vpk = if value.viewing_public_key_len == 1184 {
                    let slice = unsafe {
                        slice::from_raw_parts(
                            value.viewing_public_key,
                            value.viewing_public_key_len,
                        )
                    };
                    Ok(MlKem768EncapsulationKey::from_bytes(slice.to_vec())
                        .map_err(|_| WalletFfiError::InvalidKeyValue)?)
                } else {
                    Err(WalletFfiError::InvalidKeyValue)
                }?;

                let ask = AuthorizationSecretKey(value.authorization_secret_key.data);
                let nsk = NullifierSecretKey::from(&ask);
                if value.nullifier_secret_key.data != nsk
                    || value.nullifier_public_key.data != NullifierPublicKey::from(&nsk).0
                {
                    return Err(WalletFfiError::InvalidKeyValue);
                }

                Ok(Self::PrivateShared {
                    ask,
                    vpk,
                    identifier: value.identifier.into(),
                })
            }
            FfiAccountIdentityKind::PrivatePdaShared => {
                let vpk = if value.viewing_public_key_len == 1184 {
                    let slice = unsafe {
                        slice::from_raw_parts(
                            value.viewing_public_key,
                            value.viewing_public_key_len,
                        )
                    };
                    Ok(MlKem768EncapsulationKey::from_bytes(slice.to_vec())
                        .map_err(|_| WalletFfiError::InvalidKeyValue)?)
                } else {
                    Err(WalletFfiError::InvalidKeyValue)
                }?;

                let nsk = value.nullifier_secret_key.data;
                if value.nullifier_public_key.data != NullifierPublicKey::from(&nsk).0 {
                    return Err(WalletFfiError::InvalidKeyValue);
                }

                Ok(Self::PrivatePdaShared {
                    binding: (
                        lee::AccountId::new(value.authority_program_id.data).into(),
                        lee_core::program::PdaSeed::new(value.pda_seed.data),
                    ),
                    nsk,
                    vpk,
                    identifier: value.identifier.into(),
                })
            }
        }
    }
}

impl From<ProgramId> for FfiProgramId {
    fn from(value: ProgramId) -> Self {
        Self { data: value }
    }
}

impl From<FfiProgramId> for ProgramId {
    fn from(value: FfiProgramId) -> Self {
        value.data
    }
}

#[repr(C)]
#[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
pub struct FfiAccountIdWithPrivacy {
    pub account_id: FfiBytes32,
    pub is_private: bool,
}

impl From<AccountIdWithPrivacy> for FfiAccountIdWithPrivacy {
    fn from(value: AccountIdWithPrivacy) -> Self {
        match value {
            AccountIdWithPrivacy::Public(acc) => Self {
                account_id: acc.into(),
                is_private: false,
            },
            AccountIdWithPrivacy::Private(acc) => Self {
                account_id: acc.into(),
                is_private: true,
            },
        }
    }
}

impl From<FfiAccountIdWithPrivacy> for AccountIdWithPrivacy {
    fn from(value: FfiAccountIdWithPrivacy) -> Self {
        if value.is_private {
            Self::Private(value.account_id.into())
        } else {
            Self::Public(value.account_id.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use lee::{AccountId, PrivateKey, PublicKey};
    use lee_core::{
        encryption::ViewingPublicKey, program::PdaSeed, AuthorizationSecretKey, NullifierSecretKey,
        PrivateAccountKind,
    };
    use wallet::AccountIdentity;

    use crate::{error::WalletFfiError, FfiAccountIdentity, FfiAccountIdentityKind, FfiBytes32};

    #[test]
    fn account_identity_roundtrip() {
        let private_key = PrivateKey::try_new([42; 32]).unwrap();
        let public_key = PublicKey::new_from_private_key(&private_key);
        let pub_acc_id = (&public_key).into();

        let ask = AuthorizationSecretKey([43; 32]);
        let nsk = NullifierSecretKey::from(&ask);
        let vpk = ViewingPublicKey::from_seed(&[44; 32], &[54; 32]);
        let npk = (&nsk).into();
        let identifier = u128::from_le_bytes([45; 16]);

        let private_reg_acc_id =
            AccountId::for_private_account(&npk, &vpk, &PrivateAccountKind::Regular(identifier));
        let private_pda_acc_id = AccountId::for_private_account(
            &npk,
            &vpk,
            &PrivateAccountKind::Pda {
                program_id: [46; 8],
                seed: PdaSeed::new([47; 32]),
                identifier,
            },
        );

        let acc_identity_1 = AccountIdentity::Public(pub_acc_id);
        let acc_identity_2 = AccountIdentity::PublicNoSign(pub_acc_id);

        let acc_identity_2_5 = AccountIdentity::PublicKeycard {
            account_id: pub_acc_id,
            key_path: "path/to/key".to_owned(),
        };

        let acc_identity_3 = AccountIdentity::PrivateOwned(private_reg_acc_id);
        let acc_identity_4 = AccountIdentity::PrivateForeign {
            npk,
            vpk: vpk.clone(),
            identifier,
        };
        let acc_identity_5 = AccountIdentity::PrivatePdaOwned(private_pda_acc_id);
        let acc_identity_6 = AccountIdentity::PrivatePdaForeign {
            binding: ([0_u32; 8], lee_core::program::PdaSeed::new([9; 32])),
            npk,
            vpk: vpk.clone(),
            identifier,
        };
        let acc_identity_7 = AccountIdentity::PrivateShared {
            ask,
            vpk: vpk.clone(),
            identifier,
        };
        let acc_identity_8 = AccountIdentity::PrivatePdaShared {
            binding: ([0_u32; 8], lee_core::program::PdaSeed::new([9; 32])),
            nsk,
            vpk,
            identifier,
        };

        let ffi_acc_identity_1: FfiAccountIdentity = acc_identity_1.clone().into();
        let ffi_acc_identity_2: FfiAccountIdentity = acc_identity_2.clone().into();
        let ffi_acc_identity_2_5: FfiAccountIdentity = acc_identity_2_5.clone().into();
        let ffi_acc_identity_3: FfiAccountIdentity = acc_identity_3.clone().into();
        let ffi_acc_identity_4: FfiAccountIdentity = acc_identity_4.clone().into();
        let ffi_acc_identity_5: FfiAccountIdentity = acc_identity_5.clone().into();
        let ffi_acc_identity_6: FfiAccountIdentity = acc_identity_6.clone().into();
        let ffi_acc_identity_7: FfiAccountIdentity = acc_identity_7.clone().into();
        let ffi_acc_identity_8: FfiAccountIdentity = acc_identity_8.clone().into();

        assert_eq!(ffi_acc_identity_1.kind, FfiAccountIdentityKind::Public);
        assert_eq!(
            ffi_acc_identity_2.kind,
            FfiAccountIdentityKind::PublicNoSign
        );
        assert_eq!(
            ffi_acc_identity_2_5.kind,
            FfiAccountIdentityKind::PublicKeycard
        );
        assert_eq!(
            ffi_acc_identity_3.kind,
            FfiAccountIdentityKind::PrivateOwned
        );
        assert_eq!(
            ffi_acc_identity_4.kind,
            FfiAccountIdentityKind::PrivateForeign
        );
        assert_eq!(
            ffi_acc_identity_5.kind,
            FfiAccountIdentityKind::PrivatePdaOwned
        );
        assert_eq!(
            ffi_acc_identity_6.kind,
            FfiAccountIdentityKind::PrivatePdaForeign
        );
        assert_eq!(
            ffi_acc_identity_7.kind,
            FfiAccountIdentityKind::PrivateShared
        );
        assert_eq!(
            ffi_acc_identity_8.kind,
            FfiAccountIdentityKind::PrivatePdaShared
        );

        assert_eq!(ffi_acc_identity_7.nullifier_secret_key.data, nsk);
        assert_eq!(ffi_acc_identity_7.nullifier_public_key.data, npk.0);
        assert_eq!(ffi_acc_identity_8.nullifier_public_key.data, npk.0);

        let acc_identity_res_1: AccountIdentity = (&ffi_acc_identity_1).try_into().unwrap();
        let acc_identity_res_2: AccountIdentity = (&ffi_acc_identity_2).try_into().unwrap();
        let acc_identity_res_2_5: AccountIdentity = (&ffi_acc_identity_2_5).try_into().unwrap();
        let acc_identity_res_3: AccountIdentity = (&ffi_acc_identity_3).try_into().unwrap();
        let acc_identity_res_4: AccountIdentity = (&ffi_acc_identity_4).try_into().unwrap();
        let acc_identity_res_5: AccountIdentity = (&ffi_acc_identity_5).try_into().unwrap();
        let acc_identity_res_6: AccountIdentity = (&ffi_acc_identity_6).try_into().unwrap();
        let acc_identity_res_7: AccountIdentity = (&ffi_acc_identity_7).try_into().unwrap();
        let acc_identity_res_8: AccountIdentity = (&ffi_acc_identity_8).try_into().unwrap();

        assert_eq!(acc_identity_res_1, acc_identity_1);
        assert_eq!(acc_identity_res_2, acc_identity_2);
        assert_eq!(acc_identity_res_2_5, acc_identity_2_5);
        assert_eq!(acc_identity_res_3, acc_identity_3);
        assert_eq!(acc_identity_res_4, acc_identity_4);
        assert_eq!(acc_identity_res_5, acc_identity_5);
        assert_eq!(acc_identity_res_6, acc_identity_6);
        assert_eq!(acc_identity_res_7, acc_identity_7);
        assert_eq!(acc_identity_res_8, acc_identity_8);
    }

    #[test]
    fn inconsistent_derived_keys_are_rejected() {
        let ask = AuthorizationSecretKey([43; 32]);
        let nsk = NullifierSecretKey::from(&ask);
        let vpk = ViewingPublicKey::from_seed(&[44; 32], &[54; 32]);
        let identifier = u128::from_le_bytes([45; 16]);

        let shared = AccountIdentity::PrivateShared {
            ask,
            vpk: vpk.clone(),
            identifier,
        };
        let pda_shared = AccountIdentity::PrivatePdaShared {
            binding: ([0_u32; 8], lee_core::program::PdaSeed::new([9; 32])),
            nsk,
            vpk,
            identifier,
        };

        let mut tampered_nsk: FfiAccountIdentity = shared.clone().into();
        tampered_nsk.nullifier_secret_key.data[0] ^= 1;
        let mut tampered_npk: FfiAccountIdentity = shared.clone().into();
        tampered_npk.nullifier_public_key.data[0] ^= 1;
        let mut zeroed: FfiAccountIdentity = shared.into();
        zeroed.nullifier_secret_key = FfiBytes32::default();
        zeroed.nullifier_public_key = FfiBytes32::default();
        let mut tampered_pda_npk: FfiAccountIdentity = pda_shared.clone().into();
        tampered_pda_npk.nullifier_public_key.data[0] ^= 1;
        let mut zeroed_pda: FfiAccountIdentity = pda_shared.into();
        zeroed_pda.nullifier_public_key = FfiBytes32::default();

        for inconsistent in [
            &tampered_nsk,
            &tampered_npk,
            &zeroed,
            &tampered_pda_npk,
            &zeroed_pda,
        ] {
            assert_eq!(
                AccountIdentity::try_from(inconsistent).unwrap_err(),
                WalletFfiError::InvalidKeyValue
            );
        }
    }
}
