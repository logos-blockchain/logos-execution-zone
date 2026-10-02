use common::HashType;
use lee::{AccountId, ProgramId, PublicKey, SharedSecretKey, Signature};
use lee_core::{
    NullifierPublicKey, account::Nonce, encryption::MlKem768EncapsulationKey, program::PdaSeed,
};
use sequencer_storage_actor::actor::event_filter::Selector;

use crate::{errors::PrimitiveOperationStatus, types::vectors::FfiVecU8};

pub mod account;
pub mod block;
pub mod event;
pub mod transaction;
pub mod vectors;

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
}

impl From<[u8; 32]> for FfiBytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self { data: value }
    }
}

impl From<FfiBytes32> for [u8; 32] {
    fn from(value: FfiBytes32) -> Self {
        value.data
    }
}

/// 8-byte array type for event selectors.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FfiBytes8 {
    pub data: [u8; 8],
}

/// 64-byte array type for signatures, etc.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FfiBytes64 {
    pub data: [u8; 64],
}

/// Program ID - 8 u32 values (32 bytes total).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FfiProgramId {
    pub data: [u32; 8],
}

impl From<ProgramId> for FfiProgramId {
    fn from(value: ProgramId) -> Self {
        Self { data: value }
    }
}

/// U128 - 16 bytes little endian.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FfiU128 {
    pub data: [u8; 16],
}

impl FfiBytes32 {
    /// Create from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// Create from an `AccountId`.
    #[must_use]
    pub const fn from_account_id(id: &lee::AccountId) -> Self {
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

impl From<FfiU128> for u128 {
    fn from(value: FfiU128) -> Self {
        Self::from_le_bytes(value.data)
    }
}

impl From<Nonce> for FfiU128 {
    fn from(value: Nonce) -> Self {
        value.0.into()
    }
}

impl From<FfiU128> for Nonce {
    fn from(value: FfiU128) -> Self {
        Self(value.into())
    }
}

pub type FfiHashType = FfiBytes32;
pub type FfiBlockId = u64;
pub type FfiTimestamp = u64;
pub type FfiSignature = FfiBytes64;
pub type FfiAccountId = FfiBytes32;
pub type FfiNonce = FfiU128;
pub type FfiPublicKey = FfiBytes32;
pub type FfiSelector = FfiBytes8;

impl From<Selector> for FfiSelector {
    fn from(value: Selector) -> Self {
        Self { data: value.0 }
    }
}

impl From<FfiSelector> for Selector {
    fn from(value: FfiSelector) -> Self {
        Self(value.data)
    }
}

impl From<AccountId> for FfiBytes32 {
    fn from(value: AccountId) -> Self {
        Self {
            data: value.to_bytes(),
        }
    }
}

impl From<HashType> for FfiHashType {
    fn from(value: HashType) -> Self {
        Self { data: value.0 }
    }
}

impl From<FfiBytes32> for HashType {
    fn from(value: FfiBytes32) -> Self {
        Self(value.data)
    }
}

impl From<FfiBytes32> for AccountId {
    fn from(value: FfiBytes32) -> Self {
        Self::new(value.data)
    }
}

impl From<Signature> for FfiSignature {
    fn from(value: Signature) -> Self {
        Self { data: value.value }
    }
}

impl From<PublicKey> for FfiPublicKey {
    fn from(value: PublicKey) -> Self {
        Self {
            data: *value.value(),
        }
    }
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

pub type FfiIdentifier = FfiBytes32;

impl From<lee_core::Identifier> for FfiIdentifier {
    fn from(value: lee_core::Identifier) -> Self {
        Self {
            data: value.into_value(),
        }
    }
}

impl From<FfiIdentifier> for lee_core::Identifier {
    fn from(value: FfiIdentifier) -> Self {
        Self::new(value.data)
    }
}

impl From<SharedSecretKey> for FfiBytes32 {
    fn from(value: SharedSecretKey) -> Self {
        Self { data: value.0 }
    }
}

/// Public keys for a private account (safe to expose).
#[repr(C)]
pub struct FfiPrivateAccountKeys {
    /// Nullifier public key (32 bytes).
    pub nullifier_public_key: FfiBytes32,
    /// Viewing public key (ML-KEM-768 encapsulation key, 1184 bytes).
    pub viewing_public_key: FfiVecU8,
}

impl Default for FfiPrivateAccountKeys {
    fn default() -> Self {
        Self {
            nullifier_public_key: FfiBytes32 { data: [0; 32] },
            viewing_public_key: Vec::new().into(),
        }
    }
}

impl TryFrom<FfiVecU8> for MlKem768EncapsulationKey {
    type Error = PrimitiveOperationStatus;

    fn try_from(value: FfiVecU8) -> Result<Self, Self::Error> {
        if value.len == 1184 {
            let std_vec = value.into();
            Ok(Self::from_bytes(std_vec)
                .expect("primitives_ffi: length already validated to 1184 bytes"))
        } else {
            Err(PrimitiveOperationStatus::CastError)
        }
    }
}

impl FfiPrivateAccountKeys {
    #[must_use]
    pub const fn npk(&self) -> lee_core::NullifierPublicKey {
        lee_core::NullifierPublicKey(self.nullifier_public_key.data)
    }

    pub fn vpk(&self) -> Result<lee_core::encryption::ViewingPublicKey, PrimitiveOperationStatus> {
        if self.viewing_public_key.len == 1184 {
            let std_vec = unsafe { self.viewing_public_key.read_to_vec() };
            Ok(lee_core::encryption::ViewingPublicKey::from_bytes(std_vec)
                .expect("primitives_ffi: length already validated to 1184 bytes"))
        } else {
            Err(PrimitiveOperationStatus::CastError)
        }
    }
}

/// Public key info for a public account.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiPublicAccountKey {
    pub public_key: FfiBytes32,
}

impl From<lee::PublicKey> for FfiPublicAccountKey {
    fn from(value: lee::PublicKey) -> Self {
        Self {
            public_key: FfiBytes32::from_bytes(*value.value()),
        }
    }
}

impl TryFrom<&FfiPublicAccountKey> for lee::PublicKey {
    type Error = PrimitiveOperationStatus;

    fn try_from(value: &FfiPublicAccountKey) -> Result<Self, Self::Error> {
        let public_key = Self::try_new(value.public_key.data)
            .map_err(|_err| PrimitiveOperationStatus::CastError)?;
        Ok(public_key)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiVec<T> {
    pub entries: *mut T,
    pub len: usize,
    pub capacity: usize,
}

impl<T> From<Vec<T>> for FfiVec<T> {
    fn from(value: Vec<T>) -> Self {
        let (entries, len, capacity) = value.into_raw_parts();
        Self {
            entries,
            len,
            capacity,
        }
    }
}

impl<T> From<FfiVec<T>> for Vec<T> {
    fn from(value: FfiVec<T>) -> Self {
        unsafe { Self::from_raw_parts(value.entries, value.len, value.capacity) }
    }
}

impl<T> FfiVec<T> {
    /// # Safety
    ///
    /// `index` must be lesser than `self.len`.
    #[must_use]
    pub unsafe fn get(&self, index: usize) -> &T {
        let ptr = unsafe { self.entries.add(index) };
        unsafe { &*ptr }
    }
}

impl<T: Clone> FfiVec<T> {
    /// Reads data from pointer into new vector.
    ///
    /// # Safety
    /// `self` must be valid.
    #[must_use]
    pub unsafe fn read_to_vec(&self) -> Vec<T> {
        let mut std_vec = Vec::with_capacity(self.capacity);
        for i in 0..self.len {
            std_vec.push(unsafe { self.get(i) }.clone());
        }
        std_vec
    }
}

#[repr(C)]
pub struct FfiOption<T> {
    pub value: *mut T,
    pub is_some: bool,
}

impl<T> FfiOption<T> {
    pub fn from_value(val: T) -> Self {
        Self {
            value: Box::into_raw(Box::new(val)),
            is_some: true,
        }
    }

    #[must_use]
    pub const fn from_none() -> Self {
        Self {
            value: std::ptr::null_mut(),
            is_some: false,
        }
    }
}

impl<T> From<Option<T>> for FfiOption<T> {
    fn from(value: Option<T>) -> Self {
        value.map_or_else(Self::from_none, |val| Self::from_value(val))
    }
}

impl<T> From<FfiOption<T>> for Option<T> {
    fn from(value: FfiOption<T>) -> Self {
        value.is_some.then(|| unsafe { value.value.read() })
    }
}

/// Free private account keys struct.
///
/// # Safety
/// The keys must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_private_account_keys_owned(
    keys: FfiPrivateAccountKeys,
) {
    if keys.viewing_public_key.entries.is_null() {
        return;
    }

    let FfiPrivateAccountKeys {
        nullifier_public_key: _,
        viewing_public_key,
    } = keys;

    let std_vec: Vec<_> = viewing_public_key.into();

    drop(std_vec);
}

/// Free private boxed account keys pointer.
///
/// # Safety
/// The keys must be valid. Pointer must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_private_account_keys_boxed(
    keys: *mut FfiPrivateAccountKeys,
) {
    if keys.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }

    let boxed = unsafe { Box::from_raw(keys) };

    unsafe { primitives_ffi_free_private_account_keys_owned(*boxed) }
}

/// Free private boxed account keys pointer.
///
/// # Safety
/// The keys must be valid. Pointer must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_private_account_keys(
    keys: *mut FfiPrivateAccountKeys,
) {
    if keys.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }

    let owned = unsafe { keys.read() };

    unsafe { primitives_ffi_free_private_account_keys_owned(owned) }
}
