use lee::AccountId;

use crate::{
    primitives::{
        errors::PrimitiveOperationStatus,
        types::{FfiBytes32, FfiIdentifier, FfiNullifierPublicKey, FfiPdaSeed, vectors::FfiVecU8},
    },
    wallet::error::WalletFfiError,
};

/// Produce account id for public PDA.
///
/// # Parameters
/// - `program_account_id`: Account id of the owner program
/// - `pda_seed`: 32 byte seed
///
/// # Returns
/// - `FfiBytes32` representing account id bytes
#[unsafe(no_mangle)]
pub extern "C" fn wallet_ffi_account_id_for_public_pda(
    program_account_id: FfiBytes32,
    pda_seed: FfiPdaSeed,
) -> FfiBytes32 {
    AccountId::for_public_pda(&AccountId::from(program_account_id), &pda_seed.into()).into()
}

/// Produce account id for private PDA.
///
/// # Parameters
/// - `program_account_id`: Account id of the owner program
/// - `pda_seed`: 32 byte seed
/// - `npk`: 32 byte nullifier public key (can be obtained from
///   `wallet_ffi_get_private_account_keys`)
/// - `viewing_public_key`: pointer to u8 (can be obtained from
///   `wallet_ffi_get_private_account_keys`)
/// - `viewing_public_key_len`: length of a `viewing_public_key` (can be obtained from
///   `wallet_ffi_get_private_account_keys`), must be `1184`
/// - `identifier`: 32-byte opaque identifier
/// - `account_id`: valid pointer to `FfiBytes32`
///
/// # Returns
/// - `Success` on successful parsing
/// - Error code on failure
///
/// # Safety
/// - `viewing_public_key` must be a valid pointer to a `u8`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_account_id_for_private_pda(
    program_account_id: FfiBytes32,
    pda_seed: FfiPdaSeed,
    npk: FfiNullifierPublicKey,
    viewing_public_key: FfiVecU8,
    identifier: FfiIdentifier,
    account_id: *mut FfiBytes32,
) -> WalletFfiError {
    if viewing_public_key.entries.is_null() {
        return WalletFfiError::NullPointer;
    }

    let std_npk = npk.into();

    let vpk: Result<_, PrimitiveOperationStatus> = viewing_public_key.try_into();

    if vpk.is_err() {
        return vpk.err().unwrap().into();
    }

    unsafe {
        *account_id = AccountId::for_private_pda(
            &AccountId::from(program_account_id),
            &pda_seed.into(),
            &std_npk,
            &vpk.unwrap(),
            identifier.into(),
        )
        .into();
    }

    WalletFfiError::Success
}

#[cfg(test)]
mod tests {
    use lee::AccountId;
    use lee_core::{NullifierPublicKey, encryption::ViewingPublicKey, program::PdaSeed};

    use crate::{
        primitives::types::FfiBytes32,
        wallet::{
            error::WalletFfiError,
            pda::{wallet_ffi_account_id_for_private_pda, wallet_ffi_account_id_for_public_pda},
        },
    };

    #[test]
    fn public_pda_consistent_derivation() {
        let program_account_id = AccountId::new([100; 32]);
        let pda_seed = PdaSeed::new([42; 32]);

        let pda_id = AccountId::for_public_pda(&program_account_id, &pda_seed);
        let ffi_pda_id =
            wallet_ffi_account_id_for_public_pda(program_account_id.into(), pda_seed.into());

        assert_eq!(pda_id.into_value(), ffi_pda_id.data);
    }

    #[test]
    fn private_pda_consistent_derivation() {
        let program_account_id = AccountId::new([100; 32]);
        let pda_seed = PdaSeed::new([42; 32]);
        let vpk = ViewingPublicKey::from_bytes(vec![43; 1184]).unwrap();
        let npk = NullifierPublicKey([44; 32]);
        let identifier = lee_core::Identifier::new([100; 32]);

        let pda_id =
            AccountId::for_private_pda(&program_account_id, &pda_seed, &npk, &vpk, identifier);

        let ffi_vpk = vpk.to_bytes().to_vec().into();

        let mut ffi_pda_id_base = FfiBytes32 { data: [0; 32] };
        let ffi_pda_id = &raw mut ffi_pda_id_base;

        let err = unsafe {
            wallet_ffi_account_id_for_private_pda(
                program_account_id.into(),
                pda_seed.into(),
                npk.into(),
                ffi_vpk,
                identifier.into(),
                ffi_pda_id,
            )
        };

        assert_eq!(err, WalletFfiError::Success);

        assert_eq!(pda_id.into_value(), unsafe { (*ffi_pda_id).data });
    }
}
