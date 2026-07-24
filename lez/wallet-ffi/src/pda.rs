use lee::AccountId;

use crate::{
    error::WalletFfiError, FfiBytes32, FfiNullifierPublicKey, FfiPdaSeed, FfiPrivateAccountKeys,
    FfiProgramId, FfiU128,
};

/// Produce account id for public PDA.
///
/// # Parameters
/// - `program_id`: Id of the owner program
/// - `pda_seed`: 32 byte seed
///
/// # Returns
/// - `FfiBytes32` representing account id bytes
#[no_mangle]
pub extern "C" fn wallet_ffi_account_id_for_public_pda(
    program_id: FfiProgramId,
    pda_seed: FfiPdaSeed,
) -> FfiBytes32 {
    AccountId::for_public_pda(&program_id.data, &pda_seed.into()).into()
}

/// Produce account id for private PDA.
///
/// # Parameters
/// - `program_id`: Id of the owner program
/// - `pda_seed`: 32 byte seed
/// - `npk`: 32 byte nullifier public key (can be obtained from
///   `wallet_ffi_get_private_account_keys`)
/// - `viewing_public_key`: pointer to u8 (can be obtained from
///   `wallet_ffi_get_private_account_keys`)
/// - `viewing_public_key_len`: length of a `viewing_public_key` (can be obtained from
///   `wallet_ffi_get_private_account_keys`), must be `1184`
/// - `identifier`: little endian encoded `u128`
/// - `account_id`: valid pointer to `FfiBytes32`
///
/// # Returns
/// - `Success` on successful parsing
/// - Error code on failure
///
/// # Safety
/// - `viewing_public_key` must be a valid pointer to a `u8`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_account_id_for_private_pda(
    program_id: FfiProgramId,
    pda_seed: FfiPdaSeed,
    npk: FfiNullifierPublicKey,
    viewing_public_key: *const u8,
    viewing_public_key_len: usize,
    identifier: FfiU128,
    account_id: *mut FfiBytes32,
) -> WalletFfiError {
    if viewing_public_key.is_null() {
        return WalletFfiError::NullPointer;
    }

    let ffi_private_keys = FfiPrivateAccountKeys {
        nullifier_public_key: npk,
        authorization_public_key: FfiBytes32::default(),
        viewing_public_key,
        viewing_public_key_len,
    };

    let vpk = ffi_private_keys.vpk();

    if vpk.is_err() {
        return vpk.err().unwrap();
    }

    unsafe {
        *account_id = AccountId::for_private_pda(
            &program_id.data,
            &pda_seed.into(),
            &ffi_private_keys.npk(),
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
    use lee_core::{encryption::ViewingPublicKey, NullifierPublicKey};
    use vault_core::PdaSeed;

    use crate::{
        error::WalletFfiError,
        pda::{wallet_ffi_account_id_for_private_pda, wallet_ffi_account_id_for_public_pda},
        FfiBytes32,
    };

    #[test]
    fn public_pda_consistent_derivation() {
        let program_id = [100_u32, 101, 102, 103, 104, 105, 106, 107];
        let pda_seed = PdaSeed::new([42; 32]);

        let pda_id = AccountId::for_public_pda(&program_id, &pda_seed);
        let ffi_pda_id = wallet_ffi_account_id_for_public_pda(program_id.into(), pda_seed.into());

        assert_eq!(pda_id.into_value(), ffi_pda_id.data);
    }

    #[test]
    fn private_pda_consistent_derivation() {
        let program_id = [100_u32, 101, 102, 103, 104, 105, 106, 107];
        let pda_seed = PdaSeed::new([42; 32]);
        let vpk = ViewingPublicKey::from_bytes(vec![43; 1184]).unwrap();
        let npk = NullifierPublicKey([44; 32]);
        let identifier = 100_000_u128;

        let pda_id = AccountId::for_private_pda(&program_id, &pda_seed, &npk, &vpk, identifier);

        let vpk_ptr = Box::into_raw(vpk.to_bytes().to_vec().into_boxed_slice()) as *const u8;

        let mut ffi_pda_id_base = FfiBytes32 { data: [0; 32] };
        let ffi_pda_id = &raw mut ffi_pda_id_base;

        let err = unsafe {
            wallet_ffi_account_id_for_private_pda(
                program_id.into(),
                pda_seed.into(),
                npk.into(),
                vpk_ptr,
                1184,
                identifier.into(),
                ffi_pda_id,
            )
        };

        assert_eq!(err, WalletFfiError::Success);

        assert_eq!(pda_id.into_value(), unsafe { (*ffi_pda_id).data });

        let vpk_slice = unsafe { std::slice::from_raw_parts_mut(vpk_ptr.cast_mut(), 1184) };
        drop(unsafe { Box::from_raw(std::ptr::from_mut(vpk_slice)) });
    }
}
