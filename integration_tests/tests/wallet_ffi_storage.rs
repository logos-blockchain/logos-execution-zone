#![expect(
    clippy::redundant_test_prefix,
    reason = "Otherwise names interfere with ffi bindings"
)]
#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::shadow_unrelated,
    reason = "We don't care about these in tests"
)]

use std::{
    ffi::{CStr, CString},
    time::Duration,
};

use anyhow::Result;
use core_ffi::{
    error,
    primitives::types::{FfiBytes32, FfiPrivateAccountKeys},
    wallet::{FfiTransferResult, lifecycle::FfiCreateWalletOutput},
};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ffi_helpers::{
        primitives as primitives_ffi_helpers, sequencer as sequencer_ffi_helpers, wallet::*,
    },
};
use lee::{AccountId, PrivateKey, PublicKey};
use test_fixtures::BlockingTestContext;

#[test]
fn wallet_ffi_save_and_load_persistent_storage() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    // Create a receiving key and save
    let first_npk = unsafe {
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let npk = out_keys.nullifier_public_key.data;
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys);
        wallet_ffi_save(wallet_ffi_handle).unwrap();
        wallet_ffi_destroy(wallet_ffi_handle);
        npk
    };

    assert_eq!(
        load_existing_ffi_wallet(home.path(), sequencer_ffi_res.value, "wrong password")?,
        Err(error::FfiOperationError::WrongPassword)
    );

    // After loading, creating a new key should yield a different NPK (state was persisted)
    let second_npk = unsafe {
        let wallet_ffi_handle = load_existing_ffi_wallet(
            home.path(),
            sequencer_ffi_res.value,
            ctx.ctx().wallet_password(),
        )?
        .unwrap();
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let npk = out_keys.nullifier_public_key.data;
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys);
        wallet_ffi_destroy(wallet_ffi_handle);
        npk
    };

    assert_ne!(first_npk, [0_u8; 32], "First NPK should be non-zero");
    assert_ne!(second_npk, [0_u8; 32], "Second NPK should be non-zero");
    assert_ne!(
        first_npk, second_npk,
        "Keys should differ after state was persisted"
    );

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_account_id_to_base58() -> Result<()> {
    let private_key = PrivateKey::new_os_random();
    let public_key = PublicKey::new_from_private_key(&private_key);
    let account_id = AccountId::from(&public_key);
    let ffi_bytes: FfiBytes32 = account_id.into();
    let ptr = unsafe { wallet_ffi_account_id_to_base58(&raw const ffi_bytes) };

    let ffi_result = unsafe { CStr::from_ptr(ptr).to_str()? };

    assert_eq!(account_id.to_string(), ffi_result);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(ptr);
    }

    Ok(())
}

#[test]
fn wallet_ffi_base58_to_account_id() -> Result<()> {
    let private_key = PrivateKey::new_os_random();
    let public_key = PublicKey::new_from_private_key(&private_key);
    let account_id = AccountId::from(&public_key);
    let account_id_str = account_id.to_string();
    let account_id_c_str = CString::new(account_id_str.clone())?;
    let account_id: AccountId = unsafe {
        let mut out_account_id_bytes = FfiBytes32::default();
        wallet_ffi_account_id_from_base58(account_id_c_str.as_ptr(), &raw mut out_account_id_bytes)
            .unwrap();
        out_account_id_bytes.into()
    };

    let expected_account_id = account_id_str.parse()?;

    assert_eq!(account_id, expected_account_id);

    Ok(())
}

#[test]
fn restore_keys_from_seed_ffi() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(true)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mnemonic = unsafe { CString::from_raw(mnemonic) };

    // Create 2 new private accounts
    let (private_account_id_1, private_account_1_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id =
            lee::AccountId::for_regular_private_account(&out_keys.npk(), &out_keys.vpk().unwrap());
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };

    let (private_account_id_2, private_account_2_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id =
            lee::AccountId::for_regular_private_account(&out_keys.npk(), &out_keys.vpk().unwrap());
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };

    // Create 2 new public accounts
    let mut public_account_id_1 = FfiBytes32::default();
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut public_account_id_1).unwrap();
    }

    let mut public_account_id_2 = FfiBytes32::default();
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut public_account_id_2).unwrap();
    }

    log::info!("Accounts created");

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    // Send funds to accounts
    let from_private: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let from_public: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();

    let amount_1: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result_1 = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from_private,
            &raw const private_account_1_keys,
            &raw const amount_1,
            &raw mut transfer_result_1,
        )
        .unwrap();
    }

    // A later transfer from the same sender must see this one's spend.
    wait_for_inclusion(wallet_ffi_handle, &transfer_result_1);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let amount_2: [u8; 16] = 101_u128.to_le_bytes();

    let mut transfer_result_2 = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from_private,
            &raw const private_account_2_keys,
            &raw const amount_2,
            &raw mut transfer_result_2,
        )
        .unwrap();
    }

    // A later transfer from the same sender must see this one's spend.
    wait_for_inclusion(wallet_ffi_handle, &transfer_result_2);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let amount_3: [u8; 16] = 102_u128.to_le_bytes();

    let mut transfer_result_3 = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const from_public,
            &raw const public_account_id_1,
            &raw const amount_3,
            &raw mut transfer_result_3,
        )
        .unwrap();
    }

    // A later transfer from the same sender must see this one's spend.
    wait_for_inclusion(wallet_ffi_handle, &transfer_result_3);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let amount_4: [u8; 16] = 103_u128.to_le_bytes();

    let mut transfer_result_4 = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const from_public,
            &raw const public_account_id_2,
            &raw const amount_4,
            &raw mut transfer_result_4,
        )
        .unwrap();
    }

    // A later transfer from the same sender must see this one's spend.
    wait_for_inclusion(wallet_ffi_handle, &transfer_result_4);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result_1);
        wallet_ffi_free_transfer_result(&raw mut transfer_result_2);
        wallet_ffi_free_transfer_result(&raw mut transfer_result_3);
        wallet_ffi_free_transfer_result(&raw mut transfer_result_4);
    }

    log::info!("Preparation complete, performing keys restoration");

    // Sent by keys, both private credits are pending until the owner receives them.
    receive_pending(wallet_ffi_handle);

    log::info!("Checking balance correctness before restoration");

    let private_account_id_1_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const private_account_id_1,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let private_account_id_2_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const private_account_id_2,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let public_account_id_1_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const public_account_id_1,
            true,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let public_account_id_2_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const public_account_id_2,
            true,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    assert_eq!(private_account_id_1_balance, 100);
    assert_eq!(private_account_id_2_balance, 101);
    assert_eq!(public_account_id_1_balance, 102);
    assert_eq!(public_account_id_2_balance, 103);

    unsafe {
        wallet_ffi_restore_data(wallet_ffi_handle, mnemonic.as_ptr(), 5).unwrap();
    }

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    log::info!("Checking balance correctness after restoration");

    let private_account_id_1_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const private_account_id_1,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let private_account_id_2_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const private_account_id_2,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let public_account_id_1_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const public_account_id_1,
            true,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let public_account_id_2_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const public_account_id_2,
            true,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    assert_eq!(private_account_id_1_balance, 100);
    assert_eq!(private_account_id_2_balance, 101);
    assert_eq!(public_account_id_1_balance, 102);
    assert_eq!(public_account_id_2_balance, 103);

    log::info!("Accounts restored");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn a_pending_private_credit_survives_seed_restoration_ffi() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(true)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let mnemonic = unsafe { CString::from_raw(mnemonic) };

    let (private_account_id, private_account_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id =
            lee::AccountId::for_regular_private_account(&out_keys.npk(), &out_keys.vpk().unwrap());
        (FfiBytes32::from(account_id), out_keys)
    };
    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from,
            &raw const private_account_keys,
            &raw const amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }
    wait_for_inclusion(wallet_ffi_handle, &transfer_result);
    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_restore_data(wallet_ffi_handle, mnemonic.as_ptr(), 5).unwrap();
    }

    receive_pending(wallet_ffi_handle);

    assert_eq!(
        ffi_balance(wallet_ffi_handle, &private_account_id, false),
        100
    );

    Ok(())
}

// #[test]
// fn test_wallet_ffi_bridge_withdraw() -> Result<()> {
//     let ctx = BlockingTestContext::new()?;
//     let home = tempfile::tempdir()?;
//     let FfiCreateWalletOutput {
//         wallet: wallet_ffi_handle,
//         mnemonic: _,
//     } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
//     let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
//     let bridge_account: FfiBytes32 = system_accounts::bridge_account_id().into();
//     let bedrock_account_pk = FfiBytes32::from_bytes([0x42; 32]);
//     let amount = 100_u64;

//     let mut transfer_result = FfiTransferResult::default();
//     unsafe {
//         wallet_ffi_bridge_withdraw(
//             wallet_ffi_handle,
//             &raw const from,
//             amount,
//             &raw const bedrock_account_pk,
//             &raw mut transfer_result,
//         )
//         .unwrap();
//     }

//     log::info!("Waiting for next block creation");
//     std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

//     let from_balance = unsafe {
//         let mut out_balance: [u8; 16] = [0; 16];
//         wallet_ffi_get_balance(
//             wallet_ffi_handle,
//             &raw const from,
//             true,
//             &raw mut out_balance,
//         )
//         .unwrap();
//         u128::from_le_bytes(out_balance)
//     };

//     let bridge_balance = unsafe {
//         let mut out_balance: [u8; 16] = [0; 16];
//         wallet_ffi_get_balance(
//             wallet_ffi_handle,
//             &raw const bridge_account,
//             true,
//             &raw mut out_balance,
//         )
//         .unwrap();
//         u128::from_le_bytes(out_balance)
//     };

//     assert_eq!(from_balance, 9900);
//     assert_eq!(bridge_balance, 1_000_100);

//     unsafe {
//         wallet_ffi_free_transfer_result(&raw mut transfer_result);
//         wallet_ffi_destroy(wallet_ffi_handle);
//     }

//     Ok(())
// }

#[test]
fn a_null_sequencer_pointer_reaches_the_configured_sequencer() -> Result<()> {
    // A null pointer stands for a process with no embedded sequencer, so do not
    // start one.
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;

    let height = unsafe {
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), std::ptr::null())?;
        assert!(
            !wallet_ffi_handle.is_null(),
            "A null sequencer must fall back to the configured address, not fail"
        );

        let mut height = 0_u64;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut height).unwrap();
        wallet_ffi_save(wallet_ffi_handle).unwrap();
        wallet_ffi_destroy(wallet_ffi_handle);
        height
    };

    let reopened_height = unsafe {
        let wallet_ffi_handle =
            load_existing_ffi_wallet(home.path(), std::ptr::null(), ctx.ctx().wallet_password())?
                .unwrap();
        let mut height = 0_u64;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut height).unwrap();
        wallet_ffi_destroy(wallet_ffi_handle);
        height
    };

    assert!(
        reopened_height >= height,
        "The chain cannot go backwards between two reads"
    );

    Ok(())
}
