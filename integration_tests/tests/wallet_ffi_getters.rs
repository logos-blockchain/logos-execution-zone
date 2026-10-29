#![expect(
    clippy::redundant_test_prefix,
    reason = "Otherwise names interfere with ffi bindings"
)]
#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use core_ffi::{
    error,
    primitives::types::{
        FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey, account::FfiAccount,
    },
    wallet::lifecycle::FfiCreateWalletOutput,
};
use integration_tests::{
    config::{INITIAL_PRIVATE_BALANCES_FOR_WALLET, INITIAL_PUBLIC_BALANCES_FOR_WALLET},
    ffi_helpers::{
        primitives as primitives_ffi_helpers, sequencer as sequencer_ffi_helpers, wallet::*,
    },
};
use lee::{Account, AccountId, PublicKey};
use lee_core::{native_token::NATIVE_TOKEN_PROGRAM_ID, program::PROGRAM_LOADER_ACCOUNT_ID};

#[test]
fn test_wallet_ffi_get_balance_public() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let ffi_account_id = FfiBytes32::from(account_id);
        wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            true,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(balance, INITIAL_PUBLIC_BALANCES_FOR_WALLET[0]);

    log::info!("Successfully retrieved account balance");

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_public() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let mut out_account = FfiAccount::default();

    let account: Account = unsafe {
        let ffi_account_id = FfiBytes32::from(account_id);
        wallet_ffi_get_account_public(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };

    assert_eq!(
        account.data,
        Account::funded(INITIAL_PUBLIC_BALANCES_FOR_WALLET[0]).data
    );
    assert_eq!(account.nonce.0, 2);

    let mut out_balance_only = FfiAccount::default();
    let balance_only: Account = unsafe {
        let ffi_account_id = FfiBytes32::from(account_id);
        let ffi_native_program = FfiBytes32::from_account_id(&NATIVE_TOKEN_PROGRAM_ID);
        wallet_ffi_get_account_view(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw const ffi_native_program,
            &raw mut out_balance_only,
        )
        .unwrap();
        (&out_balance_only).try_into().unwrap()
    };

    assert_eq!(
        balance_only.data,
        Account::funded(INITIAL_PUBLIC_BALANCES_FOR_WALLET[0]).data
    );
    assert_eq!(balance_only.nonce.0, 2);

    let program_id = programs::clock_account_id();
    let mut out_program_full = FfiAccount::default();
    let program_full: Account = unsafe {
        let ffi_program_account = FfiBytes32::from(program_id);
        wallet_ffi_get_account_public(
            wallet_ffi_handle,
            &raw const ffi_program_account,
            &raw mut out_program_full,
        )
        .unwrap();
        (&out_program_full).try_into().unwrap()
    };
    let expected_actor_state = program_full.data.actor_states[&PROGRAM_LOADER_ACCOUNT_ID].clone();
    assert!(!expected_actor_state.is_empty());

    let mut out_program_view = FfiAccount::default();
    let program_view: Account = unsafe {
        let ffi_program_account = FfiBytes32::from(program_id);
        let ffi_native_program = FfiBytes32::from_account_id(&NATIVE_TOKEN_PROGRAM_ID);
        wallet_ffi_get_account_view(
            wallet_ffi_handle,
            &raw const ffi_program_account,
            &raw const ffi_native_program,
            &raw mut out_program_view,
        )
        .unwrap();
        (&out_program_view).try_into().unwrap()
    };

    assert_eq!(
        program_view.data,
        Account::funded(program_full.data.native_balance().unwrap()).data
    );

    let mut out_named_actor_state = FfiAccount::default();
    let named_actor_state: Account = unsafe {
        let ffi_program_account = FfiBytes32::from(program_id);
        let ffi_program_id = FfiBytes32::from(PROGRAM_LOADER_ACCOUNT_ID);
        wallet_ffi_get_account_view(
            wallet_ffi_handle,
            &raw const ffi_program_account,
            &raw const ffi_program_id,
            &raw mut out_named_actor_state,
        )
        .unwrap();
        (&out_named_actor_state).try_into().unwrap()
    };

    assert_eq!(
        named_actor_state.data,
        program_full.data.project([PROGRAM_LOADER_ACCOUNT_ID])
    );

    let absent_id = FfiBytes32::from(AccountId::new([0xAB; 32]));
    let ffi_native_program = FfiBytes32::from_account_id(&NATIVE_TOKEN_PROGRAM_ID);
    let mut out_absent = FfiAccount::default();
    unsafe {
        assert_eq!(
            wallet_ffi_get_account_public(
                wallet_ffi_handle,
                &raw const absent_id,
                &raw mut out_absent
            ),
            error::FfiOperationError::AccountNotFound
        );
        assert_eq!(
            wallet_ffi_get_account_view(
                wallet_ffi_handle,
                &raw const absent_id,
                &raw const ffi_native_program,
                &raw mut out_absent,
            ),
            error::FfiOperationError::AccountNotFound
        );
    }

    unsafe {
        wallet_ffi_free_account_data(&raw mut out_balance_only);
        wallet_ffi_free_account_data(&raw mut out_program_full);
        wallet_ffi_free_account_data(&raw mut out_program_view);
        wallet_ffi_free_account_data(&raw mut out_named_actor_state);
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    log::info!("Successfully retrieved account with correct details");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_private() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let mut out_account = FfiAccount::default();

    let account: Account = unsafe {
        let ffi_account_id = FfiBytes32::from(account_id);
        wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };

    // A private account, so this asserts against the private constant, not the public one.
    assert_eq!(
        account.data,
        Account::funded(INITIAL_PRIVATE_BALANCES_FOR_WALLET[0]).data
    );

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    log::info!("Successfully retrieved account with correct details");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_public_account_keys() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let mut out_key = FfiPublicAccountKey::default();

    let key: PublicKey = unsafe {
        let ffi_account_id = FfiBytes32::from(account_id);
        wallet_ffi_get_public_account_key(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut out_key,
        )
        .unwrap();
        (&out_key).try_into().unwrap()
    };

    let expected_key = {
        let private_key = ctx
            .ctx()
            .wallet()
            .get_account_public_signing_key(account_id)
            .unwrap();
        PublicKey::new_from_private_key(private_key)
    };

    assert_eq!(key, expected_key);

    log::info!("Successfully retrieved account key");

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_private_account_keys() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let mut keys = FfiPrivateAccountKeys::default();

    unsafe {
        let ffi_account_id = FfiBytes32::from(account_id);
        wallet_ffi_get_private_account_keys(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut keys,
        )
        .unwrap();
    };

    let account = &ctx
        .ctx()
        .wallet()
        .storage()
        .key_chain()
        .private_account(account_id)
        .unwrap();

    let key_chain = account.key_chain;
    let expected_npk = &key_chain.nullifier_public_key;
    let expected_vpk = &key_chain.viewing_public_key;

    assert_eq!(&keys.npk(), expected_npk);
    assert_eq!(&keys.vpk().unwrap(), expected_vpk);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut keys);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    log::info!("Successfully retrieved account keys");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
