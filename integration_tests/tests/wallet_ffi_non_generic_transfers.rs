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

use std::time::Duration;

use anyhow::Result;
use core_ffi::{
    error,
    primitives::types::{FfiBytes32, FfiPrivateAccountKeys, account::FfiAccount},
    wallet::{
        FfiTransferResult,
        fees::{FfiFeeKind, FfiFeeState},
        lifecycle::FfiCreateWalletOutput,
    },
};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    config::{INITIAL_PRIVATE_BALANCES_FOR_WALLET, min_private_fee},
    ffi_helpers::{sequencer as sequencer_ffi_helpers, wallet::*},
};
use lee::Account;
use wallet::DEFAULT_MAX_FEE;

#[test]
fn wallet_ffi_public_credit_creates_only_the_native_actor_state() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    // Create a new uninitialized public account
    let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id).unwrap();
    }

    let mut out_absent = FfiAccount::default();
    unsafe {
        assert_eq!(
            wallet_ffi_get_account_public(
                wallet_ffi_handle,
                &raw const out_account_id,
                &raw mut out_absent,
            ),
            error::FfiOperationError::AccountNotFound
        );
    }

    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();
    let mut credit_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const from,
            &raw const out_account_id,
            &raw const amount,
            &raw mut credit_result,
        )
        .unwrap();
    }

    wait_for_inclusion(wallet_ffi_handle, &credit_result);

    let account: Account = unsafe {
        let mut out_account = FfiAccount::default();
        wallet_ffi_get_account_public(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };
    assert_eq!(account.data, Account::funded(100).data);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut credit_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_public() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_public_accounts()[1].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let from_before = ffi_balance(wallet_ffi_handle, &from, true);
    let to_before = ffi_balance(wallet_ffi_handle, &to, true);

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const from,
            &raw const to,
            &raw const amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let declared = transfer_result.fee.declared;
    assert!(!transfer_result.fee.is_dry_run);
    assert_eq!(declared.kind, FfiFeeKind::Public);
    assert_eq!(declared.public_fee.payer, from);
    assert_eq!(u128::from(declared.public_fee.max_fee), DEFAULT_MAX_FEE);

    // The sleep is barely longer than one block period, so on a loaded machine the
    // transfer may still be unconfirmed. Balances only move once the transaction is
    // in a block, so wait for it rather than reading a pre-transfer state.
    let hash_bytes = unsafe { transfer_result.tx_hash_bytes() };
    let mut is_included = false;

    unsafe {
        wallet_ffi_poll_transaction_status(wallet_ffi_handle, hash_bytes, &raw mut is_included)
            .unwrap();
    }

    assert!(is_included);

    let from_balance = ffi_balance(wallet_ffi_handle, &from, true);

    let to_balance = ffi_balance(wallet_ffi_handle, &to, true);

    // Charged public transfer: the recipient gains exactly the amount; the
    // sender pays the amount plus a fee bounded by the protocol ceiling.
    assert_eq!(
        to_balance,
        to_before + 100,
        "recipient gains exactly the transferred amount"
    );
    let fee = from_before
        .checked_sub(100)
        .and_then(|rest| rest.checked_sub(from_balance))
        .expect("sender must be debited at least the transferred amount");
    assert!(
        fee > 0 && fee <= DEFAULT_MAX_FEE,
        "a charged transfer pays a positive fee within the ceiling, got {fee}"
    );

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
fn test_wallet_ffi_transfer_shielded() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id =
            lee::AccountId::for_regular_private_account(&out_keys.npk(), &out_keys.vpk().unwrap());
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let from_before = ffi_balance(wallet_ffi_handle, &from, true);

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_shielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const to_keys,
            &raw const amount,
            std::ptr::null(),
            &raw mut transfer_result,
        )
        .unwrap();
    }

    wait_for_inclusion(wallet_ffi_handle, &transfer_result);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };
    // Sent by keys, the credit is pending until the owner receives it.
    receive_pending(wallet_ffi_handle);

    let from_balance = ffi_balance(wallet_ffi_handle, &from, true);

    let to_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const to,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    // The fresh private recipient holds nothing, so a funded private account of the wallet pays
    // the in-proof fee and the public sender pays exactly the amount.
    assert_eq!(from_balance, from_before - 100);
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_deshielded() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let to_before = ffi_balance(wallet_ffi_handle, &to, true);

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_deshielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const to,
            &raw const amount,
            &raw mut transfer_result,
        )
    }
    .unwrap();

    // The sender pays the in-proof fee out of a reserve of at least the fee it is charged.
    let declared = transfer_result.fee.declared;
    assert_eq!(declared.kind, FfiFeeKind::Private);
    assert_eq!(declared.private_fee.payer, from);
    assert!(u128::from(declared.private_fee.reserve) >= min_private_fee());
    assert!(!declared.private_fee.has_refund_to);

    wait_for_inclusion(wallet_ffi_handle, &transfer_result);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    }

    let from_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const from,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let to_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result =
            wallet_ffi_get_balance(wallet_ffi_handle, &raw const to, true, &raw mut out_balance);
        u128::from_le_bytes(out_balance)
    };

    // The private sender pays the amount and the in-proof fee; the public recipient gains the
    // amount.
    assert_eq!(
        from_balance,
        INITIAL_PRIVATE_BALANCES_FOR_WALLET[0] - 100 - min_private_fee()
    );
    assert_eq!(to_balance, to_before + 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_private() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id =
            lee::AccountId::for_regular_private_account(&out_keys.npk(), &out_keys.vpk().unwrap());
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };

    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from,
            &raw const to_keys,
            &raw const amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    wait_for_inclusion(wallet_ffi_handle, &transfer_result);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };
    // Sent by keys, the credit is pending until the owner receives it.
    receive_pending(wallet_ffi_handle);

    let from_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const from,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    let to_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const to,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    // The recipient holds 100, below the fee, so the wallet pays its receipt from `from` too.
    assert_eq!(
        from_balance,
        INITIAL_PRIVATE_BALANCES_FOR_WALLET[0] - 100 - 2 * min_private_fee()
    );
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_dry_runs_report_without_sending() -> Result<()> {
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
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let public: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let other_public: FfiBytes32 = ctx.ctx().existing_public_accounts()[1].into();
    let private: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut fee_state = FfiFeeState::default();
    unsafe {
        wallet_ffi_get_fee_state(wallet_ffi_handle, &raw mut fee_state).unwrap();
        wallet_ffi_set_dry_run(wallet_ffi_handle, true).unwrap();
    }
    assert!(fee_state.base_fee_exec > 0 && fee_state.base_fee_stor > 0);

    let mut public_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const public,
            &raw const other_public,
            &raw const amount,
            &raw mut public_result,
        )
        .unwrap();
    }
    assert!(public_result.success && public_result.tx_hash.is_null());
    let public_send = &public_result.fee;
    assert!(public_send.is_dry_run);
    assert_eq!(public_send.declared.kind, FfiFeeKind::Public);
    assert_eq!(public_send.declared.public_fee.payer, public);
    assert!(public_send.dry_run.wire_bytes > 0);
    assert!(
        public_send.dry_run.revert_reason.is_null(),
        "a funded transfer applies"
    );
    assert_eq!(
        u128::from(public_send.dry_run.fee_at_head),
        u128::from(public_send.dry_run.cycles)
            * u128::from(public_send.dry_run.fee_state.base_fee_exec)
            + u128::from(public_send.dry_run.wire_bytes)
                * u128::from(public_send.dry_run.fee_state.base_fee_stor)
    );

    let mut private_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_deshielded(
            wallet_ffi_handle,
            &raw const private,
            &raw const public,
            &raw const amount,
            &raw mut private_result,
        )
        .unwrap();
    }
    assert!(private_result.success && private_result.tx_hash.is_null());
    let private_send = &private_result.fee;
    assert!(private_send.is_dry_run);
    assert_eq!(private_send.declared.kind, FfiFeeKind::Private);
    assert_eq!(private_send.declared.private_fee.payer, private);
    // The test wallet prices no headroom, so the reserve is the fee at head.
    assert_eq!(private_send.dry_run.headroom_blocks, 0);
    assert_eq!(
        u128::from(private_send.declared.private_fee.reserve),
        u128::from(private_send.dry_run.fee_at_head)
    );
    assert!(u128::from(private_send.dry_run.fee_at_head) >= min_private_fee());

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut public_result);
        wallet_ffi_free_transfer_result(&raw mut private_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
