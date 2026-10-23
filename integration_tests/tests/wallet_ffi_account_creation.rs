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

use std::collections::HashSet;

use anyhow::Result;
use core_ffi::{
    primitives::types::{FfiBytes32, FfiPrivateAccountKeys},
    wallet::{FfiAccountList, lifecycle::FfiCreateWalletOutput},
};
use integration_tests::ffi_helpers::{
    primitives as primitives_ffi_helpers, sequencer as sequencer_ffi_helpers, wallet::*,
};

#[test]
fn wallet_ffi_create_public_accounts() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let n_accounts = 10;

    // Create `n_accounts` public accounts with wallet FFI
    let new_public_account_ids_ffi = unsafe {
        let mut account_ids = Vec::new();

        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(
            &ctx,
            home.path(),
            sequencer_ffi_res.value.cast_const(),
        )?;
        for _ in 0..n_accounts {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id).unwrap();
            account_ids.push(out_account_id.data);
        }
        wallet_ffi_destroy(wallet_ffi_handle);
        account_ids
    };

    // All returned IDs must be unique and non-zero
    assert_eq!(new_public_account_ids_ffi.len(), n_accounts);
    let unique: HashSet<_> = new_public_account_ids_ffi.iter().collect();
    assert_eq!(
        unique.len(),
        n_accounts,
        "Duplicate public account IDs returned"
    );
    assert!(
        new_public_account_ids_ffi
            .iter()
            .all(|id| *id != [0_u8; 32]),
        "Zero account ID returned"
    );

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn wallet_ffi_create_private_accounts() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let n_accounts = 10;
    // Create `n_accounts` receiving keys with wallet FFI
    let new_npks_ffi = unsafe {
        let mut npks = Vec::new();

        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
        for _ in 0..n_accounts {
            let mut out_keys = FfiPrivateAccountKeys::default();
            wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
            npks.push(out_keys.nullifier_public_key.data);
            primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys);
        }
        wallet_ffi_destroy(wallet_ffi_handle);
        npks
    };

    // All returned NPKs must be unique and non-zero
    assert_eq!(new_npks_ffi.len(), n_accounts);
    let unique: HashSet<_> = new_npks_ffi.iter().collect();
    assert_eq!(unique.len(), n_accounts, "Duplicate NPKs returned");
    assert!(
        new_npks_ffi.iter().all(|id| *id != [0_u8; 32]),
        "Zero NPK returned"
    );

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_list_accounts() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    // Create the wallet FFI and track which account IDs were created as public/private
    let (wallet_ffi_handle, created_public_ids) = unsafe {
        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
        let mut public_ids: Vec<[u8; 32]> = Vec::new();

        // Create 5 public accounts and 5 receiving keys
        for _ in 0..5 {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_public(handle, &raw mut out_account_id).unwrap();
            public_ids.push(out_account_id.data);

            let mut out_keys = FfiPrivateAccountKeys::default();
            wallet_ffi_create_private_accounts_key(handle, &raw mut out_keys).unwrap();
            primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys);
        }

        (handle, public_ids)
    };

    // Get the account list with FFI method
    let mut wallet_ffi_account_list = unsafe {
        let mut out_list = FfiAccountList::default();
        wallet_ffi_list_accounts(wallet_ffi_handle, &raw mut out_list).unwrap();
        out_list
    };

    let wallet_ffi_account_list_slice = unsafe {
        core::slice::from_raw_parts(
            wallet_ffi_account_list.entries,
            wallet_ffi_account_list.count,
        )
    };

    // All created accounts must appear in the list
    let listed_public_ids: HashSet<[u8; 32]> = wallet_ffi_account_list_slice
        .iter()
        .filter(|e| e.is_public)
        .map(|e| e.account_id.data)
        .collect();
    for id in &created_public_ids {
        assert!(
            listed_public_ids.contains(id),
            "Created public account not found in list with is_public=true"
        );
    }
    // Total listed accounts must be at least the number of public accounts created
    // (receiving keys without synced accounts don't appear in the list)
    assert!(
        wallet_ffi_account_list.count >= created_public_ids.len(),
        "Listed account count ({}) is less than the number of created public accounts ({})",
        wallet_ffi_account_list.count,
        created_public_ids.len()
    );

    unsafe {
        wallet_ffi_free_account_list(&raw mut wallet_ffi_account_list);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
