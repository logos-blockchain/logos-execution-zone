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
    collections::HashSet,
    ffi::{CStr, CString, c_char},
    io::Write as _,
    path::Path,
    time::Duration,
};

use anyhow::Result;
use integration_tests::{BlockingTestContext, TIME_TO_WAIT_FOR_BLOCK_SECONDS};
use log::info;
use nssa::{Account, AccountId, PrivateKey, PublicKey, program::Program};
use nssa_core::program::DEFAULT_PROGRAM_ID;
use tempfile::tempdir;
use wallet::WalletCore;
use wallet_ffi::{
    FfiAccount, FfiAccountList, FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey,
    FfiTransferResult, WalletHandle, error,
};

unsafe extern "C" {
    fn wallet_ffi_create_new(
        config_path: *const c_char,
        storage_path: *const c_char,
        password: *const c_char,
    ) -> *mut WalletHandle;

    fn wallet_ffi_open(
        config_path: *const c_char,
        storage_path: *const c_char,
    ) -> *mut WalletHandle;

    fn wallet_ffi_destroy(handle: *mut WalletHandle);

    fn wallet_ffi_create_account_public(
        handle: *mut WalletHandle,
        out_account_id: *mut FfiBytes32,
    ) -> error::WalletFfiError;

    fn wallet_ffi_create_account_private(
        handle: *mut WalletHandle,
        out_account_id: *mut FfiBytes32,
    ) -> error::WalletFfiError;

    fn wallet_ffi_list_accounts(
        handle: *mut WalletHandle,
        out_list: *mut FfiAccountList,
    ) -> error::WalletFfiError;

    fn wallet_ffi_free_account_list(list: *mut FfiAccountList);

    fn wallet_ffi_get_balance(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        is_public: bool,
        out_balance: *mut [u8; 16],
    ) -> error::WalletFfiError;

    fn wallet_ffi_get_account_public(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::WalletFfiError;

    fn wallet_ffi_get_account_private(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::WalletFfiError;

    fn wallet_ffi_free_account_data(account: *mut FfiAccount);

    fn wallet_ffi_get_public_account_key(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_public_key: *mut FfiPublicAccountKey,
    ) -> error::WalletFfiError;

    fn wallet_ffi_get_private_account_keys(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::WalletFfiError;

    fn wallet_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys);

    fn wallet_ffi_account_id_to_base58(account_id: *const FfiBytes32) -> *mut std::ffi::c_char;

    fn wallet_ffi_free_string(ptr: *mut c_char);

    fn wallet_ffi_account_id_from_base58(
        base58_str: *const std::ffi::c_char,
        out_account_id: *mut FfiBytes32,
    ) -> error::WalletFfiError;

    fn wallet_ffi_transfer_public(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_transfer_shielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_transfer_deshielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_transfer_private(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_free_transfer_result(result: *mut FfiTransferResult);

    fn wallet_ffi_register_public_account(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_register_private_account(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_save(handle: *mut WalletHandle) -> error::WalletFfiError;

    fn wallet_ffi_sync_to_block(handle: *mut WalletHandle, block_id: u64) -> error::WalletFfiError;

    fn wallet_ffi_get_current_block_height(
        handle: *mut WalletHandle,
        out_block_height: *mut u64,
    ) -> error::WalletFfiError;
}

fn new_wallet_ffi_with_test_context_config(
    ctx: &BlockingTestContext,
    home: &Path,
) -> Result<*mut WalletHandle> {
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let mut config = ctx.ctx().wallet().config().to_owned();
    if let Some(config_overrides) = ctx.ctx().wallet().config_overrides().clone() {
        config.apply_overrides(config_overrides);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&config_path)?;

    let config_with_overrides_serialized = serde_json::to_vec_pretty(&config)?;

    file.write_all(&config_with_overrides_serialized)?;

    let config_path = CString::new(config_path.to_str().unwrap())?;
    let storage_path = CString::new(storage_path.to_str().unwrap())?;
    let password = CString::new(ctx.ctx().wallet_password())?;

    Ok(unsafe {
        wallet_ffi_create_new(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            password.as_ptr(),
        )
    })
}

fn new_wallet_ffi_with_default_config(password: &str) -> Result<*mut WalletHandle> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("wallet_config.json");
    let storage_path = tempdir.path().join("storage.json");
    let config_path_c = CString::new(config_path.to_str().unwrap())?;
    let storage_path_c = CString::new(storage_path.to_str().unwrap())?;
    let password = CString::new(password)?;

    Ok(unsafe {
        wallet_ffi_create_new(
            config_path_c.as_ptr(),
            storage_path_c.as_ptr(),
            password.as_ptr(),
        )
    })
}

fn new_wallet_rust_with_default_config(password: &str) -> Result<WalletCore> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("wallet_config.json");
    let storage_path = tempdir.path().join("storage.json");

    WalletCore::new_init_storage(config_path, storage_path, None, password.to_owned())
}

fn load_existing_ffi_wallet(home: &Path) -> Result<*mut WalletHandle> {
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let config_path = CString::new(config_path.to_str().unwrap())?;
    let storage_path = CString::new(storage_path.to_str().unwrap())?;

    Ok(unsafe { wallet_ffi_open(config_path.as_ptr(), storage_path.as_ptr()) })
}

#[test]
fn wallet_ffi_create_public_accounts() -> Result<()> {
    let password = "password_for_tests";
    let n_accounts = 10;
    // First `n_accounts` public accounts created with Rust wallet
    let new_public_account_ids_rust = {
        let mut account_ids = Vec::new();

        let mut wallet_rust = new_wallet_rust_with_default_config(password)?;
        for _ in 0..n_accounts {
            let account_id = wallet_rust.create_new_account_public(None).0;
            account_ids.push(*account_id.value());
        }
        account_ids
    };

    // First `n_accounts` public accounts created with wallet FFI
    let new_public_account_ids_ffi = unsafe {
        let mut account_ids = Vec::new();

        let wallet_ffi_handle = new_wallet_ffi_with_default_config(password)?;
        for _ in 0..n_accounts {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id);
            account_ids.push(out_account_id.data);
        }
        wallet_ffi_destroy(wallet_ffi_handle);
        account_ids
    };

    assert_eq!(new_public_account_ids_ffi, new_public_account_ids_rust);

    Ok(())
}

#[test]
fn wallet_ffi_create_private_accounts() -> Result<()> {
    let password = "password_for_tests";
    let n_accounts = 10;
    // First `n_accounts` private accounts created with Rust wallet
    let new_private_account_ids_rust = {
        let mut account_ids = Vec::new();

        let mut wallet_rust = new_wallet_rust_with_default_config(password)?;
        for _ in 0..n_accounts {
            let account_id = wallet_rust.create_new_account_private(None).0;
            account_ids.push(*account_id.value());
        }
        account_ids
    };

    // First `n_accounts` private accounts created with wallet FFI
    let new_private_account_ids_ffi = unsafe {
        let mut account_ids = Vec::new();

        let wallet_ffi_handle = new_wallet_ffi_with_default_config(password)?;
        for _ in 0..n_accounts {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_account_id);
            account_ids.push(out_account_id.data);
        }
        wallet_ffi_destroy(wallet_ffi_handle);
        account_ids
    };

    assert_eq!(new_private_account_ids_ffi, new_private_account_ids_rust);

    Ok(())
}
#[test]
fn wallet_ffi_save_and_load_persistent_storage() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let mut out_private_account_id = FfiBytes32::from_bytes([0; 32]);
    let home = tempfile::tempdir()?;

    // Create a private account with the wallet FFI and save it
    unsafe {
        let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
        wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_private_account_id);

        wallet_ffi_save(wallet_ffi_handle);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    let private_account_keys = unsafe {
        let wallet_ffi_handle = load_existing_ffi_wallet(home.path())?;

        let mut private_account = FfiAccount::default();

        let result = wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const out_private_account_id,
            &raw mut private_account,
        );
        assert_eq!(result, error::WalletFfiError::Success);

        let mut out_keys = FfiPrivateAccountKeys::default();
        let result = wallet_ffi_get_private_account_keys(
            wallet_ffi_handle,
            &raw const out_private_account_id,
            &raw mut out_keys,
        );
        assert_eq!(result, error::WalletFfiError::Success);

        wallet_ffi_destroy(wallet_ffi_handle);

        out_keys
    };

    assert_eq!(
        nssa::AccountId::from(&private_account_keys.npk()),
        out_private_account_id.into()
    );

    Ok(())
}

#[test]
fn test_wallet_ffi_list_accounts() -> Result<()> {
    let password = "password_for_tests";

    // Create the wallet FFI
    let wallet_ffi_handle = unsafe {
        let handle = new_wallet_ffi_with_default_config(password)?;
        // Create 5 public accounts and 5 private accounts
        for _ in 0..5 {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_public(handle, &raw mut out_account_id);
            wallet_ffi_create_account_private(handle, &raw mut out_account_id);
        }

        handle
    };

    // Create the wallet Rust
    let wallet_rust = {
        let mut wallet = new_wallet_rust_with_default_config(password)?;
        // Create 5 public accounts and 5 private accounts
        for _ in 0..5 {
            wallet.create_new_account_public(None);
            wallet.create_new_account_private(None);
        }
        wallet
    };

    // Get the account list with FFI method
    let mut wallet_ffi_account_list = unsafe {
        let mut out_list = FfiAccountList::default();
        wallet_ffi_list_accounts(wallet_ffi_handle, &raw mut out_list);
        out_list
    };

    let wallet_rust_account_ids = wallet_rust
        .storage()
        .user_data
        .account_ids()
        .collect::<Vec<_>>();

    // Assert same number of elements between Rust and FFI result
    assert_eq!(wallet_rust_account_ids.len(), wallet_ffi_account_list.count);

    let wallet_ffi_account_list_slice = unsafe {
        core::slice::from_raw_parts(
            wallet_ffi_account_list.entries,
            wallet_ffi_account_list.count,
        )
    };

    // Assert same account ids between Rust and FFI result
    assert_eq!(
        wallet_rust_account_ids
            .iter()
            .map(nssa::AccountId::value)
            .collect::<HashSet<_>>(),
        wallet_ffi_account_list_slice
            .iter()
            .map(|entry| &entry.account_id.data)
            .collect::<HashSet<_>>()
    );

    // Assert `is_pub` flag is correct in the FFI result
    for entry in wallet_ffi_account_list_slice {
        let account_id = AccountId::new(entry.account_id.data);
        let is_pub_default_in_rust_wallet = wallet_rust
            .storage()
            .user_data
            .default_pub_account_signing_keys
            .contains_key(&account_id);
        let is_pub_key_tree_wallet_rust = wallet_rust
            .storage()
            .user_data
            .public_key_tree
            .account_id_map
            .contains_key(&account_id);

        let is_public_in_rust_wallet = is_pub_default_in_rust_wallet || is_pub_key_tree_wallet_rust;

        assert_eq!(entry.is_public, is_public_in_rust_wallet);
    }

    unsafe {
        wallet_ffi_free_account_list(&raw mut wallet_ffi_account_list);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_balance_public() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let ffi_account_id = FfiBytes32::from(&account_id);
        wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            true,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(balance, 10000);

    info!("Successfully retrieved account balance");

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_public() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let mut out_account = FfiAccount::default();

    let account: Account = unsafe {
        let ffi_account_id = FfiBytes32::from(&account_id);
        wallet_ffi_get_account_public(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 10000);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce.0, 0);

    unsafe {
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_private() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let mut out_account = FfiAccount::default();

    let account: Account = unsafe {
        let ffi_account_id = FfiBytes32::from(&account_id);
        wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 10000);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce, 0_u128.into());

    unsafe {
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
fn test_wallet_ffi_get_public_account_keys() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let mut out_key = FfiPublicAccountKey::default();

    let key: PublicKey = unsafe {
        let ffi_account_id = FfiBytes32::from(&account_id);
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

    info!("Successfully retrieved account key");

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_get_private_account_keys() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let mut keys = FfiPrivateAccountKeys::default();

    unsafe {
        let ffi_account_id = FfiBytes32::from(&account_id);
        wallet_ffi_get_private_account_keys(
            wallet_ffi_handle,
            &raw const ffi_account_id,
            &raw mut keys,
        )
        .unwrap();
    };

    let key_chain = &ctx
        .ctx()
        .wallet()
        .storage()
        .user_data
        .get_private_account(account_id)
        .unwrap()
        .0;

    let expected_npk = &key_chain.nullifier_public_key;
    let expected_vpk = &key_chain.viewing_public_key;

    assert_eq!(&keys.npk(), expected_npk);
    assert_eq!(&keys.vpk().unwrap(), expected_vpk);

    unsafe {
        wallet_ffi_free_private_account_keys(&raw mut keys);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    info!("Successfully retrieved account keys");

    Ok(())
}

#[test]
fn test_wallet_ffi_account_id_to_base58() -> Result<()> {
    let private_key = PrivateKey::new_os_random();
    let public_key = PublicKey::new_from_private_key(&private_key);
    let account_id = AccountId::from(&public_key);
    let ffi_bytes: FfiBytes32 = (&account_id).into();
    let ptr = unsafe { wallet_ffi_account_id_to_base58(&raw const ffi_bytes) };

    let ffi_result = unsafe { CStr::from_ptr(ptr).to_str()? };

    assert_eq!(account_id.to_string(), ffi_result);

    unsafe {
        wallet_ffi_free_string(ptr);
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
        wallet_ffi_account_id_from_base58(account_id_c_str.as_ptr(), &raw mut out_account_id_bytes);
        out_account_id_bytes.into()
    };

    let expected_account_id = account_id_str.parse()?;

    assert_eq!(account_id, expected_account_id);

    Ok(())
}

#[test]
fn wallet_ffi_init_public_account_auth_transfer() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    // Create a new uninitialized public account
    let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id);
    }

    // Check its program owner is the default program id
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
    assert_eq!(account.program_owner, DEFAULT_PROGRAM_ID);

    // Call the init funciton
    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_register_public_account(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut transfer_result,
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Check that the program owner is now the authenticated transfer program
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
    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn wallet_ffi_init_private_account_auth_transfer() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    // Create a new uninitialized public account
    let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_account_id);
    }

    // Check its program owner is the default program id
    let account: Account = unsafe {
        let mut out_account = FfiAccount::default();
        wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_account,
        );
        (&out_account).try_into().unwrap()
    };
    assert_eq!(account.program_owner, DEFAULT_PROGRAM_ID);

    // Call the init funciton
    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_register_private_account(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut transfer_result,
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height);
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height);
    };

    // Check that the program owner is now the authenticated transfer program
    let account: Account = unsafe {
        let mut out_account = FfiAccount::default();
        wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_account,
        )
        .unwrap();
        (&out_account).try_into().unwrap()
    };
    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_public() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = (&ctx.ctx().existing_public_accounts()[0]).into();
    let to: FfiBytes32 = (&ctx.ctx().existing_public_accounts()[1]).into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_public(
            wallet_ffi_handle,
            &raw const from,
            &raw const to,
            &raw const amount,
            &raw mut transfer_result,
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let from_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const from,
            true,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };

    let to_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_balance(wallet_ffi_handle, &raw const to, true, &raw mut out_balance)
            .unwrap();
        u128::from_le_bytes(out_balance)
    };

    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, 20100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_shielded() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = (&ctx.ctx().existing_public_accounts()[0]).into();
    let (to, to_keys) = unsafe {
        let mut out_account_id = FfiBytes32::default();
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_account_id);
        wallet_ffi_get_private_account_keys(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_keys,
        );
        (out_account_id, out_keys)
    };
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_shielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const to_keys,
            &raw const amount,
            &raw mut transfer_result,
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height);
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height);
    };

    let from_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const from,
            true,
            &raw mut out_balance,
        )
        .unwrap();
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

    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_deshielded() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = (&ctx.ctx().existing_private_accounts()[0]).into();
    let to = FfiBytes32::from_bytes([37; 32]);
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_deshielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const to,
            &raw const amount,
            &raw mut transfer_result,
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height);
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height);
    };

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

    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_private() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let from: FfiBytes32 = (&ctx.ctx().existing_private_accounts()[0]).into();
    let (to, to_keys) = unsafe {
        let mut out_account_id = FfiBytes32::default();
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_account_id);
        wallet_ffi_get_private_account_keys(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_keys,
        );
        (out_account_id, out_keys)
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
        );
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height);
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height);
    };

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

    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}
