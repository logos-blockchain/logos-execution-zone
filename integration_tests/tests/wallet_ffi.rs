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
use wallet::account::HumanReadableAccount;
use wallet_ffi::{
    FfiAccount, FfiAccountList, FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey,
    FfiTransferResult, FfiU128, WalletHandle, error,
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

    fn wallet_ffi_import_public_account(
        handle: *mut WalletHandle,
        private_key_hex: *const c_char,
    ) -> error::WalletFfiError;

    fn wallet_ffi_create_private_accounts_key(
        handle: *mut WalletHandle,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::WalletFfiError;

    fn wallet_ffi_import_private_account(
        handle: *mut WalletHandle,
        key_chain_json: *const c_char,
        chain_index: *const c_char,
        identifier: *const FfiU128,
        account_state_json: *const c_char,
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
        to_identifier: *const FfiU128,
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
        to_identifier: *const FfiU128,
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

    let wallet_ffi_handle = unsafe {
        wallet_ffi_create_new(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            password.as_ptr(),
        )
    };

    // Import accounts from source wallet
    let source_wallet = ctx.ctx().wallet();
    let source_key_chain = source_wallet.storage().key_chain();

    for (account_id, _chain_index) in source_key_chain.public_account_ids() {
        let private_key_hex = source_wallet
            .get_account_public_signing_key(account_id)
            .unwrap()
            .to_string();
        let private_key_hex = CString::new(private_key_hex)?;
        unsafe { wallet_ffi_import_public_account(wallet_ffi_handle, private_key_hex.as_ptr()) }
            .unwrap();
    }

    for (account_id, _chain_index) in source_key_chain.private_account_ids() {
        let account = source_key_chain.private_account(account_id).unwrap();
        let key_chain_json = CString::new(serde_json::to_string(account.key_chain)?)?;
        let account_state_json = CString::new(serde_json::to_string(
            &HumanReadableAccount::from(account.account.clone()),
        )?)?;

        let chain_index = account
            .chain_index
            .map(|chain_index| CString::new(chain_index.to_string()))
            .transpose()?;
        let chain_index_ptr = chain_index
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr());
        let identifier = FfiU128 {
            data: account.identifier.to_le_bytes(),
        };

        unsafe {
            wallet_ffi_import_private_account(
                wallet_ffi_handle,
                key_chain_json.as_ptr(),
                chain_index_ptr,
                &raw const identifier,
                account_state_json.as_ptr(),
            )
        }
        .unwrap();
    }

    Ok(wallet_ffi_handle)
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

    // Create `n_accounts` public accounts with wallet FFI
    let new_public_account_ids_ffi = unsafe {
        let mut account_ids = Vec::new();

        let wallet_ffi_handle = new_wallet_ffi_with_default_config(password)?;
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

    Ok(())
}

#[test]
fn wallet_ffi_create_private_accounts() -> Result<()> {
    let password = "password_for_tests";
    let n_accounts = 10;
    // Create `n_accounts` receiving keys with wallet FFI
    let new_npks_ffi = unsafe {
        let mut npks = Vec::new();

        let wallet_ffi_handle = new_wallet_ffi_with_default_config(password)?;
        for _ in 0..n_accounts {
            let mut out_keys = FfiPrivateAccountKeys::default();
            wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
            npks.push(out_keys.nullifier_public_key.data);
            wallet_ffi_free_private_account_keys(&raw mut out_keys);
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

    Ok(())
}

#[test]
fn wallet_ffi_save_and_load_persistent_storage() -> Result<()> {
    let ctx = BlockingTestContext::new()?;
    let home = tempfile::tempdir()?;
    // Create a receiving key and save
    let first_npk = unsafe {
        let wallet_ffi_handle = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let npk = out_keys.nullifier_public_key.data;
        wallet_ffi_free_private_account_keys(&raw mut out_keys);
        wallet_ffi_save(wallet_ffi_handle).unwrap();
        wallet_ffi_destroy(wallet_ffi_handle);
        npk
    };

    // After loading, creating a new key should yield a different NPK (state was persisted)
    let second_npk = unsafe {
        let wallet_ffi_handle = load_existing_ffi_wallet(home.path())?;
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let npk = out_keys.nullifier_public_key.data;
        wallet_ffi_free_private_account_keys(&raw mut out_keys);
        wallet_ffi_destroy(wallet_ffi_handle);
        npk
    };

    assert_ne!(first_npk, [0_u8; 32], "First NPK should be non-zero");
    assert_ne!(second_npk, [0_u8; 32], "Second NPK should be non-zero");
    assert_ne!(
        first_npk, second_npk,
        "Keys should differ after state was persisted"
    );

    Ok(())
}

#[test]
fn test_wallet_ffi_list_accounts() -> Result<()> {
    let password = "password_for_tests";

    // Create the wallet FFI and track which account IDs were created as public/private
    let (wallet_ffi_handle, created_public_ids) = unsafe {
        let handle = new_wallet_ffi_with_default_config(password)?;
        let mut public_ids: Vec<[u8; 32]> = Vec::new();

        // Create 5 public accounts and 5 receiving keys
        for _ in 0..5 {
            let mut out_account_id = FfiBytes32::from_bytes([0; 32]);
            wallet_ffi_create_account_public(handle, &raw mut out_account_id).unwrap();
            public_ids.push(out_account_id.data);

            let mut out_keys = FfiPrivateAccountKeys::default();
            wallet_ffi_create_private_accounts_key(handle, &raw mut out_keys).unwrap();
            wallet_ffi_free_private_account_keys(&raw mut out_keys);
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
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 10000);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce.0, 1);

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
        let ffi_account_id = FfiBytes32::from(account_id);
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
    let ffi_bytes: FfiBytes32 = account_id.into();
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
        wallet_ffi_account_id_from_base58(account_id_c_str.as_ptr(), &raw mut out_account_id_bytes)
            .unwrap();
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
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id).unwrap();
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
        )
        .unwrap();
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

    // Create a new private account
    let mut out_account_id = FfiBytes32::default();
    unsafe {
        wallet_ffi_create_account_private(wallet_ffi_handle, &raw mut out_account_id).unwrap();
    }

    // Call the init function
    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_register_private_account(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
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
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_public_accounts()[1].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

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
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = nssa::AccountId::from((&out_keys.npk(), 0_u128));
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        let to_identifier = FfiU128 {
            data: 0_u128.to_le_bytes(),
        };
        wallet_ffi_transfer_shielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const to_keys,
            &raw const to_identifier,
            &raw const amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
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
    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();

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

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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

    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, 10100);

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

    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = nssa::AccountId::from((&out_keys.npk(), 0_u128));
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };

    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        let to_identifier = FfiU128 {
            data: 0_u128.to_le_bytes(),
        };
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from,
            &raw const to_keys,
            &raw const to_identifier,
            &raw const amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
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
