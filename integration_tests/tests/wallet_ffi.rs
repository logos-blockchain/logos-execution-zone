#![expect(
    clippy::redundant_test_prefix,
    reason = "Otherwise names interfere with ffi bindings"
)]
#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::shadow_unrelated,
    clippy::as_conversions,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char},
    io::Write as _,
    path::Path,
    str::FromStr as _,
    time::Duration,
};

use anyhow::Result;
use integration_tests::{
    BlockingTestContext, TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    config::{INITIAL_PRIVATE_BALANCES_FOR_WALLET, INITIAL_PUBLIC_BALANCES_FOR_WALLET},
};
use lee::{
    Account, AccountId, PrivateKey, PublicKey,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::program::DEFAULT_PROGRAM_OWNER;
use wallet::{DEFAULT_MAX_FEE, account::HumanReadableAccount, program_facades::vault::Vault};
use wallet_ffi::{
    FfiAccount, FfiAccountIdWithPrivacy, FfiAccountIdentity, FfiAccountList, FfiBytes32,
    FfiPrivateAccountKeys, FfiProgramId, FfiPublicAccountKey, FfiTransferResult, FfiU128,
    WalletHandle, error,
    generic_transaction::{FfiProgramWithDependencies, FfiTransactionResult},
    label::{AccountIdResolvedFromLabel, LabelAvailability, LabelList},
    wallet::FfiCreateWalletOutput,
};

unsafe extern "C" {
    fn wallet_ffi_create_new(
        config_path: *const c_char,
        storage_path: *const c_char,
        metrics_path: *const c_char,
        password: *const c_char,
    ) -> FfiCreateWalletOutput;

    fn wallet_ffi_open(
        config_path: *const c_char,
        storage_path: *const c_char,
        metrics_path: *const c_char,
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
        key_path: *const c_char,
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

    // fn wallet_ffi_bridge_withdraw(
    //     handle: *mut WalletHandle,
    //     from: *const FfiBytes32,
    //     amount: u64,
    //     bedrock_account_pk: *const FfiBytes32,
    //     out_result: *mut FfiTransferResult,
    // ) -> error::WalletFfiError;

    fn wallet_ffi_get_vault_balance(
        handle: *mut WalletHandle,
        owner: *const FfiBytes32,
        out_balance: *mut [u8; 16],
    ) -> error::WalletFfiError;

    fn wallet_ffi_vault_claim(
        handle: *mut WalletHandle,
        owner: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_vault_claim_private(
        handle: *mut WalletHandle,
        owner: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

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

    fn wallet_ffi_restore_data(
        handle: *mut WalletHandle,
        mnemonic: *const c_char,
        password: *const c_char,
        depth: u32,
    ) -> error::WalletFfiError;

    fn wallet_ffi_resolve_public_account(
        account_id: FfiBytes32,
        needs_sign: bool,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::WalletFfiError;

    fn wallet_ffi_send_generic_public_transaction(
        handle: *mut WalletHandle,
        account_identities: *const FfiAccountIdentity,
        account_identities_size: usize,
        instruction_data: *const u8,
        instruction_data_size: usize,
        program_id: FfiProgramId,
        out_result: *mut FfiTransactionResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_resolve_private_account(
        handle: *mut WalletHandle,
        account_id: FfiBytes32,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::WalletFfiError;

    fn wallet_ffi_send_generic_private_transaction(
        handle: *mut WalletHandle,
        account_identities: *const FfiAccountIdentity,
        account_identities_size: usize,
        instruction_data: *const u8,
        instruction_data_size: usize,
        program_with_dependencies: *const FfiProgramWithDependencies,
        out_result: *mut FfiTransactionResult,
    ) -> error::WalletFfiError;

    fn wallet_ffi_free_transaction_result(result: *mut FfiTransactionResult);

    fn wallet_ffi_free_account_identity(account_identity: *mut FfiAccountIdentity);

    fn wallet_ffi_check_label_available(
        handle: *mut WalletHandle,
        label: *const c_char,
    ) -> LabelAvailability;

    fn wallet_ffi_add_label(
        handle: *mut WalletHandle,
        label: *const c_char,
        account_id_with_privacy: FfiAccountIdWithPrivacy,
    ) -> error::WalletFfiError;

    fn wallet_ffi_resolve_label(
        handle: *mut WalletHandle,
        label: *const c_char,
    ) -> AccountIdResolvedFromLabel;

    fn wallet_ffi_get_all_labels_for_account(
        handle: *mut WalletHandle,
        account_id_with_privacy: FfiAccountIdWithPrivacy,
    ) -> LabelList;

    fn wallet_ffi_free_label_list(label_list: *mut LabelList) -> error::WalletFfiError;

    fn wallet_ffi_poll_transaction_status(
        handle: *mut WalletHandle,
        tx_hash: FfiBytes32,
        transaction_status: *mut bool,
    ) -> error::WalletFfiError;
}

/// Reads an account's balance through the FFI, panicking on error.
fn ffi_balance(handle: *mut WalletHandle, account_id: &FfiBytes32, is_public: bool) -> u128 {
    let mut out_balance: [u8; 16] = [0; 16];
    unsafe {
        wallet_ffi_get_balance(
            handle,
            std::ptr::from_ref(account_id),
            is_public,
            &raw mut out_balance,
        )
        .unwrap();
    }
    u128::from_le_bytes(out_balance)
}

fn new_wallet_ffi_with_test_context_config(
    ctx: &BlockingTestContext,
    home: &Path,
) -> Result<FfiCreateWalletOutput> {
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let metrics_path = home.join("metrics.json");
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
    let metrics_path = CString::new(metrics_path.to_str().unwrap())?;
    let password = CString::new(ctx.ctx().wallet_password())?;

    let create_wallet_result = unsafe {
        wallet_ffi_create_new(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            metrics_path.as_ptr(),
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
        unsafe {
            wallet_ffi_import_public_account(create_wallet_result.wallet, private_key_hex.as_ptr())
        }
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
            data: account.kind.identifier().to_le_bytes(),
        };

        unsafe {
            wallet_ffi_import_private_account(
                create_wallet_result.wallet,
                key_chain_json.as_ptr(),
                chain_index_ptr,
                &raw const identifier,
                account_state_json.as_ptr(),
            )
        }
        .unwrap();
    }

    Ok(create_wallet_result)
}

fn load_existing_ffi_wallet(home: &Path) -> Result<*mut WalletHandle> {
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let metrics_path = home.join("metrics.json");
    let config_path = CString::new(config_path.to_str().unwrap())?;
    let storage_path = CString::new(storage_path.to_str().unwrap())?;
    let metrics_path = CString::new(metrics_path.to_str().unwrap())?;

    Ok(unsafe {
        wallet_ffi_open(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            metrics_path.as_ptr(),
        )
    })
}

#[test]
fn wallet_ffi_create_public_accounts() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let n_accounts = 10;

    // Create `n_accounts` public accounts with wallet FFI
    let new_public_account_ids_ffi = unsafe {
        let mut account_ids = Vec::new();

        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
    let ctx = BlockingTestContext::new_default()?;
    let n_accounts = 10;
    // Create `n_accounts` receiving keys with wallet FFI
    let new_npks_ffi = unsafe {
        let mut npks = Vec::new();

        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    // Create a receiving key and save
    let first_npk = unsafe {
        let FfiCreateWalletOutput {
            wallet: wallet_ffi_handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
    let ctx = BlockingTestContext::new_default()?;
    // Create the wallet FFI and track which account IDs were created as public/private
    let (wallet_ffi_handle, created_public_ids) = unsafe {
        let home = tempfile::tempdir()?;
        let FfiCreateWalletOutput {
            wallet: handle,
            mnemonic: _,
        } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
    let ctx = BlockingTestContext::new_default()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

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

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_public() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
        programs::authenticated_transfer().id().into()
    );
    assert_eq!(account.balance, INITIAL_PUBLIC_BALANCES_FOR_WALLET[0]);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce.0, 1);

    unsafe {
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    log::info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
fn test_wallet_ffi_get_account_private() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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
        programs::authenticated_transfer().id().into()
    );
    // A private account: private balances stay small (fee-exempt under the
    // interim policy), so this asserts against the private constant, not the
    // LGO-scaled public one.
    assert_eq!(account.balance, INITIAL_PRIVATE_BALANCES_FOR_WALLET[0]);
    assert!(account.data.is_empty());

    unsafe {
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    log::info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
fn test_wallet_ffi_get_public_account_keys() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let account_id: AccountId = ctx.ctx().existing_public_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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

    Ok(())
}

#[test]
fn test_wallet_ffi_get_private_account_keys() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let account_id: AccountId = ctx.ctx().existing_private_accounts()[0];
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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

    log::info!("Successfully retrieved account keys");

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
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

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
    assert_eq!(account.program_owner, DEFAULT_PROGRAM_OWNER);

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

    log::info!("Waiting for next block creation");
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
        programs::authenticated_transfer().id().into()
    );

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn wallet_ffi_init_private_account_auth_transfer() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

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

    log::info!("Waiting for next block creation");
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
        programs::authenticated_transfer().id().into()
    );

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_public() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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

    // Also check for transaction inclusion
    let hash_bytes = unsafe { transfer_result.tx_hash_bytes() };
    let mut is_included = false;

    unsafe {
        wallet_ffi_poll_transaction_status(wallet_ffi_handle, hash_bytes, &raw mut is_included)
            .unwrap();
    }

    assert!(is_included);

    unsafe {
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_shielded() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = lee::AccountId::for_regular_private_account(
            &out_keys.npk(),
            &out_keys.vpk().unwrap(),
            0_u128,
        );
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };
    let amount: [u8; 16] = 100_u128.to_le_bytes();

    let from_before = ffi_balance(wallet_ffi_handle, &from, true);

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
            std::ptr::null(),
            &raw mut transfer_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

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

    // A shield moves public funds into a private account and is fee-exempt, so
    // the public sender is debited exactly the amount, with no fee.
    assert_eq!(from_balance, from_before - 100);
    assert_eq!(to_balance, 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_deshielded() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
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

    log::info!("Waiting for next block creation");
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

    // A deshield moves private funds into a public account and is fee-exempt, so
    // the private sender is debited exactly the amount and the public recipient
    // is credited exactly the amount, with no fee on either side.
    assert_eq!(from_balance, 9900);
    assert_eq!(to_balance, to_before + 100);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_private() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let (to, to_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = lee::AccountId::for_regular_private_account(
            &out_keys.npk(),
            &out_keys.vpk().unwrap(),
            0_u128,
        );
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

    log::info!("Waiting for next block creation");
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

#[test]
fn restore_keys_from_seed_ffi() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let mnemonic = unsafe { CString::from_raw(mnemonic) };

    // Create 2 new private accounts
    let (private_account_id_1, private_account_1_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = lee::AccountId::for_regular_private_account(
            &out_keys.npk(),
            &out_keys.vpk().unwrap(),
            0_u128,
        );
        let to: FfiBytes32 = account_id.into();
        (to, out_keys)
    };

    let (private_account_id_2, private_account_2_keys) = unsafe {
        let mut out_keys = FfiPrivateAccountKeys::default();
        wallet_ffi_create_private_accounts_key(wallet_ffi_handle, &raw mut out_keys).unwrap();
        let account_id = lee::AccountId::for_regular_private_account(
            &out_keys.npk(),
            &out_keys.vpk().unwrap(),
            0_u128,
        );
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
        let to_identifier = FfiU128 {
            data: 0_u128.to_le_bytes(),
        };
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from_private,
            &raw const private_account_1_keys,
            &raw const to_identifier,
            &raw const amount_1,
            &raw mut transfer_result_1,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let amount_2: [u8; 16] = 101_u128.to_le_bytes();

    let mut transfer_result_2 = FfiTransferResult::default();
    unsafe {
        let to_identifier = FfiU128 {
            data: 0_u128.to_le_bytes(),
        };
        wallet_ffi_transfer_private(
            wallet_ffi_handle,
            &raw const from_private,
            &raw const private_account_2_keys,
            &raw const to_identifier,
            &raw const amount_2,
            &raw mut transfer_result_2,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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

    let password = CString::new(ctx.ctx().wallet_password())?;

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
        wallet_ffi_restore_data(wallet_ffi_handle, mnemonic.as_ptr(), password.as_ptr(), 5)
            .unwrap();
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
fn test_wallet_ffi_transfer_generic_public() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_public_accounts()[1].into();
    let amount = 100_u128;

    let from_before = ffi_balance(wallet_ffi_handle, &from, true);
    let to_before = ffi_balance(wallet_ffi_handle, &to, true);

    let mut transaction_result = FfiTransactionResult::default();

    let mut from_account_identity = FfiAccountIdentity::default();
    let mut to_account_identity = FfiAccountIdentity::default();

    unsafe {
        wallet_ffi_resolve_public_account(from, true, &raw mut from_account_identity).unwrap();
    }

    unsafe {
        wallet_ffi_resolve_public_account(to, true, &raw mut to_account_identity).unwrap();
    }

    let ffi_accs = vec![from_account_identity, to_account_identity];
    let account_identities_size = ffi_accs.len();
    let account_identities =
        Box::into_raw(ffi_accs.into_boxed_slice()) as *const FfiAccountIdentity;

    let instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount,
        })
        .unwrap();
    let instruction_data_size = instruction_data.len();
    let instruction_data_ptr = Box::into_raw(instruction_data.into_boxed_slice()) as *const u8;

    let program_id = programs::authenticated_transfer().id();

    unsafe {
        wallet_ffi_send_generic_public_transaction(
            wallet_ffi_handle,
            account_identities,
            account_identities_size,
            instruction_data_ptr,
            instruction_data_size,
            program_id.into(),
            &raw mut transaction_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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
        let account_identities_mut = account_identities.cast_mut();
        wallet_ffi_free_account_identity(account_identities_mut);
        wallet_ffi_free_account_identity(account_identities_mut.add(1));

        let instruction_data =
            std::slice::from_raw_parts_mut(instruction_data_ptr.cast_mut(), instruction_data_size);
        drop(Box::from_raw(std::ptr::from_mut(instruction_data)));

        wallet_ffi_free_transaction_result(&raw mut transaction_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_generic_private() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;
    let from: FfiBytes32 = ctx.ctx().existing_private_accounts()[0].into();
    let to: FfiBytes32 = ctx.ctx().existing_private_accounts()[1].into();
    let amount = 100_u128;

    let mut transaction_result = FfiTransactionResult::default();

    let mut from_account_identity = FfiAccountIdentity::default();
    let mut to_account_identity = FfiAccountIdentity::default();

    unsafe {
        wallet_ffi_resolve_private_account(wallet_ffi_handle, from, &raw mut from_account_identity)
            .unwrap();
    }

    unsafe {
        wallet_ffi_resolve_private_account(wallet_ffi_handle, to, &raw mut to_account_identity)
            .unwrap();
    }

    let ffi_accs = vec![from_account_identity, to_account_identity];
    let account_identities_size = ffi_accs.len();
    let account_identities =
        Box::into_raw(ffi_accs.into_boxed_slice()) as *const FfiAccountIdentity;

    let instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount,
        })
        .unwrap();
    let instruction_data_size = instruction_data.len();
    let instruction_data_ptr = Box::into_raw(instruction_data.into_boxed_slice()) as *const u8;

    let program: ProgramWithDependencies = programs::authenticated_transfer().into();
    let program_with_dependencies: FfiProgramWithDependencies = program.into();

    unsafe {
        wallet_ffi_send_generic_private_transaction(
            wallet_ffi_handle,
            account_identities,
            account_identities_size,
            instruction_data_ptr,
            instruction_data_size,
            &raw const program_with_dependencies,
            &raw mut transaction_result,
        )
        .unwrap();
    }

    assert_eq!(transaction_result.secrets_size, 2);

    log::info!("Waiting for next block creation");
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
    assert_eq!(to_balance, 20100);

    unsafe {
        let account_identities_mut = account_identities.cast_mut();
        wallet_ffi_free_account_identity(account_identities_mut);
        wallet_ffi_free_account_identity(account_identities_mut.add(1));

        let instruction_data =
            std::slice::from_raw_parts_mut(instruction_data_ptr.cast_mut(), instruction_data_size);
        drop(Box::from_raw(std::ptr::from_mut(instruction_data)));

        wallet_ffi_free_transaction_result(&raw mut transaction_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_vault_balance_and_claim_public() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let sender = ctx.ctx().existing_public_accounts()[0];
    let owner = ctx.ctx().existing_public_accounts()[1];
    let owner_ffi: FfiBytes32 = owner.into();
    let amount: u128 = 100;

    let owner_before = ffi_balance(wallet_ffi_handle, &owner_ffi, true);

    // Fund the owner's vault, simulating an L1 bridge deposit.
    ctx.block_on(|ctx| async move {
        Vault(ctx.wallet())
            .send_transfer(sender, owner, amount)
            .await
    })
    .unwrap();

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let vault_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_vault_balance(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(vault_balance, amount);

    let mut transfer_result = FfiTransferResult::default();
    let claim_amount: [u8; 16] = amount.to_le_bytes();
    unsafe {
        wallet_ffi_vault_claim(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw const claim_amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let vault_balance_after_claim = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_vault_balance(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(vault_balance_after_claim, 0);

    let owner_balance = ffi_balance(wallet_ffi_handle, &owner_ffi, true);
    // A full vault sweep is fee-exempt, so the owner gains exactly the amount.
    assert_eq!(owner_balance, owner_before + amount);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_vault_balance_and_claim_private() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let sender = ctx.ctx().existing_public_accounts()[0];
    let owner = ctx.ctx().existing_private_accounts()[0];
    let owner_ffi: FfiBytes32 = owner.into();
    let amount: u128 = 100;

    // Fund the owner's vault. Real deposits always land via a public transfer (the bridge
    // program crediting the vault PDA), regardless of whether the owner is private.
    ctx.block_on(|ctx| async move {
        Vault(ctx.wallet())
            .send_transfer(sender, owner, amount)
            .await
    })
    .unwrap();

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let vault_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_vault_balance(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(vault_balance, amount);

    let mut transfer_result = FfiTransferResult::default();
    let claim_amount: [u8; 16] = amount.to_le_bytes();
    unsafe {
        wallet_ffi_vault_claim_private(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw const claim_amount,
            &raw mut transfer_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let vault_balance_after_claim = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        wallet_ffi_get_vault_balance(
            wallet_ffi_handle,
            &raw const owner_ffi,
            &raw mut out_balance,
        )
        .unwrap();
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(vault_balance_after_claim, 0);

    let owner_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const owner_ffi,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };
    assert_eq!(owner_balance, 10_000 + amount);

    unsafe {
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_single_label() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let mut out_account_id_1 = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id_1).unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let lab_1 = CString::from_str("LABEL1").unwrap().into_raw();

    let lab_1_availability = unsafe { wallet_ffi_check_label_available(wallet_ffi_handle, lab_1) };

    assert_eq!(lab_1_availability.error, error::WalletFfiError::Success);
    assert!(lab_1_availability.is_available);

    let acc_1_id_with_privacy = FfiAccountIdWithPrivacy {
        account_id: out_account_id_1,
        is_private: false,
    };

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_1, acc_1_id_with_privacy) };

    assert_eq!(err, error::WalletFfiError::Success);

    let lab_1_availability = unsafe { wallet_ffi_check_label_available(wallet_ffi_handle, lab_1) };

    assert!(!lab_1_availability.is_available);

    let acc_resolved = unsafe { wallet_ffi_resolve_label(wallet_ffi_handle, lab_1) };

    assert_eq!(acc_resolved.account_id, acc_1_id_with_privacy);

    unsafe {
        wallet_ffi_free_string(lab_1);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_more_labels() -> Result<()> {
    let ctx = BlockingTestContext::new_default()?;
    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path())?;

    let mut out_account_id_1 = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id_1).unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let lab_1 = CString::from_str("LABEL1").unwrap().into_raw();
    let lab_2 = CString::from_str("LABEL2").unwrap().into_raw();
    let lab_3 = CString::from_str("LABEL3").unwrap().into_raw();

    let acc_1_id_with_privacy = FfiAccountIdWithPrivacy {
        account_id: out_account_id_1,
        is_private: false,
    };

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_1, acc_1_id_with_privacy) };

    assert_eq!(err, error::WalletFfiError::Success);

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_2, acc_1_id_with_privacy) };

    assert_eq!(err, error::WalletFfiError::Success);

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_3, acc_1_id_with_privacy) };

    assert_eq!(err, error::WalletFfiError::Success);

    let mut label_list_for_out_acc =
        unsafe { wallet_ffi_get_all_labels_for_account(wallet_ffi_handle, acc_1_id_with_privacy) };

    assert_eq!(label_list_for_out_acc.error, error::WalletFfiError::Success);
    assert_eq!(label_list_for_out_acc.labels_size, 3);

    let lab_ref_1 = unsafe { &*label_list_for_out_acc.labels_data.add(0) };
    let lab_ref_c_str_1 = unsafe { CStr::from_ptr(*lab_ref_1) };

    assert_eq!(lab_ref_c_str_1.to_str().unwrap(), "LABEL1");

    let lab_ref_2 = unsafe { &*label_list_for_out_acc.labels_data.add(1) };
    let lab_ref_c_str_2 = unsafe { CStr::from_ptr(*lab_ref_2) };

    assert_eq!(lab_ref_c_str_2.to_str().unwrap(), "LABEL2");

    let lab_ref_3 = unsafe { &*label_list_for_out_acc.labels_data.add(2) };
    let lab_ref_c_str_3 = unsafe { CStr::from_ptr(*lab_ref_3) };

    assert_eq!(lab_ref_c_str_3.to_str().unwrap(), "LABEL3");

    let err = unsafe { wallet_ffi_free_label_list(&raw mut label_list_for_out_acc) };

    assert_eq!(err, error::WalletFfiError::Success);

    unsafe {
        wallet_ffi_free_string(lab_1);
        wallet_ffi_free_string(lab_2);
        wallet_ffi_free_string(lab_3);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    Ok(())
}
