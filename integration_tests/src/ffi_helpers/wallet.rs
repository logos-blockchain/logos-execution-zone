#![expect(
    clippy::multiple_unsafe_ops_per_block,
    clippy::undocumented_unsafe_blocks,
    clippy::not_unsafe_ptr_arg_deref,
    reason = "We don't care about these in tests"
)]
use std::{
    ffi::{CStr, CString, c_char},
    io::Write as _,
    path::Path,
};

use anyhow::Result;
use common::HashType;
use core_ffi::{
    error,
    primitives::types::{
        FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey, account::FfiAccount,
    },
    sequencer::SequencerServiceFFI,
    wallet::{
        FfiAccountIdWithPrivacy, FfiAccountIdentity, FfiAccountList, FfiAccountMention,
        FfiPendingMessageList, FfiTransferResult, WalletHandle,
        fees::{FfiFeeParams, FfiFeeState},
        generic_transaction::{FfiProgramCatalog, FfiTransactionResult},
        label::{AccountIdResolvedFromLabel, LabelAvailability, LabelList},
        lifecycle::FfiCreateWalletOutput,
    },
};
use lee::AccountId;
use test_fixtures::BlockingTestContext;
use wallet::account::HumanReadableAccount;

unsafe extern "C" {
    pub fn wallet_ffi_create_new(
        config_path: *const c_char,
        storage_path: *const c_char,
        password: *const c_char,
        sequencer: *const SequencerServiceFFI,
    ) -> FfiCreateWalletOutput;

    pub fn wallet_ffi_open(
        config_path: *const c_char,
        storage_path: *const c_char,
        sequencer: *const SequencerServiceFFI,
        password: *const c_char,
        out_handle: *mut *mut WalletHandle,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_destroy(handle: *mut WalletHandle);

    pub fn wallet_ffi_create_account_public(
        handle: *mut WalletHandle,
        out_account_id: *mut FfiBytes32,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_import_public_account(
        handle: *mut WalletHandle,
        private_key_hex: *const c_char,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_create_private_accounts_key(
        handle: *mut WalletHandle,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_import_private_account(
        handle: *mut WalletHandle,
        key_chain_json: *const c_char,
        chain_index: *const c_char,
        account_state_json: *const c_char,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_list_accounts(
        handle: *mut WalletHandle,
        out_list: *mut FfiAccountList,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_account_list(list: *mut FfiAccountList);

    pub fn wallet_ffi_get_balance(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        is_public: bool,
        out_balance: *mut [u8; 16],
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_account_public(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_account_private(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_account_view(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        program_account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_account_data(account: *mut FfiAccount);

    pub fn wallet_ffi_get_public_account_key(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_public_key: *mut FfiPublicAccountKey,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_private_account_keys(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys);

    pub fn wallet_ffi_account_id_to_base58(account_id: *const FfiBytes32) -> *mut std::ffi::c_char;

    pub fn wallet_ffi_free_string(ptr: *mut c_char);

    pub fn wallet_ffi_account_id_from_base58(
        base58_str: *const std::ffi::c_char,
        out_account_id: *mut FfiBytes32,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_transfer_public(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_transfer_shielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        amount: *const [u8; 16],
        key_path: *const c_char,
        out_result: *mut FfiTransferResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_transfer_deshielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_transfer_private(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_transfer_result(result: *mut FfiTransferResult);

    pub fn wallet_ffi_set_dry_run(
        handle: *mut WalletHandle,
        dry_run: bool,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_set_fee_params(
        handle: *mut WalletHandle,
        params: *const FfiFeeParams,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_fee_state(
        handle: *mut WalletHandle,
        out_fee_state: *mut FfiFeeState,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_list_pending_messages(
        handle: *mut WalletHandle,
        out_list: *mut FfiPendingMessageList,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_pending_message_list(list: *mut FfiPendingMessageList);

    pub fn wallet_ffi_receive_pending_message(
        handle: *mut WalletHandle,
        position: u64,
        out_result: *mut FfiTransferResult,
    ) -> error::FfiOperationError;

    // pub fn wallet_ffi_bridge_withdraw(
    //     handle: *mut WalletHandle,
    //     from: *const FfiBytes32,
    //     amount: u64,
    //     bedrock_account_pk: *const FfiBytes32,
    //     out_result: *mut FfiTransferResult,
    // ) -> error::FfiOperationError;

    pub fn wallet_ffi_save(handle: *mut WalletHandle) -> error::FfiOperationError;

    pub fn wallet_ffi_sync_to_block(
        handle: *mut WalletHandle,
        block_id: u64,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_get_current_block_height(
        handle: *mut WalletHandle,
        out_block_height: *mut u64,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_restore_data(
        handle: *mut WalletHandle,
        mnemonic: *const c_char,
        depth: u32,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_resolve_public_account(
        account_id: FfiBytes32,
        needs_sign: bool,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_send_generic_public_transaction(
        handle: *mut WalletHandle,
        account_mentions: *const FfiAccountMention,
        account_mentions_size: usize,
        root_mention: usize,
        message: *const u8,
        message_size: usize,
        payer: *const FfiBytes32,
        out_result: *mut FfiTransactionResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_resolve_private_account(
        handle: *mut WalletHandle,
        account_id: FfiBytes32,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_send_generic_private_transaction(
        handle: *mut WalletHandle,
        account_mentions: *const FfiAccountMention,
        account_mentions_size: usize,
        root_mention: usize,
        message: *const u8,
        message_size: usize,
        programs: *const FfiProgramCatalog,
        out_result: *mut FfiTransactionResult,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_free_transaction_result(result: *mut FfiTransactionResult);

    pub fn wallet_ffi_free_account_identity(account_identity: *mut FfiAccountIdentity);

    pub fn wallet_ffi_check_label_available(
        handle: *mut WalletHandle,
        label: *const c_char,
    ) -> LabelAvailability;

    pub fn wallet_ffi_add_label(
        handle: *mut WalletHandle,
        label: *const c_char,
        account_id_with_privacy: FfiAccountIdWithPrivacy,
    ) -> error::FfiOperationError;

    pub fn wallet_ffi_resolve_label(
        handle: *mut WalletHandle,
        label: *const c_char,
    ) -> AccountIdResolvedFromLabel;

    pub fn wallet_ffi_get_all_labels_for_account(
        handle: *mut WalletHandle,
        account_id_with_privacy: FfiAccountIdWithPrivacy,
    ) -> LabelList;

    pub fn wallet_ffi_free_label_list(label_list: *mut LabelList) -> error::FfiOperationError;

    pub fn wallet_ffi_poll_transaction_status(
        handle: *mut WalletHandle,
        tx_hash: FfiBytes32,
        transaction_status: *mut bool,
    ) -> error::FfiOperationError;
}

/// Blocks until the transfer is in a block, panicking if it never lands.
pub fn wait_for_inclusion(handle: *mut WalletHandle, result: &FfiTransferResult) {
    let tx_hash: HashType = unsafe { CStr::from_ptr(result.tx_hash) }
        .to_str()
        .expect("a transaction hash is UTF-8")
        .parse()
        .expect("a transaction hash parses");
    let mut is_included = false;
    unsafe {
        wallet_ffi_poll_transaction_status(
            handle,
            FfiBytes32::from_bytes(tx_hash.0),
            &raw mut is_included,
        )
        .unwrap();
    }
    assert!(is_included, "the transfer must land");
}

/// Receives every message pending for the wallet's accounts, syncing once each receipt lands so a
/// later one to the same account builds on it.
pub fn receive_pending(handle: *mut WalletHandle) {
    let mut list = FfiPendingMessageList::default();
    let positions: Vec<u64> = unsafe {
        wallet_ffi_list_pending_messages(handle, &raw mut list).unwrap();
        let positions = if list.count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(list.entries, list.count)
                .iter()
                .map(|pending| pending.position)
                .collect()
        };
        wallet_ffi_free_pending_message_list(&raw mut list);
        positions
    };
    for position in positions {
        let mut receipt = FfiTransferResult::default();
        unsafe {
            wallet_ffi_receive_pending_message(handle, position, &raw mut receipt).unwrap();
        }
        wait_for_inclusion(handle, &receipt);
        unsafe {
            wallet_ffi_free_transfer_result(&raw mut receipt);
            let mut current_height = 0;
            wallet_ffi_get_current_block_height(handle, &raw mut current_height).unwrap();
            wallet_ffi_sync_to_block(handle, current_height).unwrap();
        }
    }
}

/// Reads an account's balance through the FFI, panicking on error.
pub fn ffi_balance(handle: *mut WalletHandle, account_id: &FfiBytes32, is_public: bool) -> u128 {
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

pub fn new_wallet_ffi_with_test_context_config(
    ctx: &BlockingTestContext,
    home: &Path,
    sequencer: *const SequencerServiceFFI,
) -> Result<FfiCreateWalletOutput> {
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

    let create_wallet_result = unsafe {
        wallet_ffi_create_new(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            password.as_ptr(),
            sequencer,
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

        unsafe {
            wallet_ffi_import_private_account(
                create_wallet_result.wallet,
                key_chain_json.as_ptr(),
                chain_index_ptr,
                account_state_json.as_ptr(),
            )
        }
        .unwrap();
    }

    Ok(create_wallet_result)
}

pub fn load_existing_ffi_wallet(
    home: &Path,
    sequencer: *const SequencerServiceFFI,
    password: &str,
) -> Result<Result<*mut WalletHandle, error::FfiOperationError>> {
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let config_path = CString::new(config_path.to_str().unwrap())?;
    let storage_path = CString::new(storage_path.to_str().unwrap())?;
    let password = CString::new(password)?;
    let mut handle = std::ptr::null_mut();

    let result = unsafe {
        wallet_ffi_open(
            config_path.as_ptr(),
            storage_path.as_ptr(),
            sequencer,
            password.as_ptr(),
            &raw mut handle,
        )
    };
    Ok((result == error::FfiOperationError::Success)
        .then_some(handle)
        .ok_or(result))
}

#[must_use]
pub const fn mention(identity: FfiAccountIdentity, program: AccountId) -> FfiAccountMention {
    FfiAccountMention {
        identity,
        program_account_id: FfiBytes32::from_account_id(&program),
        authorizes: true,
        address_openings: std::ptr::null(),
        address_openings_size: 0,
    }
}
