use std::ffi::c_char;

use primitives_ffi::types::{
    FfiBytes32, FfiIdentifier, FfiPrivateAccountKeys, FfiPublicAccountKey, account::FfiAccount,
};
use wallet_ffi::{
    FfiAccountIdWithPrivacy, FfiAccountIdentity, FfiAccountList, FfiAccountMention,
    FfiTransferResult, WalletHandle, error,
    generic_transaction::{FfiProgramWithDependencies, FfiTransactionResult},
    label::{AccountIdResolvedFromLabel, LabelAvailability, LabelList},
    wallet::FfiCreateWalletOutput,
};

unsafe extern "C" {
    pub fn wallet_ffi_create_new(
        config_path: *const c_char,
        storage_path: *const c_char,
        metrics_path: *const c_char,
        password: *const c_char,
    ) -> FfiCreateWalletOutput;

    pub fn wallet_ffi_open(
        config_path: *const c_char,
        storage_path: *const c_char,
        metrics_path: *const c_char,
    ) -> *mut WalletHandle;

    pub fn wallet_ffi_destroy(handle: *mut WalletHandle);

    pub fn wallet_ffi_create_account_public(
        handle: *mut WalletHandle,
        out_account_id: *mut FfiBytes32,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_import_public_account(
        handle: *mut WalletHandle,
        private_key_hex: *const c_char,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_create_private_accounts_key(
        handle: *mut WalletHandle,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_import_private_account(
        handle: *mut WalletHandle,
        key_chain_json: *const c_char,
        chain_index: *const c_char,
        identifier: *const FfiIdentifier,
        account_state_json: *const c_char,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_list_accounts(
        handle: *mut WalletHandle,
        out_list: *mut FfiAccountList,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_free_account_list(list: *mut FfiAccountList);

    pub fn wallet_ffi_get_balance(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        is_public: bool,
        out_balance: *mut [u8; 16],
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_account_public(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_account_private(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_account_view(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        program_account_id: *const FfiBytes32,
        out_account: *mut FfiAccount,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_public_account_key(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_public_key: *mut FfiPublicAccountKey,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_private_account_keys(
        handle: *mut WalletHandle,
        account_id: *const FfiBytes32,
        out_keys: *mut FfiPrivateAccountKeys,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_account_id_to_base58(account_id: *const FfiBytes32) -> *mut std::ffi::c_char;

    pub fn wallet_ffi_account_id_from_base58(
        base58_str: *const std::ffi::c_char,
        out_account_id: *mut FfiBytes32,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_transfer_public(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_transfer_shielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        to_identifier: *const FfiIdentifier,
        amount: *const [u8; 16],
        key_path: *const c_char,
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_transfer_deshielded(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to: *const FfiBytes32,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_transfer_private(
        handle: *mut WalletHandle,
        from: *const FfiBytes32,
        to_keys: *const FfiPrivateAccountKeys,
        to_identifier: *const FfiIdentifier,
        amount: *const [u8; 16],
        out_result: *mut FfiTransferResult,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_free_transfer_result(result: *mut FfiTransferResult);

    // pub fn wallet_ffi_bridge_withdraw(
    //     handle: *mut WalletHandle,
    //     from: *const FfiBytes32,
    //     amount: u64,
    //     bedrock_account_pk: *const FfiBytes32,
    //     out_result: *mut FfiTransferResult,
    // ) -> error::WalletFfiError;

    pub fn wallet_ffi_save(handle: *mut WalletHandle) -> error::WalletFfiError;

    pub fn wallet_ffi_sync_to_block(
        handle: *mut WalletHandle,
        block_id: u64,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_get_current_block_height(
        handle: *mut WalletHandle,
        out_block_height: *mut u64,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_restore_data(
        handle: *mut WalletHandle,
        mnemonic: *const c_char,
        password: *const c_char,
        depth: u32,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_resolve_public_account(
        account_id: FfiBytes32,
        needs_sign: bool,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_send_generic_public_transaction(
        handle: *mut WalletHandle,
        account_mentions: *const FfiAccountMention,
        account_mentions_size: usize,
        instruction_data: *const u8,
        instruction_data_size: usize,
        program_account_id: FfiBytes32,
        payer: *const FfiBytes32,
        out_result: *mut FfiTransactionResult,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_resolve_private_account(
        handle: *mut WalletHandle,
        account_id: FfiBytes32,
        out_account_identity: *mut FfiAccountIdentity,
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_send_generic_private_transaction(
        handle: *mut WalletHandle,
        account_mentions: *const FfiAccountMention,
        account_mentions_size: usize,
        instruction_data: *const u8,
        instruction_data_size: usize,
        program_with_dependencies: *const FfiProgramWithDependencies,
        out_result: *mut FfiTransactionResult,
    ) -> error::WalletFfiError;

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
    ) -> error::WalletFfiError;

    pub fn wallet_ffi_resolve_label(
        handle: *mut WalletHandle,
        label: *const c_char,
    ) -> AccountIdResolvedFromLabel;

    pub fn wallet_ffi_get_all_labels_for_account(
        handle: *mut WalletHandle,
        account_id_with_privacy: FfiAccountIdWithPrivacy,
    ) -> LabelList;

    pub fn wallet_ffi_free_label_list(label_list: *mut LabelList) -> error::WalletFfiError;

    pub fn wallet_ffi_poll_transaction_status(
        handle: *mut WalletHandle,
        tx_hash: FfiBytes32,
        transaction_status: *mut bool,
    ) -> error::WalletFfiError;
}
