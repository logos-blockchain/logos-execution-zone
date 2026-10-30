//! Discovery and receipt of messages sent to this wallet's accounts.

use std::{ffi::c_char, ptr};

use common::HashType;
use lee::privacy_preserving_transaction::circuit::ProgramCatalog;
use wallet::{AsyncDelivery, ExecutionFailureKind, Promotions, WalletCore};

use crate::{
    error::{FfiOperationError, print_error},
    wallet::{
        FfiAccountMention, FfiAsyncDelivery, FfiPendingMessage, FfiPendingMessageList,
        FfiTransferResult, WalletHandle, block_on, c_str_to_string, c_string_or_null,
        client::WalletClient,
        fees::FfiSendFee,
        generic_transaction::{FfiProgramCatalog, mentions},
        lifecycle::get_wallet,
        list, map_execution_error,
    },
};

/// List the messages sent to this wallet's accounts that it has not received yet.
///
/// A credit to a private account the sender cannot witness stays pending until its owner receives
/// it with `wallet_ffi_receive_pending_message`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_list`: Output pointer for the pending message list
///
/// # Returns
/// - `Success` on successful listing
/// - `NetworkError` if the sequencer could not be queried
/// - Error code on other failures
///
/// # Memory
/// The returned list must be freed with `wallet_ffi_free_pending_message_list()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_list` must be a valid pointer to a `FfiPendingMessageList` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_list_pending_messages(
    handle: *mut WalletHandle,
    out_list: *mut FfiPendingMessageList,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_list.is_null() {
        print_error("Null output pointer for pending message list");
        return FfiOperationError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    let pending = match block_on(wallet.owned_pending_messages()) {
        Ok(pending) => pending,
        Err(e) => {
            print_error(format!("Failed to list pending messages: {e}"));
            return FfiOperationError::NetworkError;
        }
    };

    let entries: Box<[FfiPendingMessage]> = pending
        .into_iter()
        .map(|pending| {
            let message = pending.body.message.into_boxed_slice();
            let message_len = message.len();
            FfiPendingMessage {
                position: pending.position,
                receiving_account: pending.recipient.account_id().into(),
                from_account: pending.body.from.account_id.into(),
                from_program: pending.body.from.program_account_id.into(),
                to_program: pending.body.to.program_account_id.into(),
                message: Box::into_raw(message).cast::<u8>(),
                message_len,
            }
        })
        .collect();

    unsafe {
        (*out_list).count = entries.len();
        (*out_list).entries = if entries.is_empty() {
            ptr::null_mut()
        } else {
            Box::into_raw(entries).cast::<FfiPendingMessage>()
        };
    }

    FfiOperationError::Success
}

/// Free a pending message list returned by `wallet_ffi_list_pending_messages`.
///
/// # Safety
/// The list must be either null or a valid list returned by `wallet_ffi_list_pending_messages`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_free_pending_message_list(list: *mut FfiPendingMessageList) {
    if list.is_null() {
        return;
    }

    unsafe {
        let list = &*list;
        if !list.entries.is_null() && list.count > 0 {
            let entries = Box::from_raw(std::ptr::from_mut::<[FfiPendingMessage]>(
                std::slice::from_raw_parts_mut(list.entries, list.count),
            ));
            for entry in &entries {
                if !entry.message.is_null() {
                    drop(Box::from_raw(std::ptr::from_mut::<[u8]>(
                        std::slice::from_raw_parts_mut(entry.message.cast_mut(), entry.message_len),
                    )));
                }
            }
        }
    }
}

/// Receive a pending message sent to one of this wallet's accounts, executing it as published.
///
/// Proves and submits the receipt. Once it is included, syncing shows the receiving account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `position`: The pending message's position, as `wallet_ffi_list_pending_messages` lists it
/// - `out_result`: Output pointer for the receipt's transaction result
///
/// # Returns
/// - `Success` if the receipt was submitted successfully
/// - `MessageNotFound` if no pending message of this wallet is published at `position`
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_receive_pending_message(
    handle: *mut WalletHandle,
    position: u64,
    out_result: *mut FfiTransferResult,
) -> FfiOperationError {
    unsafe {
        wallet_ffi_receive_pending_message_with(
            handle,
            position,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            out_result,
        )
    }
}

/// Receive a pending message as `wallet_ffi_receive_pending_message` does, beside the accounts,
/// programs, async delivery and predicted cross messages a transaction takes.
///
/// The recipient takes part unauthorized unless `account_mentions` declares its account.
/// Authorization is per account: a mention authorizing the recipient's account authorizes the
/// published message too. Each declared program missing from `programs` runs from its deployment.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `position`: The pending message's position, as `wallet_ffi_list_pending_messages` lists it
/// - `account_mentions`: The accounts the receipt declares
/// - `programs`: The programs to run instead of their deployments, or null
/// - `async_delivery`: The receipt's async messages, or null
/// - `cross_messages_json`: The predicted cross messages as JSON, or null to derive them
/// - `out_result`: Output pointer for the receipt's transaction result
///
/// # Returns
/// - `Success` if the receipt was submitted successfully
/// - `MessageNotFound` if no pending message of this wallet is published at `position`
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_mentions` must point to `account_mentions_size` mentions, or be null if that is 0
/// - `async_delivery` must be null, or point to a delivery whose lists each point to their size in
///   entries, or are null if that size is 0
/// - each mention, in `account_mentions` and `async_delivery` alike, must have `address_openings`
///   pointing to `address_openings_size` openings, or null if that is 0
/// - `programs` and `cross_messages_json` must each be null or valid
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_receive_pending_message_with(
    handle: *mut WalletHandle,
    position: u64,
    account_mentions: *const FfiAccountMention,
    account_mentions_size: usize,
    programs: *const FfiProgramCatalog,
    async_delivery: *const FfiAsyncDelivery,
    cross_messages_json: *const c_char,
    out_result: *mut FfiTransferResult,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_result.is_null() {
        print_error("Null output pointer for the receipt result");
        return FfiOperationError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    let received = unsafe {
        receive(
            &mut wallet,
            position,
            account_mentions,
            account_mentions_size,
            programs,
            async_delivery,
            cross_messages_json,
        )
    }
    .and_then(|sent| {
        unsafe { (*out_result).fee.record(&wallet, sent) }.map_err(|e| {
            print_error(format!("Receipt failed: {e:?}"));
            map_execution_error(e)
        })
    });
    match received {
        Ok(tx_hash) => {
            unsafe {
                (*out_result).tx_hash = c_string_or_null(tx_hash);
                (*out_result).success = true;
            }
            FfiOperationError::Success
        }
        Err(e) => {
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
                (*out_result).fee = FfiSendFee::default();
            }
            e
        }
    }
}

unsafe fn receive(
    wallet: &mut WalletCore<WalletClient>,
    position: u64,
    account_mentions: *const FfiAccountMention,
    account_mentions_size: usize,
    programs: *const FfiProgramCatalog,
    async_delivery: *const FfiAsyncDelivery,
    cross_messages_json: *const c_char,
) -> Result<Result<HashType, ExecutionFailureKind>, FfiOperationError> {
    let mut accounts = mentions(unsafe { list(account_mentions, account_mentions_size) }?)?;
    let programs = match unsafe { programs.as_ref() } {
        Some(programs) => programs.try_into()?,
        None => ProgramCatalog::default(),
    };
    let cross_messages = if cross_messages_json.is_null() {
        None
    } else {
        let json = c_str_to_string(cross_messages_json, "cross messages")?;
        Some(serde_json::from_str(&json).map_err(|e| {
            print_error(format!("Invalid cross messages: {e}"));
            FfiOperationError::SerializationError
        })?)
    };
    let async_delivery = match unsafe { async_delivery.as_ref() } {
        Some(delivery) => {
            let (declared, joined) = wallet
                .async_destinations(
                    mentions(unsafe {
                        list(
                            delivery.async_destinations,
                            delivery.async_destinations_size,
                        )
                    }?)?,
                    mentions(unsafe {
                        list(delivery.seal_destinations, delivery.seal_destinations_size)
                    }?)?,
                )
                .map_err(map_execution_error)?;
            accounts.extend(declared);
            AsyncDelivery {
                promotions: Promotions {
                    public: unsafe {
                        list(delivery.public_promotions, delivery.public_promotions_size)
                    }?
                    .iter()
                    .copied()
                    .collect(),
                    private: unsafe {
                        list(
                            delivery.private_promotions,
                            delivery.private_promotions_size,
                        )
                    }?
                    .iter()
                    .copied()
                    .collect(),
                    listed_only: delivery.listed_only,
                },
                ..joined
            }
        }
        None => AsyncDelivery::default(),
    };

    let pending = match block_on(wallet.find_pending_message(position)) {
        Ok(Some(pending)) => pending,
        Ok(None) => {
            print_error(format!("No pending message at position {position}"));
            return Err(FfiOperationError::MessageNotFound);
        }
        Err(e) => {
            print_error(format!("Failed to find the pending message: {e}"));
            return Err(FfiOperationError::NetworkError);
        }
    };
    Ok(block_on(wallet.receive_pending_message_with(
        pending,
        accounts,
        &programs,
        cross_messages,
        async_delivery,
    ))
    .map(|(tx_hash, _)| tx_hash))
}
