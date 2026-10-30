//! Fees a send declares, dry runs and the fee market.

use std::{
    ffi::{CString, c_char},
    ptr,
};

use wallet::{
    DeclaredFee, DryRunReport, ExecutionFailureKind, FeeParams, FeeStateQuote, PrivateFee,
    WalletCore, WalletSequencerClient as _,
};

use crate::{
    error::{FfiOperationError, print_error},
    primitives::types::{FfiAccountId, FfiFeeDeclaration, FfiU128},
    wallet::{WalletHandle, block_on, c_string_or_null, lifecycle::get_wallet},
};

/// Which part of an `FfiDeclaredFee` is set.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FfiFeeKind {
    #[default]
    None = 0,
    Public = 1,
    Private = 2,
}

/// The in-proof fee of a privacy-preserving transaction.
///
/// Its proof debits `reserve` from `payer`. The surplus over the fee charged is refunded to
/// `refund_to` when `has_refund_to`, else to the payer's alias.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FfiPrivateFee {
    pub payer: FfiAccountId,
    pub reserve: FfiU128,
    pub has_refund_to: bool,
    pub refund_to: FfiAccountId,
}

/// The fee a send declared. Only the part `kind` names is set; the other is zeroed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FfiDeclaredFee {
    pub kind: FfiFeeKind,
    pub public_fee: FfiFeeDeclaration,
    pub private_fee: FfiPrivateFee,
}

impl From<Option<DeclaredFee>> for FfiDeclaredFee {
    fn from(value: Option<DeclaredFee>) -> Self {
        match value {
            None => Self::default(),
            Some(DeclaredFee::Public(fee)) => Self {
                kind: FfiFeeKind::Public,
                public_fee: fee.into(),
                ..Self::default()
            },
            Some(DeclaredFee::Private(PrivateFee {
                payer,
                reserve,
                refund_to,
            })) => Self {
                kind: FfiFeeKind::Private,
                private_fee: FfiPrivateFee {
                    payer: payer.into(),
                    reserve: reserve.into(),
                    has_refund_to: refund_to.is_some(),
                    refund_to: refund_to.unwrap_or_default().into(),
                },
                ..Self::default()
            },
        }
    }
}

/// The fee market priced off the head state.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FfiFeeState {
    /// The block height the state settled at.
    pub height: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    pub next_base_fee_exec_floor: u64,
    pub next_base_fee_exec_ceiling: u64,
    pub next_base_fee_stor_floor: u64,
    pub next_base_fee_stor_ceiling: u64,
    pub max_gas_exec: u64,
    pub max_gas_stor: u64,
}

impl From<&FeeStateQuote> for FfiFeeState {
    fn from(value: &FeeStateQuote) -> Self {
        let FeeStateQuote {
            height,
            base_fee_exec,
            base_fee_stor,
            next_base_fee_exec_floor,
            next_base_fee_exec_ceiling,
            next_base_fee_stor_floor,
            next_base_fee_stor_ceiling,
            max_gas_exec,
            max_gas_stor,
        } = *value;
        Self {
            height,
            base_fee_exec,
            base_fee_stor,
            next_base_fee_exec_floor,
            next_base_fee_exec_ceiling,
            next_base_fee_stor_floor,
            next_base_fee_stor_ceiling,
            max_gas_exec,
            max_gas_stor,
        }
    }
}

/// What a dry run simulated a send to cost at `fee_state`. The fields marked public or private
/// apply to that kind of send only and are zeroed for the other.
#[repr(C)]
#[derive(Debug)]
pub struct FfiDryRunReport {
    pub fee_state: FfiFeeState,
    /// Cycles the transaction (private: its public part) metered.
    pub cycles: u64,
    /// Public: includes the tip.
    pub fee_at_head: FfiU128,
    /// Public: what admission holds from the payer, priced at the gas limit: the least
    /// `max_fee` the sequencer accepts.
    pub reserve_at_head: FfiU128,
    /// Public: the transaction's wire size, priced at the storage base fee.
    pub wire_bytes: u64,
    /// Public: why the action reverts, or null when it applies. A reverted action still pays its
    /// fee.
    pub revert_reason: *mut c_char,
    /// Private: blocks of steepest base fee climb the reserve covers, and the base fees after
    /// them.
    pub headroom_blocks: u64,
    pub exec_ceiling: u64,
    pub stor_ceiling: u64,
    /// Private: the fee at the ceilings; the reserve is this clamped to the payer's balance.
    pub headroom_reserve: FfiU128,
    /// Private: pending credits claimed before the root.
    pub claims: u64,
    /// Private: the part of the claims reaching the payer.
    pub swept: FfiU128,
}

impl Default for FfiDryRunReport {
    fn default() -> Self {
        Self {
            fee_state: FfiFeeState::default(),
            cycles: 0,
            fee_at_head: FfiU128::default(),
            reserve_at_head: FfiU128::default(),
            wire_bytes: 0,
            revert_reason: ptr::null_mut(),
            headroom_blocks: 0,
            exec_ceiling: 0,
            stor_ceiling: 0,
            headroom_reserve: FfiU128::default(),
            claims: 0,
            swept: FfiU128::default(),
        }
    }
}

impl From<DryRunReport> for FfiDryRunReport {
    fn from(value: DryRunReport) -> Self {
        match value {
            DryRunReport::Public {
                quote,
                cycles,
                wire_bytes,
                fee_at_head,
                reserve_at_head,
                revert_reason,
                ..
            } => Self {
                fee_state: (&quote).into(),
                cycles,
                fee_at_head: fee_at_head.into(),
                reserve_at_head: reserve_at_head.into(),
                wire_bytes,
                revert_reason: c_string_or_null(revert_reason),
                ..Self::default()
            },
            DryRunReport::Private {
                quote,
                cycles,
                fee_at_head,
                headroom_blocks,
                exec_ceiling,
                stor_ceiling,
                headroom_reserve,
                claims,
                swept,
                ..
            } => Self {
                fee_state: (&quote).into(),
                cycles,
                fee_at_head: fee_at_head.into(),
                headroom_blocks,
                exec_ceiling,
                stor_ceiling,
                headroom_reserve: headroom_reserve.into(),
                claims: claims as u64,
                swept: swept.into(),
                ..Self::default()
            },
        }
    }
}

/// The fee a send declared or, when `is_dry_run`, would declare, with the dry run's report.
/// A send of several transactions declares the fee of its last; its dry run reports its first.
#[repr(C)]
#[derive(Debug, Default)]
pub struct FfiSendFee {
    pub declared: FfiDeclaredFee,
    pub is_dry_run: bool,
    pub dry_run: FfiDryRunReport,
}

impl FfiSendFee {
    /// Records the fee `wallet`'s send declared, or the report of a dry run that ended `result`,
    /// which then succeeds with nothing sent.
    pub(crate) fn record<T, C: wallet::WalletSequencerClient>(
        &mut self,
        wallet: &WalletCore<C>,
        result: Result<T, ExecutionFailureKind>,
    ) -> Result<Option<T>, ExecutionFailureKind> {
        *self = Self::default();
        match result {
            Ok(sent) => {
                self.declared = wallet.take_declared_fee().into();
                Ok(Some(sent))
            }
            Err(ExecutionFailureKind::DryRun(report)) => {
                self.declared = Some(report.fee()).into();
                self.is_dry_run = true;
                self.dry_run = (*report).into();
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Frees what `record` allocated.
    ///
    /// # Safety
    /// `self` must have been filled by `record`, and not freed before.
    pub(crate) unsafe fn free(&mut self) {
        if !self.dry_run.revert_reason.is_null() {
            drop(unsafe { CString::from_raw(self.dry_run.revert_reason) });
            self.dry_run.revert_reason = ptr::null_mut();
        }
    }
}

/// What every send declares in place of the wallet's defaults. A field whose `has_*` flag is
/// false keeps the default.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FfiFeeParams {
    /// Public: the execution gas limit, else the cycles a simulation measures plus the configured
    /// margin.
    pub has_gas_limit: bool,
    pub gas_limit: u64,
    /// Public: the fee cap, else the reserve at the headroom's base fees. A cap below the dry
    /// run's `reserve_at_head` is rejected by the sequencer.
    pub has_max_fee: bool,
    pub max_fee: FfiU128,
    /// Public: the tip, charged on top of the base fees.
    pub tip: u64,
    /// Blocks of steepest base fee climb a fee is priced to cover (a public cap, a private
    /// reserve), else the configured ones.
    pub has_headroom_blocks: bool,
    pub headroom_blocks: u64,
    /// Private: the owned private account paying every in-proof fee, else each send picks its
    /// payer.
    pub has_payer: bool,
    pub payer: FfiAccountId,
    /// Private: the public account the surplus is refunded to, else the payer's alias. Any
    /// account the transaction does not credit publicly is linked to it.
    pub has_refund_to: bool,
    pub refund_to: FfiAccountId,
}

impl From<&FfiFeeParams> for FeeParams {
    fn from(value: &FfiFeeParams) -> Self {
        Self {
            gas_limit: value.has_gas_limit.then_some(value.gas_limit),
            max_fee: value.has_max_fee.then(|| value.max_fee.into()),
            tip: value.tip,
            headroom_blocks: value.has_headroom_blocks.then_some(value.headroom_blocks),
            payer: value.has_payer.then(|| value.payer.into()),
            refund_to: value.has_refund_to.then(|| value.refund_to.into()),
        }
    }
}

/// Simulate sends and report their cost instead of sending them. A send then succeeds with a
/// null `tx_hash` and its result's `fee.is_dry_run` set.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_set_dry_run(
    handle: *mut WalletHandle,
    dry_run: bool,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    match wrapper.core.lock() {
        Ok(mut wallet) => {
            wallet.set_dry_run(dry_run);
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            FfiOperationError::InternalError
        }
    }
}

/// Declare every later send's fee with `params` in place of the wallet's defaults, replacing any
/// set before; null restores the defaults. A dry run shows what a send would then declare.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `params` must be null or a valid pointer to a `FfiFeeParams` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_set_fee_params(
    handle: *mut WalletHandle,
    params: *const FfiFeeParams,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let params = unsafe { params.as_ref() }
        .map(FeeParams::from)
        .unwrap_or_default();
    match wrapper.core.lock() {
        Ok(mut wallet) => {
            wallet.set_fee_params(params);
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            FfiOperationError::InternalError
        }
    }
}

/// Get the fee market priced off the sequencer's head state.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_fee_state` must be a valid pointer to a `FfiFeeState` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_get_fee_state(
    handle: *mut WalletHandle,
    out_fee_state: *mut FfiFeeState,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_fee_state.is_null() {
        print_error("Null output pointer");
        return FfiOperationError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    match block_on(wallet.client().get_fee_state()) {
        Ok(quote) => {
            unsafe {
                *out_fee_state = (&quote).into();
            }
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Failed to get the fee state: {e}"));
            FfiOperationError::NetworkError
        }
    }
}
