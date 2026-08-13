//! Fee-subsystem errors, split along SPECS.md's `InvalidBlock` /
//! `ConsensusFault` line.
//!
//! An [`InvalidBlockError`] rejects a block and leaves state untouched; a
//! [`ConsensusFaultError`] means an invariant the mechanism relies on was
//! violated and the caller MUST halt rather than clamp or ignore it.

/// Top-level fee-subsystem error.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeError {
    /// A validity rule was violated; the block (or transaction) is rejected
    /// and pre-block state MUST remain unchanged.
    #[error("invalid block: {0}")]
    InvalidBlock(#[from] InvalidBlockError),

    /// An invariant the mechanism relies on was violated; the caller MUST
    /// treat this as a consensus fault, not a rejection.
    #[error("consensus fault: {0}")]
    ConsensusFault(#[from] ConsensusFaultError),

    /// Genesis validation failed: `MAX_GAS_r != 2 * TARGET_GAS_r` for some
    /// resource `r` (SPECS §Genesis).
    #[error("invalid genesis parameters: MAX_GAS_r must equal 2 * TARGET_GAS_r for both resources")]
    InvalidGenesisParams,
}

/// Reasons a block or transaction fails fee-validity (SPECS §Fee-validity).
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidBlockError {
    /// Public tx `data_bytes` was 0.
    #[error("public tx serialization is empty (data_bytes must be >= 1)")]
    EmptyDataBytes,
    /// Public tx `data_bytes` exceeded `MAX_GAS_STOR`.
    #[error("data_bytes {data_bytes} exceeds MAX_GAS_STOR {max}")]
    DataBytesExceedsMax { data_bytes: u64, max: u64 },
    /// Public tx `gas_limit` exceeded `MAX_GAS_EXEC`.
    #[error("gas_limit {gas_limit} exceeds MAX_GAS_EXEC {max}")]
    GasLimitExceedsMax { gas_limit: u64, max: u64 },
    /// A tx's `fee_reserve` exceeded its signed `max_fee`.
    #[error("fee_reserve {fee_reserve} exceeds signed max_fee {max_fee}")]
    FeeReserveExceedsMaxFee { fee_reserve: u128, max_fee: u128 },
    /// The block's cumulative storage gas exceeded `MAX_GAS_STOR`.
    #[error("block storage total {total} exceeds MAX_GAS_STOR {max}")]
    StorageCapExceeded { total: u128, max: u64 },
    /// A caller-driven cumulative gas accumulation exceeded its cap (see
    /// [`crate::validity::accumulate_gas_used`]).
    #[error("cumulative gas usage {total} exceeds cap {cap}")]
    GasCapExceeded { total: u64, cap: u64 },
    /// A caller-driven cumulative gas accumulation overflowed `u64`.
    #[error("gas accumulation overflowed u64")]
    GasAccumulationOverflow,
    /// D1: the payer is not among the accounts whose fee authorization
    /// accompanies the tx (a witness signature or the fee witness).
    #[error("payer is not among the tx's fee-authorized accounts")]
    UnauthorizedPayer,
    /// D3: a private tx's public-signer set was empty.
    #[error("private transaction has an empty public-signer set")]
    EmptyPublicSignerSet,
}

/// Reasons a committed transition would violate a protocol invariant
/// (SPECS §Invariants). A conformant caller halts rather than proceeding.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusFaultError {
    /// Invariant 4: `payout <= escrow` must always hold; unreachable by
    /// construction, but checked rather than assumed.
    #[error("payout {payout} exceeds escrow {escrow}")]
    PayoutExceedsEscrow { payout: u128, escrow: u128 },
}
