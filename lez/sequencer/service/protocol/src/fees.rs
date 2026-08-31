//! Fee admission rejections and the fee-market quote, as RPC wire types.

use lee::AccountId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Why a submitted transaction was refused at the fee-admission door.
///
/// Each arm carries the values that decided it, and rides in the JSON-RPC
/// error's `data` field so a client reads them structurally rather than out of
/// the rendered reason. The door is anti-spam, not consensus: the block
/// transition enforces the same rules (and the payer-balance check's
/// block-level counterpart, the reserve debit) authoritatively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum AdmissionRejection {
    #[error("data_bytes {data_bytes} outside 1..={max}")]
    DataBytesOutOfRange { data_bytes: u64, max: u64 },
    #[error("gas_limit {gas_limit} above the block cap {max}")]
    GasLimitExceedsMax { gas_limit: u64, max: u64 },
    #[error("max_fee {max_fee} below the fee reserve {fee_reserve}")]
    MaxFeeBelowReserve { fee_reserve: u128, max_fee: u128 },
    #[error("designated payer {payer:?} authorized nothing in this transaction")]
    UnauthorizedPayer { payer: AccountId },
    #[error("payer {payer:?} holds {balance} but the fee reserve is {fee_reserve}")]
    PayerCannotFund {
        payer: AccountId,
        balance: u128,
        fee_reserve: u128,
    },
    #[error("a public transaction must declare a fee")]
    MissingFeeDeclaration,
    #[error("fee-invalid: {reason}")]
    OtherFeeValidity { reason: String },
}

impl AdmissionRejection {
    /// The JSON-RPC error code this rejection is returned under. One stable
    /// code per arm, in the `-31_980..` band reserved for fee admission.
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::DataBytesOutOfRange { .. } => -31_980,
            Self::GasLimitExceedsMax { .. } => -31_981,
            Self::MaxFeeBelowReserve { .. } => -31_982,
            Self::UnauthorizedPayer { .. } => -31_983,
            Self::PayerCannotFund { .. } => -31_984,
            Self::OtherFeeValidity { .. } => -31_985,
            Self::MissingFeeDeclaration => -31_986,
        }
    }
}

/// The fee market priced off the head state, for wallets sizing `max_fee`.
///
/// The next-block figures are a band rather than an estimate: the block being
/// filled is not observable at query time, so the quote steps the market once
/// at an empty block (floor) and once at a block filled to its caps (ceiling);
/// every possible next-block base fee lies between them. Fee-exempt classes
/// (private transactions, deployments) pay nothing under the interim policy
/// and are not quoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStateQuote {
    /// The block height the quoted state settled at, for staleness checks.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn every_rejection() -> Vec<AdmissionRejection> {
        let payer = AccountId::new([7_u8; 32]);
        vec![
            AdmissionRejection::DataBytesOutOfRange {
                data_bytes: 0,
                max: 1_000_000,
            },
            AdmissionRejection::GasLimitExceedsMax {
                gas_limit: 10_000_001,
                max: 10_000_000,
            },
            AdmissionRejection::MaxFeeBelowReserve {
                fee_reserve: 401_600,
                max_fee: 1,
            },
            AdmissionRejection::UnauthorizedPayer { payer },
            AdmissionRejection::PayerCannotFund {
                payer,
                balance: 0,
                fee_reserve: 401_600,
            },
            AdmissionRejection::MissingFeeDeclaration,
            AdmissionRejection::OtherFeeValidity {
                reason: "reason".to_owned(),
            },
        ]
    }

    #[test]
    fn every_rejection_roundtrips_through_json() {
        for rejection in every_rejection() {
            let json = serde_json::to_string(&rejection).expect("serializes");
            let back: AdmissionRejection = serde_json::from_str(&json)
                .unwrap_or_else(|err| panic!("rejection {rejection:?} does not roundtrip: {err}"));
            assert_eq!(back, rejection);
        }
    }

    #[test]
    fn rejection_codes_are_unique_and_in_band() {
        let codes: Vec<i32> = every_rejection()
            .iter()
            .map(AdmissionRejection::code)
            .collect();
        let mut deduped = codes.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), codes.len(), "codes must be unique");
        assert!(codes.iter().all(|code| (-31_989..=-31_980).contains(code)));
    }

    #[test]
    fn quote_roundtrips_through_json() {
        let quote = FeeStateQuote {
            height: 5,
            base_fee_exec: 8,
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: 9,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        };
        let json = serde_json::to_string(&quote).expect("serializes");
        let back: FeeStateQuote = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, quote);
    }
}
