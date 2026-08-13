//! Reexports of types used by sequencer rpc specification.

use std::{fmt::Display, str::FromStr};

pub use common::{HashType, block::Block, transaction::LeeTransaction};
pub use lee::{Account, AccountId, ProgramId};
pub use lee_core::{BlockId, Commitment, CommitmentSetDigest, MembershipProof, account::Nonce};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, DisplayFromStr, SerializeDisplay, serde_as};

/// One of the two block resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapResource {
    ExecutionGas,
    StorageGas,
}

impl Display for CapResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecutionGas => write!(f, "execution gas"),
            Self::StorageGas => write!(f, "storage gas"),
        }
    }
}

/// Why the sequencer refused a transaction at submission, with the values that decided it.
///
/// Travels twice in the JSON-RPC error: rendered into `message`, and serialized whole into `data`.
/// A client branches on [`Self::code`] or on the `check` tag; it never has to read the prose.
///
/// Every `u128` here is carried as a decimal *string*. The `check` tag makes this internally
/// tagged, and serde's internally-tagged deserializer buffers through a `Content` type that has no
/// `u128` variant: a bare `u128` field would serialize and then fail to read back at any value.
/// Encoding them as strings also keeps them exact for a JSON client whose numbers stop being so
/// past 2^53.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum AdmissionRejection {
    /// A public transaction must serialize to at least one byte.
    #[error("public transaction serialization is empty (data_bytes must be >= 1)")]
    EmptyDataBytes,

    /// Serialized length past what a whole block may carry.
    #[error("data_bytes {data_bytes} exceeds the block storage cap {max}")]
    DataBytesExceedsMax { data_bytes: u64, max: u64 },

    /// Declared execution bound past what a whole block may execute.
    #[error("gas_limit {gas_limit} exceeds the block execution cap {max}")]
    GasLimitExceedsMax { gas_limit: u64, max: u64 },

    /// The signed `max_fee` cannot cover the reservation at the head's base fees. Advisory: base
    /// fees move every block, so this can go stale in either direction.
    #[error(
        "signed max_fee {max_fee} is below the fee reserve {fee_reserve} at the current base fees"
    )]
    MaxFeeBelowReserve {
        #[serde_as(as = "DisplayFromStr")]
        fee_reserve: u128,
        #[serde_as(as = "DisplayFromStr")]
        max_fee: u128,
    },

    /// Only the fee witness signs, so including the transaction would burn no nonce and it would
    /// stay includable byte-for-byte for ever, draining its payer.
    #[error(
        "a charged transaction must carry at least one signer signature, so that including it \
         burns a nonce: a fee witness alone consumes no replay protection"
    )]
    FeeWitnessOnly,

    /// No signature accompanying the transaction authorizes its designated payer.
    #[error(
        "payer {payer} is not among the transaction's fee-authorized accounts: it must either \
         sign the transaction or accompany it as the fee witness"
    )]
    UnauthorizedPayer { payer: AccountId },

    /// The payer's balance at the head is below the reservation. Advisory: balances move with
    /// every transaction, this one included if a pending transfer funds it.
    #[error(
        "payer {payer} holds {balance} but its fee reserve at the current base fees is \
         {fee_reserve}"
    )]
    PayerCannotFund {
        payer: AccountId,
        #[serde_as(as = "DisplayFromStr")]
        balance: u128,
        #[serde_as(as = "DisplayFromStr")]
        fee_reserve: u128,
    },

    /// What the transaction declares does not fit an *empty* block, so no block can hold it.
    #[error(
        "transaction declares {gas_exec} execution gas and {gas_stor} storage gas, over the \
         block's {resource} cap (execution {max_gas_exec}, storage {max_gas_stor}): no block can \
         include it"
    )]
    ExceedsBlockCap {
        resource: CapResource,
        gas_exec: u64,
        gas_stor: u64,
        max_gas_exec: u64,
        max_gas_stor: u64,
    },

    /// A static fee-validity rule with no variant of its own above.
    ///
    /// Nothing the sequencer runs at admission produces this today; it exists so the mapping from
    /// `fee_core`'s error enum stays total when a rule is added there.
    #[error("transaction is not statically fee-valid: {reason}")]
    OtherFeeValidity { reason: String },
}

impl AdmissionRejection {
    /// The JSON-RPC error code this rejection is returned under: one per check, stable, and the
    /// thing a client branches on.
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::EmptyDataBytes => -31_980,
            Self::DataBytesExceedsMax { .. } => -31_981,
            Self::GasLimitExceedsMax { .. } => -31_982,
            Self::MaxFeeBelowReserve { .. } => -31_983,
            Self::FeeWitnessOnly => -31_984,
            Self::UnauthorizedPayer { .. } => -31_985,
            Self::PayerCannotFund { .. } => -31_986,
            Self::ExceedsBlockCap { .. } => -31_987,
            Self::OtherFeeValidity { .. } => -31_988,
        }
    }
}

/// What a client needs to price a transaction before it signs it.
///
/// Everything here is read off the sequencer's head fee state, so it prices the next block this
/// sequencer builds. A transaction's reservation is
/// `gas_limit * base_fee_exec + data_bytes * base_fee_stor + tip`, and it must not exceed the
/// signed `max_fee` at the base fees of the block that includes it — which is why the next-block
/// band matters: a transaction that waits is priced at prices that have moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStateQuote {
    /// Execution base fee, atomic units per gas.
    pub base_fee_exec: u64,
    /// Storage base fee, atomic units per byte.
    pub base_fee_stor: u64,
    /// The lowest the execution base fee can be next block: one update step at an empty block.
    pub next_base_fee_exec_floor: u64,
    /// The highest the execution base fee can be next block: one update step at a full block.
    pub next_base_fee_exec_ceiling: u64,
    /// The lowest the storage base fee can be next block.
    pub next_base_fee_stor_floor: u64,
    /// The highest the storage base fee can be next block.
    pub next_base_fee_stor_ceiling: u64,
    /// What a private transaction's fixed gas costs at these base fees:
    /// `PRIVATE_VERIFY_GAS * base_fee_exec + PRIVATE_GAS_STOR * base_fee_stor`. Private
    /// transactions are not charged today, so nobody is debited this.
    ///
    /// It prices the capacity one consumes only on the execution side. The storage term assumes
    /// the padded wire format that is not in place yet: a private transaction currently counts its
    /// real serialized length against the storage cap, so the storage half of this quote is what
    /// the re-pin will make true, not what it consumes today.
    pub private_fee_quote: u128,
    /// Execution gas cap per block; the ceiling on any `gas_limit`.
    pub max_gas_exec: u64,
    /// Storage bytes cap per block; the ceiling on any transaction's serialized length.
    pub max_gas_stor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct ChannelId(pub [u8; 32]);

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_string = hex::encode(self.0);
        write!(f, "{hex_string}")
    }
}

impl FromStr for ChannelId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rejection, so the round trip below covers the enum rather than a sample of it.
    fn every_rejection() -> Vec<AdmissionRejection> {
        let payer = AccountId::new([7_u8; 32]);
        vec![
            AdmissionRejection::EmptyDataBytes,
            AdmissionRejection::DataBytesExceedsMax {
                data_bytes: 1_024,
                max: 512,
            },
            AdmissionRejection::GasLimitExceedsMax {
                gas_limit: 9_000,
                max: 8_000,
            },
            AdmissionRejection::MaxFeeBelowReserve {
                fee_reserve: u128::MAX,
                max_fee: 1,
            },
            AdmissionRejection::FeeWitnessOnly,
            AdmissionRejection::UnauthorizedPayer { payer },
            AdmissionRejection::PayerCannotFund {
                payer,
                balance: 0,
                fee_reserve: u128::MAX,
            },
            AdmissionRejection::ExceedsBlockCap {
                resource: CapResource::StorageGas,
                gas_exec: 1,
                gas_stor: 2,
                max_gas_exec: 3,
                max_gas_stor: 4,
            },
            AdmissionRejection::OtherFeeValidity {
                reason: "some future rule".to_owned(),
            },
        ]
    }

    /// A rejection travels in the JSON-RPC error's `data`, so a client has to be able to read back
    /// what the sequencer wrote. Serializing alone does not prove that: `#[serde(tag = "check")]`
    /// makes deserialization buffer through serde's `Content`, which has no `u128` variant, so a
    /// raw `u128` field serializes fine and then fails to deserialize at *any* value. The
    /// `DisplayFromStr` encoding on those fields is what avoids it — and this covers every variant
    /// so a new one carrying a bare `u128` cannot reintroduce it unnoticed.
    #[test]
    fn every_rejection_round_trips_through_json() {
        for rejection in every_rejection() {
            let json = serde_json::to_string(&rejection).expect("serializes");
            let back: AdmissionRejection = serde_json::from_str(&json).unwrap_or_else(|err| {
                panic!("{rejection:?} failed to deserialize from {json}: {err}")
            });
            assert_eq!(back, rejection, "round trip changed the rejection");
        }
    }

    /// The tag is the discriminant a client branches on when it does not want the error code.
    #[test]
    fn a_rejection_carries_its_check_tag() {
        let json = serde_json::to_value(AdmissionRejection::FeeWitnessOnly).expect("serializes");
        assert_eq!(json["check"], "fee_witness_only");
    }
}
