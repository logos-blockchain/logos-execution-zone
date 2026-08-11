//! `fee_core`: pure arithmetic and state types for the LEZ fee subsystem.
//!
//! Transcribes SPECS.md's Protocol section (the normative source); Annex A
//! (Python) and Annex B (Rust) are informative reference implementations
//! this crate is cross-checked against. No I/O, no async, and no
//! dependencies on other LEZ crates: consumers convert their own
//! transaction/state types into this crate's [`assess::FeeTxView`] /
//! [`state::FeeState`] and drive the functions below from block-level code.

pub use assess::{FeeTxView, PayerId, fee_actual_base, fee_reserve, gas_stor};
pub use distribute::{distribute, record_revenue, settle_payout};
pub use error::{ConsensusFaultError, FeeError, InvalidBlockError};
pub use state::FeeState;
pub use update::next_base_fee;
pub use validity::{
    DeploymentFeePolicy, accumulate_gas_used, authorize_payer, authorize_private_payer,
    deployment_policy, validate_static_block, validate_static_tx,
};

pub mod assess;
pub mod distribute;
pub mod error;
pub mod params;
pub mod state;
pub mod update;
pub mod validity;
