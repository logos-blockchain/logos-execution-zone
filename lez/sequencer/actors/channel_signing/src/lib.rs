//! Collects the accredited-key signatures a `ChannelConfigOp` needs, and those
//! of the `ChannelTransfer` pinning a block on its deposits.
//!
//! Bedrock verifies a config against the channel's own
//! `configuration_threshold`, so raising it above one is a matter of gathering
//! signatures rather than of building a threshold scheme. The signatures are
//! over one specific funded transaction, so the turn holder proposes a
//! draft and its peers sign that exact transaction or nothing.

pub use actor::{ChannelSigningActor, MAILBOX_CAPACITY};
pub use protocol::{
    Action, BlockDeposits, ChannelView, ConfigTarget, Draft, FinalMints, FundedTx, ObservedDeposit,
    ObservedDeposits, Propose, Reset, SetPublisher, SetSubmitter, SignPin, Signature, Submission,
    SubmitConfig, Wire,
};

pub mod actor;
pub mod error;
pub mod protocol;
