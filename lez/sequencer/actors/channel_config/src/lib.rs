//! Collects the accredited-key signatures a `ChannelConfigOp` needs.
//!
//! Bedrock verifies a config against the channel's own
//! `configuration_threshold`, so raising it above one is a matter of gathering
//! signatures rather than of building a threshold scheme. The signatures are
//! over one specific funded transaction, so the turn holder proposes a
//! draft and its peers sign that exact transaction or nothing.

pub use actor::{ChannelConfigActor, MAILBOX_CAPACITY};
pub use protocol::{
    Action, ChannelView, ConfigTarget, Draft, FundedTx, Propose, SetPublisher, Signature, Wire,
};

pub mod actor;
pub mod error;
pub mod protocol;
