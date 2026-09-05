//! Collects the accredited-key signatures a `ChannelConfigOp` needs.
//!
//! Bedrock verifies a config against the channel's own
//! `configuration_threshold`, so raising it above one is a matter of gathering
//! signatures rather than of building a threshold scheme. The signatures are
//! over one specific funded transaction, so the turn holder proposes a
//! candidate and its peers sign that exact transaction or nothing.

pub use actor::ChannelConfigActor;
pub use protocol::{
    Candidate, ConfigTarget, Outbound, PeerCandidate, PeerSignature, Propose, Proposed, Report,
    SetPublisher,
};

pub mod actor;
pub mod error;
pub mod protocol;
