//! Reexports of types used by sequencer rpc specification.

use std::{fmt::Display, str::FromStr};

pub use common::{HashType, block::Block, transaction::LeeTransaction};
pub use lee::{Account, AccountId, ProgramId};
pub use lee_core::{BlockId, Commitment, CommitmentSetDigest, MembershipProof, account::Nonce};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(Debug, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct ChannelId(pub [u8; 32]);

/// A cross-zone delivery a sequencer gave up on after repeated failures.
///
/// Identifies the message rather than carrying it: zone, block id and tx index
/// locate it on the peer's channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneDeadLetter {
    pub message_key: HashType,
    pub src_zone: ChannelId,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub failed_attempts: u32,
    pub transaction_bytes: u32,
}

/// What a sequencer has given up delivering.
///
/// `total_retired` counts every give-up, `retained` only the ones still kept;
/// they diverge on eviction and on reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneDeadLetterReport {
    pub total_retired: u64,
    pub retained: Vec<CrossZoneDeadLetter>,
}

/// What requeueing a dead-lettered delivery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossZoneDeadLetterRequeue {
    /// Restored to the pending list with a clean attempt count; the next
    /// production turn attempts it again.
    Requeued,
    /// The delivery was already pending again, so only the dead letter was
    /// dropped.
    AlreadyPending,
    /// No retained dead letter under that key.
    NotFound,
    /// Listed, but its transaction exceeded the retention bound and was not
    /// kept; read the message back off the peer channel instead.
    NotRetained,
}

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
