//! Reexports of types used by sequencer rpc specification.

use std::{fmt::Display, str::FromStr};

pub use common::{HashType, block::Block, transaction::LeeTransaction};
pub use lee::{Account, AccountId, ProgramId};
pub use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, MembershipProof, ProgramCommitment, account::Nonce,
};
use serde_with::{DeserializeFromStr, SerializeDisplay};

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
