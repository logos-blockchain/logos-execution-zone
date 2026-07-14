//! Reexports of types used by sequencer rpc specification.

use std::{fmt::Display, str::FromStr};

pub use common::{HashType, block::Block, transaction::LeeTransaction};
pub use lee::{Account, AccountId, ProgramId};
pub use lee_core::{BlockId, Commitment, MembershipProof, account::Nonce};
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

/// Request for `adminConfigureChannel`: replaces the channel's accredited key
/// set and rotation parameters.
///
/// - `keys` are hex-encoded 32-byte Ed25519 public keys
/// - `keys[0]` must be this sequencer's (admin) key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfigureChannelRequest {
    pub keys: Vec<String>,
    pub posting_timeframe: u32,
    pub posting_timeout: u32,
    pub configuration_threshold: u16,
    pub withdraw_threshold: u16,
}

impl ConfigureChannelRequest {
    /// Structural sanity checks for the request.
    ///
    /// The L1 validates this too, but its async so we don't immediately
    /// know about them when we submit. Checking this here instead gives
    /// immediate feedback to the caller.
    ///
    /// We don't need a particular error type here, it's going to be logged only.
    pub fn validate(&self) -> Result<(), String> {
        let key_count = self.keys.len();
        if key_count == 0 {
            return Err("Channel key list must not be empty".to_owned());
        }
        for (name, threshold) in [
            ("configuration_threshold", self.configuration_threshold),
            ("withdraw_threshold", self.withdraw_threshold),
        ] {
            if threshold == 0 || usize::from(threshold) > key_count {
                return Err(format!(
                    "{name} must be between 1 and the key count ({key_count}), got {threshold}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_channel_request_validate_rejects_static_garbage() {
        // `validate` is structural: key contents are not parsed here.
        let base = ConfigureChannelRequest {
            keys: vec!["unparsed".to_owned(), "unparsed".to_owned()],
            posting_timeframe: 20,
            posting_timeout: 30,
            configuration_threshold: 1,
            withdraw_threshold: 2,
        };

        assert!(base.validate().is_ok());
        assert!(
            ConfigureChannelRequest {
                keys: vec![],
                ..base
            }
            .validate()
            .is_err()
        );
        assert!(
            ConfigureChannelRequest {
                configuration_threshold: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ConfigureChannelRequest {
                configuration_threshold: 3,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ConfigureChannelRequest {
                withdraw_threshold: 3,
                ..base
            }
            .validate()
            .is_err()
        );
    }
}
