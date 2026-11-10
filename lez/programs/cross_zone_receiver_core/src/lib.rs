//! The cross-zone receiver contract: the config shape, seed, and source check a
//! program needs to accept deliveries from the inbox.
//!
//! The inbox delivers to any program a peer names, so being reachable is not
//! opt-in; authorizing sources is. A receiver opts in by holding a
//! [`ReceiverConfig`] at [`receiver_config_seed`] and checking the deliverer
//! and source with [`ReceiverConfig::authorizes`] on each delivery.
//! `ping_receiver` is the reference implementation.
//!
//! WHO MAY CLAIM THE CONFIG IS PART OF THE CONTRACT. Genesis writes a builtin's
//! PDA before any user transaction exists, but a runtime-deployed receiver is
//! claimed after deployment, and a bare first write needs only the PDA's own
//! evidence, which anyone can produce. So a receiver MUST bind its claim to its
//! program account's key, as `zone_chat` does. Without that, an observer
//! front-runs the deployer and names its own `deliverer`, permanently: the
//! write happens once, so the only remedy is redeploying at a fresh account.

use borsh::{BorshDeserialize, BorshSerialize};
use cross_zone_marker_core::inbox_source_marker_account_id;
pub use cross_zone_marker_core::{Delivery, ZoneId};
use lee_core::{account::AccountId, program::PdaSeed};

const RECEIVER_CONFIG_SEED: [u8; 32] = *b"/LEZ/v0.3/XZoneReceiverCfg/0000/";

/// The borsh enum tag a conforming receiver gives its `InitConfig` variant.
///
/// Tag 0 stays free for the receiver's own first variant (`ping_receiver`'s
/// `Record`, whose tag is wire format on the emitting side), so the contract
/// pins `InitConfig` at 1.
pub const INIT_CONFIG_TAG: u8 = 1;

/// Who may deliver to a receiver, and which peer sources they may deliver from.
///
/// Shared so every receiver authorizes the same way and the host can seed or
/// read any receiver's config through one shape. A receiver with richer needs
/// (`wrapped_token`'s caps and counters) keeps its own type instead.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiverConfig {
    /// The program allowed to deliver: the cross-zone inbox.
    pub deliverer: AccountId,
    /// The program allowed to send authority messages on the authority's
    /// behalf, or `None` for top-level only.
    pub governance: Option<AccountId>,
    /// The account allowed to change `sources`, or `None` for a list fixed at
    /// initialization.
    pub authority: Option<AccountId>,
    /// The `(src_zone, src_account_id)` pairs a delivery may originate from.
    pub sources: Vec<(ZoneId, AccountId)>,
}

impl ReceiverConfig {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("receiver config serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }

    /// Whether a delivery from `(src_zone, src_account_id)` is one this config
    /// authorizes.
    ///
    /// Compares the pair directly. The marker address derived from a pair is
    /// injective in it under one deliverer, so a receiver that prefers
    /// comparing marker ids gets the identical answer for more guest cycles;
    /// see [`source_marker`]. The caller must already have pinned the delivery's
    /// origin to `self.deliverer`; this only answers the source half.
    #[must_use]
    pub fn authorizes(&self, src_zone: &ZoneId, src_account_id: AccountId) -> bool {
        self.sources.contains(&(*src_zone, src_account_id))
    }

    /// The marker address the inbox passes for `(src_zone, src_account_id)`,
    /// for a receiver that authenticates on the address rather than the pair.
    #[must_use]
    pub fn source_marker(&self, src_zone: &ZoneId, src_account_id: AccountId) -> AccountId {
        inbox_source_marker_account_id(self.deliverer, src_zone, src_account_id)
    }
}

/// The config account a receiver's authorization lives in.
#[must_use]
pub fn receiver_config_account_id(receiver_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&receiver_id, &receiver_config_seed())
}

/// Seed of the receiver config PDA, one per receiver program.
#[must_use]
pub const fn receiver_config_seed() -> PdaSeed {
    PdaSeed::new(RECEIVER_CONFIG_SEED)
}

/// The instruction bytes that initialize a conforming receiver's config:
/// [`INIT_CONFIG_TAG`], then the config.
///
/// Sent to the config PDA, at genesis for a builtin or by the deployer for a
/// runtime-deployed receiver.
#[must_use]
pub fn init_config_instruction_bytes(config: &ReceiverConfig) -> Vec<u8> {
    let mut bytes = vec![INIT_CONFIG_TAG];
    bytes.extend(config.to_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const INBOX: AccountId = AccountId::new([1; 32]);
    const SOURCE: AccountId = AccountId::new([9; 32]);
    const ZONE: ZoneId = [7; 32];

    fn config() -> ReceiverConfig {
        ReceiverConfig {
            deliverer: INBOX,
            governance: None,
            authority: None,
            sources: vec![(ZONE, SOURCE)],
        }
    }

    #[test]
    fn config_round_trips_and_empty_data_does_not_decode() {
        assert_eq!(
            ReceiverConfig::from_bytes(&config().to_bytes()),
            Some(config())
        );
        assert_eq!(ReceiverConfig::from_bytes(&[]), None);
    }

    #[test]
    fn an_authorized_pair_is_accepted_and_others_are_not() {
        assert!(config().authorizes(&ZONE, SOURCE));
        assert!(!config().authorizes(&[8; 32], SOURCE));
        assert!(!config().authorizes(&ZONE, AccountId::new([4; 32])));
    }

    #[test]
    fn init_config_bytes_are_the_tag_then_the_config() {
        let bytes = init_config_instruction_bytes(&config());
        assert_eq!(bytes[0], INIT_CONFIG_TAG);
        assert_eq!(ReceiverConfig::from_bytes(&bytes[1..]), Some(config()));
    }
}
