//! Core types for the `sequencer_stake` program.

use std::collections::BTreeMap;

pub use ed25519_dalek;
pub use lee_core::program::PdaSeed;
use lee_core::{
    account::AccountId,
    program::{InstructionData, ProgramId},
};
use serde::{Deserialize, Serialize};

/// Approvals a `Slash` must carry. Raising it moves the program id.
pub const SLASH_APPROVAL_THRESHOLD: usize = 1;

const INVALID_KEY: &str = "invalid Ed25519 public key";
const SEQUENCER_STAKE_CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/MinSequencerStake/0000";
const SLASH_APPROVAL_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/SlashApproval/00000000";
const SLASH_SINK_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/SlashedStakeSink/00000";

/// The Bedrock sequencer identity a stake backs. Holds only a valid Ed25519
/// public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequencerKey([u8; 32]);

impl SequencerKey {
    /// `None` if `bytes` is not a valid Ed25519 public key.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Option<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .is_ok()
            .then_some(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for SequencerKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for SequencerKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SequencerKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::new(bytes).ok_or_else(|| serde::de::Error::custom(INVALID_KEY))
    }
}

impl borsh::BorshSerialize for SequencerKey {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}

impl borsh::BorshDeserialize for SequencerKey {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize_reader(reader)?;
        Self::new(bytes)
            .ok_or_else(|| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, INVALID_KEY))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Locks `amount` into the ownership account for `sequencer_key`. First
    /// use claims the account; later calls top up the same account.
    Stake {
        sequencer_key: SequencerKey,
        amount: u128,
        mover_program_id: ProgramId,
        mover_instruction_data: InstructionData,
    },

    /// Self-chained only: verifies the mover deposited `expected_balance_after`.
    ConfirmStake { expected_balance_after: u128 },

    /// Records a request to release `amount` to `destination`; no balance
    /// moves yet. Must leave the account at zero or at/above the minimum.
    UnstakeRequest {
        amount: u128,
        destination: AccountId,
    },

    /// Unsigned, permissionless: releases a pending `UnstakeRequest`.
    /// Block-inclusion validity is enforced outside this program.
    FinalizeUnstake,

    /// Burns the key's whole stake to the sink and removes its entry.
    ///
    /// Only `approvals` authorize this. The reason for the offence is not checked.
    Slash {
        sequencer_key: SequencerKey,
        /// `MsgId` of the offending inscription, raw to avoid Bedrock types.
        inscription: [u8; 32],
        approvals: Vec<SlashApproval>,
    },
}

/// One accredited sequencer's signature over [`slash_approval_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashApproval {
    pub signer: SequencerKey,
    /// Ed25519 signature. A `Vec` because serde has no impl for 64 byte arrays.
    pub signature: Vec<u8>,
}

/// Tag written into a claimed ownership account: which key it backs, plus any pending unstake.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StakeRecord {
    pub sequencer_key: SequencerKey,
    pub pending_unstake: Option<PendingUnstake>,
}

impl StakeRecord {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("StakeRecord serialization should not fail")
    }

    /// Returns `None` on malformed input.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// Fixed under the staker's signature at `UnstakeRequest` time — `FinalizeUnstake` needs no
/// signature of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct PendingUnstake {
    pub amount: u128,
    pub destination: AccountId,
}

/// The single program-owned config account: minimum stake plus per-key standing, kept current
/// incrementally.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SequencerStakeConfig {
    pub minimum_sequencer_stake: u128,
    pub entries: BTreeMap<SequencerKey, SequencerEntry>,
}

impl SequencerStakeConfig {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SequencerStakeConfig serialization should not fail")
    }

    /// Returns `None` on malformed input.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// One key's standing. `account_id` makes the ownership account findable — a plain account's id
/// can't be recomputed from the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SequencerEntry {
    pub account_id: AccountId,
    pub total_staked: u128,
    pub total_pending_unstake: u128,
}

impl SequencerEntry {
    /// Stake still backing this key once every pending release has been
    /// finalized. Candidacy and every release check measure this, never the
    /// ownership account's balance: only balance decreases require owning an
    /// account, so anyone can credit one and push its balance above
    /// `total_staked`.
    #[must_use]
    pub const fn net_stake(&self) -> u128 {
        self.total_staked.saturating_sub(self.total_pending_unstake)
    }

    /// Whether releasing `amount` is a legal `UnstakeRequest` against this
    /// entry: covered by the stake tracked here, and leaving the key either
    /// fully exited or still at or above `minimum`.
    #[must_use]
    pub const fn allows_unstake_request(&self, amount: u128, minimum: u128) -> bool {
        match self.net_stake().checked_sub(amount) {
            None => false,
            Some(remaining) => remaining == 0 || remaining >= minimum,
        }
    }
}

/// Bytes an approver signs. Naming the inscription keeps the approval single use.
#[must_use]
pub fn slash_approval_message(sequencer_key: SequencerKey, inscription: [u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(96);
    message.extend_from_slice(&SLASH_APPROVAL_DOMAIN);
    message.extend_from_slice(&sequencer_key.to_bytes());
    message.extend_from_slice(&inscription);
    message
}

/// Seed of the PDA burned stakes move into. Nothing moves balance out of it.
#[must_use]
pub const fn slash_sink_seed() -> PdaSeed {
    PdaSeed::new(SLASH_SINK_SEED_DOMAIN)
}

#[must_use]
pub fn slash_sink_account_id(program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&program_id, &slash_sink_seed())
}

/// Seed of the PDA holding the [`SequencerStakeConfig`].
#[must_use]
pub const fn sequencer_stake_config_seed() -> PdaSeed {
    PdaSeed::new(SEQUENCER_STAKE_CONFIG_SEED_DOMAIN)
}

#[must_use]
pub fn sequencer_stake_config_account_id(program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&program_id, &sequencer_stake_config_seed())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM_ID: ProgramId = [9; 8];

    fn test_destination() -> AccountId {
        AccountId::new([3; 32])
    }

    /// A distinct valid key per `seed`.
    fn test_key(seed: u8) -> SequencerKey {
        let bytes = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        SequencerKey::new(bytes).expect("a derived public key is a curve point")
    }

    #[test]
    fn a_non_curve_point_is_not_a_sequencer_key() {
        let off_curve = [2_u8; 32];
        assert!(SequencerKey::new(off_curve).is_none());

        // 32 key bytes then a `None` discriminant: a `StakeRecord` with no
        // pending unstake.
        let record = [&off_curve[..], &[0_u8][..]].concat();
        assert_eq!(StakeRecord::from_bytes(&record), None);
    }

    #[test]
    fn stake_record_roundtrip() {
        let record = StakeRecord {
            sequencer_key: test_key(7),
            pending_unstake: None,
        };
        let bytes = record.to_bytes();
        assert_eq!(StakeRecord::from_bytes(&bytes), Some(record));
    }

    #[test]
    fn stake_record_with_pending_unstake_roundtrip() {
        let record = StakeRecord {
            sequencer_key: test_key(7),
            pending_unstake: Some(PendingUnstake {
                amount: 42,
                destination: test_destination(),
            }),
        };
        let bytes = record.to_bytes();
        assert_eq!(StakeRecord::from_bytes(&bytes), Some(record));
    }

    fn test_config() -> SequencerStakeConfig {
        let mut entries = BTreeMap::new();
        entries.insert(
            test_key(1),
            SequencerEntry {
                account_id: test_destination(),
                total_staked: 1_000_000,
                total_pending_unstake: 0,
            },
        );
        SequencerStakeConfig {
            minimum_sequencer_stake: 1_000_000,
            entries,
        }
    }

    #[test]
    fn sequencer_stake_config_does_not_decode_as_stake_record() {
        let bytes = test_config().to_bytes();
        assert_eq!(StakeRecord::from_bytes(&bytes), None);
    }

    #[test]
    fn stake_record_does_not_decode_as_sequencer_stake_config() {
        // Secondary to the config account's id check, which is what actually
        // keeps an ownership account from being passed as the config.
        for pending_unstake in [
            None,
            Some(PendingUnstake {
                amount: 0,
                destination: AccountId::new([0; 32]),
            }),
        ] {
            let bytes = StakeRecord {
                sequencer_key: test_key(0),
                pending_unstake,
            }
            .to_bytes();
            assert_eq!(SequencerStakeConfig::from_bytes(&bytes), None);
        }
    }

    #[test]
    fn sequencer_stake_config_roundtrip() {
        let config = test_config();
        let bytes = config.to_bytes();
        assert_eq!(SequencerStakeConfig::from_bytes(&bytes), Some(config));
    }

    fn entry(total_staked: u128, total_pending_unstake: u128) -> SequencerEntry {
        SequencerEntry {
            account_id: test_destination(),
            total_staked,
            total_pending_unstake,
        }
    }

    #[test]
    fn net_stake_discounts_what_is_already_pending() {
        assert_eq!(entry(1_000, 0).net_stake(), 1_000);
        assert_eq!(entry(1_000, 400).net_stake(), 600);
        assert_eq!(entry(1_000, 1_000).net_stake(), 0);
    }

    #[test]
    fn unstake_request_may_fully_exit_or_stay_at_the_minimum() {
        let minimum = 1_000;
        let entry = entry(3_000, 0);

        assert!(entry.allows_unstake_request(3_000, minimum), "full exit");
        assert!(
            entry.allows_unstake_request(2_000, minimum),
            "leaves exactly the minimum"
        );
        assert!(
            entry.allows_unstake_request(0, minimum),
            "no-op leaves everything"
        );
    }

    #[test]
    fn unstake_request_may_not_leave_a_nonzero_balance_below_the_minimum() {
        let minimum = 1_000;
        assert!(!entry(3_000, 0).allows_unstake_request(2_500, minimum));
    }

    #[test]
    fn unstake_request_may_not_exceed_the_tracked_stake() {
        // A donation can push the account's balance above `total_staked`; a
        // request sized off that balance is rejected here.
        let minimum = 1_000;
        let donated_balance = 3_001;
        let entry = entry(3_000, 0);

        assert!(!entry.allows_unstake_request(donated_balance, minimum));
        assert!(entry.allows_unstake_request(entry.total_staked, minimum));
    }

    #[test]
    fn unstake_request_is_measured_against_stake_not_already_pending() {
        let minimum = 1_000;
        let entry = entry(3_000, 2_000);

        assert!(
            !entry.allows_unstake_request(3_000, minimum),
            "2000 is already spoken for"
        );
        assert!(
            entry.allows_unstake_request(1_000, minimum),
            "exits what is left"
        );
    }

    #[test]
    fn sequencer_stake_config_account_id_is_deterministic() {
        assert_eq!(
            sequencer_stake_config_account_id(PROGRAM_ID),
            sequencer_stake_config_account_id(PROGRAM_ID)
        );
    }
}
