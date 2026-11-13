//! The cross-zone emission wire contract: peers decode these bytes off
//! finalized blocks, so field order and the emitters' tag-0 variant are frozen.
//! Changing either silently strands every peer.

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::account::ZoneId;
use lee_core::account::{AccountId, Actor};

/// The domain separator a generic emitter's tag-0 variant opens with, before
/// the [`CrossZoneEmission`] fields.
pub const EMITTER_MAGIC: [u8; 8] = *b"LEZXZEM1";

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CrossZoneEmission {
    pub target_zone: ZoneId,
    pub target_account_id: AccountId,
    pub target_accounts: Vec<Actor>,
    pub payload: Vec<u8>,
    /// Names the emitter's outbox slot for this message.
    pub ordinal: u32,
}

/// Decodes the emission a registered emitter's instruction declares, or `None`
/// for any instruction that is not an emission.
///
/// The generic emitter contract: borsh tag 0, [`EMITTER_MAGIC`], then the
/// [`CrossZoneEmission`] fields, with program-specific fields allowed to trail.
/// The magic makes accidental conformance implausible, not impossible, which is
/// why listing a program stays a trust assertion. The builtin emitters predate
/// the contract and keep their own decoders.
#[must_use]
pub fn declared_emission(instruction: &[u8]) -> Option<CrossZoneEmission> {
    let (&tag, rest) = instruction.split_first()?;
    if tag != 0 {
        return None;
    }
    let mut fields = rest.strip_prefix(&EMITTER_MAGIC)?;
    CrossZoneEmission::deserialize_reader(&mut fields).ok()
}

/// The instruction bytes that declare `emission` under the generic contract:
/// tag 0, [`EMITTER_MAGIC`], then the emission fields.
#[must_use]
pub fn emitting_instruction_bytes(emission: &CrossZoneEmission) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&EMITTER_MAGIC);
    bytes.extend(borsh::to_vec(emission).expect("emission serializes"));
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_emission_encoding_is_frozen() {
        let emission = CrossZoneEmission {
            target_zone: [2; 32],
            target_account_id: AccountId::new([9; 32]),
            target_accounts: vec![Actor::new(AccountId::new([3; 32]), AccountId::new([4; 32]))],
            payload: vec![0xAA, 0xBB],
            ordinal: 7,
        };
        let bytes = borsh::to_vec(&emission).expect("emission serializes");

        let mut expected = Vec::new();
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&1_u32.to_le_bytes());
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&[4; 32]);
        expected.extend_from_slice(&2_u32.to_le_bytes());
        expected.extend_from_slice(&[0xAA, 0xBB]);
        expected.extend_from_slice(&7_u32.to_le_bytes());
        assert_eq!(bytes, expected);
    }

    fn emission() -> CrossZoneEmission {
        CrossZoneEmission {
            target_zone: [2; 32],
            target_account_id: AccountId::new([9; 32]),
            target_accounts: vec![Actor::new(AccountId::new([3; 32]), AccountId::new([4; 32]))],
            payload: vec![0xAA, 0xBB],
            ordinal: 7,
        }
    }

    #[test]
    fn a_tag_zero_instruction_opening_with_the_magic_and_emission_declares_it() {
        let instruction = emitting_instruction_bytes(&emission());
        assert_eq!(instruction[0], 0);
        assert_eq!(instruction[1..9], EMITTER_MAGIC);
        assert_eq!(declared_emission(&instruction), Some(emission()));
    }

    #[test]
    fn a_wrong_magic_is_an_ordinary_instruction() {
        let mut instruction = emitting_instruction_bytes(&emission());
        instruction[1] ^= 1;
        assert_eq!(declared_emission(&instruction), None);
    }

    #[test]
    fn trailing_program_fields_do_not_hide_the_emission() {
        let mut instruction = emitting_instruction_bytes(&emission());
        instruction.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(declared_emission(&instruction), Some(emission()));
    }

    #[test]
    fn a_non_zero_tag_is_an_ordinary_instruction() {
        let mut instruction = emitting_instruction_bytes(&emission());
        instruction[0] = 1;
        assert_eq!(declared_emission(&instruction), None);
    }

    #[test]
    fn a_truncated_or_empty_instruction_is_not_an_emission() {
        assert_eq!(declared_emission(&[]), None);
        assert_eq!(declared_emission(&[0]), None);
        let truncated_magic = &emitting_instruction_bytes(&emission())[..5];
        assert_eq!(declared_emission(truncated_magic), None);
        let mut instruction = emitting_instruction_bytes(&emission());
        instruction.truncate(instruction.len() - 1);
        assert_eq!(declared_emission(&instruction), None);
    }
}
