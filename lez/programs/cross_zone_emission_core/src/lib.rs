//! The cross-zone emission wire contract: peers decode these bytes off
//! finalized blocks, so field order and the emitters' tag-0 variant are frozen.
//! Changing either silently strands every peer.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::{AccountId, Actor};

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CrossZoneEmission {
    pub target_zone: ZoneId,
    pub target_account_id: AccountId,
    pub target_accounts: Vec<Actor>,
    pub payload: Vec<u8>,
    /// Names the emitter's outbox slot for this message.
    pub ordinal: u32,
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
}
