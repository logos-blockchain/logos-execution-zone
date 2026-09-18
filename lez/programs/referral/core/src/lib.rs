use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek;
use lee_core::{
    NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
};
use serde::{Deserialize, Serialize};

pub const ORACLE_ACCOUNT_ID: AccountId = AccountId::new([
    0x52, 0x5c, 0xc5, 0x6b, 0x7f, 0x8e, 0x28, 0x49, 0xec, 0x9d, 0xa8, 0x66, 0x1c, 0x7a, 0xde, 0x0c,
    0x91, 0x8f, 0x7a, 0x0a, 0xb2, 0x3a, 0x3f, 0xa7, 0x59, 0x61, 0xd5, 0xa1, 0x99, 0xa5, 0x6e, 0xf3,
]);

pub const PROTOTYPE_ORACLE_SIGNING_KEY: [u8; 32] = [11; 32];

const AUTHORIZATION_DOMAIN: &[u8; 37] = b"LEZ/Referral/AuthorizeParticipant/v1\0";

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct NodeId([u8; 32]);

impl NodeId {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn verifying_key(self) -> Option<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub parent_node: NodeId,
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
}

impl Invitation {
    #[must_use]
    pub const fn new(parent_node: NodeId, npk: NullifierPublicKey, vpk: ViewingPublicKey) -> Self {
        Self {
            parent_node,
            npk,
            vpk,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registry {
    pub nodes: BTreeSet<NodeId>,
    pub epoch: u32,
    pub active: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Participant {
    pub node: NodeId,
    pub referrer: Option<NodeId>,
    pub children: BTreeMap<NodeId, u32>,
    pub reward_balance: u128,
}

impl Participant {
    #[must_use]
    pub const fn new(node: NodeId, referrer: Option<NodeId>) -> Self {
        Self {
            node,
            referrer,
            children: BTreeMap::new(),
            reward_balance: 0,
        }
    }

    #[must_use]
    pub fn claim(&mut self, registry: &Registry, notes: &[State]) -> u128 {
        let mut total: u128 = 0;
        for note in notes {
            match *note {
                State::Child { node, referrer } => {
                    assert_eq!(referrer, self.node, "child is announced to another node");
                    self.children.entry(node).or_insert(0);
                }
                State::Credit {
                    recipient_node,
                    amount,
                } => {
                    assert_eq!(
                        recipient_node, self.node,
                        "credit is addressed to another node"
                    );
                    total = total
                        .checked_add(amount)
                        .expect("credit total fits in u128");
                }
                State::Registry(_) | State::Participant(_) => {
                    panic!("note does not hold a child or a credit")
                }
            }
        }
        for (child, last) in &mut self.children {
            if *last < registry.epoch && registry.active.contains(child) {
                *last = registry.epoch;
                total = total.checked_add(1).expect("claim total fits in u128");
            }
        }
        self.reward_balance = self
            .reward_balance
            .checked_add(total)
            .expect("reward balance fits in u128");
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum State {
    Registry(Registry),
    Participant(Participant),
    Child {
        node: NodeId,
        referrer: NodeId,
    },
    Credit {
        recipient_node: NodeId,
        amount: u128,
    },
}

impl State {
    #[must_use]
    pub fn to_data(&self) -> ShardData {
        borsh::to_vec(self)
            .expect("borsh serialization is infallible")
            .try_into()
            .expect("referral state fits in account data")
    }

    #[must_use]
    pub fn decode(data: &ShardData) -> Option<Self> {
        (!data.is_empty())
            .then(|| borsh::from_slice(data.as_ref()).ok())
            .flatten()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ParticipantAuthorizationV1 {
    pub program_account: AccountId,
    pub node: NodeId,
    pub participant_account: AccountId,
    pub referrer: Option<NodeId>,
}

impl ParticipantAuthorizationV1 {
    #[must_use]
    pub const fn new(
        program_account: AccountId,
        node: NodeId,
        participant_account: AccountId,
        referrer: Option<NodeId>,
    ) -> Self {
        Self {
            program_account,
            node,
            participant_account,
            referrer,
        }
    }

    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut message = AUTHORIZATION_DOMAIN.to_vec();
        message.extend_from_slice(&borsh::to_vec(self).expect("borsh serialization is infallible"));
        message
    }

    #[must_use]
    pub fn verify(&self, signature: &[u8; 64]) -> bool {
        self.node.verifying_key().is_some_and(|key| {
            key.verify_strict(
                &self.message(),
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .is_ok()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    Register {
        node: NodeId,
        referrer: Option<NodeId>,
        node_signature: [u8; 64],
    },
    Publish {
        epoch: u32,
        active: BTreeSet<NodeId>,
    },
    Claim,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([9; 32]);
    const NODE: NodeId = NodeId::new([7; 32]);
    const PARTICIPANT: AccountId = AccountId::new([3; 32]);

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use risc0_zkvm::sha::{Impl, Sha256 as _};

        Impl::hash_bytes(bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long")
    }

    #[test]
    fn the_authorization_message_is_the_prefixed_encoding_itself() {
        let authorization = ParticipantAuthorizationV1::new(PROGRAM, NODE, PARTICIPANT, None);
        let message = authorization.message();

        assert_eq!(message.len(), 134);
        assert_eq!(&message[..37], AUTHORIZATION_DOMAIN);
        assert_eq!(&message[37..69], &PROGRAM.to_bytes());
        assert_eq!(
            sha256(&message),
            [
                0x0f, 0x69, 0x7b, 0x3b, 0xaa, 0x83, 0x74, 0x9f, 0xa7, 0x8f, 0x96, 0x17, 0xa9, 0x35,
                0xaa, 0x4c, 0x76, 0x24, 0x08, 0xe8, 0x28, 0xc2, 0x63, 0x21, 0xc5, 0xea, 0xbc, 0x5b,
                0x21, 0x32, 0xed, 0xf1,
            ]
        );
    }

    #[test]
    fn a_signature_over_the_bare_digest_is_rejected() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let node = NodeId::new(key.verifying_key().to_bytes());
        let authorization = ParticipantAuthorizationV1::new(PROGRAM, node, PARTICIPANT, None);

        assert!(authorization.verify(&key.sign(&authorization.message()).to_bytes()));
        assert!(!authorization.verify(&key.sign(&sha256(&authorization.message())).to_bytes()));
    }

    #[test]
    fn authorization_rejects_every_tampered_field() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let node = NodeId::new(key.verifying_key().to_bytes());
        let parent = NodeId::new(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes());
        let authorization =
            ParticipantAuthorizationV1::new(PROGRAM, node, PARTICIPANT, Some(parent));
        let signature = key.sign(&authorization.message()).to_bytes();

        assert!(authorization.verify(&signature));

        let tampered = [
            ParticipantAuthorizationV1 {
                program_account: AccountId::new([10; 32]),
                ..authorization
            },
            ParticipantAuthorizationV1 {
                participant_account: AccountId::new([4; 32]),
                ..authorization
            },
            ParticipantAuthorizationV1 {
                referrer: None,
                ..authorization
            },
            ParticipantAuthorizationV1 {
                referrer: Some(node),
                ..authorization
            },
        ];
        for candidate in tampered {
            assert!(!candidate.verify(&signature));
        }

        let other = SigningKey::from_bytes(&[2; 32]);
        assert!(!authorization.verify(&other.sign(&authorization.message()).to_bytes()));
    }

    #[test]
    fn state_decoding_rejects_empty_and_trailing_bytes() {
        let state = State::Child {
            node: NODE,
            referrer: NodeId::new([8; 32]),
        };
        let data = state.to_data();
        assert_eq!(State::decode(&data), Some(state));
        assert_eq!(State::decode(&ShardData::empty()), None);

        let mut trailing = data.to_vec();
        trailing.push(0);
        assert_eq!(State::decode(&trailing.try_into().unwrap()), None);
    }
}
