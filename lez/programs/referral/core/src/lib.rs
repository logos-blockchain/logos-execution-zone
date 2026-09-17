use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek;
use lee_core::{
    Identifier, NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use serde::{Deserialize, Serialize};

pub const MAX_REGISTERED_NODES: usize = 4096;

pub const CREDIT_IDENTIFIER: Identifier = 0;

pub const DEPLOYMENT_CONTEXT: [u8; 32] = [
    0x9d, 0x2c, 0x4b, 0x7e, 0x11, 0xa6, 0x53, 0xf0, 0x8c, 0x45, 0xd9, 0x37, 0x62, 0xbe, 0x0a, 0x18,
    0xf4, 0x71, 0x26, 0xcd, 0x5b, 0x93, 0xe8, 0x0f, 0x3a, 0xd6, 0x84, 0x1c, 0x77, 0xb2, 0x50, 0xe9,
];

pub const ORACLE_ACCOUNT_ID: AccountId = AccountId::new([
    0x52, 0x5c, 0xc5, 0x6b, 0x7f, 0x8e, 0x28, 0x49, 0xec, 0x9d, 0xa8, 0x66, 0x1c, 0x7a, 0xde, 0x0c,
    0x91, 0x8f, 0x7a, 0x0a, 0xb2, 0x3a, 0x3f, 0xa7, 0x59, 0x61, 0xd5, 0xa1, 0x99, 0xa5, 0x6e, 0xf3,
]);

pub const PROTOTYPE_ORACLE_SIGNING_KEY: [u8; 32] = [11; 32];

const REGISTRY_SEED_DOMAIN: &[u8; 25] = b"LEZ/Referral/Registry/v1\0";
const TICKET_SEED_DOMAIN: &[u8; 24] = b"LEZ/Referral/Tickets/v1\0";
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Invitation {
    pub deployment_context: [u8; 32],
    pub program_account: AccountId,
    pub parent_node: NodeId,
    pub npk: NullifierPublicKey,
    #[borsh(deserialize_with = "read_viewing_key")]
    pub vpk: ViewingPublicKey,
}

impl Invitation {
    #[must_use]
    pub const fn new(
        program_account: AccountId,
        parent_node: NodeId,
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
    ) -> Self {
        Self {
            deployment_context: DEPLOYMENT_CONTEXT,
            program_account,
            parent_node,
            npk,
            vpk,
        }
    }

    #[must_use]
    pub fn parent_node(&self, program_account: AccountId) -> Option<NodeId> {
        (self.deployment_context == DEPLOYMENT_CONTEXT && self.program_account == program_account)
            .then_some(self.parent_node)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry(Vec<NodeId>);

impl Registry {
    #[must_use]
    pub fn contains(&self, node: NodeId) -> bool {
        self.0.contains(&node)
    }

    pub fn register(&mut self, node: NodeId) -> bool {
        if self.contains(node) || self.0.len() >= MAX_REGISTERED_NODES {
            return false;
        }
        self.0.push(node);
        true
    }
}

impl BorshSerialize for Registry {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for Registry {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = read_bounded_len(reader, MAX_REGISTERED_NODES, "registry exceeds capacity")?;
        let mut nodes = Vec::with_capacity(len);
        for _ in 0..len {
            nodes.push(NodeId::deserialize_reader(reader)?);
        }
        Ok(Self(nodes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum State {
    Registry(Registry),
    Participant {
        node: NodeId,
        referrer: Option<NodeId>,
        reward_balance: u128,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ParticipantAuthorizationV1 {
    pub deployment_context: [u8; 32],
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
            deployment_context: DEPLOYMENT_CONTEXT,
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
    Grant {
        node: NodeId,
        amount: u128,
    },
    Collect,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    Impl::hash_bytes(bytes)
        .as_bytes()
        .try_into()
        .expect("Hash output must be exactly 32 bytes long")
}

fn invalid_data(message: &'static str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}

fn read_bounded_len<R: borsh::io::Read>(
    reader: &mut R,
    max: usize,
    message: &'static str,
) -> borsh::io::Result<usize> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    let len = usize::try_from(u32::from_le_bytes(bytes))
        .map_err(|_err| invalid_data("length does not fit in usize"))?;
    if len > max {
        return Err(invalid_data(message));
    }
    Ok(len)
}

fn read_viewing_key<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<ViewingPublicKey> {
    let mut encoded = [0_u8; 4 + ViewingPublicKey::LEN];
    reader.read_exact(&mut encoded[..4])?;
    if usize::try_from(u32::from_le_bytes([
        encoded[0], encoded[1], encoded[2], encoded[3],
    ]))
    .is_ok_and(|len| len == ViewingPublicKey::LEN)
    {
        reader.read_exact(&mut encoded[4..])?;
        ViewingPublicKey::try_from_slice(&encoded)
    } else {
        Err(invalid_data("viewing key has the wrong length"))
    }
}

#[must_use]
pub fn registry_seed() -> PdaSeed {
    PdaSeed::new(sha256(REGISTRY_SEED_DOMAIN))
}

#[must_use]
pub fn ticket_seed(node: NodeId) -> PdaSeed {
    let mut preimage = [0_u8; TICKET_SEED_DOMAIN.len() + 32];
    preimage[..TICKET_SEED_DOMAIN.len()].copy_from_slice(TICKET_SEED_DOMAIN);
    preimage[TICKET_SEED_DOMAIN.len()..].copy_from_slice(&node.0);
    PdaSeed::new(sha256(&preimage))
}

#[must_use]
pub fn registry_account_id(program_account: AccountId) -> AccountId {
    AccountId::for_public_pda(&program_account, &registry_seed())
}

#[must_use]
pub fn ticket_account_id(program_account: AccountId, node: NodeId) -> AccountId {
    AccountId::for_public_pda(&program_account, &ticket_seed(node))
}

#[must_use]
pub fn credit_account_id(
    program_account: AccountId,
    seed: &PdaSeed,
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
) -> AccountId {
    AccountId::for_private_pda(&program_account, seed, npk, vpk, CREDIT_IDENTIFIER)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([9; 32]);
    const NODE: NodeId = NodeId::new([7; 32]);
    const PARTICIPANT: AccountId = AccountId::new([3; 32]);

    fn viewing_key(seed: u8) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&[seed; 32], &[seed.wrapping_add(1); 32])
    }

    fn registry_bytes(nodes: &[NodeId]) -> Vec<u8> {
        let mut bytes = u32::try_from(nodes.len()).unwrap().to_le_bytes().to_vec();
        for node in nodes {
            bytes.extend_from_slice(&node.to_bytes());
        }
        bytes
    }

    fn sequential_nodes(count: usize) -> Vec<NodeId> {
        (0..count)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
                NodeId::new(bytes)
            })
            .collect()
    }

    #[test]
    fn seeds_and_account_ids_match_pinned_vectors() {
        assert_eq!(
            registry_seed().as_bytes(),
            &[
                0x94, 0x56, 0x67, 0xc4, 0x1d, 0xca, 0xef, 0x40, 0x92, 0x4b, 0xcb, 0xe3, 0x39, 0xdf,
                0x90, 0x2d, 0xdf, 0xaa, 0xe2, 0x1e, 0x9d, 0x26, 0xa8, 0x0d, 0x61, 0x9c, 0x84, 0x91,
                0xfa, 0x46, 0xd0, 0x4e,
            ]
        );
        assert_eq!(
            ticket_seed(NODE).as_bytes(),
            &[
                0x1c, 0x5b, 0xe2, 0x43, 0x18, 0x80, 0x87, 0xdf, 0x32, 0xf1, 0x58, 0xd7, 0x54, 0x66,
                0x52, 0x25, 0x04, 0x35, 0x70, 0x39, 0x2b, 0x8f, 0xfb, 0xff, 0x12, 0xb7, 0x1f, 0xb7,
                0xe1, 0x32, 0xb0, 0x31,
            ]
        );
        assert_eq!(
            registry_account_id(PROGRAM).to_bytes(),
            [
                0x94, 0xe6, 0x37, 0x70, 0x00, 0xb2, 0x79, 0x0b, 0xc0, 0x88, 0x7b, 0x23, 0x0a, 0x9d,
                0x21, 0xcd, 0xcb, 0xc0, 0x50, 0x81, 0xc2, 0x89, 0x35, 0xac, 0x97, 0x98, 0x87, 0x7a,
                0x63, 0xa6, 0x18, 0x4e,
            ]
        );
        assert_eq!(
            ticket_account_id(PROGRAM, NODE).to_bytes(),
            [
                0x68, 0x70, 0x83, 0x11, 0x8b, 0xfe, 0xb2, 0xb2, 0x85, 0xff, 0x11, 0xbc, 0x00, 0x76,
                0x82, 0x5a, 0xb1, 0x15, 0x02, 0x7b, 0x12, 0x9c, 0x90, 0xfb, 0x00, 0xe0, 0x83, 0xd3,
                0xbf, 0x97, 0x5f, 0xf2,
            ]
        );
    }

    #[test]
    fn the_authorization_message_is_the_prefixed_encoding_itself() {
        let authorization = ParticipantAuthorizationV1::new(PROGRAM, NODE, PARTICIPANT, None);
        let message = authorization.message();

        assert_eq!(message.len(), 166);
        assert_eq!(&message[..37], AUTHORIZATION_DOMAIN);
        assert_eq!(&message[37..69], &DEPLOYMENT_CONTEXT);
        assert_eq!(
            sha256(&message),
            [
                0x27, 0xdb, 0xe7, 0x7b, 0xb8, 0x4d, 0xb7, 0x91, 0x8b, 0x4e, 0x5b, 0xd7, 0x2a, 0x30,
                0x6e, 0xfe, 0xc9, 0xf0, 0x6a, 0x9c, 0xb0, 0x63, 0x86, 0x19, 0x2c, 0x92, 0x5a, 0xfc,
                0x6a, 0xc2, 0x8d, 0x02,
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
            ParticipantAuthorizationV1 {
                deployment_context: [0; 32],
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
    fn registration_owns_uniqueness_and_roundtrips() {
        let mut registry = Registry::default();
        assert!(registry.register(NodeId::new([1; 32])));
        assert!(registry.register(NodeId::new([2; 32])));
        assert!(!registry.register(NodeId::new([1; 32])));

        assert!(registry.contains(NodeId::new([1; 32])));
        assert!(!registry.contains(NodeId::new([9; 32])));

        let encoded = borsh::to_vec(&registry).unwrap();
        assert_eq!(borsh::from_slice::<Registry>(&encoded).unwrap(), registry);
    }

    #[test]
    fn registry_is_bounded_by_capacity() {
        let mut registry = Registry::default();
        for node in sequential_nodes(MAX_REGISTERED_NODES) {
            assert!(registry.register(node));
        }
        assert!(!registry.register(NodeId::new([0xff; 32])));

        let full = borsh::to_vec(&registry).unwrap();
        assert_eq!(borsh::from_slice::<Registry>(&full).unwrap(), registry);

        let over_capacity = registry_bytes(&sequential_nodes(MAX_REGISTERED_NODES + 1));
        assert!(borsh::from_slice::<Registry>(&over_capacity).is_err());

        let mut trailing = registry_bytes(&[NodeId::new([1; 32])]);
        trailing.push(0);
        assert!(borsh::from_slice::<Registry>(&trailing).is_err());
    }

    #[test]
    fn state_decoding_rejects_empty_and_trailing_bytes() {
        let state = State::Credit {
            recipient_node: NODE,
            amount: 5,
        };
        let data = state.to_data();
        assert_eq!(State::decode(&data), Some(state));
        assert_eq!(State::decode(&ShardData::empty()), None);

        let mut trailing = data.to_vec();
        trailing.push(0);
        assert_eq!(State::decode(&trailing.try_into().unwrap()), None);
    }

    #[test]
    fn a_viewing_key_length_prefix_is_checked_before_its_body_is_read() {
        let valid = borsh::to_vec(&Invitation::new(
            PROGRAM,
            NODE,
            NullifierPublicKey([1; 32]),
            viewing_key(1),
        ))
        .unwrap();
        assert!(borsh::from_slice::<Invitation>(&valid).is_ok());

        let mut overlong = [0; 128].to_vec();
        overlong.extend_from_slice(
            &u32::try_from(ViewingPublicKey::LEN + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(borsh::from_slice::<Invitation>(&overlong).is_err());

        let mut short = [0; 128].to_vec();
        short.extend_from_slice(&3_u32.to_le_bytes());
        short.extend_from_slice(&[0; 3]);
        assert!(borsh::from_slice::<Invitation>(&short).is_err());
    }
}
