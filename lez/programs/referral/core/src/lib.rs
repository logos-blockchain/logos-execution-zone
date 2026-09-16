use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek;
use lee_core::{
    Identifier, NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use serde::{Deserialize, Serialize};

pub const MAX_OBSERVED_NODES: usize = 4096;

pub const STATE_VERSION: u16 = 2;
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

const REGISTRY_SEED_DOMAIN: &[u8; 26] = b"LEZ/Referral/FirstSeen/v1\0";
const TICKET_SEED_DOMAIN: &[u8; 24] = b"LEZ/Referral/Tickets/v1\0";
const AUTHORIZATION_DOMAIN: &[u8; 37] = b"LEZ/Referral/AuthorizeParticipant/v1\0";

pub type L1Epoch = u64;

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

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NodeBatch(Vec<NodeId>);

impl NodeBatch {
    #[must_use]
    pub fn new(values: Vec<NodeId>) -> Option<Self> {
        (values.len() <= MAX_OBSERVED_NODES).then_some(Self(values))
    }
}

impl std::ops::Deref for NodeBatch {
    type Target = [NodeId];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BorshSerialize for NodeBatch {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for NodeBatch {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = read_bounded_len(
            reader,
            MAX_OBSERVED_NODES,
            "node batch exceeds its maximum length",
        )?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(NodeId::deserialize_reader(reader)?);
        }
        Ok(Self(values))
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ParticipantDescriptor {
    pub npk: NullifierPublicKey,
    #[borsh(deserialize_with = "read_viewing_key")]
    pub vpk: ViewingPublicKey,
    pub identifier: Identifier,
}

impl ParticipantDescriptor {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk, &self.vpk, self.identifier)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    introduced: BTreeMap<L1Epoch, Vec<NodeId>>,
}

impl Registry {
    #[must_use]
    pub fn first_used(&self, node: NodeId) -> Option<L1Epoch> {
        self.introduced
            .iter()
            .find_map(|(epoch, nodes)| nodes.contains(&node).then_some(*epoch))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.introduced.values().map(Vec::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.introduced.is_empty()
    }

    pub fn insert_batch(&mut self, epoch: L1Epoch, nodes: &[NodeId]) -> bool {
        let batch: BTreeSet<NodeId> = nodes.iter().copied().collect();
        if nodes.is_empty() || batch.len() != nodes.len() {
            return false;
        }
        if self
            .len()
            .checked_add(nodes.len())
            .is_none_or(|total| total > MAX_OBSERVED_NODES)
        {
            return false;
        }
        if self
            .introduced
            .values()
            .any(|recorded| recorded.iter().any(|node| batch.contains(node)))
        {
            return false;
        }

        self.introduced
            .entry(epoch)
            .or_default()
            .extend_from_slice(nodes);
        true
    }
}

impl BorshSerialize for Registry {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.introduced, writer)
    }
}

impl BorshDeserialize for Registry {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let buckets = read_bounded_len(
            reader,
            MAX_OBSERVED_NODES,
            "registry bucket count exceeds capacity",
        )?;

        let mut introduced = BTreeMap::new();
        let mut previous: Option<L1Epoch> = None;
        let mut total = 0_usize;
        for _ in 0..buckets {
            let epoch = L1Epoch::deserialize_reader(reader)?;
            if previous.is_some_and(|last| epoch <= last) {
                return Err(invalid_data("registry epochs must strictly ascend"));
            }
            previous = Some(epoch);

            let remaining = MAX_OBSERVED_NODES.saturating_sub(total);
            let len = read_bounded_len(reader, remaining, "registry exceeds capacity")?;
            if len == 0 {
                return Err(invalid_data("registry bucket is empty"));
            }
            total = total.saturating_add(len);

            let mut nodes = Vec::with_capacity(len);
            for _ in 0..len {
                nodes.push(NodeId::deserialize_reader(reader)?);
            }
            introduced.insert(epoch, nodes);
        }
        Ok(Self { introduced })
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize)]
pub struct StoredState {
    pub version: u16,
    pub state: State,
}

impl StoredState {
    #[must_use]
    pub const fn new(state: State) -> Self {
        Self {
            version: STATE_VERSION,
            state,
        }
    }

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

impl BorshDeserialize for StoredState {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let version = u16::deserialize_reader(reader)?;
        if version != STATE_VERSION {
            return Err(invalid_data("unknown referral state version"));
        }
        Ok(Self {
            version,
            state: State::deserialize_reader(reader)?,
        })
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
pub struct FirstUse {
    pub node: NodeId,
    pub referrer: Option<NodeId>,
    pub node_signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    AddEpochData {
        epoch: L1Epoch,
        new_node_ids: NodeBatch,
    },
    Grant {
        node: NodeId,
        amount: u128,
    },
    Collect {
        participant: ParticipantDescriptor,
        first_use: Option<FirstUse>,
    },
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

