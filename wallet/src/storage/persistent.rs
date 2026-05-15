use std::collections::BTreeMap;

use key_protocol::key_management::{
    group_key_holder::GroupKeyHolder,
    key_tree::{
        chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
    },
};
use serde::{Deserialize, Serialize};
use testnet_initial_state::{PrivateAccountPrivateInitialData, PublicAccountPrivateInitialData};

use crate::{
    account::{AccountIdWithPrivacy, Label},
    storage::key_chain::SharedAccountEntry,
};

#[derive(Serialize, Deserialize)]
pub struct PersistentStorage {
    pub key_chain: KeyChainPersistentData,
    pub last_synced_block: u64,
    #[serde(default)]
    pub labels: BTreeMap<Label, AccountIdWithPrivacy>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyChainPersistentData {
    pub accounts: Vec<PersistentAccountData>,
    #[serde(default)]
    pub sealing_secret_key: Option<nssa_core::encryption::Scalar>,
    #[serde(default)]
    pub group_key_holders: BTreeMap<Label, GroupKeyHolder>,
    #[serde(default)]
    pub shared_private_accounts: BTreeMap<nssa::AccountId, SharedAccountEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistentAccountData {
    Public(PersistentAccountDataPublic),
    Private(Box<PersistentAccountDataPrivate>),
    ImportedPublic(PublicAccountPrivateInitialData),
    ImportedPrivate(Box<PrivateAccountPrivateInitialData>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPublic {
    pub account_id: nssa::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPrivate {
    pub account_id: nssa::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPrivatePersistent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildKeysPrivatePersistent {
    pub value: (
        key_protocol::key_management::KeyChain,
        Vec<(nssa_core::PrivateAccountKind, nssa::Account)>,
    ),
    pub ccc: [u8; 32],
    pub cci: Option<u32>,
}

impl From<ChildKeysPrivate> for ChildKeysPrivatePersistent {
    fn from(value: ChildKeysPrivate) -> Self {
        let ChildKeysPrivate { value, ccc, cci } = value;

        Self {
            value: (value.0, Vec::from_iter(value.1)),
            ccc,
            cci,
        }
    }
}

impl From<ChildKeysPrivatePersistent> for ChildKeysPrivate {
    fn from(value: ChildKeysPrivatePersistent) -> Self {
        let ChildKeysPrivatePersistent { value, ccc, cci } = value;

        Self {
            value: (value.0, BTreeMap::from_iter(value.1)),
            ccc,
            cci,
        }
    }
}
