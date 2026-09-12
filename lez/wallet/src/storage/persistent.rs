use std::collections::BTreeMap;

use key_protocol::key_management::{
    KeyChain,
    group_key_holder::GroupKeyHolder,
    key_tree::{
        chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
    },
    secret_holders::ViewingSecretKey,
};
use lee_core::{Identifier, PrivateAccountKind};
use serde::{Deserialize, Serialize};
use testnet_initial_state::PublicAccountPrivateInitialData;

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
    pub sealing_secret_key: Option<ViewingSecretKey>,
    #[serde(default)]
    pub group_key_holders: BTreeMap<Label, GroupKeyHolder>,
    #[serde(default)]
    pub shared_private_accounts: BTreeMap<lee::AccountId, SharedAccountEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistentAccountData {
    Public(PersistentAccountDataPublic),
    Private(Box<PersistentAccountDataPrivate>),
    ImportedPublic(PublicAccountPrivateInitialData),
    ImportedPrivate(Box<PersistentImportedPrivateAccount>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentImportedPrivateAccount {
    pub account: lee_core::account::Account,
    pub key_chain: KeyChain,
    pub chain_index: Option<ChainIndex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<PrivateAccountKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Identifier>,
}

impl PersistentImportedPrivateAccount {
    pub fn resolve_kind(&self) -> anyhow::Result<PrivateAccountKind> {
        match (&self.kind, self.identifier) {
            (Some(kind), None) => Ok(kind.clone()),
            (Some(kind), Some(identifier)) if kind.identifier() == identifier => Ok(kind.clone()),
            (Some(_), Some(_)) => Err(anyhow::anyhow!(
                "Imported private account has contradictory kind and identifier"
            )),
            (None, Some(identifier)) => Ok(PrivateAccountKind::Regular(identifier)),
            (None, None) => Err(anyhow::anyhow!(
                "Imported private account has no kind or identifier"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPublic {
    pub account_id: lee::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPrivate {
    pub account_id: lee::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPrivatePersistent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildKeysPrivatePersistent {
    pub value: (
        key_protocol::key_management::KeyChain,
        Vec<(lee_core::PrivateAccountKind, lee::Account)>,
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
