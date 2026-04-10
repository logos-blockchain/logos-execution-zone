use std::collections::BTreeMap;

use key_protocol::key_management::key_tree::{
    chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
};
use serde::{Deserialize, Serialize};
use testnet_initial_state::{PrivateAccountPrivateInitialData, PublicAccountPrivateInitialData};

use crate::account::{AccountIdWithPrivacy, Label};

#[derive(Serialize, Deserialize)]
pub struct PersistentStorage {
    pub accounts: Vec<PersistentAccountData>,
    pub last_synced_block: u64,
    #[serde(default)]
    pub labels: BTreeMap<Label, AccountIdWithPrivacy>,
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
    pub data: ChildKeysPrivate,
}
