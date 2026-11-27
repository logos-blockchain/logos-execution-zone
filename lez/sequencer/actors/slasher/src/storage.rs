//! What the slasher keeps in the store.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use sequencer_stake_core::SequencerKey;
use sequencer_storage_actor::{
    ColumnFamily, Storable, Stores, encoding::SingletonKey, full_type_name,
};
use trait_set::trait_set;

use crate::protocol::Offence;

trait_set! {
    /// A storage actor keeping everything the slasher stores.
    pub trait SlasherStorage = Stores<SlashRecord>;
}

/// Peers' signatures, by offence and then by signer.
pub type Approvals = BTreeMap<Offence, BTreeMap<SequencerKey, [u8; 64]>>;

/// Offences this node found and peers' approvals of them.
///
/// Tagged so a later build can migrate instead of failing to decode.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum SlashRecord {
    V2 {
        found: BTreeSet<Offence>,
        approvals: Approvals,
    },
}

impl Storable for SlashRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(SlashRecord);
}
