//! What the Bedrock actor keeps in the store.

use std::io;

use borsh::{BorshDeserialize, BorshSerialize};
use sequencer_storage_actor::{
    ColumnFamily, Storable, Stores, encoding::SingletonKey, full_type_name,
};
use trait_set::trait_set;

use crate::{
    actor::finality::ConfigIndex,
    protocol::{DeserializeOp as _, SequencerCheckpoint, SerializeOp as _},
};

trait_set! {
    /// A storage actor keeping everything the Bedrock actor stores.
    pub trait BedrockStorage = Stores<ZoneCheckpoint> + Stores<FinalConfigs>;
}

/// The zone-sdk checkpoint following resumes from.
pub struct ZoneCheckpoint(pub SequencerCheckpoint);

impl Storable for ZoneCheckpoint {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(ZoneCheckpoint);
}

/// Kept as zone-sdk encodes it, behind a length prefix.
impl BorshSerialize for ZoneCheckpoint {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let bytes = self.0.to_bytes().map_err(io::Error::other)?;
        <[u8] as BorshSerialize>::serialize(&bytes, writer)
    }
}

impl BorshDeserialize for ZoneCheckpoint {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        SequencerCheckpoint::from_bytes(&bytes)
            .map(Self)
            .map_err(io::Error::other)
    }
}

/// The channel's final configs.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct FinalConfigs(pub(crate) ConfigIndex);

impl Storable for FinalConfigs {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(FinalConfigs);
}
