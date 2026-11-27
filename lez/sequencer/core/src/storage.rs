//! What the sequencer core keeps in the store.

use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use common::{HashType, block::BlockMeta};
use kameo::message::Message;
use lee::V03State;
use lee_core::BlockId;
use sequencer_storage_actor::{
    ColumnFamily, Result, Storable, Stores,
    encoding::{BorshArc, SingletonKey},
    full_type_name,
    protocol::{Store, WriteBatch},
};
use trait_set::trait_set;

use self::{
    blocks::{
        AccountBlockRecord, BlockDeletes, BlockEventsRecord, BlockIdByHashRecord,
        BlockIdByTransactionRecord, BlockRecord, ChainWrites, HeadWrites,
    },
    bridge::{DepositWrites, PendingDepositEventRecord, PendingWithdrawalRecord, WithdrawalWrites},
};

pub mod blocks;
pub mod bridge;

trait_set! {
    /// A storage actor keeping everything the sequencer core stores.
    pub trait CoreStorage = Stores<SystemApprovalsRecord>
        + Stores<ZoneAnchorRecord>
        + Stores<ChannelViewRecord>
        + Stores<BlockRecord>
        + Stores<BlockIdByHashRecord>
        + Stores<BlockIdByTransactionRecord>
        + Stores<AccountBlockRecord>
        + Stores<BlockEventsRecord>
        + Stores<HeadStateRecord>
        + Stores<FinalSnapshotRecord>
        + Stores<PendingDepositEventRecord>
        + Stores<PendingWithdrawalRecord>
        + Message<WriteBatch<ChainWrites>, Reply = Result<()>>
        + Message<WriteBatch<FollowWrites>, Reply = Result<()>>
        + Message<WriteBatch<PublishWrites>, Reply = Result<()>>
        + Message<WriteBatch<ReplayWrites>, Reply = Result<()>>
        + Message<WriteBatch<BlockDeletes>, Reply = Result<()>>
        + Message<WriteBatch<HeadWrites>, Reply = Result<()>>;
}

/// Writes of a channel update the sequencer follows.
pub type FollowWrites = (ChainWrites, DepositWrites, WithdrawalWrites);

/// Writes of a block the sequencer publishes.
pub type PublishWrites = (ChainWrites, WithdrawalWrites);

/// Writes of finalized channel entries replayed while bootstrapping.
pub type ReplayWrites = (
    ChainWrites,
    Option<Store<ZoneAnchorRecord>>,
    DepositWrites,
    WithdrawalWrites,
);

/// The state after the last stored block.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct HeadStateRecord {
    pub state: BorshArc<V03State>,
}

impl Storable for HeadStateRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LargeRewritten;
    const TYPE_NAME: &'static str = full_type_name!(HeadStateRecord);
}

impl HeadStateRecord {
    #[must_use]
    pub fn into_state(self) -> V03State {
        Arc::unwrap_or_clone(self.state.0)
    }
}

/// State and meta of the last L1-finalized block.
///
/// One record rather than two, so the pair can never disagree about which block
/// the state belongs to.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct FinalSnapshotRecord {
    pub state: BorshArc<V03State>,
    pub meta: BlockMeta,
}

impl Storable for FinalSnapshotRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LargeRewritten;
    const TYPE_NAME: &'static str = full_type_name!(FinalSnapshotRecord);
}

impl FinalSnapshotRecord {
    #[must_use]
    pub fn into_parts(self) -> (V03State, BlockMeta) {
        (Arc::unwrap_or_clone(self.state.0), self.meta)
    }
}

/// The last channel block read back and verified from Bedrock: the anchor for
/// the startup consistency check and the resume point for reconstruction.
///
/// `slot` is the raw L1 inscription slot; the caller converts to and from the
/// zone-sdk `Slot`, which does not derive borsh and so cannot be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchorRecord {
    pub slot: u64,
    pub block_id: BlockId,
    pub hash: HashType,
}

impl Storable for ZoneAnchorRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(ZoneAnchorRecord);
}

/// The unfinalized channel view the head is folded from, as
/// [`ChainState`](chain_state::ChainState) encodes it.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ChannelViewRecord {
    pub bytes: Vec<u8>,
}

impl Storable for ChannelViewRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(ChannelViewRecord);
}

/// The pending `system_upgrader` approvals, as
/// [`SystemApprovals`](crate::system_approvals::SystemApprovals) encodes them.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SystemApprovalsRecord {
    pub bytes: Vec<u8>,
}

impl Storable for SystemApprovalsRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(SystemApprovalsRecord);
}
