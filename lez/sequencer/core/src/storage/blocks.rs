//! The blocks the sequencer core keeps in the store, and the indexes over them.

use std::collections::{BTreeSet, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use chain_state::{ChainState, Tip};
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta},
    transaction::{LeeTransaction, TxEvents},
};
use lee::AccountId;
use lee_core::BlockId;
use sequencer_storage_actor::{
    ColumnFamily, Storable,
    encoding::{BigEndian, BorshArc},
    full_type_name,
    protocol::{Delete, Store, WriteBatch},
};

use super::{ChannelViewRecord, FinalSnapshotRecord, HeadStateRecord};

/// A stored block.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct BlockRecord {
    pub block: Block,
}

impl Storable for BlockRecord {
    type Key = BigEndian<BlockId>;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Appended;
    const TYPE_NAME: &'static str = full_type_name!(BlockRecord);
}

/// The id of the stored block with a given hash.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct BlockIdByHashRecord {
    pub block_id: BlockId,
}

impl Storable for BlockIdByHashRecord {
    type Key = HashType;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Index;
    const TYPE_NAME: &'static str = full_type_name!(BlockIdByHashRecord);
}

/// The id of the stored block holding a transaction with a given hash.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct BlockIdByTransactionRecord {
    pub block_id: BlockId,
}

impl Storable for BlockIdByTransactionRecord {
    type Key = HashType;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Index;
    const TYPE_NAME: &'static str = full_type_name!(BlockIdByTransactionRecord);
}

/// A stored block holding a transaction that affects a public account.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct AccountBlockRecord {
    pub account_id: AccountId,
    pub block_id: BlockId,
}

impl Storable for AccountBlockRecord {
    type Key = AccountBlockKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Index;
    const TYPE_NAME: &'static str = full_type_name!(AccountBlockRecord);
}

/// Key of an [`AccountBlockRecord`]: the account, then the block id, so the blocks of one account
/// are kept together, lowest id first.
#[derive(Clone)]
pub struct AccountBlockKey {
    bytes: [u8; 32 + 8],
}

impl AccountBlockKey {
    #[must_use]
    pub fn new(account_id: AccountId, block_id: BlockId) -> Self {
        let mut bytes = [0; 32 + 8];
        bytes[..32].copy_from_slice(account_id.as_ref());
        bytes[32..].copy_from_slice(BigEndian::new(&block_id).as_ref());
        Self { bytes }
    }
}

impl AsRef<[u8]> for AccountBlockKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for AccountBlockKey {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: bytes.try_into()?,
        })
    }
}

/// The events of the transactions of a stored block.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct BlockEventsRecord {
    pub events: Vec<TxEvents>,
}

impl Storable for BlockEventsRecord {
    type Key = BigEndian<BlockId>;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LargeAppended;
    const TYPE_NAME: &'static str = full_type_name!(BlockEventsRecord);
}

/// The chain the store holds, taken before an update so [`chain_writes`] can tell what the update
/// changes.
pub struct StoredChain {
    /// The stored blocks above the final tier, lowest first.
    head_blocks: Vec<Block>,
    final_tip: Option<Tip>,
}

impl StoredChain {
    /// The chain `chain` holds, when the store holds the same.
    #[must_use]
    pub fn of(chain: &ChainState) -> Self {
        Self::new(chain.head_blocks().cloned().collect(), chain.final_tip())
    }

    /// The chain of `head_blocks`, lowest first, over the final tier at `final_tip`.
    #[must_use]
    pub const fn new(head_blocks: Vec<Block>, final_tip: Option<Tip>) -> Self {
        Self {
            head_blocks,
            final_tip,
        }
    }

    fn head_tip(&self) -> Option<Tip> {
        self.head_blocks
            .last()
            .map(Tip::from)
            .or_else(|| self.final_tip.clone())
    }
}

/// Writes moving the store from `before` to `chain`.
///
/// Head blocks that left the chain are deleted with their index entries, new head blocks are
/// stored as pending and `finalized` as finalized. `finalized` are the blocks the update
/// finalized, or found finalized again. `events` are the events of the blocks the update applied.
///
/// The head state is written only when the chain moved or the final tier advanced, as it is large.
#[must_use]
pub fn chain_writes(
    before: &StoredChain,
    chain: &ChainState,
    finalized: &[Block],
    events: Vec<(BlockId, Vec<TxEvents>)>,
) -> WriteBatch {
    let mut writes = WriteBatch::new();

    let kept: HashSet<HashType> = chain
        .head_blocks()
        .chain(finalized)
        .map(|block| block.header.hash)
        .collect();
    let removed: Vec<&Block> = before
        .head_blocks
        .iter()
        .filter(|block| !kept.contains(&block.header.hash))
        .collect();
    for block in &removed {
        delete_block(&mut writes, block);
    }

    let held: HashSet<HashType> = before
        .head_blocks
        .iter()
        .map(|block| block.header.hash)
        .collect();
    let added: Vec<&Block> = chain
        .head_blocks()
        .filter(|block| !held.contains(&block.header.hash))
        .collect();
    for block in &added {
        store_block(&mut writes, (*block).clone());
    }
    for block in finalized {
        let mut block = block.clone();
        block.bedrock_status = BedrockStatus::Finalized;
        store_block(&mut writes, block);
    }

    for (block_id, block_events) in events {
        writes.store(Store::new(
            BigEndian::new(&block_id),
            BlockEventsRecord {
                events: block_events,
            },
        ));
    }

    let final_tip = chain.final_tip();
    let final_advanced = final_tip != before.final_tip;
    let chain_moved =
        chain.head_tip() != before.head_tip() || !removed.is_empty() || !added.is_empty();
    if chain_moved || final_advanced {
        store_head_state(&mut writes, chain);
    }
    if final_advanced && let Some(tip) = final_tip {
        writes.store(Store::from_value(FinalSnapshotRecord {
            state: BorshArc(chain.share_final_state()),
            meta: BlockMeta::from(&tip),
        }));
    }
    store_view(&mut writes, chain);

    writes
}

/// Deletes `blocks` with their index entries and events.
#[must_use]
pub fn block_deletes(blocks: &[Block]) -> WriteBatch {
    let mut writes = WriteBatch::new();
    for block in blocks {
        delete_block(&mut writes, block);
    }
    writes
}

/// Writes the head state and the view of `chain`.
#[must_use]
pub fn head_writes(chain: &ChainState) -> WriteBatch {
    let mut writes = WriteBatch::new();
    store_head_state(&mut writes, chain);
    store_view(&mut writes, chain);
    writes
}

fn store_head_state(writes: &mut WriteBatch, chain: &ChainState) {
    writes.store(Store::from_value(HeadStateRecord {
        state: BorshArc(chain.share_head_state()),
    }));
}

fn store_view(writes: &mut WriteBatch, chain: &ChainState) {
    writes.store(Store::from_value(ChannelViewRecord {
        bytes: chain.encode_view(),
    }));
}

/// Stores `block` with its index entries.
fn store_block(writes: &mut WriteBatch, block: Block) {
    let block_id = block.header.block_id;
    writes.store(Store::new(
        block.header.hash,
        BlockIdByHashRecord { block_id },
    ));
    for transaction in &block.body.transactions {
        writes.store(Store::new(
            transaction.hash(),
            BlockIdByTransactionRecord { block_id },
        ));
    }
    for account_id in affected_accounts(&block) {
        writes.store(Store::new(
            AccountBlockKey::new(account_id, block_id),
            AccountBlockRecord {
                account_id,
                block_id,
            },
        ));
    }
    writes.store(Store::new(BigEndian::new(&block_id), BlockRecord { block }));
}

/// Deletes `block` with its index entries and events.
fn delete_block(writes: &mut WriteBatch, block: &Block) {
    let block_id = block.header.block_id;
    writes.delete(&Delete::<BlockIdByHashRecord>::new(block.header.hash));
    for transaction in &block.body.transactions {
        writes.delete(&Delete::<BlockIdByTransactionRecord>::new(
            transaction.hash(),
        ));
    }
    for account_id in affected_accounts(block) {
        writes.delete(&Delete::<AccountBlockRecord>::new(AccountBlockKey::new(
            account_id, block_id,
        )));
    }
    writes.delete(&Delete::<BlockEventsRecord>::new(BigEndian::new(&block_id)));
    writes.delete(&Delete::<BlockRecord>::new(BigEndian::new(&block_id)));
}

/// The public accounts the transactions of `block` affect, each once.
fn affected_accounts(block: &Block) -> BTreeSet<AccountId> {
    block
        .body
        .transactions
        .iter()
        .flat_map(LeeTransaction::affected_public_account_ids)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chain_state::{ChainState, ChannelEntry};
    use common::{
        HashType,
        block::{BedrockStatus, Block, HashableBlockData},
        test_utils::{producer_account_for_testing, producer_seed},
        transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
    };
    use lee_core::BlockId;
    use sequencer_bedrock_actor::{mock::mock_msg_of, protocol::MsgId};
    use sequencer_storage_actor::{
        encoding::{BigEndian, SingletonKey},
        mock::StoredValues,
    };

    use super::{
        AccountBlockKey, AccountBlockRecord, BlockIdByHashRecord, BlockIdByTransactionRecord,
        BlockRecord, StoredChain, chain_writes,
    };
    use crate::storage::{FinalSnapshotRecord, HeadStateRecord};

    /// A valid empty block: only the fee and clock transactions.
    fn block_at(id: BlockId, prev: HashType, timestamp: u64) -> Block {
        HashableBlockData {
            receipts: Vec::new(),
            block_id: id,
            prev_block_hash: prev,
            timestamp,
            transactions: vec![
                LeeTransaction::Public(fee_invocation(
                    fee_core::BlockFeeSummary::default(),
                    0,
                    FeePayee::Present(producer_account_for_testing()),
                )),
                LeeTransaction::Public(clock_invocation(id, timestamp)),
            ],
        }
        .into_pending_block()
    }

    /// `count` blocks from genesis on, each chained on the one before, made at `timestamp`.
    fn chain_of(count: u64, timestamp: u64) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        for id in 1..=count {
            let prev = blocks
                .last()
                .map_or(HashType([0; 32]), |block| block.header.hash);
            blocks.push(block_at(id, prev, timestamp));
        }
        blocks
    }

    fn empty_chain() -> ChainState {
        ChainState::new(
            testnet_initial_state::initial_state().with_public_accounts([producer_seed()]),
        )
    }

    /// View entries carrying `blocks`, each chained on the one before.
    fn entries(blocks: &[Block]) -> Vec<ChannelEntry> {
        let mut parent = MsgId::root();
        blocks
            .iter()
            .map(|block| {
                let entry = ChannelEntry {
                    msg: mock_msg_of(block),
                    parent,
                    block: Some(block.clone()),
                    finally_absent_keys: BTreeSet::new(),
                    final_slot: None,
                };
                parent = entry.msg;
                entry
            })
            .collect()
    }

    /// Moves `chain` to hold `blocks` in its head, storing what that changes in `values`.
    fn hold(values: &StoredValues, chain: &mut ChainState, blocks: &[Block]) {
        let stored = StoredChain::of(chain);
        chain.apply_conflict(entries(blocks));
        write(values, &stored, chain, &[]);
    }

    fn write(values: &StoredValues, stored: &StoredChain, chain: &ChainState, finalized: &[Block]) {
        values
            .write(chain_writes(stored, chain, finalized, Vec::new()))
            .expect("Failed to write the chain");
    }

    fn stored_block(values: &StoredValues, block_id: BlockId) -> Option<Block> {
        values
            .get::<BlockRecord>(&BigEndian::new(&block_id))
            .expect("Failed to read the block")
            .map(|record| record.block)
    }

    fn block_id_by_hash(values: &StoredValues, hash: HashType) -> Option<BlockId> {
        values
            .get::<BlockIdByHashRecord>(&hash)
            .expect("Failed to read the hash index")
            .map(|record| record.block_id)
    }

    fn block_id_by_transaction(values: &StoredValues, hash: HashType) -> Option<BlockId> {
        values
            .get::<BlockIdByTransactionRecord>(&hash)
            .expect("Failed to read the transaction index")
            .map(|record| record.block_id)
    }

    fn holds_account_block(values: &StoredValues, block_id: BlockId) -> bool {
        values
            .get::<AccountBlockRecord>(&AccountBlockKey::new(
                producer_account_for_testing(),
                block_id,
            ))
            .expect("Failed to read the account index")
            .is_some()
    }

    fn clock_hash(block: &Block) -> HashType {
        block
            .body
            .transactions
            .last()
            .expect("A block ends with its clock transaction")
            .hash()
    }

    #[test]
    fn new_head_blocks_are_stored_pending_with_their_indexes() {
        let values = StoredValues::default();
        let mut chain = empty_chain();
        let blocks = chain_of(2, 0);

        hold(&values, &mut chain, &blocks);

        for block in &blocks {
            let block_id = block.header.block_id;
            let stored = stored_block(&values, block_id).expect("The block is stored");
            assert_eq!(stored.header.hash, block.header.hash);
            assert!(matches!(stored.bedrock_status, BedrockStatus::Pending));
            assert_eq!(block_id_by_hash(&values, block.header.hash), Some(block_id));
            assert_eq!(
                block_id_by_transaction(&values, clock_hash(block)),
                Some(block_id)
            );
            assert!(holds_account_block(&values, block_id));
        }
        assert!(
            values
                .get::<HeadStateRecord>(&SingletonKey)
                .expect("Failed to read the head state")
                .is_some()
        );
        assert!(
            values
                .get::<FinalSnapshotRecord>(&SingletonKey)
                .expect("Failed to read the final snapshot")
                .is_none(),
            "Nothing finalized yet"
        );
    }

    /// A block that left the head takes its index entries with it, so no lookup finds it again.
    #[test]
    fn a_replaced_head_block_leaves_no_index_entries() {
        let values = StoredValues::default();
        let mut chain = empty_chain();
        let blocks = chain_of(2, 0);
        hold(&values, &mut chain, &blocks);

        let competitor = block_at(2, blocks[0].header.hash, 7);
        hold(
            &values,
            &mut chain,
            &[blocks[0].clone(), competitor.clone()],
        );

        let stored = stored_block(&values, 2).expect("Block 2 is stored");
        assert_eq!(stored.header.hash, competitor.header.hash);
        assert_eq!(block_id_by_hash(&values, blocks[1].header.hash), None);
        assert_eq!(
            block_id_by_transaction(&values, clock_hash(&blocks[1])),
            None
        );
        assert_eq!(
            block_id_by_transaction(&values, clock_hash(&competitor)),
            Some(2)
        );
        assert!(holds_account_block(&values, 2));
    }

    #[test]
    fn a_shorter_head_drops_the_blocks_above_its_tip() {
        let values = StoredValues::default();
        let mut chain = empty_chain();
        let blocks = chain_of(3, 0);
        hold(&values, &mut chain, &blocks);

        hold(&values, &mut chain, &blocks[..1]);

        assert!(stored_block(&values, 1).is_some());
        for block in &blocks[1..] {
            let block_id = block.header.block_id;
            assert!(stored_block(&values, block_id).is_none());
            assert_eq!(block_id_by_hash(&values, block.header.hash), None);
            assert!(!holds_account_block(&values, block_id));
        }
    }

    #[test]
    fn finalized_blocks_are_stored_finalized_with_the_final_snapshot() {
        let values = StoredValues::default();
        let mut chain = empty_chain();
        let blocks = chain_of(2, 0);
        hold(&values, &mut chain, &blocks);

        let stored = StoredChain::of(&chain);
        let genesis = &entries(&blocks)[0];
        chain.apply_finalized(
            genesis.msg,
            genesis.parent,
            genesis.block.as_ref(),
            &BTreeSet::new(),
        );
        let newly_final = chain.take_newly_final();
        write(&values, &stored, &chain, &newly_final);

        assert!(matches!(
            stored_block(&values, 1)
                .expect("Genesis is stored")
                .bedrock_status,
            BedrockStatus::Finalized
        ));
        assert!(matches!(
            stored_block(&values, 2)
                .expect("Block 2 is stored")
                .bedrock_status,
            BedrockStatus::Pending
        ));
        let (_, meta) = values
            .get::<FinalSnapshotRecord>(&SingletonKey)
            .expect("Failed to read the final snapshot")
            .expect("The final snapshot is stored")
            .into_parts();
        assert_eq!(meta.id, 1);
        assert_eq!(meta.hash, blocks[0].header.hash);
    }

    /// The head state is large, so an update that moves no chain does not rewrite it.
    #[test]
    fn an_update_that_moves_nothing_does_not_write_the_head_state() {
        let values = StoredValues::default();
        let mut chain = empty_chain();
        hold(&values, &mut chain, &chain_of(1, 0));
        values.delete::<HeadStateRecord>(&SingletonKey);

        write(&values, &StoredChain::of(&chain), &chain, &[]);

        assert!(
            values
                .get::<HeadStateRecord>(&SingletonKey)
                .expect("Failed to read the head state")
                .is_none()
        );
    }
}
