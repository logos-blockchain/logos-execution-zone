//! Two-tier chain state: a `final` tier of settled blocks, and a `head` the
//! sequencer builds on, derived by folding `final` over the channel's message
//! lineage above it.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use borsh::{BorshDeserialize, BorshSerialize};
use common::{
    HashType,
    block::{Block, DigestedBlock},
    transaction::TxEvents,
};
use lee::{V03State, privacy_preserving_transaction::circuit::ProofDigest};
use log::warn;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::{
    BlockIngestError, ProofStore,
    apply::{Tip, apply_block, validate_link},
    stake_config,
};

/// Attempts at a block whose failure may be transient before it counts as invalid.
const APPLY_ATTEMPTS: usize = 3;

/// One inscription on the channel's message lineage.
#[derive(Clone, Debug)]
pub struct ChannelEntry {
    pub msg: MsgId,
    pub parent: MsgId,
    /// The bytes of the key that signed the inscription; `None` for a config entry.
    pub signer: Option<[u8; 32]>,
    /// The L1 slot the inscription finalized in; `None` until it is final.
    pub slot: Option<Slot>,
    /// `None` for an entry that carries no block: an empty or undecodable payload.
    pub block: Option<DigestedBlock>,
}

/// What recording one of our own publishes did.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishRecord {
    /// The entry is in the view and its block entered the head.
    Extended,
    /// The entry is in the view but the head did not gain its block.
    Skipped,
    /// The view already holds the entry.
    AlreadyInView,
    /// The view moved past the entry's parent since the block was built.
    Stale,
}

/// What a fold of finalized entries decided.
pub struct FoldOutcome {
    /// One verdict per finalized entry decided: misplaced, late, ignored and
    /// cut entries as soon as their fold is decided, settled ones as the final
    /// tier reaches them.
    pub judged: Vec<Judged>,
    /// Every block the final tier applied, ancestors a finalized entry pulled in included.
    pub settled: Vec<SettledBlock>,
    /// The signer of every final skip judged, once per skip.
    pub skipped: Vec<[u8; 32]>,
}

/// What became of one finalized entry carrying a block.
#[derive(Debug)]
pub struct Judged {
    pub msg: MsgId,
    pub signer: Option<[u8; 32]>,
    pub block: DigestedBlock,
    pub verdict: Verdict,
}

#[derive(Clone, Debug)]
pub enum Verdict {
    /// The block joined the final tier.
    Settled,
    /// A re-delivery of the final tip.
    AlreadySettled(Block),
    /// The block is not on the branch; `next` says it is an offence.
    Dropped { error: BlockIngestError, next: bool },
    /// Cut by a valid skip, or dropped with a dead ancestor.
    Cut,
    /// A skip that came after its window.
    LateSkip,
    /// A block whose parent is not known.
    Ignored,
}

/// A block the final tier settled, with the state after it and its events.
pub struct SettledBlock {
    msg: MsgId,
    slot: Option<Slot>,
    block: Block,
    state: V03State,
    events: Vec<TxEvents>,
}

impl SettledBlock {
    /// A settlement built outside the fold, for other crates' tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn new(
        msg: MsgId,
        slot: Option<Slot>,
        block: Block,
        state: V03State,
        events: Vec<TxEvents>,
    ) -> Self {
        Self {
            msg,
            slot,
            block,
            state,
            events,
        }
    }

    #[must_use]
    pub const fn msg(&self) -> MsgId {
        self.msg
    }

    #[must_use]
    pub const fn slot(&self) -> Option<Slot> {
        self.slot
    }

    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    #[must_use]
    pub const fn state(&self) -> &V03State {
        &self.state
    }

    #[must_use]
    pub const fn events(&self) -> &[TxEvents] {
        self.events.as_slice()
    }

    /// The block and its events, for a consumer that keeps them.
    #[must_use]
    pub fn into_block_and_events(self) -> (Block, Vec<TxEvents>) {
        (self.block, self.events)
    }
}

/// The first block on the head's branch past its tip, which the head has not executed.
#[derive(Debug)]
pub struct Blocker {
    /// The entry that placed it.
    pub msg: MsgId,
    pub signer: Option<[u8; 32]>,
    pub private: bool,
    /// The L1 slot its entry finalized in; `None` until it is final.
    pub slot: Option<Slot>,
    /// It failed to apply; otherwise its proofs are missing.
    pub dead: bool,
    /// It is still in the unconfirmed run.
    pub in_run: bool,
}

/// The persisted form of the view.
#[derive(BorshSerialize, BorshDeserialize)]
struct StoredView {
    final_msg: [u8; 32],
    lib_slot: u64,
    /// The final tier's unconfirmed run.
    run: Vec<BlockRecord>,
    finalized: Vec<StoredEntry>,
    entries: Vec<StoredEntry>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredEntry {
    msg: [u8; 32],
    parent: [u8; 32],
    signer: Option<[u8; 32]>,
    slot: Option<u64>,
    block: Option<StoredBlock>,
    judged: bool,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum StoredBlock {
    Full(Block),
    Digested(DigestedBlock),
}

/// The final tier (settled blocks) and the head, which is always `final_state`
/// folded over `view`.
///
/// `view` is the lineage above the final tier: the finalized entries up to
/// `final_msg`, then the unfinalized ones. The fold places each entry's block
/// by the skip rule, reading only the entries before it, their slots and the
/// validity of blocks, and the pin is the view's last entry.
///
/// Each entry keeps the head it folded to, so a view that changes past an
/// entry refolds from there rather than from `final_state`. The states share
/// structure, so keeping one per entry costs only what each block changed.
pub struct ChainState {
    final_state: V03State,
    final_tip: Option<Tip>,
    /// The newest finalized entry on the message lineage, block or not.
    final_msg: MsgId,
    lib_slot: Slot,
    /// What placement reads at the final tier.
    record: Record,

    /// The message lineage above the final tier, oldest first.
    view: Vec<ChannelEntry>,
    /// How many entries at the front of the view are finalized.
    finalized: usize,
    /// `folds[i]` is the head after folding `view[..=i]`.
    folds: Vec<Fold>,
    hydrated: Hydrated,
    /// The finalized entries whose verdicts have been returned.
    judged: HashSet<MsgId>,
}

/// The head after folding one view entry.
struct Fold {
    /// The state after the branch's last executed block.
    state: V03State,
    record: Record,
    /// The events of the entry's block, when the fold executed it.
    events: Option<Vec<TxEvents>>,
    /// The entry's own verdict, when folding it reached one.
    verdict: Option<Verdict>,
    /// The entries whose blocks left the branch here, with the failure of a dead one.
    left: Vec<(MsgId, Option<BlockIngestError>)>,
    /// Held behind a pending block of its signer: neither placed nor judged.
    held: bool,
    /// Its block was placed as a skip.
    skipped: bool,
}

/// What placement reads: the selected branch and the unconfirmed run.
#[derive(Clone, Default)]
pub(crate) struct Record {
    /// The branch above the final tier, oldest first.
    pub(crate) branch: Vec<Placed>,
    /// A block leaves the run, unless it is the tip, once a finalized entry is past its window.
    pub(crate) run: Vec<BlockRecord>,
    /// The blocks of the entries held behind a pending block.
    held: Vec<HashType>,
}

impl Record {
    pub(crate) fn confirm(&mut self, signer: Option<[u8; 32]>) {
        if self.run.first().is_some_and(|run| run.signer != signer) {
            let run = std::mem::take(&mut self.run);
            for below in &mut self.branch {
                below.confirmed |= run
                    .iter()
                    .any(|confirmed| confirmed.hash == below.block.hash);
            }
        }
    }

    pub(crate) fn prune_run(
        &mut self,
        settled: Option<&Tip>,
        passed: impl Fn(Option<u64>) -> bool,
    ) {
        let tip = self
            .branch
            .last()
            .map(|placed| placed.block.hash)
            .or_else(|| settled.map(|tip| tip.hash));
        self.run
            .retain(|run| Some(run.hash) == tip || !passed(run.slot));
    }
}

/// A block on the branch.
#[derive(Clone)]
pub(crate) struct Placed {
    /// The entry that placed it.
    pub(crate) entry: MsgId,
    pub(crate) block: BlockRecord,
    pub(crate) status: Status,
    /// A block by another signer was placed above it.
    pub(crate) confirmed: bool,
}

impl Placed {
    pub(crate) const fn tip(&self) -> Tip {
        Tip {
            block_id: self.block.block_id,
            hash: self.block.hash,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Status {
    Executed,
    /// Failed to apply, so the blocks placed on it cannot execute.
    Dead(BlockIngestError),
    /// Behind a dead or pending block.
    Unexecutable,
    /// Its proofs are missing.
    Pending,
}

/// A block as placement reads it.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct BlockRecord {
    pub(crate) block_id: u64,
    pub(crate) hash: HashType,
    pub(crate) parent: HashType,
    /// The L1 slot of the entry that placed it, once final.
    pub(crate) slot: Option<u64>,
    pub(crate) private: bool,
    pub(crate) signer: Option<[u8; 32]>,
}

impl BlockRecord {
    pub(crate) fn new(entry: &ChannelEntry, block: &DigestedBlock) -> Self {
        let header = &block.header;
        Self {
            block_id: header.block_id,
            hash: header.hash,
            parent: header.prev_block_hash,
            slot: entry.slot.map(Slot::into_inner),
            private: block.body.proofs().next().is_some(),
            signer: entry.signer,
        }
    }
}

/// Where the rules of selection put a block.
pub(crate) enum Placement {
    /// On the tip.
    Extends,
    /// A valid skip, cutting the branch back to before this position.
    Skips(usize),
    /// A skip that came after its window.
    Late,
    /// Out of place on a known parent.
    Misplaced(BlockIngestError),
    /// On an unknown parent.
    Ignored,
}

struct Hydrated {
    blocks: HashMap<MsgId, Block>,
    proofs: ProofStore,
}

impl Hydrated {
    fn insert(&mut self, msg: MsgId, block: Block) {
        for proof in block.body.proofs() {
            self.proofs.pin(proof);
        }
        if let Some(replaced) = self.blocks.insert(msg, block) {
            Self::unpin(&self.proofs, &replaced);
        }
    }

    fn remove(&mut self, msg: &MsgId) {
        if let Some(block) = self.blocks.remove(msg) {
            Self::unpin(&self.proofs, &block);
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&MsgId) -> bool) {
        self.blocks
            .extract_if(|msg, _| !keep(msg))
            .for_each(|(_, block)| Self::unpin(&self.proofs, &block));
    }

    fn unpin(proofs: &ProofStore, block: &Block) {
        for proof in block.body.proofs() {
            proofs.unpin(&proof.digest());
        }
    }
}

impl std::ops::Deref for Hydrated {
    type Target = HashMap<MsgId, Block>;

    fn deref(&self) -> &Self::Target {
        &self.blocks
    }
}

impl Drop for Hydrated {
    fn drop(&mut self) {
        self.retain(|_| false);
    }
}

impl ChainState {
    /// Fresh state anchored at the genesis/initial state, no blocks applied.
    #[must_use]
    pub fn new(initial_state: V03State, proofs: ProofStore) -> Self {
        Self::from_final(initial_state, None, proofs)
    }

    /// State restored from a persisted final tier, with an empty view.
    #[must_use]
    pub fn from_final(final_state: V03State, final_tip: Option<Tip>, proofs: ProofStore) -> Self {
        Self {
            final_state,
            final_tip,
            final_msg: MsgId::root(),
            lib_slot: Slot::from(0),
            record: Record::default(),
            view: Vec::new(),
            finalized: 0,
            folds: Vec::new(),
            hydrated: Hydrated {
                blocks: HashMap::new(),
                proofs,
            },
            judged: HashSet::new(),
        }
    }

    /// State the sequencer builds its next block on.
    #[must_use]
    pub fn head_state(&self) -> &V03State {
        self.folds
            .last()
            .map_or(&self.final_state, |fold| &fold.state)
    }

    /// A shared handle on the head state, for callers that need to own it.
    #[must_use]
    pub fn share_head_state(&self) -> Arc<V03State> {
        Arc::new(self.head_state().clone())
    }

    /// The last fold's state, or the final state when the view is empty, for
    /// tests to mutate.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn head_state_mut(&mut self) -> &mut V03State {
        self.folds
            .last_mut()
            .map_or(&mut self.final_state, |fold| &mut fold.state)
    }

    #[must_use]
    pub const fn final_state(&self) -> &V03State {
        &self.final_state
    }

    /// A shared handle on the final state, for callers that need to own it.
    #[must_use]
    pub fn share_final_state(&self) -> Arc<V03State> {
        Arc::new(self.final_state.clone())
    }

    /// Parent the next produced block must chain on: the branch's last
    /// executed block.
    #[must_use]
    pub fn head_tip(&self) -> Option<Tip> {
        self.head_record()
            .branch
            .iter()
            .rev()
            .find(|placed| matches!(placed.status, Status::Executed))
            .map(Placed::tip)
            .or_else(|| self.final_tip.clone())
    }

    /// The blocks the head holds above the final tier.
    pub fn head_blocks(&self) -> impl Iterator<Item = &Block> {
        self.head_record()
            .branch
            .iter()
            .filter(|placed| matches!(placed.status, Status::Executed))
            .filter_map(|placed| self.hydrated.get(&placed.entry))
    }

    #[must_use]
    pub fn missing_proofs(&self) -> Vec<ProofDigest> {
        let pending = self.pending().and_then(|idx| self.view[idx].block.as_ref());
        let mut missing = Vec::new();
        for digest in pending.into_iter().flat_map(|block| block.body.proofs()) {
            if !self.hydrated.proofs.contains(digest) && !missing.contains(digest) {
                missing.push(*digest);
            }
        }
        missing
    }

    /// The first block on the head's branch past [`Self::head_tip`].
    #[must_use]
    pub fn blocker(&self) -> Option<Blocker> {
        let record = self.head_record();
        let past = record
            .branch
            .iter()
            .rposition(|placed| matches!(placed.status, Status::Executed))
            .map_or(0, |tip| tip.saturating_add(1));
        let placed = record.branch.get(past)?;
        Some(Blocker {
            msg: placed.entry,
            signer: placed.block.signer,
            private: placed.block.private,
            slot: placed.block.slot.map(Slot::from),
            dead: matches!(placed.status, Status::Dead(_)),
            in_run: record.run.iter().any(|run| run.hash == placed.block.hash),
        })
    }

    /// Whether the fold stopped short of the view, behind a pending block.
    #[must_use]
    pub const fn fold_stopped(&self) -> bool {
        self.folds.len() < self.view.len()
    }

    /// Parent the next inscription must chain on: the view's last entry.
    #[must_use]
    pub fn pin(&self) -> MsgId {
        self.view.last().map_or(self.final_msg, |entry| entry.msg)
    }

    #[must_use]
    pub const fn final_msg(&self) -> MsgId {
        self.final_msg
    }

    /// The first unfinalized view entry not chained on the one before it, or
    /// on `final_msg` for the first. Entries the tier already holds are skipped.
    #[must_use]
    pub fn check_for_gaps_in_lineage(&self) -> Option<&ChannelEntry> {
        let final_id = self.final_tip.as_ref().map(|tip| tip.block_id);
        let settled = |entry: &ChannelEntry| {
            entry
                .block
                .as_ref()
                .is_some_and(|block| final_id.is_some_and(|id| block.header.block_id <= id))
        };
        let unfinalized = &self.view[self.finalized..];
        let start = unfinalized
            .iter()
            .position(|entry| !settled(entry))
            .unwrap_or(unfinalized.len());
        // The first kept entry chains on the last skipped one, not on `final_msg`.
        let mut parent = start
            .checked_sub(1)
            .map_or(self.final_msg, |prev| unfinalized[prev].msg);
        unfinalized[start..].iter().find(|entry| {
            let gap = entry.parent != parent;
            parent = entry.msg;
            gap
        })
    }

    #[must_use]
    pub fn view(&self) -> &[ChannelEntry] {
        &self.view
    }

    #[must_use]
    pub fn final_tip(&self) -> Option<Tip> {
        self.final_tip.clone()
    }

    #[must_use]
    pub const fn proofs(&self) -> &ProofStore {
        &self.hydrated.proofs
    }

    /// The view, `final_msg` and what placement reads at the final tier, in
    /// their persisted form. An entry keeps its full block once hydrated, its
    /// digest form otherwise.
    #[must_use]
    pub fn encode_view(&self) -> Vec<u8> {
        let stored_entry = |entry: &ChannelEntry| StoredEntry {
            msg: entry.msg.into(),
            parent: entry.parent.into(),
            signer: entry.signer,
            slot: entry.slot.map(Slot::into_inner),
            block: entry.block.as_ref().map(|digested| {
                self.hydrated.get(&entry.msg).map_or_else(
                    || StoredBlock::Digested(digested.clone()),
                    |block| StoredBlock::Full(block.clone()),
                )
            }),
            judged: self.judged.contains(&entry.msg),
        };
        let (finalized, unfinalized) = self.view.split_at(self.finalized);
        let stored = StoredView {
            final_msg: self.final_msg.into(),
            lib_slot: self.lib_slot.into_inner(),
            run: self.record.run.clone(),
            finalized: finalized.iter().map(stored_entry).collect(),
            entries: unfinalized.iter().map(stored_entry).collect(),
        };
        borsh::to_vec(&stored).expect("view serializes")
    }

    /// Installs a persisted view on the restored final tier and folds it.
    pub fn restore_view(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let stored = StoredView::try_from_slice(bytes)?;
        self.final_msg = MsgId::from(stored.final_msg);
        self.lib_slot = Slot::from(stored.lib_slot);
        self.record = Record {
            run: stored.run,
            ..Record::default()
        };
        self.finalized = stored.finalized.len();
        self.view = stored
            .finalized
            .into_iter()
            .chain(stored.entries)
            .map(|entry| {
                let msg = MsgId::from(entry.msg);
                if entry.judged {
                    self.judged.insert(msg);
                }
                let block = entry.block.map(|stored_block| match stored_block {
                    StoredBlock::Full(block) => {
                        let digested = block.digested();
                        self.hydrated.insert(msg, block);
                        digested
                    }
                    StoredBlock::Digested(block) => block,
                });
                ChannelEntry {
                    msg,
                    parent: MsgId::from(entry.parent),
                    signer: entry.signer,
                    slot: entry.slot.map(Slot::from),
                    block,
                }
            })
            .collect();
        self.fold_from(0);
        Ok(())
    }

    /// Refolds from the first pending block once its proofs are all present;
    /// returns whether it did.
    pub fn hydrate(&mut self) -> bool {
        let Some(idx) = self.pending() else {
            return false;
        };
        let Some(block) = self.view[idx]
            .block
            .as_ref()
            .and_then(|block| block.hydrate(|digest| self.hydrated.proofs.get(digest)))
        else {
            return false;
        };
        self.hydrated.insert(self.view[idx].msg, block);
        self.fold_from(idx);
        true
    }

    /// Entries that entered the view, on a channel update that dropped nothing.
    pub fn apply_extension(&mut self, adopted: Vec<ChannelEntry>) {
        for entry in adopted {
            // The sdk re-reports held entries after a restart.
            if self.view.iter().any(|held| held.msg == entry.msg) {
                continue;
            }
            if entry.parent != self.pin() {
                warn!(
                    "Adopted channel entry {} chains on {}, not on the pin {}",
                    entry.msg,
                    entry.parent,
                    self.pin()
                );
            }
            self.push(entry);
        }
    }

    /// The unfinalized view at the new tip, on a channel update that dropped
    /// entries.
    pub fn apply_conflict(&mut self, canonical: Vec<ChannelEntry>) {
        let final_len = self.finalized;
        // A conflict can re-seat entries the lineage already finalized.
        let start = canonical
            .iter()
            .position(|entry| entry.msg == self.final_msg)
            .map_or(0, |idx| idx.saturating_add(1));
        let mut seen: HashSet<MsgId> = self.view[..final_len]
            .iter()
            .map(|entry| entry.msg)
            .collect();
        let canonical: Vec<ChannelEntry> = canonical
            .into_iter()
            .skip(start)
            .filter(|entry| seen.insert(entry.msg))
            .collect();
        let mut parent = self.final_msg;
        for entry in &canonical {
            if entry.parent != parent {
                warn!(
                    "Channel view entry {} chains on {}, not on {parent}",
                    entry.msg, entry.parent
                );
            }
            parent = entry.msg;
        }
        // The entries both views hold keep their folds: a `MsgId` commits to
        // its payload, so the same id carries the same block.
        let fork = self.view[final_len..]
            .iter()
            .zip(&canonical)
            .take_while(|(held, entry)| held.msg == entry.msg)
            .count();
        self.view.truncate(final_len);
        self.view.extend(canonical);
        self.hydrated.retain(|msg| seen.contains(msg));
        self.judged.retain(|msg| seen.contains(msg));
        self.fold_from(final_len.saturating_add(fork));
    }

    /// Records an inscription of ours, which chains on the pin it was built on.
    pub fn record_publish(&mut self, entry: ChannelEntry) -> PublishRecord {
        if self.view.iter().any(|held| held.msg == entry.msg) {
            return PublishRecord::AlreadyInView;
        }
        let hash = entry.block.as_ref().map(|block| block.header.hash);
        let in_head = |chain: &Self| {
            chain
                .head_blocks()
                .any(|block| Some(block.header.hash) == hash)
        };
        let held_before = in_head(self);
        let on_pin = entry.parent == self.pin();
        if !on_pin && !self.insert_before_child(&entry) {
            return PublishRecord::Stale;
        }
        if on_pin {
            self.push(entry);
        }
        if !held_before && in_head(self) {
            PublishRecord::Extended
        } else {
            PublishRecord::Skipped
        }
    }

    /// Takes in the finalized `entries` and the LIB, refolds what that changes,
    /// and returns what it decided since the last call.
    pub fn apply_finalized(&mut self, entries: &[ChannelEntry], lib_slot: Slot) -> FoldOutcome {
        // The LIB only moves forward; a replay passes each entry's own slot.
        let lib_slot = lib_slot.max(self.lib_slot);
        let lib_moved = lib_slot != self.lib_slot;
        self.lib_slot = lib_slot;
        let mut judged = Vec::new();
        let mut changed = None;
        for entry in entries {
            let at = self.finalize(entry, &mut judged);
            changed = changed.into_iter().chain(at).min();
        }
        // An unfinalized entry's slot test reads the LIB.
        if lib_moved {
            changed = changed.into_iter().chain([self.finalized]).min();
        }
        if let Some(idx) = changed {
            self.refold(idx, true);
        }
        let (mut settled, mut skipped) = (Vec::new(), Vec::new());
        judged.extend(self.judge(&mut skipped));
        judged.extend(self.settle(&mut settled));
        // A root lineage over a held tier is a store restored without its view.
        let judgeable = self.final_tip.is_some() && self.final_msg != MsgId::root();
        for outcome in &mut judged {
            if let Verdict::Dropped { next, .. } = &mut outcome.verdict {
                *next &= judgeable;
            }
        }
        FoldOutcome {
            judged,
            settled,
            skipped,
        }
    }

    /// Makes `entry` the newest final entry, after the held entries it chains
    /// on, and returns where the view changed. A finalized entry off the lineage
    /// is a re-delivery: a held copy leaves the view and its verdict goes to
    /// `judged`.
    fn finalize(&mut self, entry: &ChannelEntry, judged: &mut Vec<Judged>) -> Option<usize> {
        // Finality is prefix-monotone: the held entries this one chains on
        // finalize first, found by parent link since a stale re-report can
        // sit out of order in the view.
        let ancestor = self.view[self.finalized..]
            .iter()
            .find(|held| entry.parent != self.final_msg && held.msg == entry.parent)
            .cloned();
        let changed = ancestor.and_then(|held| self.finalize(&held, judged));
        let final_len = self.finalized;
        if entry.parent != self.final_msg {
            if self.view[..final_len]
                .iter()
                .any(|held| held.msg == entry.msg)
            {
                return changed;
            }
            let held = self.view[final_len..]
                .iter()
                .position(|held| held.msg == entry.msg)
                .map(|at| final_len.saturating_add(at));
            if let Some(idx) = held {
                self.view.remove(idx);
                self.forget(entry.msg);
            }
            judged.extend(self.redelivery(entry));
            return changed.into_iter().chain(held).min();
        }
        // The entries held ahead of it are siblings the channel did not keep.
        let ahead = self.view[final_len..]
            .iter()
            .position(|held| held.msg == entry.msg);
        let siblings: Vec<ChannelEntry> = self
            .view
            .drain(final_len..final_len.saturating_add(ahead.unwrap_or(0)))
            .collect();
        for sibling in siblings {
            self.forget(sibling.msg);
        }
        if ahead.is_some() {
            self.view[final_len] = entry.clone();
        } else {
            self.view.insert(final_len, entry.clone());
        }
        self.final_msg = entry.msg;
        self.finalized = final_len.saturating_add(1);
        let mut lineage = HashSet::from([entry.msg]);
        for later in self.view.split_off(self.finalized) {
            if lineage.contains(&later.parent) && lineage.insert(later.msg) {
                self.view.push(later);
            } else {
                self.forget(later.msg);
            }
        }
        changed.into_iter().chain([final_len]).min()
    }

    /// The verdict on a finalized block off the lineage, judged against the
    /// final tip and never an offence.
    fn redelivery(&self, entry: &ChannelEntry) -> Option<Judged> {
        let block = entry.block.as_ref()?;
        let verdict = if self
            .final_tip
            .as_ref()
            .is_some_and(|tip| tip.hash == block.header.hash)
        {
            Verdict::AlreadySettled(block.hydrate(|digest| self.hydrated.proofs.get(digest))?)
        } else {
            let computed = block.recompute_hash();
            let linked = if computed == block.header.hash {
                validate_link(self.final_tip.as_ref(), &block.header)
            } else {
                Err(BlockIngestError::HashMismatch {
                    computed,
                    header: block.header.hash,
                })
            };
            linked.map_or_else(
                |error| Verdict::Dropped { error, next: false },
                |()| Verdict::Ignored,
            )
        };
        Some(Judged {
            msg: entry.msg,
            signer: entry.signer,
            block: block.clone(),
            verdict,
        })
    }

    /// The verdicts of the finalized entries decided since the last call:
    /// each entry's own, and those of the entries whose blocks left the branch
    /// at it.
    fn judge(&mut self, newly_skipped: &mut Vec<[u8; 32]>) -> Vec<Judged> {
        let decided = self.finalized.min(self.folds.len());
        let mut judged = Vec::new();
        for (entry, fold) in self.view[..decided].iter().zip(&self.folds) {
            if fold.held || !self.judged.insert(entry.msg) {
                continue;
            }
            if fold.skipped {
                newly_skipped.extend(entry.signer);
            }
            let left = fold.left.iter().filter_map(|(msg, dead)| {
                let left_entry = self.view.iter().find(|held| held.msg == *msg)?;
                let verdict = dead
                    .clone()
                    .map_or(Verdict::Cut, |error| Verdict::Dropped { error, next: true });
                Some((left_entry, verdict))
            });
            judged.extend(
                fold.verdict
                    .clone()
                    .map(|verdict| (entry, verdict))
                    .into_iter()
                    .chain(left)
                    .filter_map(|(judged_entry, verdict)| {
                        Some(Judged {
                            msg: judged_entry.msg,
                            signer: judged_entry.signer,
                            block: judged_entry.block.clone()?,
                            verdict,
                        })
                    }),
            );
        }
        judged
    }

    /// Settles the decided, finalized branch from its bottom while its blocks
    /// settle, then drops the decided entries the final tier has passed.
    fn settle(&mut self, newly_final: &mut Vec<SettledBlock>) -> Vec<Judged> {
        let final_len = self.finalized;
        let decided = final_len.min(self.folds.len());
        let settled = decided
            .checked_sub(1)
            .map_or_else(Vec::new, |last| self.settling(&self.folds[last], final_len));
        let mut judged = Vec::new();
        for placed in &settled {
            let idx = self
                .position(placed.entry)
                .expect("a branch block's entry is in the view");
            let (entry, fold) = (&self.view[idx], &self.folds[idx]);
            let events = fold
                .events
                .clone()
                .expect("an executed block's fold has its events");
            judged.push(Judged {
                msg: entry.msg,
                signer: entry.signer,
                block: entry
                    .block
                    .clone()
                    .expect("a placed entry carries its block"),
                verdict: Verdict::Settled,
            });
            newly_final.push(SettledBlock {
                msg: entry.msg,
                slot: entry.slot,
                block: self
                    .hydrated
                    .get(&entry.msg)
                    .cloned()
                    .expect("an executed block is hydrated"),
                state: fold.state.clone(),
                events,
            });
            self.final_state = fold.state.clone();
            self.final_tip = Some(placed.tip());
        }
        if let Some(last) = settled.last() {
            let from = self
                .position(last.entry)
                .expect("a branch block's entry is in the view");
            for fold in &mut self.folds[from..] {
                debug_assert!(
                    fold.record
                        .branch
                        .iter()
                        .map(|placed| placed.block.hash)
                        .take(settled.len())
                        .eq(settled.iter().map(|placed| placed.block.hash)),
                    "no fold cuts at or below the settled tip"
                );
                fold.record.branch.drain(..settled.len());
            }
        }
        let undecided = self.folds[..decided]
            .iter()
            .take_while(|fold| !fold.held)
            .count();
        if let Some(last) = self.folds[..undecided]
            .iter()
            .rposition(|fold| fold.record.branch.is_empty())
        {
            self.record = self.folds[last].record.clone();
            let passed: Vec<ChannelEntry> = self.view.drain(..=last).collect();
            for entry in passed {
                self.forget(entry.msg);
            }
            self.folds.drain(..=last);
            self.finalized = self.finalized.saturating_sub(last.saturating_add(1));
        }
        judged
    }

    /// The blocks of `fold`'s branch that settle, from its bottom up: each
    /// executed, and plain, confirmed or timed out.
    fn settling(&self, fold: &Fold, final_len: usize) -> Vec<Placed> {
        let delta = skip_window(&fold.state);
        // A timeout needs every finalized entry up to its window's end folded decided.
        let undecided = self.view[..final_len]
            .iter()
            .enumerate()
            .find(|&(idx, _)| self.folds.get(idx).is_none_or(|held| held.held))
            .map(|(_, entry)| entry.slot);
        let timed_out = |slot: Option<u64>| {
            window_passed(slot, delta, None, self.lib_slot)
                && undecided.is_none_or(|first| {
                    first
                        .is_some_and(|sigma| window_passed(slot, delta, Some(sigma), self.lib_slot))
                })
        };
        fold.record
            .branch
            .iter()
            .take_while(|placed| {
                matches!(placed.status, Status::Executed)
                    && (!placed.block.private || placed.confirmed || timed_out(placed.block.slot))
            })
            .cloned()
            .collect()
    }

    /// Inserts `entry` before a held entry chained on it, when it chains on
    /// that entry's predecessor: the view learned of the child first.
    fn insert_before_child(&mut self, entry: &ChannelEntry) -> bool {
        let Some(idx) = self.view.iter().position(|held| held.parent == entry.msg) else {
            return false;
        };
        let before = idx
            .checked_sub(1)
            .map_or(self.final_msg, |prev| self.view[prev].msg);
        if entry.parent != before {
            return false;
        }
        self.view.insert(idx, entry.clone());
        self.fold_from(idx);
        true
    }

    /// Appends `entry` to the view and folds it onto the head.
    fn push(&mut self, entry: ChannelEntry) {
        let idx = self.view.len();
        self.view.push(entry);
        self.fold_from(idx);
    }

    /// Refolds the view from `idx` on, after it changed there.
    fn fold_from(&mut self, idx: usize) {
        self.refold(idx, false);
    }

    /// Refolds from `idx` on. With `reuse`, a block the replaced folds executed
    /// keeps its execution: only finality and the LIB moved, not the entries.
    fn refold(&mut self, idx: usize, reuse: bool) {
        let mut refolded = self.folds.split_off(idx.min(self.folds.len()));
        if !reuse {
            refolded.clear();
        }
        while let Some(fold) = self.fold_next(&refolded) {
            self.folds.push(fold);
        }
    }

    /// The head after folding the next view entry onto it, or `None` where a
    /// node lacking a pending block's proofs stops.
    fn fold_next(&mut self, refolded: &[Fold]) -> Option<Fold> {
        let entry = self.view.get(self.folds.len())?.clone();
        let (state, record) = self
            .folds
            .last()
            .map_or((&self.final_state, &self.record), |fold| {
                (&fold.state, &fold.record)
            });
        let mut fold = Fold {
            state: state.clone(),
            record: record.clone(),
            events: None,
            verdict: None,
            left: Vec::new(),
            held: false,
            skipped: false,
        };
        let Some(block) = &entry.block else {
            return Some(fold);
        };
        let computed = block.recompute_hash();
        if computed != block.header.hash {
            fold.verdict = Some(Verdict::Dropped {
                error: BlockIngestError::HashMismatch {
                    computed,
                    header: block.header.hash,
                },
                next: true,
            });
            return Some(fold);
        }
        let delta = skip_window(&fold.state);
        let (sigma, lib) = (entry.slot, self.lib_slot);
        let passed = |slot| window_passed(slot, delta, sigma, lib);
        // Behind a pending block, only what cannot depend on its validity folds.
        if let Some(pending) = fold
            .record
            .branch
            .last()
            .filter(|placed| matches!(placed.status, Status::Pending))
        {
            let parent = block.header.prev_block_hash;
            let builds_on_it = parent == pending.block.hash || fold.record.held.contains(&parent);
            if passed(pending.block.slot) || (entry.signer != pending.block.signer && builds_on_it)
            {
                return None;
            }
            fold.held = entry.signer == pending.block.signer;
        }
        if fold.held {
            fold.record.held.push(block.header.hash);
        } else {
            // A dead block leaves with its descendants once its window closes.
            if let Some(dead) = fold.record.branch.iter().position(|placed| {
                matches!(placed.status, Status::Dead(_)) && passed(placed.block.slot)
            }) {
                fold.left = cut(&mut fold.record, dead);
            }
            self.place(&entry, block, &mut fold, passed, refolded);
        }
        if sigma.is_some() {
            fold.record.prune_run(self.final_tip.as_ref(), passed);
        }
        Some(fold)
    }

    /// Places `block` where the rules of selection put it, with the
    /// confirmation that follows, and executes it there.
    fn place(
        &mut self,
        entry: &ChannelEntry,
        block: &DigestedBlock,
        fold: &mut Fold,
        passed: impl Fn(Option<u64>) -> bool,
        refolded: &[Fold],
    ) {
        match placement(&fold.record, self.final_tip.as_ref(), entry, block, passed) {
            Placement::Extends => {}
            Placement::Skips(at) => {
                fold.skipped = true;
                fold.left.extend(cut(&mut fold.record, at));
                // Only a final skip decides the entries held behind the pending block it cuts.
                if entry.slot.is_some() {
                    for (held, stored) in self
                        .view
                        .iter()
                        .zip(&mut self.folds)
                        .filter(|(_, stored)| stored.held)
                    {
                        stored.held = false;
                        fold.left.push((held.msg, None));
                    }
                }
                fold.state = fold.record.branch.last().map_or_else(
                    || self.final_state.clone(),
                    |below| {
                        let idx = self
                            .position(below.entry)
                            .expect("a branch block's entry is in the view");
                        self.folds[idx].state.clone()
                    },
                );
            }
            Placement::Late => {
                fold.verdict = Some(Verdict::LateSkip);
                return;
            }
            Placement::Misplaced(error) => {
                fold.verdict = Some(Verdict::Dropped { error, next: true });
                return;
            }
            Placement::Ignored => {
                fold.verdict = Some(Verdict::Ignored);
                return;
            }
        }
        // A block by another signer confirms the run below it and starts its own.
        fold.record.confirm(entry.signer);
        fold.record.held.clear();
        let placed = BlockRecord::new(entry, block);
        fold.record.run.push(placed.clone());
        let below = fold.record.branch.last();
        let status = if below.is_some_and(|parent| !matches!(parent.status, Status::Executed)) {
            Status::Unexecutable
        } else {
            let parent = below.map_or_else(|| self.final_tip.clone(), |parent| Some(parent.tip()));
            match self.execute(entry, parent.as_ref(), &fold.state, refolded) {
                Ok((state, events)) => {
                    fold.state = state;
                    fold.events = Some(events);
                    Status::Executed
                }
                Err(None) => Status::Pending,
                Err(Some(error)) if placed.private => Status::Dead(error),
                // A plain block that fails leaves the branch, and the tip stays.
                Err(Some(error)) => {
                    fold.record.run.pop();
                    fold.verdict = Some(Verdict::Dropped { error, next: true });
                    return;
                }
            }
        };
        fold.record.branch.push(Placed {
            entry: entry.msg,
            block: placed,
            status,
            confirmed: false,
        });
    }

    /// `entry`'s block executed on `state`, reusing a refolded fold that
    /// already executed it; `Err(None)` while its proofs are missing.
    fn execute(
        &mut self,
        entry: &ChannelEntry,
        parent: Option<&Tip>,
        state: &V03State,
        refolded: &[Fold],
    ) -> Result<(V03State, Vec<TxEvents>), Option<BlockIngestError>> {
        if let Some(executed) = refolded.iter().find_map(|fold| {
            let events = fold.events.as_ref()?;
            (fold.record.branch.last()?.entry == entry.msg)
                .then(|| (fold.state.clone(), events.clone()))
        }) {
            return Ok(executed);
        }
        if !self.hydrated.contains_key(&entry.msg) {
            let Some(block) = entry
                .block
                .as_ref()
                .and_then(|block| block.hydrate(|digest| self.hydrated.proofs.get(digest)))
            else {
                return Err(None);
            };
            self.hydrated.insert(entry.msg, block);
        }
        let block = &self.hydrated[&entry.msg];
        apply_with_retries(parent, block, state).map_err(|err| {
            warn!(
                "Channel block {} ({}) does not apply: {err}",
                block.header.block_id, block.header.hash
            );
            Some(err)
        })
    }

    fn head_record(&self) -> &Record {
        self.folds.last().map_or(&self.record, |fold| &fold.record)
    }

    /// The view index of the entry that placed the head's pending block.
    fn pending(&self) -> Option<usize> {
        let pending = self
            .head_record()
            .branch
            .iter()
            .find(|placed| matches!(placed.status, Status::Pending))?;
        self.position(pending.entry)
    }

    fn position(&self, msg: MsgId) -> Option<usize> {
        self.view.iter().position(|entry| entry.msg == msg)
    }

    /// Takes `msg` out of what the view caches for its entries.
    fn forget(&mut self, msg: MsgId) {
        self.hydrated.remove(&msg);
        self.judged.remove(&msg);
    }
}

/// Applies `block` on a copy of `state`, retrying a failure that may be transient.
fn apply_with_retries(
    tip: Option<&Tip>,
    block: &Block,
    state: &V03State,
) -> Result<(V03State, Vec<TxEvents>), BlockIngestError> {
    let mut attempt = 1;
    loop {
        let mut next = state.clone();
        match apply_block(tip, block, &mut next) {
            Ok(block_events) => return Ok((next, block_events)),
            Err(err) if err.is_retryable() && attempt < APPLY_ATTEMPTS => {
                warn!(
                    "Block {} failed to apply (attempt {attempt}), retrying: {err}",
                    block.header.block_id
                );
                attempt = attempt.saturating_add(1);
            }
            Err(err) => return Err(err),
        }
    }
}

/// The skip window Δ the channel parameters in `state` set: 0 before genesis
/// sets them.
fn skip_window(state: &V03State) -> u64 {
    stake_config::channel_params(state).map_or(0, |params| u64::from(params.skip_window))
}

/// Whether an entry at `sigma` comes after the window of a block whose entry
/// finalized at `slot`. An unfinalized entry lies above the LIB.
pub(crate) fn window_passed(slot: Option<u64>, delta: u64, sigma: Option<Slot>, lib: Slot) -> bool {
    slot.is_some_and(|start| {
        let end = start.saturating_add(delta);
        sigma.map_or_else(|| lib.into_inner() >= end, |at| at.into_inner() > end)
    })
}

/// Where the rules of selection put `block`, against `record` above `settled`.
pub(crate) fn placement(
    record: &Record,
    settled: Option<&Tip>,
    entry: &ChannelEntry,
    block: &DigestedBlock,
    passed: impl Fn(Option<u64>) -> bool,
) -> Placement {
    let header = &block.header;
    let parent = header.prev_block_hash;
    let tip = record
        .branch
        .last()
        .map_or_else(|| settled.cloned(), |placed| Some(placed.tip()));
    let Err(error) = validate_link(tip.as_ref(), header) else {
        return Placement::Extends;
    };
    let run_signer = record.run.first().map(|run| run.signer);
    let skipped = record.run.iter().find(|run| {
        run.private
            && run.parent == parent
            && run.block_id == header.block_id
            && run_signer != Some(entry.signer)
    });
    match skipped {
        Some(skipped) if passed(skipped.slot) => Placement::Late,
        Some(skipped) => {
            let at = record
                .branch
                .iter()
                .position(|placed| placed.block.hash == skipped.hash);
            debug_assert!(at.is_some(), "no fold cuts at or below the settled tip");
            at.map_or(Placement::Late, Placement::Skips)
        }
        None if tip.is_some_and(|structural| structural.hash == parent)
            || record
                .run
                .iter()
                .any(|run| run.hash == parent || run.parent == parent) =>
        {
            Placement::Misplaced(error)
        }
        None => Placement::Ignored,
    }
}

/// Cuts `record`'s branch back to before `at`, and its run with it. Returns
/// the cut entries, each with the failure of a dead one.
pub(crate) fn cut(record: &mut Record, at: usize) -> Vec<(MsgId, Option<BlockIngestError>)> {
    let cut = record.branch.split_off(at);
    record
        .run
        .retain(|run| cut.iter().all(|placed| placed.block.hash != run.hash));
    cut.into_iter()
        .map(|placed| match placed.status {
            Status::Dead(error) => (placed.entry, Some(error)),
            Status::Executed | Status::Unexecutable | Status::Pending => (placed.entry, None),
        })
        .collect()
}

#[cfg(test)]
mod skip_rule;

#[cfg(test)]
mod tests {
    use common::{
        HashType,
        test_utils::{create_transaction_native_token_transfer, produce_dummy_block},
    };
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    const INITIAL_TO_BALANCE: u128 = 20_000_000_000_000;

    fn msg(n: u8) -> MsgId {
        MsgId::from([n; 32])
    }

    /// The shared initial state with the test producer's reward account claimed,
    /// simulating the stake a real sequencer holds before producing: fee
    /// settlement credits it, and crediting an unclaimed account is rejected.
    fn claimed_initial_state() -> V03State {
        initial_state(true).with_public_accounts([common::test_utils::producer_seed()])
    }

    fn entry(n: u8, parent: MsgId, block: Option<&Block>) -> ChannelEntry {
        ChannelEntry {
            msg: msg(n),
            parent,
            signer: None,
            slot: None,
            block: block.map(Block::digested),
        }
    }

    /// Blocks 1..=n chained on one another.
    fn chain_of(n: u64) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        for id in 1..=n {
            let prev = blocks.last().map(|block| block.header.hash);
            blocks.push(produce_dummy_block(id, prev, vec![]));
        }
        blocks
    }

    /// One view entry per block, entry `i + 1` carrying `blocks[i]`.
    fn entries_for(blocks: &[Block]) -> Vec<ChannelEntry> {
        let mut parent = MsgId::root();
        blocks
            .iter()
            .zip(1_u8..)
            .map(|(block, n)| {
                let entry = entry(n, parent, Some(block));
                parent = entry.msg;
                entry
            })
            .collect()
    }

    /// A valid block 2 on `blocks[0]` that differs from `blocks[1]`.
    fn competing_block2(blocks: &[Block]) -> Block {
        let accounts = initial_pub_accounts_private_keys();
        let mut on_block1 = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        on_block1.apply_extension(vec![entry(1, MsgId::root(), Some(&blocks[0]))]);
        let tx = create_transaction_native_token_transfer(
            accounts[0].account_id,
            0,
            accounts[1].account_id,
            1,
            &accounts[0].pub_sign_key,
        );
        settled(on_block1.head_state(), 2, blocks[0].header.hash, vec![tx])
    }

    fn head_id(chain: &ChainState) -> Option<u64> {
        chain.head_tip().map(|tip| tip.block_id)
    }

    fn state_bytes(state: &V03State) -> Vec<u8> {
        borsh::to_vec(state).expect("state serializes")
    }

    /// The head equals a fresh fold of `final` over the view.
    fn assert_head_is_the_fold(chain: &ChainState) {
        let mut fresh = ChainState::from_final(
            chain.final_state().clone(),
            chain.final_tip(),
            chain.proofs().clone(),
        );
        fresh.final_msg = chain.final_msg;
        fresh.view = chain.view.clone();
        fresh.fold_from(0);
        let hashes = |of: &ChainState| {
            of.head_blocks()
                .map(|block| block.header.hash)
                .collect::<Vec<_>>()
        };
        assert_eq!(hashes(&fresh), hashes(chain));
        assert_eq!(
            state_bytes(fresh.head_state()),
            state_bytes(chain.head_state()),
            "head_state must equal final_state folded over the view"
        );
    }

    /// Builds a block whose fee transaction settles `txs` against `state`.
    fn settled(
        state: &V03State,
        id: u64,
        prev: HashType,
        txs: Vec<common::transaction::LeeTransaction>,
    ) -> Block {
        use common::{
            block::HashableBlockData,
            test_utils::producer_account_for_testing,
            transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
        };
        let timestamp = id.saturating_mul(100);
        let (summary, payout, reverted) =
            crate::apply::derive_block_summary(state, &txs, id, timestamp)
                .expect("test transactions settle");
        let producer = producer_account_for_testing();
        let mut transactions = txs;
        transactions.push(LeeTransaction::Public(fee_invocation(
            summary,
            payout,
            FeePayee::Present(producer),
        )));
        transactions.push(LeeTransaction::Public(clock_invocation(id, timestamp)));
        HashableBlockData {
            block_id: id,
            prev_block_hash: prev,
            timestamp,
            transactions,
            reverted,
        }
        .into_pending_block()
    }

    #[test]
    fn an_extension_advances_the_head_and_the_pin() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.pin(), msg(2));
        assert!(chain.final_tip().is_none());
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn an_entry_without_a_block_moves_the_pin_but_not_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), None),
            entry(3, msg(2), Some(&blocks[1])),
        ]);

        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.pin(), msg(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn an_invalid_block_is_skipped_and_the_next_block_chains_on_the_last_valid_one() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        let broken = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&broken)),
        ]);
        assert_eq!(head_id(&chain), Some(1));
        assert_eq!(chain.pin(), msg(2));

        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[1]))]);
        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.head_tip().unwrap().hash, blocks[1].header.hash);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_duplicate_height_on_the_channel_never_rewinds_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        let duplicate = competing_block2(&blocks);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&blocks[1])),
            entry(3, msg(2), Some(&duplicate)),
            entry(4, msg(3), Some(&blocks[2])),
        ]);

        assert_eq!(head_id(&chain), Some(3));
        assert_eq!(chain.head_tip().unwrap().hash, blocks[2].header.hash);
        assert_eq!(chain.pin(), msg(4));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn an_adopted_entry_off_the_pin_leaves_a_lineage_gap() {
        let blocks = chain_of(3);
        let entries = entries_for(&blocks);
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        assert!(chain.check_for_gaps_in_lineage().is_none());

        chain.apply_extension(vec![entries[0].clone(), entries[2].clone()]);
        assert_eq!(
            chain.check_for_gaps_in_lineage().map(|entry| entry.msg),
            Some(entries[2].msg)
        );
    }

    #[test]
    fn an_entry_without_a_block_is_no_lineage_gap() {
        let blocks = chain_of(1);
        let entries = entries_for(&blocks);
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        chain.apply_extension(vec![entries[0].clone(), entry(9, entries[0].msg, None)]);
        assert!(chain.check_for_gaps_in_lineage().is_none());
    }

    #[test]
    fn a_conflict_seating_already_final_entries_is_no_lineage_gap() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(4);
        finalize_all(&mut chain, &blocks[..3]);

        chain.apply_conflict(entries_for(&blocks));

        assert!(chain.check_for_gaps_in_lineage().is_none());
    }

    #[test]
    fn a_gap_above_already_final_entries_is_still_found() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(4);
        finalize_all(&mut chain, &blocks[..2]);
        let entries = entries_for(&blocks);

        // Entry 3 is missing.
        chain.apply_conflict(vec![
            entries[0].clone(),
            entries[1].clone(),
            entries[3].clone(),
        ]);

        assert_eq!(
            chain.check_for_gaps_in_lineage().map(|entry| entry.msg),
            Some(entries[3].msg)
        );
    }

    #[test]
    fn an_extension_is_appended_as_the_sdk_sends_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        // Chained elsewhere: appended all the same, and the fold skips its block.
        let off_pin = competing_block2(&blocks);
        chain.apply_extension(vec![entry(9, msg(1), Some(&off_pin))]);

        assert_eq!(chain.view().len(), 3);
        assert_eq!(chain.pin(), msg(9));
        assert_eq!(chain.head_tip().unwrap().hash, blocks[1].header.hash);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn an_extension_skips_entries_already_in_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        // The sdk re-reports the held entries ahead of a new one.
        let mut more = blocks.clone();
        more.push(produce_dummy_block(3, Some(blocks[1].header.hash), vec![]));
        chain.apply_extension(entries_for(&more));

        assert_eq!(chain.view().len(), 3);
        assert_eq!(chain.pin(), msg(3));
        assert_eq!(chain.head_tip().unwrap().hash, more[2].header.hash);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_conflict_rebuilds_the_head_from_the_canonical_chain() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));

        let block2_prime = competing_block2(&blocks);
        chain.apply_conflict(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(12, msg(1), Some(&block2_prime)),
        ]);

        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.head_tip().unwrap().hash, block2_prime.header.hash);
        assert_eq!(chain.pin(), msg(12));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_the_view_prefix_keeps_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        let head_before = state_bytes(chain.head_state());

        let outcome = chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0));

        // Block 1 finalized first, as the parent of the entry that finalized.
        assert!(matches!(outcome.judged[0].verdict, Verdict::Settled));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_eq!(chain.final_msg(), msg(2));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_eq!(state_bytes(chain.head_state()), head_before);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_sibling_drops_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        // A different entry on root finalizes, with no block.
        chain.apply_finalized(&[entry(20, MsgId::root(), None)], Slot::from(0));

        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(20));
        assert_eq!(head_id(&chain), None);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_redelivery_leaves_the_view_alone() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        // Block 1 again, and a garbage entry the lineage already passed.
        assert!(matches!(
            chain
                .apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::AlreadySettled(_)
        ));
        chain.apply_finalized(&[entry(30, msg(31), None)], Slot::from(0));

        assert_eq!(chain.final_msg(), msg(1));
        assert_eq!(chain.view().len(), 2);
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_block_off_the_lineage_advances_neither_the_tier_nor_the_lineage() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        // Block 2 again, on an entry we never saw.
        let outcome = chain.apply_finalized(&[entry(9, msg(8), Some(&blocks[1]))], Slot::from(0));

        assert!(matches!(outcome.judged[0].verdict, Verdict::Ignored));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_eq!(chain.final_msg(), msg(1));
        assert_eq!(chain.pin(), msg(2));
        assert_eq!(
            head_id(&chain),
            Some(2),
            "the held entry keeps block 2 in the head"
        );
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn our_publish_extends_the_head_when_it_chains_on_the_pin() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(vec![entry(1, MsgId::root(), Some(&blocks[0]))]);

        assert_eq!(
            chain.record_publish(entry(2, msg(1), Some(&blocks[1]))),
            PublishRecord::Extended
        );
        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.pin(), msg(2));

        // The channel reports it back inside a conflict's common prefix.
        assert_eq!(
            chain.record_publish(entry(2, msg(1), Some(&blocks[1]))),
            PublishRecord::AlreadyInView
        );
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_publish_on_a_pin_that_moved_is_stale() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        let ours = produce_dummy_block(2, Some(blocks[0].header.hash), vec![]);

        assert_eq!(
            chain.record_publish(entry(9, msg(1), Some(&ours))),
            PublishRecord::Stale
        );
        assert_eq!(chain.head_tip().unwrap().hash, blocks[1].header.hash);
    }

    #[test]
    fn the_view_round_trips_through_its_persisted_form() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        let broken = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&broken)),
            entry(3, msg(2), Some(&blocks[1])),
        ]);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        let mut restored = ChainState::from_final(
            chain.final_state().clone(),
            chain.final_tip(),
            ProofStore::new(usize::MAX),
        );
        restored.restore_view(&chain.encode_view()).unwrap();

        assert_eq!(restored.final_msg(), msg(1));
        assert_eq!(restored.pin(), msg(3));
        assert!(
            restored.view()[0].block.is_some(),
            "an unplaced block is stored: the fold reads it"
        );
        assert_eq!(head_id(&restored), Some(2));
        assert_eq!(
            state_bytes(restored.head_state()),
            state_bytes(chain.head_state())
        );
    }

    #[test]
    fn newly_final_blocks_include_the_ancestors_a_finalized_entry_pulls_in() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks[..2]));

        let outcome = chain.apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0));

        let ids: Vec<u64> = outcome
            .settled
            .iter()
            .map(|newly_final| newly_final.block.header.block_id)
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(chain.apply_finalized(&[], Slot::from(0)).settled.is_empty());
    }

    #[test]
    fn a_finalized_entry_finalizes_its_ancestors_in_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks[..2]));

        // Entry 3 was never adopted, but it chains on entry 2.
        let outcome = chain.apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0));

        assert!(matches!(outcome.judged[0].verdict, Verdict::Settled));
        assert_eq!(chain.final_tip().unwrap().block_id, 3);
        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_block_reinscribed_under_a_new_entry_is_misplaced() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(1);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        // The same block again, as the next entry on the lineage.
        let outcome = chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[0]))], Slot::from(0));

        assert!(matches!(
            outcome.judged[0].verdict,
            Verdict::Dropped {
                error: BlockIngestError::UnexpectedBlockId { .. },
                ..
            }
        ));
        assert_eq!(chain.final_tip().unwrap().hash, blocks[0].header.hash);
        assert_eq!(chain.final_msg(), msg(2), "the lineage moves past the copy");
    }

    #[test]
    fn a_hash_alias_with_the_wrong_id_is_not_absorbed() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        // Block 1's hash claimed at height 2: the hash no longer matches.
        let mut alias = blocks[0].clone();
        alias.header.block_id = 2;
        alias.header.prev_block_hash = blocks[0].header.hash;

        // Unfinalized, the fold skips it; the real block 2 still applies.
        chain.apply_extension(vec![
            entry(2, msg(1), Some(&alias)),
            entry(3, msg(2), Some(&blocks[1])),
        ]);
        assert_eq!(chain.head_tip().unwrap().hash, blocks[1].header.hash);

        // Finalized, it parks.
        assert!(matches!(
            chain
                .apply_finalized(&[entry(2, msg(1), Some(&alias))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped {
                error: BlockIngestError::HashMismatch { .. },
                ..
            }
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_an_unheld_parent_keeps_its_children_in_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(5);
        for (block, n) in blocks[..3].iter().zip(1_u8..) {
            let parent = if n == 1 { MsgId::root() } else { msg(n - 1) };
            chain.apply_finalized(&[entry(n, parent, Some(block))], Slot::from(0));
        }
        // Entry 5 arrives before entry 4 finalizes.
        chain.apply_extension(vec![entry(5, msg(4), Some(&blocks[4]))]);
        assert_eq!(head_id(&chain), Some(3));

        chain.apply_finalized(&[entry(4, msg(3), Some(&blocks[3]))], Slot::from(0));

        assert_eq!(chain.view().len(), 1);
        assert_eq!(chain.pin(), msg(5));
        assert_eq!(head_id(&chain), Some(5));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_drops_a_stray_entry_listed_after_a_kept_one_from_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        // Entry 3 chains on the root, not on entry 2, yet its block folds on block 2.
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&blocks[1])),
            entry(3, MsgId::root(), Some(&blocks[2])),
        ]);
        assert_eq!(head_id(&chain), Some(3));

        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        assert_eq!(chain.view().len(), 1);
        assert_eq!(chain.pin(), msg(2));
        assert_eq!(head_id(&chain), Some(2));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_foreign_block_below_the_final_tip_is_not_taken_as_final() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        for (block, n) in blocks.iter().zip(1_u8..) {
            let parent = if n == 1 { MsgId::root() } else { msg(n - 1) };
            chain.apply_finalized(&[entry(n, parent, Some(block))], Slot::from(0));
        }
        let foreign = competing_block2(&blocks);

        assert!(matches!(
            chain
                .apply_finalized(&[entry(4, msg(3), Some(&foreign))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped { .. }
        ));
        assert_eq!(chain.final_tip().unwrap().hash, blocks[2].header.hash);
    }

    #[test]
    fn finalizing_past_a_skipped_entry_trims_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&bad)),
            entry(3, msg(2), Some(&blocks[1])),
            entry(4, msg(3), Some(&blocks[2])),
        ]);
        let head_before = state_bytes(chain.head_state());

        chain.apply_finalized(&[entry(3, msg(2), Some(&blocks[1]))], Slot::from(0));

        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_eq!(chain.final_msg(), msg(3));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_eq!(state_bytes(chain.head_state()), head_before);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_a_rival_of_the_head_refolds_onto_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));
        let rival = competing_block2(&blocks);

        chain.apply_finalized(&[entry(9, msg(1), Some(&rival))], Slot::from(0));

        assert!(chain.view().is_empty());
        assert_eq!(chain.head_blocks().count(), 0);
        assert_eq!(chain.head_tip().unwrap().hash, rival.header.hash);
        assert_eq!(
            state_bytes(chain.head_state()),
            state_bytes(chain.final_state())
        );
    }

    #[test]
    fn a_restored_view_finalizes_like_the_live_one() {
        let mut live = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        live.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&bad)),
            entry(3, msg(2), Some(&blocks[1])),
        ]);
        let mut restored = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        restored.restore_view(&live.encode_view()).unwrap();
        assert_eq!(restored.encode_view(), live.encode_view());

        for chain in [&mut live, &mut restored] {
            chain.apply_finalized(&[entry(2, msg(1), Some(&bad))], Slot::from(0));
            assert_eq!(chain.final_msg(), msg(2));
            assert_eq!(chain.view().len(), 1);
            assert_eq!(head_id(chain), Some(2));
        }
        assert_eq!(restored.encode_view(), live.encode_view());
    }

    #[test]
    fn a_publish_is_stale_against_the_pin_not_the_head() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), None),
        ]);

        assert_eq!(
            chain.record_publish(entry(9, msg(1), Some(&blocks[1]))),
            PublishRecord::Stale
        );
        assert_eq!(head_id(&chain), Some(1));
        assert_eq!(
            chain.record_publish(entry(9, msg(2), Some(&blocks[1]))),
            PublishRecord::Extended
        );
        assert_eq!(head_id(&chain), Some(2));
    }

    #[test]
    fn a_publish_of_a_block_the_head_already_holds_is_skipped() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        assert_eq!(
            chain.record_publish(entry(9, msg(2), Some(&blocks[1]))),
            PublishRecord::Skipped
        );
        assert_eq!(chain.head_blocks().count(), 2);
    }

    #[test]
    fn our_publish_goes_before_a_peer_entry_that_chained_on_it_first() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(vec![entry(1, MsgId::root(), Some(&blocks[0]))]);
        // A peer built on our inscription before we recorded it.
        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[2]))]);
        assert_eq!(head_id(&chain), Some(1));

        assert_eq!(
            chain.record_publish(entry(2, msg(1), Some(&blocks[1]))),
            PublishRecord::Extended
        );
        let msgs: Vec<MsgId> = chain.view().iter().map(|entry| entry.msg).collect();
        assert_eq!(msgs, vec![msg(1), msg(2), msg(3)]);
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_conflict_naming_an_entry_twice_holds_it_once() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        let mut canonical = entries_for(&blocks);
        canonical.push(canonical[1].clone());

        chain.apply_conflict(canonical);

        assert_eq!(chain.view().len(), 2);
        chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0));
        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(2));
    }

    #[test]
    fn finalizing_a_held_entry_finalizes_the_entries_before_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));

        // Out of order.
        chain.apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0));
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        assert_eq!(chain.final_tip().unwrap().block_id, 3);
        assert_eq!(
            chain.final_msg(),
            msg(3),
            "a late re-delivery does not rewind it"
        );
        assert!(chain.view().is_empty());
    }

    #[test]
    fn an_invalid_finalized_block_parks_and_the_lineage_moves_past_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(1);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        let bad = produce_dummy_block(3, Some(blocks[0].header.hash), vec![]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(2, msg(1), Some(&bad))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped { .. }
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_eq!(chain.final_msg(), msg(2));
    }

    #[test]
    fn a_valid_finalized_successor_applies_after_an_invalid_one() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));
        let bad = produce_dummy_block(3, Some(blocks[0].header.hash), vec![]);
        chain.apply_finalized(&[entry(2, msg(1), Some(&bad))], Slot::from(0));

        assert!(matches!(
            chain
                .apply_finalized(&[entry(3, msg(2), Some(&blocks[1]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Settled
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_conflicting_finalized_block_at_the_final_tip_parks() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));
        chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0));

        let block2_prime = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(3, msg(1), Some(&block2_prime))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped { .. }
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
    }

    /// Finalizes `blocks` as entries `1..`, each chained on the one before.
    fn finalize_all(chain: &mut ChainState, blocks: &[Block]) {
        let mut parent = MsgId::root();
        for (block, n) in blocks.iter().zip(1_u8..) {
            chain.apply_finalized(&[entry(n, parent, Some(block))], Slot::from(0));
            parent = msg(n);
        }
    }

    #[test]
    fn a_stale_adopted_entry_finalized_below_the_tier_does_not_rewind_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(4);
        finalize_all(&mut chain, &blocks[..3]);

        // The sdk reports entry 1 as adopted after the tier already passed it.
        chain.apply_extension(vec![entry(1, MsgId::root(), Some(&blocks[0]))]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped {
                error: BlockIngestError::UnexpectedBlockId { .. },
                ..
            }
        ));
        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(3));

        // The final tip's own entry, re-adopted and re-finalized.
        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[2]))]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::AlreadySettled(_)
        ));
        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());

        chain.apply_extension(vec![entry(4, msg(3), Some(&blocks[3]))]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(4, msg(3), Some(&blocks[3]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Settled
        ));
        assert_eq!(chain.final_msg(), msg(4));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn stale_adopted_entries_in_one_extension_leave_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        finalize_all(&mut chain, &blocks);

        chain.apply_extension(entries_for(&blocks[..2]));
        chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0));

        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(3));
        assert_eq!(chain.final_tip().unwrap().block_id, 3);
    }

    #[test]
    fn a_held_misplaced_block_on_the_final_tier_is_still_next() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(1);
        finalize_all(&mut chain, &blocks);

        let skips_ahead = produce_dummy_block(3, Some(blocks[0].header.hash), vec![]);
        chain.apply_extension(vec![entry(2, msg(1), Some(&skips_ahead))]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(2, msg(1), Some(&skips_ahead))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped {
                error: BlockIngestError::UnexpectedBlockId { .. },
                ..
            }
        ));

        assert_eq!(chain.final_msg(), msg(2));
        assert!(chain.view().is_empty());
    }

    #[test]
    fn a_held_entry_past_a_gap_is_not_taken_as_final() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        finalize_all(&mut chain, &blocks[..1]);

        // Chained on an entry never seen, carrying a block that does not apply.
        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[2]))]);
        assert!(matches!(
            chain
                .apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Dropped { .. }
        ));
        assert_eq!(chain.final_msg(), msg(1));
        assert!(chain.view().is_empty());

        // A block past the gap advances neither the tier nor the lineage.
        assert!(matches!(
            chain
                .apply_finalized(&[entry(9, msg(8), Some(&blocks[1]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Ignored
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_eq!(chain.final_msg(), msg(1));
    }

    #[test]
    fn a_late_redelivery_neither_applies_nor_rewinds_the_lineage() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        finalize_all(&mut chain, &blocks[..1]);
        // Entry 3 chains on entry 2, whose block never reached the tier.
        chain.apply_finalized(&[entry(2, msg(1), None)], Slot::from(0));
        chain.apply_finalized(&[entry(3, msg(2), None)], Slot::from(0));

        assert!(matches!(
            chain
                .apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Ignored
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_eq!(chain.final_msg(), msg(3));
    }

    #[test]
    fn a_reread_below_the_final_entry_keeps_the_lineage_and_the_view() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        finalize_all(&mut chain, &blocks[..2]);
        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[2]))]);

        // A warm start re-reads entries 1 and 2 before resuming the lineage.
        finalize_all(&mut chain, &blocks[..2]);

        assert_eq!(chain.final_msg(), msg(2));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_stale_reported_entry_behind_a_held_one_does_not_finalize_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(4);
        finalize_all(&mut chain, &blocks[..3]);
        chain.apply_extension(vec![entry(4, msg(3), Some(&blocks[3]))]);

        let mut restored = ChainState::from_final(
            chain.final_state().clone(),
            chain.final_tip(),
            ProofStore::new(usize::MAX),
        );
        restored.restore_view(&chain.encode_view()).unwrap();

        // After a restart the sdk re-reports the final tip's entry after entry 4.
        restored.apply_extension(vec![
            entry(3, msg(2), Some(&blocks[2])),
            entry(4, msg(3), Some(&blocks[3])),
        ]);
        let view: Vec<MsgId> = restored.view().iter().map(|entry| entry.msg).collect();
        assert_eq!(view, vec![msg(4), msg(3)]);

        assert!(matches!(
            restored
                .apply_finalized(&[entry(3, msg(2), Some(&blocks[2]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::AlreadySettled(_)
        ));
        assert_eq!(
            restored.final_tip().unwrap().block_id,
            3,
            "entry 4 is not final yet"
        );
        assert_eq!(restored.final_msg(), msg(3));
        assert_eq!(restored.pin(), msg(4));
        assert_eq!(head_id(&restored), Some(4));

        assert!(matches!(
            restored
                .apply_finalized(&[entry(4, msg(3), Some(&blocks[3]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Settled
        ));
        assert_eq!(restored.final_msg(), msg(4));
        assert!(restored.view().is_empty());
        assert_head_is_the_fold(&restored);
    }

    #[test]
    fn a_held_entry_finalizes_past_a_stale_entry_it_chains_on() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(4);
        finalize_all(&mut chain, &blocks[..3]);
        chain.apply_extension(vec![entry(4, msg(3), Some(&blocks[3]))]);
        chain.apply_extension(vec![entry(3, msg(2), Some(&blocks[2]))]);

        // Entry 4 finalizes first, so the walk reaches the stale entry 3.
        assert!(matches!(
            chain
                .apply_finalized(&[entry(4, msg(3), Some(&blocks[3]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Settled
        ));
        assert_eq!(chain.final_msg(), msg(4));
        assert!(chain.view().is_empty());
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_held_entry_without_a_block_finalizes_as_an_ancestor() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        finalize_all(&mut chain, &blocks[..1]);
        chain.apply_extension(vec![
            entry(2, msg(1), None),
            entry(3, msg(2), Some(&blocks[1])),
        ]);

        assert!(matches!(
            chain
                .apply_finalized(&[entry(3, msg(2), Some(&blocks[1]))], Slot::from(0))
                .judged[0]
                .verdict,
            Verdict::Settled
        ));
        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());
    }

    #[test]
    fn the_head_reflects_applied_transfers() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_extension(vec![entry(1, MsgId::root(), Some(&genesis))]);

        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = settled(chain.head_state(), 2, genesis.header.hash, vec![tx]);
        chain.apply_extension(vec![entry(2, msg(1), Some(&block2))]);

        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(
            chain
                .head_state()
                .get_account_by_id(to)
                .data
                .native_balance()
                .unwrap(),
            INITIAL_TO_BALANCE + 10
        );
        assert_head_is_the_fold(&chain);
    }

    /// Marks the fold of `view[idx]` with an account no block creates, so a
    /// test can tell a kept fold from a recomputed one.
    fn mark_fold(chain: &mut ChainState, idx: usize) {
        let state = &mut chain.folds[idx].state;
        *state = state
            .clone()
            .with_public_accounts([(marker(), lee::Account::funded(1))]);
    }

    fn marker() -> lee::AccountId {
        lee::AccountId::new([7; 32])
    }

    fn is_marked(state: &V03State) -> bool {
        state.get_account_by_id_ref(marker()).is_some()
    }

    #[test]
    fn a_conflict_keeps_the_folds_both_views_hold() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        mark_fold(&mut chain, 0);

        let block2_prime = competing_block2(&blocks);
        chain.apply_conflict(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(12, msg(1), Some(&block2_prime)),
        ]);

        assert!(is_marked(&chain.folds[0].state));
        assert!(is_marked(chain.head_state()));
        assert_eq!(chain.head_tip().unwrap().hash, block2_prime.header.hash);
    }

    #[test]
    fn a_conflict_from_the_first_entry_refolds_everything() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        mark_fold(&mut chain, 0);

        chain.apply_conflict(vec![
            entry(11, MsgId::root(), Some(&blocks[0])),
            entry(12, msg(11), Some(&blocks[1])),
        ]);

        assert!(!is_marked(chain.head_state()));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_a_folded_block_takes_its_fold() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        mark_fold(&mut chain, 0);

        let outcome =
            chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        assert!(matches!(outcome.judged[0].verdict, Verdict::Settled));
        assert!(is_marked(chain.final_state()));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(2));
    }

    #[test]
    fn finalizing_an_entry_keeps_the_folds_after_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        mark_fold(&mut chain, 1);

        chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        assert!(!is_marked(chain.final_state()));
        assert!(is_marked(chain.head_state()));
        assert_eq!(head_id(&chain), Some(2));
    }

    #[test]
    fn a_redelivery_keeps_the_folds_before_the_entry_it_removes() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(9, msg(1), None),
            entry(2, msg(9), Some(&blocks[1])),
        ]);
        mark_fold(&mut chain, 0);

        chain.apply_finalized(&[entry(9, msg(8), None)], Slot::from(0));

        assert_eq!(chain.view().len(), 2);
        assert!(is_marked(&chain.folds[0].state));
        assert_eq!(head_id(&chain), Some(2));
    }

    #[test]
    fn a_publish_inserted_before_its_child_keeps_the_folds_before_it() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(3, msg(2), Some(&blocks[2])),
        ]);
        mark_fold(&mut chain, 0);

        chain.record_publish(entry(2, msg(1), Some(&blocks[1])));

        assert!(is_marked(&chain.folds[0].state));
        assert!(is_marked(chain.head_state()));
        assert_eq!(head_id(&chain), Some(3));
    }

    #[test]
    fn a_block_the_fold_skipped_is_applied_again_at_finality() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        // As if block 1 had failed transiently while folding, and block 2,
        // no longer chaining, had been skipped too.
        let unfolded = || Fold {
            state: chain.final_state().clone(),
            record: Record::default(),
            events: None,
            verdict: None,
            left: Vec::new(),
            held: false,
            skipped: false,
        };
        chain.folds = vec![unfolded(), unfolded()];

        let outcome =
            chain.apply_finalized(&[entry(1, MsgId::root(), Some(&blocks[0]))], Slot::from(0));

        assert!(matches!(outcome.judged[0].verdict, Verdict::Settled));
        assert_eq!(chain.final_tip().unwrap().hash, blocks[0].header.hash);
        assert_eq!(head_id(&chain), Some(2));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_blocks_the_fold_skipped_refolds_the_entries_after_them() {
        let mut chain = ChainState::new(claimed_initial_state(), ProofStore::new(usize::MAX));
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        // As if blocks 2 and 3 had failed transiently while folding.
        let unfolded = || Fold {
            state: chain.folds[0].state.clone(),
            record: chain.folds[0].record.clone(),
            events: None,
            verdict: None,
            left: Vec::new(),
            held: false,
            skipped: false,
        };
        let (second, third) = (unfolded(), unfolded());
        chain.folds[1] = second;
        chain.folds[2] = third;
        assert_eq!(head_id(&chain), Some(1));

        chain.apply_finalized(&[entry(2, msg(1), Some(&blocks[1]))], Slot::from(0));

        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }
}
