//! Two-tier chain state: an irreversible `final` tier, and a `head` the
//! sequencer builds on, derived by folding `final` over the channel's
//! unfinalized message lineage.

use std::{collections::HashSet, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use common::{HashType, block::Block, transaction::TxEvents};
use lee::V03State;
use log::warn;
use logos_blockchain_core::mantle::ops::channel::MsgId;

use crate::{
    AcceptOutcome, BlockIngestError,
    apply::{Tip, apply_block, validate_against_tip},
};

/// Attempts at a block whose failure may be transient before it counts as invalid.
const APPLY_ATTEMPTS: usize = 3;

/// One inscription on the channel's message lineage.
#[derive(Clone, Debug)]
pub struct ChannelEntry {
    pub msg: MsgId,
    pub parent: MsgId,
    /// `None` for an entry that carries no block: an empty or undecodable payload.
    pub block: Option<Block>,
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

/// The persisted form of the view.
#[derive(BorshSerialize, BorshDeserialize)]
struct StoredView {
    final_msg: [u8; 32],
    entries: Vec<StoredEntry>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredEntry {
    msg: [u8; 32],
    parent: [u8; 32],
    block: Option<Block>,
}

/// The final tier (irreversible, from `finalized`) and the head, which is
/// always `final_state` folded over `view`.
///
/// `view` is the only unfinalized input. The fold applies every entry whose
/// block extends the tip so far and skips the rest, so every node holding the
/// same view derives the same head, and the pin is the view's last entry.
pub struct ChainState {
    final_state: Arc<V03State>,
    final_tip: Option<Tip>,
    /// The newest finalized entry on the message lineage, block or not.
    final_msg: MsgId,
    /// Blocks the final tier applied since the last [`Self::take_newly_final`].
    newly_final: Vec<Block>,

    /// The unfinalized message lineage, oldest first, chained on `final_msg`.
    view: Vec<ChannelEntry>,

    head_state: Arc<V03State>,
    /// The blocks the fold applied, in order.
    head_blocks: Vec<Block>,
}

impl ChainState {
    /// Fresh state anchored at the genesis/initial state, no blocks applied.
    #[must_use]
    pub fn new(initial_state: V03State) -> Self {
        Self::from_final(initial_state, None)
    }

    /// State restored from a persisted final tier, with an empty view.
    #[must_use]
    pub fn from_final(final_state: V03State, final_tip: Option<Tip>) -> Self {
        let final_state = Arc::new(final_state);
        Self {
            head_state: Arc::clone(&final_state),
            final_state,
            final_tip,
            final_msg: MsgId::root(),
            newly_final: Vec::new(),
            view: Vec::new(),
            head_blocks: Vec::new(),
        }
    }

    /// State the sequencer builds its next block on.
    #[must_use]
    pub fn head_state(&self) -> &V03State {
        &self.head_state
    }

    /// A shared handle on the head state, for callers that need to own it.
    #[must_use]
    pub fn share_head_state(&self) -> Arc<V03State> {
        Arc::clone(&self.head_state)
    }

    /// Mutable access to the head state, bypassing the fold. For tests.
    #[must_use]
    pub fn head_state_mut(&mut self) -> &mut V03State {
        Arc::make_mut(&mut self.head_state)
    }

    #[must_use]
    pub fn final_state(&self) -> &V03State {
        &self.final_state
    }

    /// A shared handle on the final state, for callers that need to own it.
    #[must_use]
    pub fn share_final_state(&self) -> Arc<V03State> {
        Arc::clone(&self.final_state)
    }

    /// Parent the next produced block must chain on.
    #[must_use]
    pub fn head_tip(&self) -> Option<Tip> {
        self.head_blocks
            .last()
            .map(Tip::from)
            .or_else(|| self.final_tip.clone())
    }

    /// The blocks the head holds above the final tier.
    #[must_use]
    pub fn head_blocks(&self) -> &[Block] {
        &self.head_blocks
    }

    /// Parent the next inscription must chain on: the view's last entry.
    #[must_use]
    pub fn pin(&self) -> MsgId {
        self.view.last().map_or(self.final_msg, |entry| entry.msg)
    }

    /// Every block the final tier applied since the last call, ancestors a
    /// finalized entry pulled in included.
    pub fn take_newly_final(&mut self) -> Vec<Block> {
        std::mem::take(&mut self.newly_final)
    }

    #[must_use]
    pub const fn final_msg(&self) -> MsgId {
        self.final_msg
    }

    #[must_use]
    pub fn view(&self) -> &[ChannelEntry] {
        &self.view
    }

    #[must_use]
    pub fn final_tip(&self) -> Option<Tip> {
        self.final_tip.clone()
    }

    /// The view and `final_msg` in their persisted form. A skipped entry is
    /// stored without its block: it folds the same either way.
    #[must_use]
    pub fn encode_view(&self) -> Vec<u8> {
        let applied: HashSet<HashType> = self
            .head_blocks
            .iter()
            .map(|block| block.header.hash)
            .collect();
        let stored = StoredView {
            final_msg: self.final_msg.into(),
            entries: self
                .view
                .iter()
                .map(|entry| StoredEntry {
                    msg: entry.msg.into(),
                    parent: entry.parent.into(),
                    block: entry
                        .block
                        .as_ref()
                        .filter(|block| applied.contains(&block.header.hash))
                        .cloned(),
                })
                .collect(),
        };
        borsh::to_vec(&stored).expect("view serializes")
    }

    /// Installs a persisted view on the restored final tier and folds it.
    pub fn restore_view(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let stored = StoredView::try_from_slice(bytes)?;
        self.final_msg = MsgId::from(stored.final_msg);
        self.view = stored
            .entries
            .into_iter()
            .map(|entry| ChannelEntry {
                msg: MsgId::from(entry.msg),
                parent: MsgId::from(entry.parent),
                block: entry.block,
            })
            .collect();
        self.refold();
        Ok(())
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

    /// The whole view at the new tip, on a channel update that dropped entries.
    pub fn apply_conflict(&mut self, canonical: Vec<ChannelEntry>) {
        let mut seen = HashSet::new();
        let canonical: Vec<ChannelEntry> = canonical
            .into_iter()
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
        self.view = canonical;
        self.refold();
    }

    /// Records an inscription of ours, which chains on the pin it was built on.
    pub fn record_publish(&mut self, entry: ChannelEntry) -> PublishRecord {
        if self.view.iter().any(|held| held.msg == entry.msg) {
            return PublishRecord::AlreadyInView;
        }
        let hash = entry.block.as_ref().map(|block| block.header.hash);
        let in_head = |chain: &Self| {
            chain
                .head_blocks
                .iter()
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

    /// A finalized entry, `parent` when the caller knows it. Returns the final
    /// tier's outcome for its block, `None` when it carries none. `final_msg`
    /// moves only on the lineage's next entry; anything else is a re-delivery.
    pub fn apply_finalized(
        &mut self,
        msg: MsgId,
        parent: Option<MsgId>,
        block: Option<&Block>,
    ) -> Option<AcceptOutcome> {
        // Finality is prefix-monotone: an entry chained on a view entry
        // finalizes the view up to it.
        if let Some(parent) = parent
            && let Some(idx) = self.view.iter().position(|entry| entry.msg == parent)
        {
            let ancestors: Vec<ChannelEntry> = self.view[..=idx].to_vec();
            for ancestor in ancestors {
                self.apply_finalized(ancestor.msg, None, ancestor.block.as_ref());
            }
        }

        // The same for the entries before it in the view.
        if let Some(idx) = self.view.iter().position(|entry| entry.msg == msg)
            && idx > 0
        {
            let earlier: Vec<ChannelEntry> = self.view[..idx].to_vec();
            for entry in earlier {
                self.apply_finalized(entry.msg, None, entry.block.as_ref());
            }
        }

        let outcome = block.map(|block| self.apply_final_block(block));
        let held_at = self.view.iter().position(|entry| entry.msg == msg);
        let is_next = matches!(outcome, Some(AcceptOutcome::Applied(_)))
            || parent == Some(self.final_msg)
            || held_at.is_some();
        if !is_next {
            return outcome;
        }

        self.final_msg = msg;
        if let Some(idx) = held_at {
            self.view.drain(..=idx);
            self.trim_head();
        } else {
            // Its siblings in the view, and everything chained on them, can
            // never land; entries chained on it stay.
            let children = self
                .view
                .iter()
                .position(|entry| entry.parent == msg)
                .unwrap_or(self.view.len());
            self.view.drain(..children);
            self.refold();
        }
        outcome
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
        self.refold();
        true
    }

    /// Appends `entry` to the view and folds it onto the head.
    fn push(&mut self, entry: ChannelEntry) {
        if let Some(block) = &entry.block {
            let tip = self.head_tip();
            if let Some(state) = fold_block(tip.as_ref(), block, &self.head_state) {
                self.head_state = state;
                self.head_blocks.push(block.clone());
            }
        }
        self.view.push(entry);
    }

    /// Rebuilds the head by folding `final` over the whole view.
    fn refold(&mut self) {
        let mut state = Arc::clone(&self.final_state);
        let mut tip = self.final_tip.clone();
        let mut blocks = Vec::new();
        for block in self.view.iter().filter_map(|entry| entry.block.as_ref()) {
            if let Some(next) = fold_block(tip.as_ref(), block, &state) {
                state = next;
                tip = Some(Tip::from(block));
                blocks.push(block.clone());
            }
        }
        self.head_state = state;
        self.head_blocks = blocks;
    }

    /// Drops the head blocks the final tier now holds, or refolds when the
    /// two tiers disagree about them.
    fn trim_head(&mut self) {
        let final_id = self.final_tip.as_ref().map(|tip| tip.block_id);
        let cut = self
            .head_blocks
            .iter()
            .take_while(|block| final_id.is_some_and(|id| block.header.block_id <= id))
            .count();
        let final_hash = self.final_tip.as_ref().map(|tip| tip.hash);
        let cut_matches = cut
            .checked_sub(1)
            .is_none_or(|last| Some(self.head_blocks[last].header.hash) == final_hash);
        let rest_chains = self
            .head_blocks
            .get(cut)
            .is_none_or(|block| validate_against_tip(self.final_tip.as_ref(), block).is_ok());
        if !(cut_matches && rest_chains) {
            self.refold();
            return;
        }
        self.head_blocks.drain(..cut);
        if self.head_blocks.is_empty() {
            self.head_state = Arc::clone(&self.final_state);
        }
    }

    /// Applies a finalized block straight to the final tier.
    fn apply_final_block(&mut self, block: &Block) -> AcceptOutcome {
        // The final tip again is a re-delivery. A block below it cannot be
        // checked against the tier, so it is not taken as final; a different
        // block at the tip height falls through to validation and parks.
        if let Some(tip) = &self.final_tip {
            if block.header.block_id == tip.block_id && block.header.hash == tip.hash {
                return AcceptOutcome::AlreadyApplied;
            }
            if block.header.block_id < tip.block_id {
                return AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                    expected: tip.block_id.saturating_add(1),
                    got: block.header.block_id,
                });
            }
        }

        match apply_with_retries(self.final_tip.as_ref(), block, &self.final_state) {
            Ok((state, events)) => {
                self.final_state = state;
                self.final_tip = Some(Tip::from(block));
                self.newly_final.push(block.clone());
                AcceptOutcome::Applied(vec![(block.header.block_id, events)])
            }
            Err(err) => AcceptOutcome::Parked(err),
        }
    }
}

/// `state` after `block` when it extends `tip`, `None` when the fold skips it.
fn fold_block(tip: Option<&Tip>, block: &Block, state: &Arc<V03State>) -> Option<Arc<V03State>> {
    validate_against_tip(tip, block).ok()?;
    match apply_with_retries(tip, block, state) {
        Ok((next, _)) => Some(next),
        Err(err) => {
            warn!(
                "Skipping channel block {} ({}): {err}",
                block.header.block_id, block.header.hash
            );
            None
        }
    }
}

/// Applies `block` on a copy of `state`, retrying a failure that may be transient.
fn apply_with_retries(
    tip: Option<&Tip>,
    block: &Block,
    state: &Arc<V03State>,
) -> Result<(Arc<V03State>, Vec<TxEvents>), BlockIngestError> {
    let mut attempt = 1;
    loop {
        let mut scratch = Arc::clone(state);
        match apply_block(tip, block, Arc::make_mut(&mut scratch)) {
            Ok(block_events) => return Ok((scratch, block_events)),
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
            block: block.cloned(),
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
        let mut on_block1 = ChainState::new(claimed_initial_state());
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
        let mut fresh = ChainState::from_final(chain.final_state().clone(), chain.final_tip());
        fresh.final_msg = chain.final_msg;
        fresh.view = chain.view.clone();
        fresh.refold();
        let hashes = |blocks: &[Block]| {
            blocks
                .iter()
                .map(|block| block.header.hash)
                .collect::<Vec<_>>()
        };
        assert_eq!(hashes(&fresh.head_blocks), hashes(&chain.head_blocks));
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
            test_utils::sequencer_sign_key_for_testing,
            transaction::{LeeTransaction, clock_invocation, fee_invocation},
        };
        let timestamp = id.saturating_mul(100);
        let summary = crate::apply::derive_block_summary(state, &txs, id, timestamp)
            .expect("test transactions settle");
        let producer = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
            &sequencer_sign_key_for_testing(),
        ));
        let mut transactions = txs;
        transactions.push(LeeTransaction::Public(fee_invocation(summary, producer)));
        transactions.push(LeeTransaction::Public(clock_invocation(timestamp)));
        HashableBlockData {
            block_id: id,
            prev_block_hash: prev,
            timestamp,
            transactions,
        }
        .into_pending_block(&sequencer_sign_key_for_testing())
    }

    #[test]
    fn an_extension_advances_the_head_and_the_pin() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        assert_eq!(head_id(&chain), Some(2));
        assert_eq!(chain.pin(), msg(2));
        assert!(chain.final_tip().is_none());
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn an_entry_without_a_block_moves_the_pin_but_not_the_head() {
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
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
    fn an_extension_is_appended_as_the_sdk_sends_it() {
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        let head_before = state_bytes(chain.head_state());

        let outcome = chain.apply_finalized(msg(2), Some(msg(1)), Some(&blocks[1]));

        // Block 1 finalized first, as the parent of the entry that finalized.
        assert!(matches!(outcome, Some(AcceptOutcome::Applied(_))));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_eq!(chain.final_msg(), msg(2));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_eq!(state_bytes(chain.head_state()), head_before);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_sibling_drops_the_view() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        // A different entry on root finalizes, with no block.
        chain.apply_finalized(msg(20), Some(MsgId::root()), None);

        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(20));
        assert_eq!(head_id(&chain), None);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_redelivery_leaves_the_view_alone() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

        // Block 1 again, and a garbage entry the lineage already passed.
        assert!(matches!(
            chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0])),
            Some(AcceptOutcome::AlreadyApplied)
        ));
        chain.apply_finalized(msg(30), Some(msg(31)), None);

        assert_eq!(chain.final_msg(), msg(1));
        assert_eq!(chain.view().len(), 2);
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_finalized_block_the_view_never_held_resyncs_the_lineage() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_extension(vec![entry(1, MsgId::root(), Some(&blocks[0]))]);

        // Block 2 on an entry we never saw: the final tier takes it.
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));
        let outcome = chain.apply_finalized(msg(9), Some(msg(8)), Some(&blocks[1]));

        assert!(matches!(outcome, Some(AcceptOutcome::Applied(_))));
        assert_eq!(chain.final_msg(), msg(9));
        assert_eq!(chain.pin(), msg(9));
        assert_eq!(head_id(&chain), Some(2));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn our_publish_extends_the_head_when_it_chains_on_the_pin() {
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        let broken = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&broken)),
            entry(3, msg(2), Some(&blocks[1])),
        ]);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

        let mut restored = ChainState::from_final(chain.final_state().clone(), chain.final_tip());
        restored.restore_view(&chain.encode_view()).unwrap();

        assert_eq!(restored.final_msg(), msg(1));
        assert_eq!(restored.pin(), msg(3));
        assert!(
            restored.view()[0].block.is_none(),
            "a skipped block is not stored"
        );
        assert_eq!(head_id(&restored), Some(2));
        assert_eq!(
            state_bytes(restored.head_state()),
            state_bytes(chain.head_state())
        );
    }

    #[test]
    fn newly_final_blocks_include_the_ancestors_a_finalized_entry_pulls_in() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks[..2]));

        chain.apply_finalized(msg(3), Some(msg(2)), Some(&blocks[2]));

        let ids: Vec<u64> = chain
            .take_newly_final()
            .iter()
            .map(|block| block.header.block_id)
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(chain.take_newly_final().is_empty());
    }

    #[test]
    fn a_finalized_entry_finalizes_its_ancestors_in_the_view() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks[..2]));

        // Entry 3 was never adopted, but it chains on entry 2.
        let outcome = chain.apply_finalized(msg(3), Some(msg(2)), Some(&blocks[2]));

        assert!(matches!(outcome, Some(AcceptOutcome::Applied(_))));
        assert_eq!(chain.final_tip().unwrap().block_id, 3);
        assert_eq!(chain.final_msg(), msg(3));
        assert!(chain.view().is_empty());
        assert_eq!(head_id(&chain), Some(3));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_block_reinscribed_under_a_new_entry_is_already_final() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(1);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

        // The same block again, as the next entry on the lineage.
        let outcome = chain.apply_finalized(msg(2), Some(msg(1)), Some(&blocks[0]));

        assert!(matches!(outcome, Some(AcceptOutcome::AlreadyApplied)));
        assert_eq!(chain.final_tip().unwrap().hash, blocks[0].header.hash);
        assert_eq!(chain.final_msg(), msg(2), "the lineage moves past the copy");
    }

    #[test]
    fn a_hash_alias_with_the_wrong_id_is_not_absorbed() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

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
            chain.apply_finalized(msg(2), Some(msg(1)), Some(&alias)),
            Some(AcceptOutcome::Parked(BlockIngestError::HashMismatch { .. }))
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_an_unheld_parent_keeps_its_children_in_the_view() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(5);
        for (block, n) in blocks[..3].iter().zip(1_u8..) {
            let parent = if n == 1 { MsgId::root() } else { msg(n - 1) };
            chain.apply_finalized(msg(n), Some(parent), Some(block));
        }
        // Entry 5 arrives before entry 4 finalizes.
        chain.apply_extension(vec![entry(5, msg(4), Some(&blocks[4]))]);
        assert_eq!(head_id(&chain), Some(3));

        chain.apply_finalized(msg(4), Some(msg(3)), Some(&blocks[3]));

        assert_eq!(chain.view().len(), 1);
        assert_eq!(chain.pin(), msg(5));
        assert_eq!(head_id(&chain), Some(5));
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_foreign_block_below_the_final_tip_is_not_taken_as_final() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        for (block, n) in blocks.iter().zip(1_u8..) {
            let parent = if n == 1 { MsgId::root() } else { msg(n - 1) };
            chain.apply_finalized(msg(n), Some(parent), Some(block));
        }
        let foreign = competing_block2(&blocks);

        assert!(matches!(
            chain.apply_finalized(msg(4), Some(msg(3)), Some(&foreign)),
            Some(AcceptOutcome::Parked(_))
        ));
        assert_eq!(chain.final_tip().unwrap().hash, blocks[2].header.hash);
    }

    #[test]
    fn finalizing_past_a_skipped_entry_trims_the_head() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        chain.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&bad)),
            entry(3, msg(2), Some(&blocks[1])),
            entry(4, msg(3), Some(&blocks[2])),
        ]);
        let head_before = state_bytes(chain.head_state());

        chain.apply_finalized(msg(3), Some(msg(2)), Some(&blocks[1]));

        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_eq!(chain.final_msg(), msg(3));
        assert_eq!(chain.view().len(), 1);
        assert_eq!(head_id(&chain), Some(3));
        assert_eq!(state_bytes(chain.head_state()), head_before);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn finalizing_a_rival_of_the_head_refolds_onto_it() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));
        let rival = competing_block2(&blocks);

        chain.apply_finalized(msg(9), Some(msg(1)), Some(&rival));

        assert!(chain.view().is_empty());
        assert!(chain.head_blocks().is_empty());
        assert_eq!(chain.head_tip().unwrap().hash, rival.header.hash);
        assert_eq!(
            state_bytes(chain.head_state()),
            state_bytes(chain.final_state())
        );
    }

    #[test]
    fn a_restored_view_finalizes_like_the_live_one() {
        let mut live = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        live.apply_extension(vec![
            entry(1, MsgId::root(), Some(&blocks[0])),
            entry(2, msg(1), Some(&bad)),
            entry(3, msg(2), Some(&blocks[1])),
        ]);
        let mut restored = ChainState::new(claimed_initial_state());
        restored.restore_view(&live.encode_view()).unwrap();
        assert_eq!(restored.encode_view(), live.encode_view());

        for chain in [&mut live, &mut restored] {
            chain.apply_finalized(msg(2), Some(msg(1)), Some(&bad));
            assert_eq!(chain.final_msg(), msg(2));
            assert_eq!(chain.view().len(), 1);
            assert_eq!(head_id(chain), Some(2));
        }
        assert_eq!(restored.encode_view(), live.encode_view());
    }

    #[test]
    fn a_publish_is_stale_against_the_pin_not_the_head() {
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_extension(entries_for(&blocks));

        assert_eq!(
            chain.record_publish(entry(9, msg(2), Some(&blocks[1]))),
            PublishRecord::Skipped
        );
        assert_eq!(chain.head_blocks().len(), 2);
    }

    #[test]
    fn our_publish_goes_before_a_peer_entry_that_chained_on_it_first() {
        let mut chain = ChainState::new(claimed_initial_state());
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
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        let mut canonical = entries_for(&blocks);
        canonical.push(canonical[1].clone());

        chain.apply_conflict(canonical);

        assert_eq!(chain.view().len(), 2);
        chain.apply_finalized(msg(2), Some(msg(1)), Some(&blocks[1]));
        assert!(chain.view().is_empty());
        assert_eq!(chain.pin(), msg(2));
    }

    #[test]
    fn finalizing_a_held_entry_finalizes_the_entries_before_it() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(3);
        chain.apply_extension(entries_for(&blocks));

        // Out of order, with no parent to go on.
        chain.apply_finalized(msg(3), None, Some(&blocks[2]));
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

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
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(1);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));

        let bad = produce_dummy_block(3, Some(blocks[0].header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(2), Some(msg(1)), Some(&bad)),
            Some(AcceptOutcome::Parked(_))
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 1);
        assert_eq!(chain.final_msg(), msg(2));
    }

    #[test]
    fn a_valid_finalized_successor_applies_after_an_invalid_one() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));
        let bad = produce_dummy_block(3, Some(blocks[0].header.hash), vec![]);
        chain.apply_finalized(msg(2), Some(msg(1)), Some(&bad));

        assert!(matches!(
            chain.apply_finalized(msg(3), Some(msg(2)), Some(&blocks[1])),
            Some(AcceptOutcome::Applied(_))
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
        assert_head_is_the_fold(&chain);
    }

    #[test]
    fn a_conflicting_finalized_block_at_the_final_tip_parks() {
        let mut chain = ChainState::new(claimed_initial_state());
        let blocks = chain_of(2);
        chain.apply_finalized(msg(1), Some(MsgId::root()), Some(&blocks[0]));
        chain.apply_finalized(msg(2), Some(msg(1)), Some(&blocks[1]));

        let block2_prime = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(3), Some(msg(1)), Some(&block2_prime)),
            Some(AcceptOutcome::Parked(_))
        ));
        assert_eq!(chain.final_tip().unwrap().block_id, 2);
    }

    #[test]
    fn the_head_reflects_applied_transfers() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
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
                .balance()
                .unwrap(),
            INITIAL_TO_BALANCE + 10
        );
        assert_head_is_the_fold(&chain);
    }
}
