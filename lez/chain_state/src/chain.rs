//! Two-tier chain state: a reorg-able `head` the sequencer builds on, plus an
//! irreversible `final` tier.

use std::{collections::HashMap, sync::Arc};

use common::{HashType, block::Block};
use lee::V03State;
use log::warn;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::{
    AcceptOutcome, BlockIngestError, StallReason,
    apply::{Tip, apply_block},
};

/// An inscription of ours the channel has not reported on yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct OwnPublish {
    /// The entry it chained on.
    parent: MsgId,
    /// The entry it created.
    msg: MsgId,
}

/// What one channel update did to each tier, aligned with the blocks passed in.
pub struct FollowOutcome {
    /// One per adopted block, in order.
    pub adopted: Vec<AcceptOutcome>,
    /// One per finalized block, in order.
    pub finalized: Vec<AcceptOutcome>,
    /// Whether the update's channel tip was believed and became the new pin.
    pub cursor_moved: bool,
}

/// The head tier (reorg-able, from `adopted`/`orphaned`) over the final tier
/// (irreversible, from `finalized`).
///
/// `head_state` is given by `final_state` replayed through `head_blocks`.
///
/// Only the final tier stalls: an invalid `adopted` block just freezes the
/// head tip and self-heals via reorg or finalization.
pub struct ChainState {
    final_state: Arc<V03State>,
    final_tip: Option<Tip>,
    final_stall: Option<StallReason>,

    head_state: Arc<V03State>,
    head_blocks: Vec<Block>,

    /// The channel tip as of the last processed sdk snapshot (a follow
    /// update's checkpoint, or our own publish), block or not: an ignorable
    /// inscription (garbage, an invalid block, a config op) moves the channel
    /// tip without moving the head, and the next publish must chain on it.
    channel_cursor: Option<MsgId>,

    /// Our own inscriptions the channel has not reported on yet, keyed by the
    /// block each carried.
    own_publishes: HashMap<HashType, OwnPublish>,
}

impl ChainState {
    /// Fresh state anchored at the genesis/initial state, no blocks applied.
    #[must_use]
    pub fn new(initial_state: V03State) -> Self {
        Self::from_final(initial_state, None)
    }

    /// State restored from a persisted final tier; head mirrors final.
    #[must_use]
    pub fn from_final(final_state: V03State, final_tip: Option<Tip>) -> Self {
        let final_state = Arc::new(final_state);
        Self {
            head_state: Arc::clone(&final_state),
            final_state,
            final_tip,
            head_blocks: Vec::new(),
            final_stall: None,
            channel_cursor: None,
            own_publishes: HashMap::new(),
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

    /// Mutable access to the head state. Bypasses the `head_blocks` invariant, so
    /// it is meant for tests and low-level callers.
    ///
    /// Copies the state while a handle from [`Self::share_head_state`] is alive.
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

    /// Parent the next inscription must be pinned on. The cursor alone: a
    /// restored head block carries no `MsgId`, so the head is not a fallback.
    #[must_use]
    pub const fn pin_parent(&self) -> Option<MsgId> {
        self.channel_cursor
    }

    #[must_use]
    pub const fn channel_cursor(&self) -> Option<MsgId> {
        self.channel_cursor
    }

    /// Whether the pin names an inscription of ours the channel has yet to report.
    #[must_use]
    pub fn pin_is_ours(&self) -> bool {
        self.own_publishes
            .values()
            .any(|publish| Some(publish.msg) == self.channel_cursor)
    }

    /// Moves the cursor to an entry the channel reported.
    const fn set_channel_cursor(&mut self, msg: MsgId) {
        self.channel_cursor = Some(msg);
    }

    /// Restores a persisted cursor at startup. Records nothing as ours: a
    /// previous run's inscriptions are not in flight for this one.
    pub const fn restore_cursor(&mut self, msg: MsgId) {
        self.set_channel_cursor(msg);
    }

    /// Records an inscription of ours over a block the head already holds, and
    /// pins on it. The entry it chained on is whatever the pin was.
    pub fn record_own_inscription(&mut self, msg: MsgId, block: HashType) {
        let parent = self.channel_cursor.unwrap_or_else(MsgId::root);
        self.own_publishes.insert(block, OwnPublish { parent, msg });
        self.channel_cursor = Some(msg);
    }

    /// Drops our record of every block this update reports on. The sdk omits our
    /// own landed block from `adopted` except on a branch change, so `finalized`
    /// carries the ordinary case.
    fn resolve_own_publishes(&mut self, reports: [&[Block]; 3]) {
        for block in reports.into_iter().flatten() {
            self.own_publishes.remove(&block.header.hash);
        }
    }

    #[must_use]
    pub fn final_tip(&self) -> Option<Tip> {
        self.final_tip.clone()
    }

    #[must_use]
    pub const fn final_stall(&self) -> Option<&StallReason> {
        self.final_stall.as_ref()
    }

    /// Position of a head entry, matched by block hash at the same claimed
    /// height: a hash collision with a different `block_id` is malformed and
    /// must fall through to validation. Channel `MsgId`s are not part of the
    /// match — a re-inscription changes the id but never the hash.
    fn head_position_of(&self, block: &Block) -> Option<usize> {
        self.head_blocks.iter().position(|held| {
            held.header.block_id == block.header.block_id && held.header.hash == block.header.hash
        })
    }

    /// Applies an adopted head block.
    ///
    /// The adopted stream is authoritative: a competitor at a height
    /// the head already holds reorgs the head back to that height with
    /// no orphan event required.
    ///
    /// On failure the head stays unchanged and no stall is recorded.
    pub fn apply_adopted(&mut self, block: &Block) -> AcceptOutcome {
        if self.head_position_of(block).is_some() {
            return AcceptOutcome::AlreadyApplied;
        }

        // If we receive a pre-final adoption, its an SDK fault; just log and ignore it
        if let Some(final_tip) = &self.final_tip
            && block.header.block_id <= final_tip.block_id
        {
            // The final tier is irreversible: a matching block here is a stale
            // re-delivery, a conflicting one an SDK contract breach.
            if block.header.block_id == final_tip.block_id && block.header.hash != final_tip.hash {
                warn!(
                    "Ignoring adopted block {} with hash {} conflicting with the \
                     finalized block ({}) at this height",
                    block.header.block_id, block.header.hash, final_tip.hash
                );
            }
            return AcceptOutcome::AlreadyApplied;
        }

        // A tip extension applies on the current head state, a lower-or-equal
        // id rebuilds the state at the competitor's parent instead.
        //
        // If adoptions are over the current head, `reorg_at` is None.
        let reorg_at = self
            .head_blocks
            .iter()
            .position(|held| held.header.block_id >= block.header.block_id);
        let (mut scratch, tip) = match reorg_at {
            // continue from the tip
            None => (Arc::clone(&self.head_state), self.head_tip()),
            // reorg upto `idx`
            Some(idx) => self.replay_head_prefix(idx),
        };

        match apply_block(tip.as_ref(), block, Arc::make_mut(&mut scratch)) {
            Ok(()) => {
                // now that `apply_block` succeeded, actually reorg the head
                if let Some(idx) = reorg_at {
                    self.head_blocks.truncate(idx);
                }
                self.head_state = scratch;
                self.head_blocks.push(block.to_owned());
                AcceptOutcome::Applied
            }
            Err(err) => AcceptOutcome::Parked(err),
        }
    }

    /// Applies a block we produced ourselves.
    ///
    /// Unlike [`Self::apply_adopted`] this never reorgs: our block is not on
    /// the channel yet, so it may only *extend* the head. A head already at
    /// (or past) this height means a peer's block won the race on the
    /// channel — ours is stale and the caller drops it.
    pub fn apply_produced(&mut self, block: &Block, this_msg: MsgId) -> AcceptOutcome {
        if self
            .head_tip()
            .is_some_and(|tip| block.header.block_id <= tip.block_id)
        {
            return AcceptOutcome::AlreadyApplied;
        }
        let outcome = self.apply_adopted(block);
        // Only a block that became the head is ours to pin on.
        if matches!(outcome, AcceptOutcome::Applied) {
            self.record_own_inscription(this_msg, block.header.hash);
        }
        outcome
    }

    /// Reverts an orphaned head block and everything after it, then re-derives head.
    pub fn revert_orphan(&mut self, block: &Block) {
        if let Some(idx) = self.head_position_of(block) {
            self.head_blocks.truncate(idx);
            self.rederive_head();
        }
    }

    /// One channel update: revert every `orphaned` (one truncate + re-derive),
    /// then apply every `adopted` in order. Outcomes align with `adopted`.
    pub fn apply_channel_update(
        &mut self,
        orphaned: &[Block],
        adopted: &[Block],
    ) -> Vec<AcceptOutcome> {
        let earliest = orphaned
            .iter()
            .filter_map(|block| self.head_position_of(block))
            .min();
        if let Some(idx) = earliest {
            self.head_blocks.truncate(idx);
            self.rederive_head();
        }
        adopted
            .iter()
            .map(|block| self.apply_adopted(block))
            .collect()
    }

    /// A finalized block replayed off the channel at startup. The channel
    /// replays in order, so a block that applies leaves its own inscription as
    /// the tip so far.
    pub fn apply_reconstructed(
        &mut self,
        block: &Block,
        l1_slot: Slot,
        this_msg: MsgId,
    ) -> AcceptOutcome {
        let outcome = self.apply_finalized(block, l1_slot);
        if matches!(
            outcome,
            AcceptOutcome::Applied | AcceptOutcome::AlreadyApplied
        ) {
            self.set_channel_cursor(this_msg);
        }
        outcome
    }

    /// One channel update applied as a whole: the head reorg, the finalized
    /// blocks, and the channel tip they leave behind. The only way a
    /// channel-reported tip reaches the cursor.
    pub fn apply_follow(
        &mut self,
        orphaned: &[Block],
        adopted: &[Block],
        finalized: &[Block],
        finalized_slot: Slot,
        channel_tip: MsgId,
    ) -> FollowOutcome {
        // Before the tip is judged, so this update's news frees its own parents.
        self.resolve_own_publishes([orphaned, adopted, finalized]);

        let adopted_outcomes = self.apply_channel_update(orphaned, adopted);
        let finalized_outcomes = finalized
            .iter()
            .map(|block| self.apply_finalized(block, finalized_slot))
            .collect();

        let cursor_moved = self.cursor_may_move_to(channel_tip);
        if cursor_moved {
            self.set_channel_cursor(channel_tip);
        }
        FollowOutcome {
            adopted: adopted_outcomes,
            finalized: finalized_outcomes,
            cursor_moved,
        }
    }

    /// Whether a channel update may move the cursor onto `channel_tip`. A tip we
    /// already chained an unreported block on publishes on the wrong parent.
    fn cursor_may_move_to(&self, channel_tip: MsgId) -> bool {
        if let Some(publish) = self
            .own_publishes
            .values()
            .find(|publish| publish.parent == channel_tip)
        {
            warn!(
                "Ignoring channel tip {channel_tip:?}: our unreported {:?} already chains on it",
                publish.msg
            );
            return false;
        }
        true
    }

    /// Rebuilds one head entry from a persisted block, applying it in place (the
    /// caller treats `Err` as fatal).
    pub fn restore_head_block(&mut self, block: Block) -> Result<(), BlockIngestError> {
        apply_block(
            self.head_tip().as_ref(),
            &block,
            Arc::make_mut(&mut self.head_state),
        )?;
        self.head_blocks.push(block);
        Ok(())
    }

    /// A finalized inscription. In steady state the block is already in head and is
    /// moved into `final`; on backfill (not in head) it is applied directly and may
    /// set `final_stall`.
    pub fn apply_finalized(&mut self, block: &Block, l1_slot: Slot) -> AcceptOutcome {
        if let Some(idx) = self.head_position_of(block) {
            self.finalize_through(idx);
            return AcceptOutcome::Applied;
        }

        // Finality is prefix-monotone: a finalized block chaining on an
        // unfinalized head entry finalizes that prefix too.
        if let Some(idx) = self
            .head_blocks
            .iter()
            .position(|held| held.header.hash == block.header.prev_block_hash)
        {
            self.finalize_through(idx);
        }
        self.apply_finalized_direct(block, l1_slot)
    }

    /// Moves `head_blocks[0..=idx]` into the final tier (already validated in head).
    fn finalize_through(&mut self, idx: usize) {
        let finalized: Vec<Block> = self.head_blocks.drain(0..=idx).collect();
        for block in finalized {
            apply_block(
                self.final_tip.as_ref(),
                &block,
                Arc::make_mut(&mut self.final_state),
            )
            .expect("validated head block must apply to the final tier");
            self.final_tip = Some(Tip::from(&block));
        }
        self.final_stall = None;
    }

    /// Applies a finalized block straight to the final tier. On success the
    /// finalized chain is authoritative, so head rebases onto it.
    fn apply_finalized_direct(&mut self, block: &Block, l1_slot: Slot) -> AcceptOutcome {
        // A finalized block at or below the final tip is a re-delivery:
        // idempotent. A *different* block at the tip height falls through
        // to validation and parks.
        if let Some(tip) = &self.final_tip
            && (block.header.block_id < tip.block_id
                || (block.header.block_id == tip.block_id && block.header.hash == tip.hash))
        {
            return AcceptOutcome::AlreadyApplied;
        }

        let mut scratch = Arc::clone(&self.final_state);
        match apply_block(self.final_tip.as_ref(), block, Arc::make_mut(&mut scratch)) {
            Ok(()) => {
                self.final_state = scratch;
                self.final_tip = Some(Tip::from(block));
                self.final_stall = None;
                // Any head suffix dropped here was already reverted as
                // `orphaned` earlier in the same channel update (the sdk
                // orders orphans before their finalized replacement), so its
                // txs are back in the caller's mempool.
                self.head_blocks.clear();
                self.head_state = Arc::clone(&self.final_state);
                AcceptOutcome::Applied
            }
            Err(err) => {
                self.record_final_stall(block, l1_slot, err.clone());
                AcceptOutcome::Parked(err)
            }
        }
    }

    /// Rebuilds `head_state` from the final tier plus the current `head_blocks`.
    fn rederive_head(&mut self) {
        self.head_state = self.replay_head_prefix(self.head_blocks.len()).0;
    }

    /// State and tip after replaying `head_blocks[..count]` on the final tier.
    fn replay_head_prefix(&self, count: usize) -> (Arc<V03State>, Option<Tip>) {
        let mut state = Arc::clone(&self.final_state);
        let mut tip = self.final_tip.clone();
        for block in &self.head_blocks[..count] {
            apply_block(tip.as_ref(), block, Arc::make_mut(&mut state))
                .expect("validated head blocks must replay");
            tip = Some(Tip::from(block));
        }
        (state, tip)
    }

    /// First stall is stored verbatim; later ones only bump `orphans_since`.
    fn record_final_stall(&mut self, block: &Block, l1_slot: Slot, error: BlockIngestError) {
        self.final_stall = Some(self.final_stall.take().map_or_else(
            || StallReason::new(Some(&block.header), l1_slot, error),
            StallReason::escalate,
        ));
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

    fn slot(n: u64) -> Slot {
        Slot::from(n)
    }

    /// The shared initial state with the test producer's reward account claimed,
    /// simulating the stake a real sequencer holds before producing: fee
    /// settlement credits it, and crediting an unclaimed account is rejected.
    fn claimed_initial_state() -> V03State {
        let mut state = initial_state(true);
        common::test_utils::claim_producer_account(&mut state);
        state
    }

    /// `head_state` equals `final_state` replayed through `head_blocks`.
    fn assert_head_matches_replay(chain: &ChainState) {
        let mut state = Arc::clone(&chain.final_state);
        let mut tip = chain.final_tip.clone();
        for block in &chain.head_blocks {
            apply_block(tip.as_ref(), block, Arc::make_mut(&mut state))
                .expect("head blocks must replay");
            tip = Some(Tip::from(block));
        }
        assert_eq!(
            borsh::to_vec(state.as_ref()).expect("state serializes"),
            borsh::to_vec(chain.head_state()).expect("state serializes"),
            "head_state must equal final_state replayed through head_blocks"
        );
    }

    /// Builds a block whose fee transaction settles `txs` against `state`, and
    /// returns the state after it, so forks can branch from any position.
    fn settled(
        state: &V03State,
        id: u64,
        prev: HashType,
        txs: Vec<common::transaction::LeeTransaction>,
    ) -> (common::block::Block, V03State) {
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
        let block = HashableBlockData {
            block_id: id,
            prev_block_hash: prev,
            timestamp,
            transactions,
        }
        .into_pending_block(&sequencer_sign_key_for_testing());
        let mut next = state.clone();
        crate::apply::apply_block_to_state(&block, &mut next).expect("settled block applies");
        (block, next)
    }

    #[test]
    fn adopted_blocks_advance_head() {
        let mut chain = ChainState::new(claimed_initial_state());

        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_adopted(&genesis),
            AcceptOutcome::Applied
        ));
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block2),
            AcceptOutcome::Applied
        ));

        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        // Nothing finalized yet.
        assert!(chain.final_tip().is_none());
    }

    #[test]
    fn adopted_bad_block_freezes_head_without_stall() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        // Skips ahead (id 3 while head tip is 1).
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&bad),
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 2,
                got: 3
            })
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
        assert!(
            chain.final_stall().is_none(),
            "head freeze records no stall"
        );
    }

    #[test]
    fn adopted_is_idempotent() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        assert!(matches!(
            chain.apply_adopted(&genesis),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
    }

    #[test]
    fn orphan_reverts_head() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        chain.apply_adopted(&block3);

        chain.revert_orphan(&block3);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);

        // A competing block 3 now applies cleanly on block 2.
        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block3_prime),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn channel_update_reverts_then_applies() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        chain.apply_adopted(&block3);

        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let outcomes = chain.apply_channel_update(&[block3], &[block3_prime]);
        assert!(matches!(outcomes.as_slice(), [AcceptOutcome::Applied]));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn finalize_moves_head_into_final() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        chain.apply_adopted(&block3);

        // Finalize through block 2.
        assert!(matches!(
            chain.apply_finalized(&block2, slot(100)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        // Head tip unchanged; head still ends at 3.
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn backfill_applies_directly_to_final() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_finalized(&genesis, slot(10)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 1);
        // Head mirrors final during backfill.
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
    }

    #[test]
    fn invalid_finalized_block_sets_final_stall() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(&genesis, slot(10));

        // Skip-ahead finalized block, not in head: parks the final tier.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(&bad, slot(20)),
            AcceptOutcome::Parked(_)
        ));
        let stall = chain.final_stall().expect("final stall recorded");
        assert_eq!(stall.block_id, Some(3));
    }

    #[test]
    fn orphaning_a_suffix_rederives_head_state() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        let s1 = chain.head_state().clone();
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&s1, 2, genesis.header.hash, vec![tx2]);
        chain.apply_adopted(&block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        chain.apply_adopted(&block3);
        let tx4 = create_transaction_native_token_transfer(from, 2, to, 10, &sign_key);
        let (block4, _s4) = settled(&s3, 4, block3.header.hash, vec![tx4]);
        chain.apply_adopted(&block4);

        // Orphaning block 3 drops the whole suffix (3 and 4).
        chain.revert_orphan(&block3);

        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 10
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn channel_update_replaces_multi_block_suffix() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        let s1 = chain.head_state().clone();
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&s1, 2, genesis.header.hash, vec![tx2]);
        chain.apply_adopted(&block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        chain.apply_adopted(&block3);
        let tx4 = create_transaction_native_token_transfer(from, 2, to, 10, &sign_key);
        let (block4, _s4) = settled(&s3, 4, block3.header.hash, vec![tx4]);
        chain.apply_adopted(&block4);

        // A competing branch replaces blocks 3 and 4; orphans arrive unordered.
        let tx3_prime = create_transaction_native_token_transfer(from, 1, to, 20, &sign_key);
        let (block3_prime, s3_prime) = settled(&s2, 3, block2.header.hash, vec![tx3_prime]);
        let tx4_prime = create_transaction_native_token_transfer(from, 2, to, 30, &sign_key);
        let (block4_prime, _s4_prime) =
            settled(&s3_prime, 4, block3_prime.header.hash, vec![tx4_prime]);

        let outcomes = chain.apply_channel_update(&[block4, block3], &[block3_prime, block4_prime]);

        assert!(matches!(
            outcomes.as_slice(),
            [AcceptOutcome::Applied, AcceptOutcome::Applied]
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 4);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 60
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn adopted_only_channel_update_replaces_suffix() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);
        let s1 = chain.head_state().clone();
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&s1, 2, genesis.header.hash, vec![tx2]);
        chain.apply_adopted(&block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, _s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        chain.apply_adopted(&block3);

        // The replacement branch arrives with no orphan events: the adopted
        // list alone reorgs the head.
        let tx2_prime = create_transaction_native_token_transfer(from, 0, to, 20, &sign_key);
        let (block2_prime, s2_prime) = settled(&s1, 2, genesis.header.hash, vec![tx2_prime]);
        let tx3_prime = create_transaction_native_token_transfer(from, 1, to, 30, &sign_key);
        let (block3_prime, _s3_prime) =
            settled(&s2_prime, 3, block2_prime.header.hash, vec![tx3_prime]);

        let outcomes = chain.apply_channel_update(&[], &[block2_prime, block3_prime]);

        assert!(matches!(
            outcomes.as_slice(),
            [AcceptOutcome::Applied, AcceptOutcome::Applied]
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 50
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn channel_update_ignores_unknown_orphan() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);

        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let unknown = produce_dummy_block(9, Some(HashType([7; 32])), vec![]);
        let outcomes = chain.apply_channel_update(&[unknown], &[block3]);

        assert!(matches!(outcomes.as_slice(), [AcceptOutcome::Applied]));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn adopted_competitor_reorgs_head_without_orphan_event() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);
        let s1 = chain.head_state().clone();
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&s1, 2, genesis.header.hash, vec![tx2]);
        chain.apply_adopted(&block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, _s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        chain.apply_adopted(&block3);

        // A valid competitor at height 2, no orphan events: the head reorgs
        // back onto it, dropping the old 2..=3 suffix and its transfers.
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block2_prime),
            AcceptOutcome::Applied
        ));
        let tip = chain.head_tip().expect("head tip");
        assert_eq!(tip.block_id, 2);
        assert_eq!(tip.hash, block2_prime.header.hash);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn produced_block_losing_a_race_does_not_reorg_the_head() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        // A peer's block wins height 2 on the channel.
        let peer = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(&peer);

        // Our own block at that height is not on the channel, so — unlike an
        // adopted competitor — it must not reorg the head onto itself.
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let ours = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        assert!(matches!(
            chain.apply_produced(&ours, msg(2)),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(chain.head_tip().expect("head tip").hash, peer.header.hash);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn produced_block_extending_the_head_applies() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        let ours = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_produced(&ours, msg(2)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_tip().expect("head tip").hash, ours.header.hash);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn invalid_adopted_competitor_leaves_head_intact() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        chain.apply_adopted(&block3);

        // A competitor at height 2 with a bogus parent parks; the truncation
        // is not committed, so the 2..=3 suffix survives.
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_adopted(&bad),
            AcceptOutcome::Parked(BlockIngestError::BrokenChainLink { .. })
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn adopted_conflicting_with_final_tip_is_ignored() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(&genesis, slot(10));
        chain.apply_finalized(&block2, slot(20));

        // Finalized is irreversible: an adopted competitor at (or below) the
        // final tip is ignored, not reorged onto.
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block2_prime),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            chain.final_tip().expect("final tip").hash,
            block2.header.hash
        );
        assert_eq!(chain.head_tip().expect("head tip").hash, block2.header.hash);
        assert_head_matches_replay(&chain);
    }

    /// The pin parent is the cursor alone: a head block never stands in for
    /// it, so a restored placeholder id can never reach a publish.
    #[test]
    fn pin_parent_follows_the_cursor_and_never_the_head() {
        let mut chain = ChainState::new(claimed_initial_state());
        assert_eq!(chain.pin_parent(), None);

        let block1 = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_adopted(&block1),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.pin_parent(), None, "the head is not a pin source");

        // Garbage moved the channel tip; the head stays, the pin follows.
        chain.set_channel_cursor(msg(9));
        assert_eq!(chain.pin_parent(), Some(msg(9)));
    }

    /// A head holding a block of ours, published on `parent` and pinned on `ours`.
    fn chain_with_our_block(parent: MsgId, ours: MsgId) -> (ChainState, Block) {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_adopted(&genesis),
            AcceptOutcome::Applied
        ));
        chain.restore_cursor(parent);

        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_produced(&block, ours),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.pin_parent(), Some(ours));
        (chain, block)
    }

    /// The first inscription on a channel chains on root, so root is a used
    /// parent from then on and a tip naming it is refused like any other.
    #[test]
    fn a_root_tip_is_refused_once_we_have_published_the_first_inscription() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_adopted(&genesis),
            AcceptOutcome::Applied
        ));
        // Nothing published yet: root is the parent the first inscription needs.
        assert!(
            chain
                .apply_follow(&[], &[], &[], Slot::from(0), MsgId::root())
                .cursor_moved
        );

        chain.record_own_inscription(msg(1), genesis.header.hash);

        let outcome = chain.apply_follow(&[], &[], &[], Slot::from(0), MsgId::root());
        assert!(!outcome.cursor_moved);
        assert_eq!(
            chain.pin_parent(),
            Some(msg(1)),
            "a root tip must not rewind the pin off our inscription"
        );
    }

    /// Pinning back on an entry we already built on would put a second block at
    /// one height, and the channel keeps only one of them.
    #[test]
    fn a_tip_naming_an_entry_we_already_chained_on_is_refused() {
        let (mut chain, _ours) = chain_with_our_block(msg(2), msg(3));

        let outcome = chain.apply_follow(&[], &[], &[], Slot::from(0), msg(2));

        assert!(!outcome.cursor_moved);
        assert_eq!(
            chain.pin_parent(),
            Some(msg(3)),
            "the pin must stay on our block, not fall back to its parent"
        );
    }

    /// A garbage inscription or a config op moves the tip while naming no block,
    /// and must still be followed.
    #[test]
    fn a_tip_elsewhere_is_taken_even_when_no_block_of_ours_is_named() {
        let (mut chain, _ours) = chain_with_our_block(msg(2), msg(3));

        let outcome = chain.apply_follow(&[], &[], &[], Slot::from(0), msg(9));

        assert!(outcome.cursor_moved);
        assert_eq!(chain.pin_parent(), Some(msg(9)));
    }

    /// News about our block frees the entry it chained on, however it arrives.
    #[test]
    fn an_update_naming_our_block_frees_the_entry_it_chained_on() {
        for report in ["adopted", "orphaned", "finalized"] {
            let (mut chain, ours) = chain_with_our_block(msg(2), msg(3));
            let held = vec![ours];
            let (orphaned, adopted, finalized) = match report {
                "adopted" => (Vec::new(), held, Vec::new()),
                "orphaned" => (held, Vec::new(), Vec::new()),
                _ => (Vec::new(), Vec::new(), held),
            };

            let outcome =
                chain.apply_follow(&orphaned, &adopted, &finalized, Slot::from(0), msg(2));

            assert!(
                outcome.cursor_moved,
                "an update reporting our block as {report} must free its parent"
            );
            assert_eq!(chain.pin_parent(), Some(msg(2)));
        }
    }

    /// The pin counts as ours only until the channel rules on the block behind it.
    #[test]
    fn the_pin_is_ours_until_the_channel_reports_the_block() {
        let (mut chain, ours) = chain_with_our_block(msg(2), msg(3));
        assert!(chain.pin_is_ours());

        chain.apply_follow(&[], &[], &[ours], Slot::from(0), msg(3));

        assert_eq!(chain.pin_parent(), Some(msg(3)));
        assert!(
            !chain.pin_is_ours(),
            "a block the channel has finalized is no longer in flight"
        );
    }

    #[test]
    fn restore_head_block_rebuilds_head_and_correlates_by_hash() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Restart shape: final tier from a persisted snapshot, head rebuilt from
        // stored blocks with no MsgIds.
        let mut state = claimed_initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut chain = ChainState::from_final(state.clone(), Some(Tip::from(&genesis)));

        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&state, 2, genesis.header.hash, vec![tx2]);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, _s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        for block in [&block2, &block3] {
            chain
                .restore_head_block(block.clone())
                .expect("stored blocks must replay");
        }
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_head_matches_replay(&chain);

        // The L1 orphans restored block 3 under its real (unknown-to-us) MsgId:
        // correlated by hash, the revert works and a competitor applies.
        chain.revert_orphan(&block3);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);

        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block3_prime),
            AcceptOutcome::Applied
        ));
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 10
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn restore_head_block_rejects_non_chaining_block() {
        let mut chain = ChainState::new(claimed_initial_state());
        let skipped = produce_dummy_block(3, Some(HashType([9; 32])), vec![]);
        assert!(chain.restore_head_block(skipped).is_err());
    }

    #[test]
    fn finalized_hash_alias_with_wrong_id_is_not_absorbed() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        // A malformed message reusing genesis's hash under a different claimed
        // id must not match the held entry as a re-delivery; it falls through
        // to validation and parks.
        let mut alias = genesis.clone();
        alias.header.block_id = 6;
        assert!(matches!(
            chain.apply_finalized(&alias, slot(10)),
            AcceptOutcome::Parked(_)
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
        assert!(chain.final_tip().is_none());
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn finalized_reinscription_matches_by_block_hash() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        chain.apply_adopted(&block3);

        // Block 2 finalizes re-inscribed under a fresh MsgId: matched by hash,
        // finalized through, and the head above it survives.
        assert!(matches!(
            chain.apply_finalized(&block2, slot(5)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert!(chain.final_stall().is_none());
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn finalize_through_preserves_head_state_and_advances_final_state() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);
        let s1 = chain.head_state().clone();
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, s2) = settled(&s1, 2, genesis.header.hash, vec![tx2]);
        chain.apply_adopted(&block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let (block3, _s3) = settled(&s2, 3, block2.header.hash, vec![tx3]);
        chain.apply_adopted(&block3);

        chain.apply_finalized(&block2, slot(10));

        // Head still reflects both transfers
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 20
        );
        // ...while final reflects only the finalized prefix.
        assert_eq!(
            chain.final_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 10
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn head_self_heals_with_valid_competitor_after_park() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        // Correct id, wrong parent: parked, head frozen at 1, no stall.
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_adopted(&bad),
            AcceptOutcome::Parked(BlockIngestError::BrokenChainLink { .. })
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
        assert!(chain.final_stall().is_none());

        // A valid competitor at the same height applies without any reorg event.
        let good = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(chain.apply_adopted(&good), AcceptOutcome::Applied));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn repeated_invalid_finalized_bumps_orphans_since() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(&genesis, slot(10));

        let bad3 = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(&bad3, slot(20));
        let bad5 = produce_dummy_block(5, Some(bad3.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(&bad5, slot(30)),
            AcceptOutcome::Parked(_)
        ));

        let stall = chain.final_stall().expect("final stall recorded");
        assert_eq!(stall.block_id, Some(3), "first stall reason is preserved");
        assert_eq!(stall.orphans_since, 1);
    }

    #[test]
    fn valid_finalized_successor_clears_final_stall() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(&genesis, slot(10));

        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(&bad, slot(20));
        assert!(chain.final_stall().is_some());

        // The valid successor of the frozen final tip finalizes: stall clears.
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(&block2, slot(30)),
            AcceptOutcome::Applied
        ));
        assert!(chain.final_stall().is_none());
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn finalized_successor_of_head_entry_finalizes_the_prefix() {
        // Head holds unfinalized blocks 1..=2 (e.g. restored after a restart);
        // a peer block 3 we never saw adopted arrives finalized. Its ancestry
        // finalizes our prefix implicitly, then 3 applies to final directly.
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_adopted(&block2);
        assert!(chain.final_tip().is_none());

        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(&block3, slot(10)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 3);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert!(chain.final_stall().is_none());
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn finalized_redelivery_at_or_below_final_tip_is_already_applied() {
        // Restart shape: the store's tip (incl. not-yet-finalized blocks) is
        // restored as the final tier, so their later finalization arrives for
        // blocks that were never in `head_blocks`.
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(&genesis, slot(10));
        chain.apply_finalized(&block2, slot(20));

        // Below the tip, and at the tip with a matching hash: idempotent.
        assert!(matches!(
            chain.apply_finalized(&genesis, slot(30)),
            AcceptOutcome::AlreadyApplied
        ));
        assert!(matches!(
            chain.apply_finalized(&block2, slot(30)),
            AcceptOutcome::AlreadyApplied
        ));
        assert!(chain.final_stall().is_none());
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn conflicting_finalized_at_final_tip_parks() {
        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(&genesis, slot(10));
        chain.apply_finalized(&block2, slot(20));

        // A different finalized block at the final height: finalized is
        // irreversible, so this is a genuine stall, not a re-delivery.
        let block2_prime = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_finalized(&block2_prime, slot(30)),
            AcceptOutcome::Parked(_)
        ));
        assert!(chain.final_stall().is_some());
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
    }

    #[test]
    fn finalized_unknown_block_rebases_head() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);
        chain.apply_finalized(&genesis, slot(10));

        // Head advances on a competing branch…
        let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(&block2a);

        // …but a different block 2 finalizes. The finalized chain is
        // authoritative, so head rebases onto it.
        let s1 = chain.final_state().clone();
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2b, _s2b) = settled(&s1, 2, genesis.header.hash, vec![tx]);
        match chain.apply_finalized(&block2b, slot(20)) {
            AcceptOutcome::Applied => {}
            AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err) => {
                panic!("not applied: {err:?}")
            }
            AcceptOutcome::AlreadyApplied => panic!("already applied"),
        }

        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 10
        );
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn head_state_reflects_applied_transfers() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(claimed_initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(&genesis);

        let s1 = chain.head_state().clone();
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (block2, _s2) = settled(&s1, 2, genesis.header.hash, vec![tx]);
        chain.apply_adopted(&block2);

        // The recipient gains exactly the transfer; the sender also paid a fee.
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 10
        );
        assert!(chain.head_state().get_account_by_id(from).balance < 10_000_000_000_000 - 10);
    }
}
