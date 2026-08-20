//! Two-tier chain state: a reorg-able `head` the sequencer builds on, plus an
//! irreversible `final` tier.

use std::sync::Arc;

use common::block::Block;
use lee::V03State;
use log::warn;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;

use crate::{
    AcceptOutcome, BlockIngestError, StallReason,
    apply::{Tip, apply_block},
};

/// A head block plus the channel message that carried it.
pub struct HeadEntry {
    pub this_msg: MsgId,
    pub block: Block,
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
    head_blocks: Vec<HeadEntry>,
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
            .map(|entry| Tip::from(&entry.block))
            .or_else(|| self.final_tip.clone())
    }

    #[must_use]
    pub fn final_tip(&self) -> Option<Tip> {
        self.final_tip.clone()
    }

    #[must_use]
    pub const fn final_stall(&self) -> Option<&StallReason> {
        self.final_stall.as_ref()
    }

    /// Position of a head entry, matched by `MsgId` or block hash (restored
    /// entries carry sentinel `MsgId`s; re-inscriptions arrive under fresh ones)
    /// — always at the same claimed height: a hash or `MsgId` collision with a
    /// different `block_id` is malformed and must fall through to validation.
    fn head_position_of(&self, this_msg: MsgId, block: &Block) -> Option<usize> {
        self.head_blocks.iter().position(|entry| {
            entry.block.header.block_id == block.header.block_id
                && (entry.this_msg == this_msg || entry.block.header.hash == block.header.hash)
        })
    }

    /// Applies an adopted head block.
    ///
    /// The adopted stream is authoritative: a competitor at a height
    /// the head already holds reorgs the head back to that height with
    /// no orphan event required.
    ///
    /// On failure the head stays unchanged and no stall is recorded.
    pub fn apply_adopted(&mut self, this_msg: MsgId, block: &Block) -> AcceptOutcome {
        if self.head_position_of(this_msg, block).is_some() {
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
            .position(|entry| entry.block.header.block_id >= block.header.block_id);
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
                self.head_blocks.push(HeadEntry {
                    this_msg,
                    block: block.to_owned(),
                });
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
    pub fn apply_produced(&mut self, this_msg: MsgId, block: &Block) -> AcceptOutcome {
        if self
            .head_tip()
            .is_some_and(|tip| block.header.block_id <= tip.block_id)
        {
            return AcceptOutcome::AlreadyApplied;
        }
        self.apply_adopted(this_msg, block)
    }

    /// Reverts an orphaned head block and everything after it, then re-derives head.
    pub fn revert_orphan(&mut self, this_msg: MsgId, block: &Block) {
        if let Some(idx) = self.head_position_of(this_msg, block) {
            self.head_blocks.truncate(idx);
            self.rederive_head();
        }
    }

    /// One channel update: revert every `orphaned` (one truncate + re-derive),
    /// then apply every `adopted` in order. Outcomes align with `adopted`.
    pub fn apply_channel_update(
        &mut self,
        orphaned: &[(MsgId, Block)],
        adopted: &[(MsgId, Block)],
    ) -> Vec<AcceptOutcome> {
        let earliest = orphaned
            .iter()
            .filter_map(|(msg, block)| self.head_position_of(*msg, block))
            .min();
        if let Some(idx) = earliest {
            self.head_blocks.truncate(idx);
            self.rederive_head();
        }
        adopted
            .iter()
            .map(|(msg, block)| self.apply_adopted(*msg, block))
            .collect()
    }

    /// Rebuilds one head entry from a persisted block, applying it in place (the
    /// caller treats `Err` as fatal).
    ///
    /// The entry gets a hash-derived sentinel `MsgId` (the real one is not
    /// persisted — that would need a sidecar `block_id -> MsgId` cell); later
    /// orphan/finalize events correlate by block hash.
    pub fn restore_head_block(&mut self, block: Block) -> Result<(), BlockIngestError> {
        apply_block(
            self.head_tip().as_ref(),
            &block,
            Arc::make_mut(&mut self.head_state),
        )?;
        let this_msg = MsgId::from(block.header.hash.0);
        self.head_blocks.push(HeadEntry { this_msg, block });
        Ok(())
    }

    /// A finalized inscription. In steady state the block is already in head and is
    /// moved into `final`; on backfill (not in head) it is applied directly and may
    /// set `final_stall`.
    pub fn apply_finalized(
        &mut self,
        this_msg: MsgId,
        block: &Block,
        checkpoint: SequencerCheckpoint,
    ) -> AcceptOutcome {
        // Match by `MsgId` or block hash (re-inscriptions, restored entries).
        if let Some(idx) = self.head_position_of(this_msg, block) {
            self.finalize_through(idx);
            return AcceptOutcome::Applied;
        }

        // Finality is prefix-monotone: a finalized block chaining on an
        // unfinalized head entry finalizes that prefix too.
        if let Some(idx) = self
            .head_blocks
            .iter()
            .position(|entry| entry.block.header.hash == block.header.prev_block_hash)
        {
            self.finalize_through(idx);
        }
        self.apply_finalized_direct(block, checkpoint)
    }

    /// Moves `head_blocks[0..=idx]` into the final tier (already validated in head).
    fn finalize_through(&mut self, idx: usize) {
        let finalized: Vec<HeadEntry> = self.head_blocks.drain(0..=idx).collect();
        for entry in finalized {
            apply_block(
                self.final_tip.as_ref(),
                &entry.block,
                Arc::make_mut(&mut self.final_state),
            )
            .expect("validated head block must apply to the final tier");
            self.final_tip = Some(Tip::from(&entry.block));
        }
        self.final_stall = None;
    }

    /// Applies a finalized block straight to the final tier. On success the
    /// finalized chain is authoritative, so head rebases onto it.
    fn apply_finalized_direct(
        &mut self,
        block: &Block,
        checkpoint: SequencerCheckpoint,
    ) -> AcceptOutcome {
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
                self.record_final_stall(block, checkpoint, err.clone());
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
        for entry in &self.head_blocks[..count] {
            apply_block(tip.as_ref(), &entry.block, Arc::make_mut(&mut state))
                .expect("validated head blocks must replay");
            tip = Some(Tip::from(&entry.block));
        }
        (state, tip)
    }

    /// First stall is stored verbatim; later ones only bump `orphans_since`.
    fn record_final_stall(
        &mut self,
        block: &Block,
        checkpoint: SequencerCheckpoint,
        error: BlockIngestError,
    ) {
        self.final_stall = Some(self.final_stall.take().map_or_else(
            || StallReason::new(Some(&block.header), checkpoint, error),
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
    use logos_blockchain_zone_sdk::Slot;
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    fn msg(n: u8) -> MsgId {
        MsgId::from([n; 32])
    }

    fn checkpoint(msg: MsgId, n: u64) -> SequencerCheckpoint {
        SequencerCheckpoint {
            last_msg_id: msg,
            pending_txs: vec![],
            lib: [1_u8; 32].into(),
            lib_slot: Slot::from(n),
        }
    }

    /// `head_state` equals `final_state` replayed through `head_blocks`.
    fn assert_head_matches_replay(chain: &ChainState) {
        let mut state = Arc::clone(&chain.final_state);
        let mut tip = chain.final_tip.clone();
        for entry in &chain.head_blocks {
            apply_block(tip.as_ref(), &entry.block, Arc::make_mut(&mut state))
                .expect("head blocks must replay");
            tip = Some(Tip::from(&entry.block));
        }
        assert_eq!(
            borsh::to_vec(state.as_ref()).expect("state serializes"),
            borsh::to_vec(chain.head_state()).expect("state serializes"),
            "head_state must equal final_state replayed through head_blocks"
        );
    }

    #[test]
    fn adopted_blocks_advance_head() {
        let mut chain = ChainState::new(initial_state());

        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(1), &genesis),
            AcceptOutcome::Applied
        ));
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(2), &block2),
            AcceptOutcome::Applied
        ));

        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        // Nothing finalized yet.
        assert!(chain.final_tip().is_none());
    }

    #[test]
    fn adopted_bad_block_freezes_head_without_stall() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        // Skips ahead (id 3 while head tip is 1).
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(3), &bad),
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
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        assert!(matches!(
            chain.apply_adopted(msg(1), &genesis),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
    }

    #[test]
    fn orphan_reverts_head() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        chain.apply_adopted(msg(3), &block3);

        chain.revert_orphan(msg(3), &block3);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);

        // A competing block 3 now applies cleanly on block 2.
        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(13), &block3_prime),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn channel_update_reverts_then_applies() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        chain.apply_adopted(msg(3), &block3);

        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let outcomes = chain.apply_channel_update(&[(msg(3), block3)], &[(msg(13), block3_prime)]);
        assert!(matches!(outcomes.as_slice(), [AcceptOutcome::Applied]));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn finalize_moves_head_into_final() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        chain.apply_adopted(msg(3), &block3);

        // Finalize through block 2.
        assert!(matches!(
            chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 100)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        // Head tip unchanged; head still ends at 3.
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
    }

    #[test]
    fn backfill_applies_directly_to_final() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10)),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.final_tip().expect("final tip").block_id, 1);
        // Head mirrors final during backfill.
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
    }

    #[test]
    fn invalid_finalized_block_sets_final_stall() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));

        // Skip-ahead finalized block, not in head: parks the final tier.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(3), &bad, checkpoint(msg(3), 20)),
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

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        chain.apply_adopted(msg(2), &block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        chain.apply_adopted(msg(3), &block3);
        let tx4 = create_transaction_native_token_transfer(from, 2, to, 10, &sign_key);
        let block4 = produce_dummy_block(4, Some(block3.header.hash), vec![tx4]);
        chain.apply_adopted(msg(4), &block4);

        // Orphaning block 3 drops the whole suffix (3 and 4).
        chain.revert_orphan(msg(3), &block3);

        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_eq!(chain.head_state().get_account_by_id(from).balance, 9990);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20010);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn channel_update_replaces_multi_block_suffix() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        chain.apply_adopted(msg(2), &block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        chain.apply_adopted(msg(3), &block3);
        let tx4 = create_transaction_native_token_transfer(from, 2, to, 10, &sign_key);
        let block4 = produce_dummy_block(4, Some(block3.header.hash), vec![tx4]);
        chain.apply_adopted(msg(4), &block4);

        // A competing branch replaces blocks 3 and 4; orphans arrive unordered.
        let tx3_prime = create_transaction_native_token_transfer(from, 1, to, 20, &sign_key);
        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![tx3_prime]);
        let tx4_prime = create_transaction_native_token_transfer(from, 2, to, 30, &sign_key);
        let block4_prime = produce_dummy_block(4, Some(block3_prime.header.hash), vec![tx4_prime]);

        let outcomes = chain.apply_channel_update(
            &[(msg(4), block4), (msg(3), block3)],
            &[(msg(13), block3_prime), (msg(14), block4_prime)],
        );

        assert!(matches!(
            outcomes.as_slice(),
            [AcceptOutcome::Applied, AcceptOutcome::Applied]
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 4);
        assert_eq!(chain.head_state().get_account_by_id(from).balance, 9940);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20060);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn adopted_only_channel_update_replaces_suffix() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        chain.apply_adopted(msg(2), &block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        chain.apply_adopted(msg(3), &block3);

        // The replacement branch arrives with no orphan events: the adopted
        // list alone reorgs the head.
        let tx2_prime = create_transaction_native_token_transfer(from, 0, to, 20, &sign_key);
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2_prime]);
        let tx3_prime = create_transaction_native_token_transfer(from, 1, to, 30, &sign_key);
        let block3_prime = produce_dummy_block(3, Some(block2_prime.header.hash), vec![tx3_prime]);

        let outcomes =
            chain.apply_channel_update(&[], &[(msg(12), block2_prime), (msg(13), block3_prime)]);

        assert!(matches!(
            outcomes.as_slice(),
            [AcceptOutcome::Applied, AcceptOutcome::Applied]
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20050);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn channel_update_ignores_unknown_orphan() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);

        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let unknown = produce_dummy_block(9, Some(HashType([7; 32])), vec![]);
        let outcomes = chain.apply_channel_update(&[(msg(99), unknown)], &[(msg(3), block3)]);

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

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        chain.apply_adopted(msg(2), &block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        chain.apply_adopted(msg(3), &block3);

        // A valid competitor at height 2, no orphan events: the head reorgs
        // back onto it, dropping the old 2..=3 suffix and its transfers.
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(12), &block2_prime),
            AcceptOutcome::Applied
        ));
        let tip = chain.head_tip().expect("head tip");
        assert_eq!(tip.block_id, 2);
        assert_eq!(tip.hash, block2_prime.header.hash);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20000);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn produced_block_losing_a_race_does_not_reorg_the_head() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        // A peer's block wins height 2 on the channel.
        let peer = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(2), &peer);

        // Our own block at that height is not on the channel, so — unlike an
        // adopted competitor — it must not reorg the head onto itself.
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let ours = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        assert!(matches!(
            chain.apply_produced(msg(12), &ours),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(chain.head_tip().expect("head tip").hash, peer.header.hash);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20000);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn produced_block_extending_the_head_applies() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        let ours = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_produced(msg(2), &ours),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_tip().expect("head tip").hash, ours.header.hash);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn invalid_adopted_competitor_leaves_head_intact() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        chain.apply_adopted(msg(3), &block3);

        // A competitor at height 2 with a bogus parent parks; the truncation
        // is not committed, so the 2..=3 suffix survives.
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(12), &bad),
            AcceptOutcome::Parked(BlockIngestError::BrokenChainLink { .. })
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn adopted_conflicting_with_final_tip_is_ignored() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));
        chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 20));

        // Finalized is irreversible: an adopted competitor at (or below) the
        // final tip is ignored, not reorged onto.
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(12), &block2_prime),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            chain.final_tip().expect("final tip").hash,
            block2.header.hash
        );
        assert_eq!(chain.head_tip().expect("head tip").hash, block2.header.hash);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn restore_head_block_rebuilds_head_and_correlates_by_hash() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Restart shape: final tier from a persisted snapshot, head rebuilt from
        // stored blocks under hash-derived sentinel MsgIds.
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut chain = ChainState::from_final(state, Some(Tip::from(&genesis)));

        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        for block in [&block2, &block3] {
            chain
                .restore_head_block(block.clone())
                .expect("stored blocks must replay");
        }
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_head_matches_replay(&chain);

        // The L1 orphans restored block 3 under its real (unknown-to-us) MsgId:
        // correlated by hash, the revert works and a competitor applies.
        chain.revert_orphan(msg(33), &block3);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);

        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(13), &block3_prime),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20010);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn restore_head_block_rejects_non_chaining_block() {
        let mut chain = ChainState::new(initial_state());
        let skipped = produce_dummy_block(3, Some(HashType([9; 32])), vec![]);
        assert!(chain.restore_head_block(skipped).is_err());
    }

    #[test]
    fn finalized_hash_alias_with_wrong_id_is_not_absorbed() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        // A malformed message reusing genesis's hash under a different claimed
        // id must not match the held entry as a re-delivery; it falls through
        // to validation and parks.
        let mut alias = genesis.clone();
        alias.header.block_id = 6;
        assert!(matches!(
            chain.apply_finalized(msg(66), &alias, checkpoint(msg(66), 10)),
            AcceptOutcome::Parked(_)
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
        assert!(chain.final_tip().is_none());
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn finalized_reinscription_matches_by_block_hash() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        chain.apply_adopted(msg(3), &block3);

        // Block 2 finalizes re-inscribed under a fresh MsgId: matched by hash,
        // finalized through, and the head above it survives.
        assert!(matches!(
            chain.apply_finalized(msg(42), &block2, checkpoint(msg(42), 5)),
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

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);
        let tx2 = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        chain.apply_adopted(msg(2), &block2);
        let tx3 = create_transaction_native_token_transfer(from, 1, to, 10, &sign_key);
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        chain.apply_adopted(msg(3), &block3);

        chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 10));

        // Head still reflects both transfers
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20020);
        // ...while final reflects only the finalized prefix.
        assert_eq!(chain.final_state().get_account_by_id(to).balance, 20010);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn head_self_heals_with_valid_competitor_after_park() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        // Correct id, wrong parent: parked, head frozen at 1, no stall.
        let bad = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(2), &bad),
            AcceptOutcome::Parked(BlockIngestError::BrokenChainLink { .. })
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
        assert!(chain.final_stall().is_none());

        // A valid competitor at the same height applies without any reorg event.
        let good = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(msg(12), &good),
            AcceptOutcome::Applied
        ));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn repeated_invalid_finalized_bumps_orphans_since() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));

        let bad3 = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(3), &bad3, checkpoint(msg(3), 20));
        let bad5 = produce_dummy_block(5, Some(bad3.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(5), &bad5, checkpoint(msg(5), 30)),
            AcceptOutcome::Parked(_)
        ));

        let stall = chain.final_stall().expect("final stall recorded");
        assert_eq!(stall.block_id, Some(3), "first stall reason is preserved");
        assert_eq!(stall.orphans_since, 1);
    }

    #[test]
    fn valid_finalized_successor_clears_final_stall() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));

        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(3), &bad, checkpoint(msg(3), 20));
        assert!(chain.final_stall().is_some());

        // The valid successor of the frozen final tip finalizes: stall clears.
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 30)),
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
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);
        assert!(chain.final_tip().is_none());

        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(3), &block3, checkpoint(msg(3), 10)),
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
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));
        chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 20));

        // Below the tip, and at the tip with a matching hash: idempotent.
        assert!(matches!(
            chain.apply_finalized(msg(41), &genesis, checkpoint(msg(41), 30)),
            AcceptOutcome::AlreadyApplied
        ));
        assert!(matches!(
            chain.apply_finalized(msg(42), &block2, checkpoint(msg(42), 30)),
            AcceptOutcome::AlreadyApplied
        ));
        assert!(chain.final_stall().is_none());
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn conflicting_finalized_at_final_tip_parks() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));
        chain.apply_finalized(msg(2), &block2, checkpoint(msg(2), 20));

        // A different finalized block at the final height: finalized is
        // irreversible, so this is a genuine stall, not a re-delivery.
        let block2_prime = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(22), &block2_prime, checkpoint(msg(22), 30)),
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

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_finalized(msg(1), &genesis, checkpoint(msg(1), 10));

        // Head advances on a competing branch…
        let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(2), &block2a);

        // …but a different block 2 finalizes. The finalized chain is
        // authoritative, so head rebases onto it.
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2b = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        assert!(matches!(
            chain.apply_finalized(msg(22), &block2b, checkpoint(msg(22), 20)),
            AcceptOutcome::Applied
        ));

        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20010);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn head_state_reflects_applied_transfers() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        chain.apply_adopted(msg(1), &genesis);

        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        chain.apply_adopted(msg(2), &block2);

        assert_eq!(chain.head_state().get_account_by_id(from).balance, 9990);
        assert_eq!(chain.head_state().get_account_by_id(to).balance, 20010);
    }
}
