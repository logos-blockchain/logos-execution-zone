//! Two-tier chain state: a reorg-able `head` the sequencer builds on, plus an
//! irreversible `final` tier. See `DESIGN.md` for the model and rationale.

use common::block::Block;
use lee::V03State;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

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
pub struct ChainState {
    final_state: V03State,
    final_tip: Option<Tip>,
    final_stall: Option<StallReason>,

    head_state: V03State,
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
        Self {
            head_state: final_state.clone(),
            final_state,
            final_tip,
            head_blocks: Vec::new(),
            final_stall: None,
        }
    }

    /// State the sequencer builds its next block on.
    #[must_use]
    pub const fn head_state(&self) -> &V03State {
        &self.head_state
    }

    /// Mutable access to the head state. Bypasses the `head_blocks` invariant, so
    /// it is meant for tests and low-level callers.
    #[must_use]
    pub const fn head_state_mut(&mut self) -> &mut V03State {
        &mut self.head_state
    }

    #[must_use]
    pub const fn final_state(&self) -> &V03State {
        &self.final_state
    }

    /// Parent the next produced block must chain on.
    #[must_use]
    pub fn head_tip(&self) -> Option<Tip> {
        self.head_blocks
            .last()
            .map(|entry| tip_of(&entry.block))
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

    /// Applies an adopted head block. On failure the head tip stays at the last
    /// valid block and no stall is recorded (§4a); the head self-heals.
    pub fn apply_adopted(&mut self, this_msg: MsgId, block: &Block) -> AcceptOutcome {
        let tip = self.head_tip();
        if self
            .head_blocks
            .iter()
            .any(|entry| entry.this_msg == this_msg)
            || tip
                .as_ref()
                .is_some_and(|current| block.header.block_id <= current.block_id)
        {
            return AcceptOutcome::AlreadyApplied;
        }

        let mut scratch = self.head_state.clone();
        match apply_block(tip.as_ref(), block, &mut scratch) {
            Ok(()) => {
                self.head_state = scratch;
                self.head_blocks.push(HeadEntry {
                    this_msg,
                    block: block.clone(),
                });
                AcceptOutcome::Applied
            }
            Err(err) => AcceptOutcome::Parked(err),
        }
    }

    /// Reverts an orphaned head block and everything after it, then re-derives head.
    pub fn revert_orphan(&mut self, this_msg: MsgId) {
        if let Some(idx) = self
            .head_blocks
            .iter()
            .position(|entry| entry.this_msg == this_msg)
        {
            self.head_blocks.truncate(idx);
            self.rederive_head();
        }
    }

    /// One channel update: revert every `orphaned`, then apply every `adopted`.
    pub fn apply_channel_update(
        &mut self,
        orphaned: &[MsgId],
        adopted: &[(MsgId, Block)],
    ) -> Vec<AcceptOutcome> {
        let earliest = orphaned
            .iter()
            .filter_map(|msg| {
                self.head_blocks
                    .iter()
                    .position(|entry| entry.this_msg == *msg)
            })
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

    /// A finalized inscription. In steady state the block is already in head and is
    /// moved into `final`; on backfill (not in head) it is applied directly and may
    /// set `final_stall`.
    pub fn apply_finalized(
        &mut self,
        this_msg: MsgId,
        block: &Block,
        l1_slot: Slot,
    ) -> AcceptOutcome {
        // Match by MsgId, or by block identity to handle a re-inscribed but
        // identical block arriving under a fresh MsgId.
        let in_head = self.head_blocks.iter().position(|entry| {
            entry.this_msg == this_msg || entry.block.header.hash == block.header.hash
        });
        match in_head {
            Some(idx) => {
                self.finalize_through(idx);
                AcceptOutcome::Applied
            }
            None => self.apply_finalized_direct(block, l1_slot),
        }
    }

    /// Moves `head_blocks[0..=idx]` into the final tier (already validated in head).
    fn finalize_through(&mut self, idx: usize) {
        let finalized: Vec<HeadEntry> = self.head_blocks.drain(0..=idx).collect();
        for entry in finalized {
            apply_block(self.final_tip.as_ref(), &entry.block, &mut self.final_state)
                .expect("a validated head block must apply to the final tier");
            self.final_tip = Some(tip_of(&entry.block));
        }
        self.final_stall = None;
    }

    /// Applies a finalized block straight to the final tier. On success the
    /// finalized chain is authoritative, so head rebases onto it.
    fn apply_finalized_direct(&mut self, block: &Block, l1_slot: Slot) -> AcceptOutcome {
        let mut scratch = self.final_state.clone();
        match apply_block(self.final_tip.as_ref(), block, &mut scratch) {
            Ok(()) => {
                self.final_state = scratch;
                self.final_tip = Some(tip_of(block));
                self.final_stall = None;
                self.head_blocks.clear();
                self.head_state = self.final_state.clone();
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
        let mut state = self.final_state.clone();
        let mut tip = self.final_tip.clone();
        for entry in &self.head_blocks {
            apply_block(tip.as_ref(), &entry.block, &mut state)
                .expect("validated head blocks must replay");
            tip = Some(tip_of(&entry.block));
        }
        self.head_state = state;
    }

    /// First stall is stored verbatim; later ones only bump `orphans_since`.
    fn record_final_stall(&mut self, block: &Block, l1_slot: Slot, error: BlockIngestError) {
        self.final_stall = Some(match self.final_stall.take() {
            Some(mut existing) => {
                existing.orphans_since = existing.orphans_since.saturating_add(1);
                existing
            }
            None => stall_for(block, l1_slot, error),
        });
    }
}

const fn tip_of(block: &Block) -> Tip {
    Tip {
        block_id: block.header.block_id,
        hash: block.header.hash,
    }
}

const fn stall_for(block: &Block, l1_slot: Slot, error: BlockIngestError) -> StallReason {
    StallReason {
        block_id: Some(block.header.block_id),
        block_hash: Some(block.header.hash),
        prev_block_hash: Some(block.header.prev_block_hash),
        l1_slot,
        error,
        first_seen: Some(block.header.timestamp),
        orphans_since: 0,
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

    fn msg(n: u8) -> MsgId {
        MsgId::from([n; 32])
    }

    fn slot(n: u64) -> Slot {
        Slot::from(n)
    }

    /// `head_state` equals `final_state` replayed through `head_blocks`.
    fn assert_head_matches_replay(chain: &ChainState) {
        let mut state = chain.final_state.clone();
        let mut tip = chain.final_tip.clone();
        for entry in &chain.head_blocks {
            apply_block(tip.as_ref(), &entry.block, &mut state).expect("head blocks must replay");
            tip = Some(tip_of(&entry.block));
        }
        assert_eq!(
            borsh::to_vec(&state).expect("state serializes"),
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

        chain.revert_orphan(msg(3));
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
        let outcomes = chain.apply_channel_update(&[msg(3)], &[(msg(13), block3_prime)]);
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
            chain.apply_finalized(msg(2), &block2, slot(100)),
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
            chain.apply_finalized(msg(1), &genesis, slot(10)),
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
        chain.apply_finalized(msg(1), &genesis, slot(10));

        // Skip-ahead finalized block, not in head: parks the final tier.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(3), &bad, slot(20)),
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
        chain.revert_orphan(msg(3));

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
            &[msg(4), msg(3)],
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
    fn channel_update_ignores_unknown_orphan() {
        let mut chain = ChainState::new(initial_state());
        let genesis = produce_dummy_block(1, None, vec![]);
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(1), &genesis);
        chain.apply_adopted(msg(2), &block2);

        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let outcomes = chain.apply_channel_update(&[msg(99)], &[(msg(3), block3)]);

        assert!(matches!(outcomes.as_slice(), [AcceptOutcome::Applied]));
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
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
            chain.apply_finalized(msg(42), &block2, slot(5)),
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

        chain.apply_finalized(msg(2), &block2, slot(10));

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
        chain.apply_finalized(msg(1), &genesis, slot(10));

        let bad3 = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(3), &bad3, slot(20));
        let bad5 = produce_dummy_block(5, Some(bad3.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(5), &bad5, slot(30)),
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
        chain.apply_finalized(msg(1), &genesis, slot(10));

        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        chain.apply_finalized(msg(3), &bad, slot(20));
        assert!(chain.final_stall().is_some());

        // The valid successor of the frozen final tip finalizes: stall clears.
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(msg(2), &block2, slot(30)),
            AcceptOutcome::Applied
        ));
        assert!(chain.final_stall().is_none());
        assert_eq!(chain.final_tip().expect("final tip").block_id, 2);
        assert_head_matches_replay(&chain);
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
        chain.apply_finalized(msg(1), &genesis, slot(10));

        // Head advances on a competing branch…
        let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        chain.apply_adopted(msg(2), &block2a);

        // …but a different block 2 finalizes. The finalized chain is
        // authoritative, so head rebases onto it.
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let block2b = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        assert!(matches!(
            chain.apply_finalized(msg(22), &block2b, slot(20)),
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
