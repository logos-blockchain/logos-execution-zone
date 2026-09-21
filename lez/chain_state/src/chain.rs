//! Two-tier chain state: a reorg-able `head` the sequencer builds on, plus an
//! irreversible `final` tier.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use common::block::Block;
use lee::V03State;
use log::warn;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::{
    AcceptOutcome, BlockIngestError, StallReason,
    apply::{Tip, apply_block},
    lineage::{ChannelLineage, LineageEntry, Stale},
};


/// What one derivation did to the head tier.
#[derive(Debug, Default)]
pub struct TipDerivation {
    /// Blocks that left the head, oldest first: their transactions go back to
    /// the mempool unless the same block is back on the chain.
    pub dropped: Vec<Block>,
    /// Blocks applied onto the head, oldest first.
    pub applied: Vec<Block>,
}

/// The head tier (reorg-able, from `adopted`/`orphaned`) over the final tier
/// (irreversible, from `finalized`).
///
/// `head_state` is given by `final_state` replayed through `head_blocks`.
///
/// Only the final tier stalls: an invalid `adopted` block just freezes the
/// head tip and self-heals via a reported orphan, a valid successor, or
/// finalization.
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


    /// The newest entry the channel reported finalized, where the unfinalized
    /// entries end.
    finalized_entry: Option<MsgId>,



    /// Whether the last derivation could not account for the chain.
    derivation_stale: bool,

    /// Consecutive derivations that found the chain behind the head. One or
    /// two are ordinary — the sdk buffers a checkpoint across a reconnect. A
    /// run of them means the head has left the channel behind and the pin is
    /// frozen, which no further event can undo on its own.
    consecutive_regressions: u32,

    /// Channel entries the sdk's checkpoint does not carry, kept across
    /// events.
    ///
    /// The sdk mirrors only its own two clean shapes into `pending`, so a
    /// peer's `Custom`-shaped entry reaches a node once, in the `adopted` of
    /// the event that reports it — and `adopted` is a set difference that
    /// never re-sends. Genesis is that shape on every follower, so without
    /// this the walk would gap on it from the second event until it finalized,
    /// freezing the head for the whole unfinalized window.
    supplement: HashMap<MsgId, LineageEntry>,

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
            finalized_entry: None,
            derivation_stale: false,
            consecutive_regressions: 0,
            supplement: HashMap::new(),
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

    /// Moves the cursor to an entry the channel reported.
    const fn set_channel_cursor(&mut self, msg: MsgId) {
        self.channel_cursor = Some(msg);
    }

    /// Restores the pin at startup from the stored sdk checkpoint. Records
    /// nothing as ours: a previous run's inscriptions are not in flight for
    /// this one.
    pub const fn restore_cursor(&mut self, msg: MsgId) {
        self.set_channel_cursor(msg);
    }

    /// Where the chain walk terminates: the newest entry seen finalized.
    /// Persisted, because a restart otherwise cannot tell the boundary from a
    /// gap and the walk fails on every update until something new finalizes.
    #[must_use]
    pub const fn finalized_entry(&self) -> Option<MsgId> {
        self.finalized_entry
    }

    /// Restores the persisted walk terminus at startup.
    pub const fn restore_finalized_entry(&mut self, entry: MsgId) {
        self.finalized_entry = Some(entry);
    }

    /// An entry a replay holds no block for — garbage, or a payload this build
    /// cannot decode. It moved the channel tip, so the pin follows it.
    pub const fn skip_channel_entry(&mut self, msg: MsgId) {
        self.set_channel_cursor(msg);
        // Replayed from finalized history like `apply_reconstructed`, so it
        // moves the boundary too even though it leaves no block behind.
        self.finalized_entry = Some(msg);
    }

    /// Pins on an inscription of ours the channel has not reported yet.
    pub const fn record_own_inscription(&mut self, msg: MsgId) {
        self.set_channel_cursor(msg);
    }

    #[must_use]
    pub fn final_tip(&self) -> Option<Tip> {
        self.final_tip.clone()
    }

    #[must_use]
    pub const fn final_stall(&self) -> Option<&StallReason> {
        self.final_stall.as_ref()
    }

    /// Rebuilds the head tier from the channel chain ending at `tip`.
    ///
    /// The chain decides membership and order; the head is the longest prefix
    /// of it this node can actually apply. An entry carrying no block (garbage,
    /// an undecodable payload, a config) is skipped without ending the walk —
    /// it moved the channel tip, not the head. An entry whose bytes we do not
    /// hold, or whose block does not apply, ends the head there: the head
    /// trails the chain until a later derivation can continue it.
    ///
    /// # Errors
    ///
    /// [`Stale`] when the reported entries cannot account for the chain, in
    /// which case nothing is changed.
    pub fn derive_head(
        &mut self,
        tip: MsgId,
        lineage: &ChannelLineage,
        finalized_entry: Option<MsgId>,
        orphaned: &[Block],
    ) -> Result<TipDerivation, Stale> {
        let derived = self.try_derive_head(tip, lineage, finalized_entry, orphaned);
        // A node with no pin takes the reported one even from a derivation
        // that did not commit: there is no position to rewind, and without
        // this a node whose head holds a block the chain does not carry yet
        // regresses on its first walk and never pins at all — a regression
        // clears only on an orphan report, and genesis never gets one.
        //
        // An established pin moves only on a derivation that committed, or a
        // checkpoint the sdk buffered from before our publishes would rewind
        // it onto a parent the channel has since moved past.
        if self.channel_cursor.is_none() {
            self.channel_cursor = Some(tip);
        }
        // The produce gate reads this: a head that could not be checked against
        // the channel is not one to publish on.
        //
        // A regressed checkpoint is not that case. It says the checkpoint is
        // behind the head, not that the head is unknown — the sdk buffers one
        // across a reconnect, and the bootstrap publishes outrun the first. The
        // head stands, so the turn runs; a stale publish is refused by L1
        // anyway, because it pins on an entry the channel has moved past.
        self.derivation_stale = matches!(
            derived,
            Err(Stale::LineageGap { .. } | Stale::Unbounded)
        );
        // A regression leaves the pin where it was, so a run of them is a pin
        // that can no longer follow the channel.
        self.consecutive_regressions = match derived {
            Err(Stale::Regressed { .. }) => self.consecutive_regressions.saturating_add(1),
            _ => 0,
        };
        derived
    }

    fn try_derive_head(
        &mut self,
        tip: MsgId,
        lineage: &ChannelLineage,
        finalized_entry: Option<MsgId>,
        orphaned: &[Block],
    ) -> Result<TipDerivation, Stale> {
        if finalized_entry.is_some() {
            self.finalized_entry = finalized_entry;
        }
        let chain = self.above_lib(tip, lineage)?;

        // The blocks the chain carries, in order. Entries carrying none
        // (garbage, an undecodable payload, a config) moved the channel tip
        // without ever belonging to the head.
        let wanted: Vec<Block> = chain
            .iter()
            .filter_map(|msg| self.entry_at(*msg, lineage)?.block.clone())
            .collect();

        // The prefix the head already holds and the chain still agrees with,
        // matched by hash. A pure extension keeps all of it and applies only
        // the new tail; anything past the match left the chain.
        let keep = self
            .head_blocks
            .iter()
            .zip(&wanted)
            .take_while(|(held, want)| held.header.hash == want.header.hash)
            .count();

        // A held block may only leave the head on evidence: an orphan report,
        // or the final tier having settled past it. Without that rule a
        // checkpoint older than the head — the sdk buffers one across a
        // reconnect — would wipe work that is still on the channel.
        if let Some(held) = self.head_blocks[keep..].iter().find(|held| {
            !orphaned
                .iter()
                .any(|gone| gone.header.hash == held.header.hash)
                && self
                    .final_tip
                    .as_ref()
                    .is_none_or(|settled| held.header.block_id > settled.block_id)
        }) {
            return Err(Stale::Regressed {
                dropped: held.header.hash,
            });
        }

        // Only now that the derivation commits: a chain the head could not be
        // reconciled with returns above without touching the supplement, which
        // the next event still needs.
        self.forget_settled_supplement(&chain);

        let mut derivation = TipDerivation::default();
        if keep < self.head_blocks.len() {
            derivation.dropped = self.head_blocks.split_off(keep);
            self.rederive_head();
        }

        for block in wanted.iter().skip(keep) {
            match self.apply_adopted(block) {
                AcceptOutcome::Applied => derivation.applied.push(block.clone()),
                // The final tier already holds it; the chain still names it,
                // but it is not the head's to apply.
                AcceptOutcome::AlreadyApplied => {}
                // Validity is a pure function of the chain prefix and the
                // payload, so a block that does not apply is a verdict on the
                // block rather than on this node: every node reaches it, the
                // entry is not counted, and the chain continues past it.
                //
                // Every `Parked` is skipped, including `StateTransition`, which
                // is where a block carrying a transaction that does not settle
                // lands. `BlockIngestError::is_retryable` cannot separate that
                // from an infra failure yet — its own FIXME says so — and
                // stopping on it would halt production on every honest node
                // until the entry finalized. The residual hazard is the other
                // direction: an infra failure here is read as a verdict, so
                // this node skips an entry its peers count and its `block_id`
                // diverges. Closing that needs a structured cause on
                // `lee::Error`; until then liveness wins, as it did before the
                // head was derived.
                //
                // `RetryableFailure` is never emitted by this `ChainState` — it
                // parks on every failure — so it joins the same arm.
                AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err) => {
                    warn!(
                        "Channel entry at block {} did not apply and is skipped: {err}",
                        block.header.block_id
                    );
                }
            }
        }

        self.channel_cursor = Some(tip);
        Ok(derivation)
    }

    /// Keeps channel entries the checkpoint does not carry, so later
    /// derivations can still account for them. See [`Self::supplement`].
    pub fn remember_supplement(&mut self, entries: impl IntoIterator<Item = (MsgId, LineageEntry)>) {
        self.supplement.extend(entries);
    }

    /// The entry for `msg`, from the checkpoint's view or from what earlier
    /// events supplied that it does not carry.
    fn entry_at<'entry>(
        &'entry self,
        msg: MsgId,
        lineage: &'entry ChannelLineage,
    ) -> Option<&'entry LineageEntry> {
        lineage.get(&msg).or_else(|| self.supplement.get(&msg))
    }

    /// Keeps only the supplement entries the current above-LIB chain still
    /// names.
    ///
    /// By entry id, never by block height: a `Custom` entry carries no block to
    /// take a height from, and one at a height the final tier has passed can
    /// still sit above the boundary on the channel. Anything off the chain has
    /// either finalized or gone to an abandoned branch; if such a branch comes
    /// back it left the old lineage, so `adopted` reports it again.
    fn forget_settled_supplement(&mut self, chain: &[MsgId]) {
        self.supplement.retain(|msg, _| chain.contains(msg));
    }

    /// The channel entries between the finalized boundary and `tip`, oldest
    /// first — the chain the head tier is derived from.
    ///
    /// The terminus is checked before the lookup on purpose: a finalized entry
    /// has left the sdk's pending set, so running out of reported entries *at*
    /// the boundary is the end of the chain, not a gap. Running out anywhere
    /// else is [`Stale::LineageGap`], and staying strict about that is what
    /// keeps a short chain from becoming a short `block_id` and a block
    /// published at an id the channel disagrees with.
    ///
    /// # Errors
    ///
    /// [`Stale`] when the reported entries cannot account for the chain.
    fn above_lib(
        &self,
        tip: MsgId,
        lineage: &ChannelLineage,
    ) -> Result<Vec<MsgId>, Stale> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = tip;
        // Revisiting an id means the entries describe a cycle, not a chain.
        while seen.insert(current) {
            if Some(current) == self.finalized_entry || current == MsgId::root() {
                chain.reverse();
                return Ok(chain);
            }
            let Some(entry) = self.entry_at(current, lineage) else {
                return Err(Stale::LineageGap { at: current });
            };
            chain.push(current);
            current = entry.parent;
        }
        Err(Stale::Unbounded)
    }

    /// Whether the next block may be published: the head must be one the last
    /// derivation could check against the channel.
    ///
    /// Read off that derivation rather than walked — the head is built from the
    /// channel chain, so "does the head match the channel" is already settled
    /// by the time a turn asks.
    #[must_use]
    pub const fn may_publish(&self) -> bool {
        !self.derivation_stale
    }

    /// How many derivations in a row found the chain behind the head.
    #[must_use]
    pub const fn consecutive_regressions(&self) -> u32 {
        self.consecutive_regressions
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
    /// Only an extension of the head applies. A block at a height the head
    /// already holds parks: the channel is append-only, so the head only
    /// shortens through a reported orphan.
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

        let mut scratch = Arc::clone(&self.head_state);
        match apply_block(self.head_tip().as_ref(), block, Arc::make_mut(&mut scratch)) {
            Ok(()) => {
                self.head_state = scratch;
                self.head_blocks.push(block.to_owned());
                AcceptOutcome::Applied
            }
            Err(err) => AcceptOutcome::Parked(err),
        }
    }

    /// Applies a block we produced ourselves.
    ///
    /// Our block is not on the channel yet, so a head already at (or past)
    /// this height means a peer's block won the race — ours is stale and the
    /// caller drops it, without the parked outcome an adoption would get.
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
            self.record_own_inscription(this_msg);
        }
        outcome
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
            // Replay walks finalized history, so this entry is below the
            // boundary and moves it. Without that a freshly reconstructed node
            // has no terminus, every walk reads the boundary as a gap, and it
            // never produces until the channel finalizes something new — on a
            // quiet channel, never.
            self.finalized_entry = Some(this_msg);
        }
        outcome
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
        initial_state(true).with_public_accounts([common::test_utils::claimed_producer_seed()])
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

        // Skip-ahead finalized block, not in head: parks the final tier, and
        // the stall records the slot it was threaded with.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_finalized(&bad, slot(20)),
            AcceptOutcome::Parked(_)
        ));
        let stall = chain.final_stall().expect("final stall recorded");
        assert_eq!(stall.block_id, Some(3));
        assert_eq!(stall.l1_slot, slot(20));
    }

    /// Entries in channel order, each chaining on the one before it.
    fn lineage_of(entries: &[(MsgId, Option<&Block>)]) -> ChannelLineage {
        let mut map = HashMap::new();
        let mut parent = MsgId::root();
        for (msg, block) in entries {
            map.insert(
                *msg,
                crate::lineage::LineageEntry {
                    parent,
                    block: block.cloned(),
                },
            );
            parent = *msg;
        }
        ChannelLineage::new(map)
    }

    /// Entries for `blocks` as `msg(1..=n)`, chaining in order.
    fn lineage_for(blocks: &[Block]) -> ChannelLineage {
        let entries: Vec<(MsgId, Option<&Block>)> = blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| {
                let position = u8::try_from(idx).expect("few blocks").saturating_add(1);
                (msg(position), Some(block))
            })
            .collect();
        lineage_of(&entries)
    }

    /// Sets the finalized boundary the walk terminates at.
    fn with_boundary(chain: &mut ChainState, finalized_entry: Option<MsgId>) {
        chain.finalized_entry = finalized_entry;
    }

    #[test]
    fn above_lib_walks_from_the_pin_back_to_the_finalized_entry() {
        let chain = ChainState::new(claimed_initial_state());
        let lineage = lineage_of(&[(msg(1), None), (msg(2), None), (msg(3), None)]);

        assert_eq!(
            chain.above_lib(msg(3), &lineage),
            Ok(vec![msg(1), msg(2), msg(3)]),
            "the chain reads oldest first, from the boundary up to the pin"
        );
    }

    #[test]
    fn above_lib_stops_at_the_finalized_entry_without_including_it() {
        // msg(1) finalized, so it has left the reported entries.
        let mut chain = ChainState::new(claimed_initial_state());
        with_boundary(&mut chain, Some(msg(1)));
        let mut map = HashMap::new();
        map.insert(
            msg(2),
            crate::lineage::LineageEntry {
                parent: msg(1),
                block: None,
            },
        );
        map.insert(
            msg(3),
            crate::lineage::LineageEntry {
                parent: msg(2),
                block: None,
            },
        );
        let lineage = ChannelLineage::new(map);

        assert_eq!(
            chain.above_lib(msg(3), &lineage),
            Ok(vec![msg(2), msg(3)]),
            "the finalized entry is the terminus, not a member"
        );
    }

    #[test]
    fn above_lib_is_empty_when_the_pin_is_the_finalized_entry() {
        let mut chain = ChainState::new(claimed_initial_state());
        with_boundary(&mut chain, Some(msg(7)));

        assert_eq!(
            chain.above_lib(msg(7), &ChannelLineage::default()),
            Ok(Vec::new()),
            "nothing sits above the boundary the pin already names"
        );
    }

    #[test]
    fn above_lib_reports_a_gap_for_an_entry_the_checkpoint_does_not_carry() {
        // What a peer's `Custom`-shaped inscription looks like from here: the
        // channel holds it, the sdk's pending set never mirrored it, so the
        // walk cannot account for the pin. The genesis block is this shape.
        let chain = ChainState::new(claimed_initial_state());
        let lineage = lineage_of(&[(msg(1), None)]);

        assert_eq!(
            chain.above_lib(msg(9), &lineage),
            Err(Stale::LineageGap { at: msg(9) }),
            "an unaccounted entry is a gap, never a silently shorter chain"
        );
    }

    #[test]
    fn above_lib_rejects_entries_that_describe_a_cycle() {
        let chain = ChainState::new(claimed_initial_state());
        let mut map = HashMap::new();
        map.insert(
            msg(1),
            crate::lineage::LineageEntry {
                parent: msg(2),
                block: None,
            },
        );
        map.insert(
            msg(2),
            crate::lineage::LineageEntry {
                parent: msg(1),
                block: None,
            },
        );

        assert_eq!(
            chain.above_lib(msg(1), &ChannelLineage::new(map)),
            Err(Stale::Unbounded),
            "a cycle in the reported entries must not spin"
        );
    }

    #[test]
    fn a_restored_boundary_lets_the_first_derivation_after_a_restart_succeed() {
        // After a restart the entries the checkpoint carries chain on the last
        // finalized inscription, which is not root. Without the persisted
        // boundary the walk cannot tell that terminus from a gap, and a quiet
        // channel never supplies a new one.
        let s0 = claimed_initial_state();
        let (b1, s1) = settled(&s0, 1, HashType([0_u8; 32]), vec![]);
        let (b2, _) = settled(&s1, 2, b1.header.hash, vec![]);
        let mut map = HashMap::new();
        map.insert(
            msg(2),
            crate::lineage::LineageEntry {
                parent: msg(1),
                block: Some(b2),
            },
        );
        let lineage = ChannelLineage::new(map);
        let at_b1 = || ChainState::from_final(s1.clone(), Some(Tip::from(&b1)));

        let mut cold = at_b1();
        assert_eq!(
            cold.derive_head(msg(2), &lineage, None, &[])
                .expect_err("without the boundary the terminus reads as a gap"),
            Stale::LineageGap { at: msg(1) }
        );

        let mut restored = at_b1();
        restored.restore_finalized_entry(msg(1));
        restored
            .derive_head(msg(2), &lineage, None, &[])
            .expect("the restored boundary terminates the walk");

        assert_eq!(restored.head_tip().expect("head tip").block_id, 2);
        assert!(restored.may_publish());
    }

    #[test]
    fn a_supplied_entry_still_derives_on_later_events_that_do_not_carry_it() {
        // A peer's `Custom`-shaped entry — the genesis block on every
        // follower — reaches a node once, in the `adopted` of the event that
        // reports it. The sdk never mirrors that shape into `pending` and
        // `adopted` never re-sends, so a chain that consulted only the
        // checkpoint would gap on it from the very next event until it
        // finalized, freezing the head for the whole unfinalized window.
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let supplied = || {
            (
                msg(1),
                LineageEntry {
                    parent: MsgId::root(),
                    block: Some(b1.clone()),
                },
            )
        };
        // The next event's checkpoint carries b2 alone, chained on the entry
        // only the first event ever reported.
        let later = || {
            let mut map = HashMap::new();
            map.insert(
                msg(2),
                LineageEntry {
                    parent: msg(1),
                    block: Some(b2.clone()),
                },
            );
            ChannelLineage::new(map)
        };

        let mut kept = ChainState::new(claimed_initial_state());
        kept.remember_supplement([supplied()]);
        kept.derive_head(msg(1), &ChannelLineage::default(), None, &[])
            .expect("the supplied entry accounts for the first chain");
        kept.derive_head(msg(2), &later(), None, &[])
            .expect("and still accounts for the next one");
        assert_eq!(kept.head_tip().expect("head tip").block_id, 2);

        // Without keeping it, the same second event cannot be accounted for.
        let mut forgotten = ChainState::new(claimed_initial_state());
        assert_eq!(
            forgotten
                .derive_head(msg(2), &later(), None, &[])
                .expect_err("an unsupplied entry gaps the walk"),
            Stale::LineageGap { at: msg(1) }
        );
    }

    #[test]
    fn a_first_walk_that_regresses_still_leaves_a_pin() {
        // A node that joins an existing channel holds genesis on its head
        // before the chain reports it — a peer's genesis is `Custom`-shaped,
        // so it reaches the walk only once `adopted` supplies it. That first
        // walk regresses. The pin must still take the reported tip: a
        // regression clears only on an orphan report, and genesis never gets
        // one, so a pin withheld here is withheld for good.
        let genesis = produce_dummy_block(1, None, vec![]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain.apply_adopted(&genesis);
        assert_eq!(chain.pin_parent(), None, "nothing followed yet");

        // The chain carries one entry naming no block, so it accounts for
        // nothing the head holds.
        let lineage = lineage_of(&[(msg(2), None)]);
        assert!(matches!(
            chain.derive_head(msg(2), &lineage, None, &[]),
            Err(Stale::Regressed { .. })
        ));

        assert_eq!(
            chain.pin_parent(),
            Some(msg(2)),
            "an unset pin takes the reported tip even from a walk that did not commit"
        );
        assert_eq!(
            chain.head_tip().expect("head tip").block_id,
            1,
            "and the head it could not reconcile is left alone"
        );
    }

    #[test]
    fn an_established_pin_is_not_rewound_by_a_walk_that_regresses() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let lineage = lineage_for(&[b1.clone()]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(1), &lineage, None, &[])
            .expect("derives");
        assert_eq!(chain.pin_parent(), Some(msg(1)));

        // A checkpoint the sdk built before that publish names none of it.
        assert!(matches!(
            chain.derive_head(MsgId::root(), &ChannelLineage::default(), None, &[]),
            Err(Stale::Regressed { .. })
        ));
        assert_eq!(
            chain.pin_parent(),
            Some(msg(1)),
            "a buffered checkpoint must not rewind a pin we already have"
        );
    }

    #[test]
    fn a_derived_head_may_publish() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let lineage = lineage_for(&[b1]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(1), &lineage, None, &[])
            .expect("derives");

        assert!(chain.may_publish());
    }

    #[test]
    fn an_underivable_chain_refuses_the_turn_and_keeps_the_head() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let lineage = lineage_for(&[b1]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(1), &lineage, None, &[])
            .expect("derives");

        // The pin names an entry this checkpoint cannot account for — a peer's
        // `Custom` inscription that the adopted merge did not supply.
        assert_eq!(
            chain
                .derive_head(msg(9), &lineage, None, &[])
                .expect_err("the chain is not accountable"),
            Stale::LineageGap { at: msg(9) }
        );
        assert!(
            !chain.may_publish(),
            "a head that could not be checked against the channel is not one to publish on"
        );
        assert_eq!(
            chain.head_tip().expect("head tip").block_id,
            1,
            "and the head it had is left alone"
        );
    }

    #[test]
    fn a_regressed_checkpoint_keeps_the_head_and_still_allows_the_turn() {
        // A checkpoint behind the head says the checkpoint is stale, not that
        // the head is unknown — the sdk buffers one across a reconnect. The
        // head stands and the turn runs; L1 refuses a publish pinned on an
        // entry the channel has moved past, so nothing can land wrongly.
        let s0 = claimed_initial_state();
        let (b1, s1) = settled(&s0, 1, HashType([0_u8; 32]), vec![]);
        let (b2, _) = settled(&s1, 2, b1.header.hash, vec![]);
        let full = lineage_of(&[(msg(1), Some(&b1)), (msg(2), Some(&b2))]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(2), &full, None, &[])
            .expect("both derive");

        chain
            .derive_head(msg(1), &lineage_of(&[(msg(1), Some(&b1))]), None, &[])
            .expect_err("the regressed chain is refused");

        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert!(
            chain.may_publish(),
            "a stale checkpoint must not stop the node producing"
        );
    }

    #[test]
    fn a_later_derivable_chain_clears_the_refusal() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let lineage = lineage_for(&[b1, b2]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(9), &lineage, None, &[])
            .expect_err("gaps first");
        assert!(!chain.may_publish());

        chain
            .derive_head(msg(2), &lineage, None, &[])
            .expect("the next update derives");

        assert!(chain.may_publish());
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
    }

    #[test]
    fn derive_head_applies_the_whole_chain_in_order() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let lineage = lineage_for(&[b1, b2]);
        let mut chain = ChainState::new(claimed_initial_state());

        let derivation = chain
            .derive_head(msg(2), &lineage, None, &[])
            .expect("chain is accounted for");

        assert_eq!(derivation.applied.len(), 2);
        assert!(derivation.dropped.is_empty());
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn derive_head_extends_without_reapplying_the_prefix() {
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let lineage = lineage_for(&[b1, b2.clone()]);
        let mut chain = ChainState::new(claimed_initial_state());

        chain
            .derive_head(msg(1), &lineage, None, &[])
            .expect("prefix derives");
        let derivation = chain
            .derive_head(msg(2), &lineage, None, &[])
            .expect("extension derives");

        assert_eq!(
            derivation.applied.len(),
            1,
            "a pure extension applies only the new tail"
        );
        assert_eq!(derivation.applied[0].header.hash, b2.header.hash);
        assert!(derivation.dropped.is_empty(), "nothing left the head");
    }

    #[test]
    fn a_block_whose_transactions_do_not_settle_is_skipped_and_the_turn_holds() {
        // The common deterministic failure: a peer's block carries a
        // transaction that cannot settle against the prefix state. It lands in
        // `BlockIngestError::StateTransition`, which `is_retryable` still
        // reports as transient. Stopping the head there would halt production
        // on every honest node until the entry finalized, so the entry is
        // skipped and a valid competitor at the same height takes its place.
        let s0 = claimed_initial_state();
        let (b1, s1) = settled(&s0, 1, HashType([0_u8; 32]), vec![]);

        let sign_key = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
        let from = initial_pub_accounts_private_keys()[0].account_id;
        let to = initial_pub_accounts_private_keys()[1].account_id;
        // A nonce the account is nowhere near: settlement rejects it.
        let doomed = create_transaction_native_token_transfer(from, 99, to, 10, &sign_key);
        let unsettleable = produce_dummy_block(2, Some(b1.header.hash), vec![doomed]);
        let (rival, _) = settled(&s1, 2, b1.header.hash, vec![]);
        assert_ne!(unsettleable.header.hash, rival.header.hash);

        let lineage = lineage_of(&[
            (msg(1), Some(&b1)),
            (msg(2), Some(&unsettleable)),
            (msg(3), Some(&rival)),
        ]);
        let mut chain = ChainState::new(claimed_initial_state());

        let derivation = chain
            .derive_head(msg(3), &lineage, None, &[])
            .expect("the chain is accounted for");

        assert_eq!(
            derivation
                .applied
                .iter()
                .map(|block| block.header.hash)
                .collect::<Vec<_>>(),
            vec![b1.header.hash, rival.header.hash],
            "the competitor takes the height the unsettleable block could not"
        );
        assert_eq!(chain.head_tip().expect("head tip").hash, rival.header.hash);
        assert!(
            chain.may_publish(),
            "one peer's bad block must not hold every node's turn"
        );
    }

    #[test]
    fn derive_head_skips_a_block_that_is_deterministically_invalid() {
        // The chain carries three entries and the third does not chain on the
        // second. Validity is a pure function of the chain prefix and the
        // payload, so every node reaches the same verdict: the entry is not
        // counted and the chain continues past it. Stopping instead would halt
        // production fleet-wide for the whole unfinalized window.
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let orphaned_b3 = produce_dummy_block(3, Some(HashType([9_u8; 32])), vec![]);
        let lineage = lineage_for(&[b1, b2, orphaned_b3]);
        let mut chain = ChainState::new(claimed_initial_state());

        let derivation = chain
            .derive_head(msg(3), &lineage, None, &[])
            .expect("the chain is accounted for");

        assert_eq!(
            derivation.applied.len(),
            2,
            "the invalid entry contributes nothing to the head"
        );
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
        assert!(
            chain.may_publish(),
            "an invalid entry is a verdict on the block, not a reason to stop producing"
        );
    }

    #[test]
    fn derive_head_refuses_to_drop_a_held_block_without_an_orphan_report() {
        // A checkpoint older than the head — the sdk buffers one across a
        // reconnect — names a chain missing blocks the head holds. Believing it
        // would wipe work that is still on the channel.
        let s0 = claimed_initial_state();
        let (b1, s1) = settled(&s0, 1, HashType([0_u8; 32]), vec![]);
        let (b2, _) = settled(&s1, 2, b1.header.hash, vec![]);
        let full = lineage_of(&[(msg(1), Some(&b1)), (msg(2), Some(&b2))]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(2), &full, None, &[])
            .expect("both derive");

        let stale = lineage_of(&[(msg(1), Some(&b1))]);

        assert_eq!(
            chain
                .derive_head(msg(1), &stale, None, &[])
                .expect_err("a regressed chain is refused"),
            Stale::Regressed {
                dropped: b2.header.hash
            },
            "a block leaves the head only on evidence that it left the channel"
        );
        assert_eq!(
            chain.head_tip().expect("head tip").block_id,
            2,
            "and the head is left alone"
        );
    }

    #[test]
    fn derive_head_skips_an_entry_carrying_no_block() {
        // Garbage moved the channel tip without moving the head.
        let b1 = produce_dummy_block(1, None, vec![]);
        let b2 = produce_dummy_block(2, Some(b1.header.hash), vec![]);
        let lineage = lineage_of(&[(msg(1), Some(&b1)), (msg(2), None), (msg(3), Some(&b2))]);
        let mut chain = ChainState::new(claimed_initial_state());

        let derivation = chain
            .derive_head(msg(3), &lineage, None, &[])
            .expect("the chain is accounted for");

        assert_eq!(derivation.applied.len(), 2, "garbage is stepped over");
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);
    }

    #[test]
    fn derive_head_drops_a_suffix_the_chain_no_longer_carries() {
        let s0 = claimed_initial_state();
        let (b1, s1) = settled(&s0, 1, HashType([0_u8; 32]), vec![]);
        let (b2, _) = settled(&s1, 2, b1.header.hash, vec![]);
        let before = lineage_of(&[(msg(1), Some(&b1)), (msg(2), Some(&b2))]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain
            .derive_head(msg(2), &before, None, &[])
            .expect("both derive");
        assert_eq!(chain.head_tip().expect("head tip").block_id, 2);

        // A reorg replaced the second entry with a different block at the same
        // height. It must differ in content: an identical block re-inscribed
        // under a new entry id is the same block, not a competitor — which is
        // why the prefix is matched by hash and never by entry id.
        let sign_key = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
        let from = initial_pub_accounts_private_keys()[0].account_id;
        let to = initial_pub_accounts_private_keys()[1].account_id;
        let tx = create_transaction_native_token_transfer(from, 0, to, 10, &sign_key);
        let (rival, _) = settled(&s1, 2, b1.header.hash, vec![tx]);
        assert_ne!(rival.header.hash, b2.header.hash, "the rival must differ");
        let after = lineage_of(&[(msg(1), Some(&b1)), (msg(5), Some(&rival))]);

        let derivation = chain
            .derive_head(msg(5), &after, None, std::slice::from_ref(&b2))
            .expect("the new chain derives");

        assert_eq!(
            derivation.dropped.len(),
            1,
            "the entry the chain dropped leaves the head"
        );
        assert_eq!(derivation.dropped[0].header.hash, b2.header.hash);
        assert_eq!(derivation.applied.len(), 1, "the competitor takes its place");
        assert_eq!(chain.head_tip().expect("head tip").hash, rival.header.hash);
        assert_head_matches_replay(&chain);
    }

    #[test]
    fn derive_head_treats_a_re_inscribed_block_as_the_same_block() {
        // The same block under a new entry id is a re-inscription, not a
        // competitor: nothing leaves the head and nothing is re-applied.
        let b1 = produce_dummy_block(1, None, vec![]);
        let before = lineage_of(&[(msg(1), Some(&b1))]);
        let mut chain = ChainState::new(claimed_initial_state());
        chain.derive_head(msg(1), &before, None, &[]).expect("derives");

        let after = lineage_of(&[(msg(4), Some(&b1))]);
        let derivation = chain
            .derive_head(msg(4), &after, None, &[])
            .expect("the re-inscription derives");

        assert!(derivation.dropped.is_empty(), "the block never left");
        assert!(derivation.applied.is_empty(), "and is not applied twice");
        assert_eq!(chain.head_tip().expect("head tip").block_id, 1);
    }

    #[test]
    fn adopted_competitor_without_orphan_event_parks() {
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

        // A second block 2 lands after block 3 with nothing orphaned: it parks.
        let block2_prime = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            chain.apply_adopted(&block2_prime),
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 4,
                got: 2
            })
        ));
        let tip = chain.head_tip().expect("head tip");
        assert_eq!(tip.block_id, 3);
        assert_eq!(tip.hash, block3.header.hash);
        assert_eq!(
            chain.head_state().get_account_by_id(to).balance,
            INITIAL_TO_BALANCE + 20
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

        // Our own block at that height is not on the channel, so it must not
        // reorg the head onto itself.
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

    /// The first inscription on a channel chains on root, so root is a used
    /// parent from then on and a tip naming it is refused like any other.
    /// Pinning back on an entry we already built on would put a second block at
    /// one height, and the channel keeps only one of them.
    /// A garbage inscription or a config op moves the tip while naming no block,
    /// and must still be followed.
    /// News about our block frees the entry it chained on, however it arrives.
    /// The pin counts as ours only until the channel rules on the block behind it.
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

        // The L1 orphans restored block 3 under its real (unknown-to-us) MsgId.
        // The head holds no ids for restored blocks, so the chain it is matched
        // against is correlated by hash: block 2 stays, block 3 leaves on the
        // orphan report, and the competitor takes its height.
        let block3_prime = produce_dummy_block(3, Some(block2.header.hash), vec![]);
        let after = lineage_of(&[(msg(1), Some(&block2)), (msg(2), Some(&block3_prime))]);
        let derivation = chain
            .derive_head(msg(2), &after, None, std::slice::from_ref(&block3))
            .expect("the new chain derives");

        assert_eq!(derivation.dropped.len(), 1);
        assert_eq!(derivation.dropped[0].header.hash, block3.header.hash);
        assert_eq!(chain.head_tip().expect("head tip").block_id, 3);
        assert_eq!(
            chain.head_tip().expect("head tip").hash,
            block3_prime.header.hash
        );
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
