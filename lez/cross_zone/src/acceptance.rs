//! The one peer-block acceptance policy.
//!
//! The sequencer's watcher and the indexer's verifier both admit peer blocks
//! through here, so they cannot disagree about which block holds an id: a
//! disagreement makes the verifier re-derive a delivery against a block the
//! watcher never delivered from, and ingestion halts.

use std::fmt::{self, Display, Formatter};

use common::{
    HashType,
    block::{Block, PeerChainTip},
};
use cross_zone_inbox_core::{CrossZonePeer, ZoneId};
use lee::{GENESIS_BLOCK_ID, PublicKey};

/// Consecutive passes a reader spends stuck on one slot before it says so as
/// something more than the per-pass failure. It never reads past the slot.
///
/// The cadence bounds log volume only: at one pass per poll interval, 5 passes
/// is roughly seconds to tens of seconds depending on each side's interval.
pub const STUCK_SLOT_ALERT_PASSES: u32 = 5;

/// How many consecutive failed committee reads keep the last known size.
///
/// Past this the floor fails closed again. An absent channel folds in here
/// too: it also yields no messages, so within this bound nothing is consumed
/// on its word either way.
pub const KEPT_FLOOR_READ_FAILURES: u32 = STUCK_SLOT_ALERT_PASSES;

/// Where a screened peer block sits relative to the chain pinned by `tip`.
#[derive(Debug, PartialEq, Eq)]
pub enum Link {
    /// The next block on the peer's chain, carrying its recomputed hash.
    Next(HashType),
    /// At or below the tip, so already accepted from. The ordinary shape of a
    /// re-read slot. `equivocates` is set when the block claims the tip's own
    /// id under a different hash, so callers can say so; below the tip there is
    /// no held hash to compare against and it is never set.
    AlreadySeen { equivocates: bool },
    /// Not on the chain the tip pins, so not acceptable. Callers read on: the
    /// peer's own next block still links to the tip, and treating this as
    /// terminal would hand the peer a way to stop its deliveries permanently.
    OffChain(OffChain),
}

/// Why a block is not on the chain the tip pins.
#[derive(Debug, PartialEq, Eq)]
pub enum OffChain {
    /// The next id off the tip, but linking to some other predecessor.
    DoesNotLink {
        block_id: u64,
        tip_id: u64,
        links_to: HashType,
        expected: HashType,
    },
    /// Read with no stored tip, and not the peer's genesis. Anchoring on
    /// whatever arrived first would let the peer pick the id, and burn every
    /// replay key below it with one block.
    NotTheGenesis { block_id: u64 },
    /// An id above the next one on the chain.
    SkipsAhead { block_id: u64, next: u64 },
}

impl Display for OffChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DoesNotLink {
                block_id,
                tip_id,
                links_to,
                expected,
            } => write!(
                f,
                "block {block_id} does not follow block {tip_id}: it links to {links_to} rather than {expected}"
            ),
            Self::NotTheGenesis { block_id } => write!(
                f,
                "block {block_id} is the first one read, but with no stored chain tip acceptance has to start at the peer's genesis block {GENESIS_BLOCK_ID}"
            ),
            Self::SkipsAhead { block_id, next } => write!(
                f,
                "block {block_id} skips past {next}, which is either a hole in what this node read or an id claimed ahead of the peer's chain"
            ),
        }
    }
}

/// Why a peer block was refused before any chain placement.
///
/// The channel authorizes who may write, not what they may claim. The hash
/// check is unconditional: the signature does not cover `header.hash`, and the
/// chain link compares hashes, so an unchecked one lets a peer assert links it
/// never built. The pinned keys, checked only when any are configured, are what
/// say one of the peer's own sequencers produced the block; they subsume
/// nothing here, since a correctly signed block may still carry a bogus hash.
#[derive(Debug, PartialEq, Eq)]
pub enum ScreenRefusal {
    /// `header.hash` is not the hash of the block's contents.
    HashMismatch {
        block_id: u64,
        declared: HashType,
        recomputed: HashType,
    },
    /// The block is not signed by any pinned block-signing key.
    KeyMismatch { block_id: u64 },
}

impl Display for ScreenRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::HashMismatch {
                block_id,
                declared,
                recomputed,
            } => write!(
                f,
                "block {block_id} carries header hash {declared} but its contents hash to {recomputed}"
            ),
            Self::KeyMismatch { block_id } => write!(
                f,
                "block {block_id} is not signed by any pinned block-signing key"
            ),
        }
    }
}

/// The pass-to-pass stall of one peer reader: the slot it is stuck on and how
/// many consecutive passes it has spent there. Keyed by slot so a failure at a
/// new slot does not inherit an older slot's count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallState<S> {
    stalled: Option<(S, u32)>,
}

impl<S> Default for StallState<S> {
    fn default() -> Self {
        Self { stalled: None }
    }
}

impl<S: Copy + PartialEq + PartialOrd> StallState<S> {
    /// The slot the reader is stuck on and for how many passes, or `None` when
    /// it is not stuck.
    #[must_use]
    pub const fn current(&self) -> Option<(S, u32)> {
        self.stalled
    }

    /// Folds one pass in: `stuck_on` is the slot the pass ended inside, `None`
    /// for a pass that ended cleanly. Returns the slot the reader is stuck on
    /// and how long it has been stuck, so the caller can say so on the
    /// [`alerts_at`] cadence.
    ///
    /// `read_to` is the read position after the pass, and is what tells a
    /// stream that truncated early apart from one that genuinely drained: the
    /// zone-sdk ends a stream on a fetch failure exactly as it does on catching
    /// up, so without it a flaky peer endpoint resets the count for ever and a
    /// reader stuck for hours never says so.
    pub fn after_pass(&mut self, stuck_on: Option<S>, read_to: Option<S>) -> Option<(S, u32)> {
        let Some(slot) = stuck_on else {
            if self.passed_the_stall(read_to) {
                self.stalled = None;
            }
            return None;
        };
        let attempts = match self.stalled {
            Some((held, attempts)) if held == slot => attempts.saturating_add(1),
            _ => 1,
        };
        self.stalled = Some((slot, attempts));
        self.stalled
    }

    /// Whether the read position is now past whatever the reader was stuck on.
    /// Vacuously true when it was not stuck.
    fn passed_the_stall(self, read_to: Option<S>) -> bool {
        self.stalled
            .is_none_or(|(stuck_on, _)| read_to.is_some_and(|slot| slot >= stuck_on))
    }
}

/// The pass-to-pass committee-floor latch of one peer reader: whether the
/// peer's live committee was last seen at or above the configured floor.
///
/// A committee below the floor is not misbehaviour: with join/exit queues a
/// peer's committee legitimately dips while an exit drains. The floor is a
/// trust policy, so the reader holds rather than dropping anything, and it
/// resumes on its own once the committee recovers. The live (adopted) set is
/// what is read, deliberately: suspension only errs in the reversible
/// direction, while a finalized-only view would keep deliveries flowing for
/// the whole finalization lag of a real committee collapse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeFloorState {
    min: u32,
    /// Last successfully read committee size and the channel tip slot it was
    /// read at.
    ///
    /// A read failure keeps it for [`KEPT_FLOOR_READ_FAILURES`] passes: the
    /// floor is a policy on the committee, not a liveness probe, and a
    /// transient failure suspending it would only flap. The keep is bounded
    /// because the committee read and the message stream are different routes
    /// whose failures are not fate-shared: a route that breaks while messages
    /// still flow would otherwise disarm the floor for good, silently.
    last_known: Option<(usize, u64)>,
    /// Consecutive failed reads, 0 after any successful one.
    failed_reads: u32,
    /// Consecutive suspended passes, 0 while active.
    suspended_passes: u32,
}

/// What [`CommitteeFloorState::after_read`] decided for this pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorVerdict {
    /// Run the pass. `resumed` marks the suspended-to-active edge.
    Active { resumed: bool },
    /// Skip the pass. `passes` counts consecutive suspended passes including
    /// this one, 1 on the transition, so the caller reports on the
    /// [`alerts_at`] cadence. `last_read` is the size and channel tip slot
    /// behind the verdict, `None` before any successful read.
    Suspended {
        passes: u32,
        last_read: Option<(usize, u64)>,
    },
}

impl CommitteeFloorState {
    #[must_use]
    pub const fn new(min_committee_size: u32) -> Self {
        Self {
            min: min_committee_size,
            last_known: None,
            failed_reads: 0,
            suspended_passes: 0,
        }
    }

    /// Whether a floor is set at all. Callers skip the channel-state read when
    /// it is not, so a floorless peer costs no extra request and a floor of 0
    /// can never suspend.
    #[must_use]
    pub const fn enforced(&self) -> bool {
        self.min > 0
    }

    /// Folds one pass's channel-state read in: `Some((committee size, tip
    /// slot))` on a successful read, `None` on a failed read or an absent
    /// channel, both unknown rather than zero.
    ///
    /// Unknown before the first successful read suspends: with a floor set,
    /// running on a committee never yet seen would be trusting exactly what
    /// the floor exists to check.
    pub fn after_read(&mut self, read: Option<(usize, u64)>) -> FloorVerdict {
        if !self.enforced() {
            return FloorVerdict::Active { resumed: false };
        }
        if let Some(read) = read {
            self.failed_reads = 0;
            self.last_known = Some(read);
        } else {
            self.failed_reads = self.failed_reads.saturating_add(1);
        }
        let known = if self.failed_reads > KEPT_FLOOR_READ_FAILURES {
            None
        } else {
            self.last_known
        };
        let met = known
            .is_some_and(|(size, _)| size >= usize::try_from(self.min).expect("u32 fits usize"));
        if met {
            let resumed = self.suspended_passes > 0;
            self.suspended_passes = 0;
            FloorVerdict::Active { resumed }
        } else {
            self.suspended_passes = self.suspended_passes.saturating_add(1);
            FloorVerdict::Suspended {
                passes: self.suspended_passes,
                last_read: self.last_known,
            }
        }
    }
}

/// Whether a reader stuck for `attempts` passes should say so on this one.
///
/// Every [`STUCK_SLOT_ALERT_PASSES`], not on the crossing alone: a stall that
/// never clears would otherwise be reported once and then look resolved for as
/// long as it lasts. Not every pass, since that is one line per block time.
#[must_use]
pub const fn alerts_at(attempts: u32) -> bool {
    attempts > 0 && attempts.is_multiple_of(STUCK_SLOT_ALERT_PASSES)
}

/// The one report both sides log for a differing block at an id the accepted
/// chain already holds.
#[must_use]
pub fn equivocation_report(
    peer_zone: &ZoneId,
    block_id: u64,
    holding: HashType,
    refusing: HashType,
) -> String {
    format!(
        "Peer zone {} equivocated at block {block_id}: holding {holding}, refusing {refusing}. Nothing at or above block {block_id} can be delivered from until that peer inscribes a block continuing the run verified from its genesis.",
        hex::encode(peer_zone)
    )
}

/// Whether `block` continues the peer chain pinned by `tip`.
///
/// `recomputed` is the hash [`screen_peer_block`] returned for it, so a tip
/// stored off [`Link::Next`] pins contents rather than a declared field.
///
/// This is what closes the id suppression. A delivered message's replay key
/// covers `(src_zone, src_block_id, src_tx_index)` and nothing else, so a peer
/// that can get a block accepted under an id of its choosing burns the key an
/// honest block would later use, and the inbox then no-ops the real message as
/// a replay. Off a hash link ids are only claimable in order, so the only id
/// within reach is the one the peer is about to publish anyway.
#[must_use]
pub fn link_to_tip(tip: Option<&PeerChainTip>, block: &Block, recomputed: HashType) -> Link {
    let block_id = block.header.block_id;
    let Some(tip) = tip else {
        return if block_id == GENESIS_BLOCK_ID {
            Link::Next(recomputed)
        } else {
            Link::OffChain(OffChain::NotTheGenesis { block_id })
        };
    };

    if block_id <= tip.block_id {
        return Link::AlreadySeen {
            equivocates: block_id == tip.block_id && recomputed != tip.block_hash,
        };
    }
    let next = tip.block_id.saturating_add(1);
    if block_id > next {
        return Link::OffChain(OffChain::SkipsAhead { block_id, next });
    }
    if block.header.prev_block_hash != tip.block_hash {
        return Link::OffChain(OffChain::DoesNotLink {
            block_id,
            tip_id: tip.block_id,
            links_to: block.header.prev_block_hash,
            expected: tip.block_hash,
        });
    }
    Link::Next(recomputed)
}

/// Whether a block read off a peer's channel may be considered for the chain at
/// all, returning the recomputed hash every later placement has to use.
pub fn screen_peer_block(
    block: &Block,
    expected_pubkeys: &[PublicKey],
) -> Result<HashType, ScreenRefusal> {
    let recomputed = block.recompute_hash();
    if recomputed != block.header.hash {
        return Err(ScreenRefusal::HashMismatch {
            block_id: block.header.block_id,
            declared: block.header.hash,
            recomputed,
        });
    }
    if !signed_by_any(block, expected_pubkeys) {
        return Err(ScreenRefusal::KeyMismatch {
            block_id: block.header.block_id,
        });
    }
    Ok(recomputed)
}

/// Whether `block` is signed by one of the peer's pinned keys.
///
/// Vacuously true with none pinned: the check is opt-in, and every place that
/// judges a peer block's signature goes through here so they cannot diverge on
/// that rule.
#[must_use]
pub fn signed_by_any(block: &Block, pinned: &[PublicKey]) -> bool {
    pinned.is_empty() || pinned.iter().any(|key| block.is_signed_by(key))
}

/// The peer's configured block-signing keys, parsed. Panics on a malformed
/// entry: both sides read this at startup, so a bad config byte fails the
/// process before it judges any block.
#[must_use]
pub fn pinned_keys(peer: &CrossZonePeer) -> Vec<PublicKey> {
    peer.expected_block_signing_pubkeys
        .iter()
        .map(|&bytes| {
            PublicKey::try_new(bytes).expect("configured peer block-signing pubkey is a valid key")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use common::test_utils::produce_dummy_block;

    use super::*;
    use crate::test_utils::linked_chain_to;

    /// The peer's block at `block_id`, on its one honest chain.
    fn chain_block(block_id: u64) -> Block {
        linked_chain_to(block_id, |_| vec![])
            .pop()
            .expect("chain reaches block_id")
    }

    /// The hash the block after `block_id` has to link to.
    fn chain_hash(block_id: u64) -> HashType {
        chain_block(block_id).header.hash
    }

    /// The tip a reader holds after accepting up to `block_id`.
    fn tip_at(block_id: u64) -> PeerChainTip {
        PeerChainTip {
            block_id,
            block_hash: chain_hash(block_id),
        }
    }

    fn screened(block: &Block) -> HashType {
        screen_peer_block(block, &[]).expect("honest block passes screening")
    }

    /// Runs the stall machine over `(stuck_on, read_to)` pass results.
    fn run_stalls(passes: &[(Option<u64>, Option<u64>)]) -> StallState<u64> {
        let mut state = StallState::default();
        for (stuck_on, read_to) in passes {
            state.after_pass(*stuck_on, *read_to);
        }
        state
    }

    #[test]
    fn only_the_next_block_off_the_tip_links() {
        let tip = tip_at(2);

        let next = chain_block(3);
        assert_eq!(
            link_to_tip(Some(&tip), &next, screened(&next)),
            Link::Next(chain_hash(3)),
            "the block that continues the chain is the one accepted"
        );

        // The #677 suppression. The peer's chain is public, so the version that
        // matters is the block linking correctly and lying only about the id:
        // one with no link at all is caught by the same check and proves
        // nothing about this one.
        for ahead in [
            produce_dummy_block(5, Some(chain_hash(2)), vec![]),
            produce_dummy_block(5, None, vec![]),
        ] {
            assert_eq!(
                link_to_tip(Some(&tip), &ahead, screened(&ahead)),
                Link::OffChain(OffChain::SkipsAhead {
                    block_id: 5,
                    next: 3
                })
            );
        }

        // Right id, wrong ancestry: the peer forked at our tip, or reset it.
        let forked = produce_dummy_block(3, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            link_to_tip(Some(&tip), &forked, screened(&forked)),
            Link::OffChain(OffChain::DoesNotLink { .. })
        ));
    }

    #[test]
    fn a_reader_with_no_tip_starts_at_the_peers_genesis() {
        let genesis = chain_block(GENESIS_BLOCK_ID);
        assert_eq!(
            link_to_tip(None, &genesis, screened(&genesis)),
            Link::Next(chain_hash(GENESIS_BLOCK_ID))
        );
        // Anchoring on whatever arrived first is the whole attack: the peer
        // would pick the id, and every key below it with one block.
        let mid_chain = chain_block(GENESIS_BLOCK_ID + 1);
        assert_eq!(
            link_to_tip(None, &mid_chain, screened(&mid_chain)),
            Link::OffChain(OffChain::NotTheGenesis {
                block_id: GENESIS_BLOCK_ID + 1
            })
        );
    }

    #[test]
    fn a_differing_block_at_the_tip_id_reports_equivocation() {
        // Two blocks claiming one id collapse to one replay key on chain, so
        // accepting both delivers one message twice. The re-read of the block
        // the tip holds is ordinary; only a differing hash is worth a report.
        let tip = tip_at(2);

        let held = chain_block(2);
        assert_eq!(
            link_to_tip(Some(&tip), &held, screened(&held)),
            Link::AlreadySeen { equivocates: false }
        );

        let differing = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert_eq!(
            link_to_tip(Some(&tip), &differing, screened(&differing)),
            Link::AlreadySeen { equivocates: true }
        );

        // Below the tip there is no held hash to compare against.
        let below = produce_dummy_block(1, Some(HashType([9; 32])), vec![]);
        assert_eq!(
            link_to_tip(Some(&tip), &below, screened(&below)),
            Link::AlreadySeen { equivocates: false }
        );
    }

    #[test]
    fn a_block_whose_header_hash_is_not_its_contents_is_refused() {
        // A correctly signed block can still carry any value in `header.hash`.
        let mut tampered = chain_block(3);
        tampered.header.hash = HashType([9; 32]);
        assert!(matches!(
            screen_peer_block(&tampered, &[]),
            Err(ScreenRefusal::HashMismatch { block_id: 3, .. })
        ));

        // And the hash verdict comes first, whatever else is wrong.
        let other = lee::PublicKey::try_new([42; 32]).expect("test key");
        assert!(matches!(
            screen_peer_block(&tampered, &[other]),
            Err(ScreenRefusal::HashMismatch { .. })
        ));
    }

    #[test]
    fn a_block_not_signed_by_the_pinned_key_is_refused() {
        let signer = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([37; 32]).expect("test key"),
        );
        let block = chain_block(GENESIS_BLOCK_ID);
        assert_eq!(
            screen_peer_block(&block, &[signer]),
            Ok(chain_hash(GENESIS_BLOCK_ID)),
            "produce_dummy_block signs with this key, so the pin must accept it"
        );

        let other = lee::PublicKey::try_new([42; 32]).expect("test key");
        assert!(matches!(
            screen_peer_block(&block, &[other]),
            Err(ScreenRefusal::KeyMismatch {
                block_id: GENESIS_BLOCK_ID
            })
        ));
    }

    #[test]
    fn a_block_signed_by_any_key_in_the_set_is_accepted() {
        // The multi-sequencer peer shape: the block's signer is one configured
        // key among several, not the first one listed.
        let signer = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([37; 32]).expect("test key"),
        );
        let other = lee::PublicKey::try_new([42; 32]).expect("test key");
        let block = chain_block(GENESIS_BLOCK_ID);
        assert_eq!(
            screen_peer_block(&block, &[other.clone(), signer]),
            Ok(chain_hash(GENESIS_BLOCK_ID)),
            "any listed key admits the block, whatever its position"
        );

        // A set none of whose keys signed refuses, exactly like a wrong single
        // key.
        let third = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([99; 32]).expect("test key"),
        );
        assert!(matches!(
            screen_peer_block(&block, &[other, third]),
            Err(ScreenRefusal::KeyMismatch {
                block_id: GENESIS_BLOCK_ID
            })
        ));
    }

    #[test]
    fn a_stuck_slot_is_counted_but_never_read_past() {
        // Counting is only how loud to be about a slot a reader is stuck on;
        // nothing here ever moves a cursor.
        let passes = vec![(Some(4), Some(3)); 3];
        assert_eq!(run_stalls(&passes).stalled, Some((4, 3)));
        assert_eq!(run_stalls(&passes).current(), Some((4, 3)));

        let long = vec![
            (Some(4), Some(3));
            usize::try_from(STUCK_SLOT_ALERT_PASSES).expect("alert threshold fits") * 2
        ];
        assert_eq!(
            run_stalls(&long).stalled,
            Some((4, STUCK_SLOT_ALERT_PASSES.saturating_mul(2))),
            "a slot is retried for as long as it stays stuck"
        );
    }

    #[test]
    fn a_stream_that_ended_before_the_stalled_slot_does_not_reset_the_count() {
        // The zone-sdk ends a stream on a fetch failure exactly as it does on
        // catching up. Treating that as a clean pass would reset the count for
        // ever, and a reader stuck for hours would never say so.
        let mut passes = vec![(Some(4), Some(3)); 5];
        passes.push((None, Some(3)));
        assert_eq!(
            run_stalls(&passes).stalled,
            Some((4, 5)),
            "the count survives a pass that never reached the stalled slot"
        );

        // Getting past it is what actually clears the stall.
        let mut read_past = vec![(Some(4), Some(3)); 5];
        read_past.push((None, Some(7)));
        assert_eq!(run_stalls(&read_past).stalled, None);
    }

    #[test]
    fn a_stall_at_a_new_slot_starts_its_own_count() {
        let passes = [(Some(4), Some(3)), (Some(4), Some(3)), (Some(9), Some(8))];
        assert_eq!(run_stalls(&passes).stalled, Some((9, 1)));
    }

    #[test]
    fn a_stall_says_so_on_a_cadence_rather_than_once() {
        // Reporting only on the crossing leaves a reader that never recovers
        // looking resolved.
        assert!(!alerts_at(0));
        assert!(!alerts_at(1));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES - 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES + 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES * 3));
    }

    /// A floor of 0 is the off switch: no read, failed read, or empty
    /// committee may suspend.
    #[test]
    fn a_zero_floor_never_suspends() {
        let mut floor = CommitteeFloorState::new(0);
        assert!(!floor.enforced());
        for read in [None, Some((0, 1)), Some((100, 2))] {
            assert_eq!(
                floor.after_read(read),
                FloorVerdict::Active { resumed: false }
            );
        }
    }

    /// With a floor set, a committee never yet seen is exactly what the floor
    /// exists to check, so the reader starts suspended.
    #[test]
    fn an_unread_committee_fails_closed() {
        let mut floor = CommitteeFloorState::new(3);
        assert_eq!(
            floor.after_read(None),
            FloorVerdict::Suspended {
                passes: 1,
                last_read: None
            }
        );
    }

    #[test]
    fn suspended_passes_count_consecutively_onto_the_alert_cadence() {
        let mut floor = CommitteeFloorState::new(3);
        for expected in 1..=STUCK_SLOT_ALERT_PASSES {
            let verdict = floor.after_read(Some((2, u64::from(expected))));
            assert_eq!(
                verdict,
                FloorVerdict::Suspended {
                    passes: expected,
                    last_read: Some((2, u64::from(expected)))
                }
            );
        }
        let FloorVerdict::Suspended { passes, .. } = floor.after_read(Some((2, 9))) else {
            panic!("still below the floor");
        };
        assert_eq!(passes, STUCK_SLOT_ALERT_PASSES + 1);
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES));
        assert!(!alerts_at(passes));
    }

    /// A read failure after a healthy read keeps the last known size: the
    /// floor is a committee policy, not a liveness probe. The keep is a grace
    /// window, not a waiver: a run of failures outliving it fails closed, or a
    /// broken committee-read route would disarm the floor for good, silently.
    #[test]
    fn a_run_of_failed_reads_outlives_the_grace_and_suspends() {
        let mut floor = CommitteeFloorState::new(3);
        assert_eq!(
            floor.after_read(Some((3, 7))),
            FloorVerdict::Active { resumed: false }
        );
        for _ in 0..KEPT_FLOOR_READ_FAILURES {
            assert_eq!(
                floor.after_read(None),
                FloorVerdict::Active { resumed: false }
            );
        }
        assert_eq!(
            floor.after_read(None),
            FloorVerdict::Suspended {
                passes: 1,
                last_read: Some((3, 7))
            },
            "past the grace the floor fails closed again"
        );
        assert_eq!(
            floor.after_read(Some((3, 8))),
            FloorVerdict::Active { resumed: true },
            "one healthy read at the floor resumes and resets the grace"
        );
    }

    /// A zero committee is a real observation, not an unknown: it suspends.
    /// Above the floor is as spendable as at it.
    #[test]
    fn a_zero_committee_suspends_and_above_the_floor_runs() {
        let mut floor = CommitteeFloorState::new(3);
        assert_eq!(
            floor.after_read(Some((0, 1))),
            FloorVerdict::Suspended {
                passes: 1,
                last_read: Some((0, 1))
            }
        );
        assert_eq!(
            floor.after_read(Some((4, 2))),
            FloorVerdict::Active { resumed: true }
        );
    }

    /// The same failure while the last read was below the floor stays
    /// suspended, and still carries that last read for the report.
    #[test]
    fn a_read_failure_below_the_floor_stays_suspended() {
        let mut floor = CommitteeFloorState::new(3);
        assert!(matches!(
            floor.after_read(Some((2, 7))),
            FloorVerdict::Suspended { passes: 1, .. }
        ));
        assert_eq!(
            floor.after_read(None),
            FloorVerdict::Suspended {
                passes: 2,
                last_read: Some((2, 7))
            }
        );
    }

    /// The boundary is at the floor itself, the resume edge fires exactly
    /// once, and a re-dip starts a fresh count.
    #[test]
    fn recovery_at_the_floor_resumes_once_and_a_re_dip_restarts() {
        let mut floor = CommitteeFloorState::new(3);
        assert!(matches!(
            floor.after_read(Some((2, 1))),
            FloorVerdict::Suspended { .. }
        ));
        assert_eq!(
            floor.after_read(Some((3, 2))),
            FloorVerdict::Active { resumed: true }
        );
        assert_eq!(
            floor.after_read(Some((3, 3))),
            FloorVerdict::Active { resumed: false }
        );
        assert_eq!(
            floor.after_read(Some((1, 4))),
            FloorVerdict::Suspended {
                passes: 1,
                last_read: Some((1, 4))
            }
        );
    }
}
