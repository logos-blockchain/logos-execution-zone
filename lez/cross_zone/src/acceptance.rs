//! The one peer-block acceptance policy.

use std::fmt::{self, Display, Formatter};

use common::{
    HashType,
    block::{Block, PeerChainTip},
};
use cross_zone_inbox_core::ZoneId;
use lee::GENESIS_BLOCK_ID;

/// Consecutive passes a reader spends stuck on one slot before it says so as something more than
/// the per-pass failure.
pub const STUCK_SLOT_ALERT_PASSES: u32 = 5;

/// How many consecutive failed committee reads keep the last known size.
pub const KEPT_FLOOR_READ_FAILURES: u32 = STUCK_SLOT_ALERT_PASSES;

/// Where a screened peer block sits relative to the chain pinned by `tip`.
#[derive(Debug, PartialEq, Eq)]
pub enum Link {
    Next(HashType),
    AlreadySeen { equivocates: bool },
    OffChain(OffChain),
}

/// Why a block is not on the chain the tip pins.
#[derive(Debug, PartialEq, Eq)]
pub enum OffChain {
    DoesNotLink {
        block_id: u64,
        tip_id: u64,
        links_to: HashType,
        expected: HashType,
    },
    NotTheGenesis {
        block_id: u64,
    },
    WrongGenesis {
        recomputed: HashType,
        pinned: HashType,
    },
    SkipsAhead {
        block_id: u64,
        next: u64,
    },
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
            Self::WrongGenesis { recomputed, pinned } => write!(
                f,
                "the peer's genesis block hashes to {recomputed}, not the pinned {pinned}; this channel does not carry the configured peer chain"
            ),
            Self::SkipsAhead { block_id, next } => write!(
                f,
                "block {block_id} skips past {next}, which is either a hole in what this node read or an id claimed ahead of the peer's chain"
            ),
        }
    }
}

/// Why a peer block was refused before any chain placement.
#[derive(Debug, PartialEq, Eq)]
pub enum ScreenRefusal {
    HashMismatch {
        block_id: u64,
        declared: HashType,
        recomputed: HashType,
    },
}

impl Display for ScreenRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self::HashMismatch {
            block_id,
            declared,
            recomputed,
        } = *self;
        write!(
            f,
            "block {block_id} carries header hash {declared} but its contents hash to {recomputed}"
        )
    }
}

/// The pass-to-pass stall of one peer reader: the slot it is stuck on and how many consecutive
/// passes it has spent there.
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
    /// The slot the reader is stuck on and for how many passes, or `None` when it is not stuck.
    #[must_use]
    pub const fn current(&self) -> Option<(S, u32)> {
        self.stalled
    }

    /// Folds one pass in: `stuck_on` is the slot the pass ended inside, `None` for a pass that
    /// ended cleanly.
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

    fn passed_the_stall(self, read_to: Option<S>) -> bool {
        self.stalled
            .is_none_or(|(stuck_on, _)| read_to.is_some_and(|slot| slot >= stuck_on))
    }
}

/// The pass-to-pass committee-floor latch of one peer reader: whether the peer's live committee was
/// last seen at or above the configured floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeFloorState {
    min: u32,
    last_known: Option<(usize, u64)>,
    failed_reads: u32,
    suspended_passes: u32,
}

/// What [`CommitteeFloorState::after_read`] decided for this pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorVerdict {
    Active {
        resumed: bool,
    },
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

    /// Whether a floor is set at all.
    #[must_use]
    pub const fn enforced(&self) -> bool {
        self.min > 0
    }

    /// Folds one pass's channel-state read in: `Some((committee size, tip slot))` on a successful
    /// read, `None` on a failed read or an absent channel, both unknown rather than zero.
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
#[must_use]
pub const fn alerts_at(attempts: u32) -> bool {
    attempts > 0 && attempts.is_multiple_of(STUCK_SLOT_ALERT_PASSES)
}

/// Logs the one report both sides give for a differing block at an id the accepted chain already
/// holds.
pub fn log_equivocation(peer_zone: &ZoneId, block_id: u64, holding: HashType, refusing: HashType) {
    tracing::error!(
        peer_zone = %hex::encode(peer_zone),
        block_id,
        %holding,
        %refusing,
        "Peer zone equivocated. Nothing at or above this block can be delivered from until that \
         peer inscribes a block continuing the run verified from its genesis."
    );
}

/// Whether `block` continues the peer chain pinned by `tip`.
#[must_use]
pub fn link_to_tip(
    tip: Option<&PeerChainTip>,
    block: &Block,
    recomputed: HashType,
    pinned_genesis: Option<HashType>,
) -> Link {
    let block_id = block.header.block_id;
    let Some(tip) = tip else {
        if block_id != GENESIS_BLOCK_ID {
            return Link::OffChain(OffChain::NotTheGenesis { block_id });
        }
        if let Some(pinned) = pinned_genesis
            && recomputed != pinned
        {
            return Link::OffChain(OffChain::WrongGenesis { recomputed, pinned });
        }
        return Link::Next(recomputed);
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

/// Whether a block read off a peer's channel may be considered for the chain at all, returning the
/// recomputed hash every later placement has to use.
pub fn screen_peer_block(block: &Block) -> Result<HashType, ScreenRefusal> {
    let recomputed = block.recompute_hash();
    if recomputed != block.header.hash {
        return Err(ScreenRefusal::HashMismatch {
            block_id: block.header.block_id,
            declared: block.header.hash,
            recomputed,
        });
    }
    Ok(recomputed)
}

#[cfg(test)]
mod tests {
    use common::test_utils::produce_dummy_block;

    use super::*;
    use crate::test_utils::linked_chain_to;

    fn chain_block(block_id: u64) -> Block {
        linked_chain_to(block_id, |_| vec![])
            .pop()
            .expect("chain reaches block_id")
    }

    fn chain_hash(block_id: u64) -> HashType {
        chain_block(block_id).header.hash
    }

    fn tip_at(block_id: u64) -> PeerChainTip {
        PeerChainTip {
            block_id,
            block_hash: chain_hash(block_id),
        }
    }

    fn screened(block: &Block) -> HashType {
        screen_peer_block(block).expect("honest block passes screening")
    }

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
            link_to_tip(Some(&tip), &next, screened(&next), None),
            Link::Next(chain_hash(3)),
            "the block that continues the chain is the one accepted"
        );

        for ahead in [
            produce_dummy_block(5, Some(chain_hash(2)), vec![]),
            produce_dummy_block(5, None, vec![]),
        ] {
            assert_eq!(
                link_to_tip(Some(&tip), &ahead, screened(&ahead), None),
                Link::OffChain(OffChain::SkipsAhead {
                    block_id: 5,
                    next: 3
                })
            );
        }

        let forked = produce_dummy_block(3, Some(HashType([9; 32])), vec![]);
        assert!(matches!(
            link_to_tip(Some(&tip), &forked, screened(&forked), None),
            Link::OffChain(OffChain::DoesNotLink { .. })
        ));
    }

    #[test]
    fn a_reader_with_no_tip_starts_at_the_peers_genesis() {
        let genesis = chain_block(GENESIS_BLOCK_ID);
        assert_eq!(
            link_to_tip(None, &genesis, screened(&genesis), None),
            Link::Next(chain_hash(GENESIS_BLOCK_ID))
        );
        let mid_chain = chain_block(GENESIS_BLOCK_ID + 1);
        assert_eq!(
            link_to_tip(None, &mid_chain, screened(&mid_chain), None),
            Link::OffChain(OffChain::NotTheGenesis {
                block_id: GENESIS_BLOCK_ID + 1
            })
        );
    }

    #[test]
    fn a_pinned_genesis_only_anchors_on_the_pinned_chain() {
        let genesis = chain_block(GENESIS_BLOCK_ID);
        let honest = screened(&genesis);
        assert_eq!(
            link_to_tip(None, &genesis, honest, Some(honest)),
            Link::Next(honest)
        );

        let fabricated = HashType([9; 32]);
        assert_eq!(
            link_to_tip(None, &genesis, honest, Some(fabricated)),
            Link::OffChain(OffChain::WrongGenesis {
                recomputed: honest,
                pinned: fabricated
            })
        );

        let next = chain_block(GENESIS_BLOCK_ID + 1);
        assert_eq!(
            link_to_tip(
                Some(&tip_at(GENESIS_BLOCK_ID)),
                &next,
                screened(&next),
                Some(fabricated)
            ),
            Link::Next(chain_hash(GENESIS_BLOCK_ID + 1))
        );
    }

    #[test]
    fn a_differing_block_at_the_tip_id_reports_equivocation() {
        let tip = tip_at(2);

        let held = chain_block(2);
        assert_eq!(
            link_to_tip(Some(&tip), &held, screened(&held), None),
            Link::AlreadySeen { equivocates: false }
        );

        let differing = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
        assert_eq!(
            link_to_tip(Some(&tip), &differing, screened(&differing), None),
            Link::AlreadySeen { equivocates: true }
        );

        let below = produce_dummy_block(1, Some(HashType([9; 32])), vec![]);
        assert_eq!(
            link_to_tip(Some(&tip), &below, screened(&below), None),
            Link::AlreadySeen { equivocates: false }
        );
    }

    #[test]
    fn a_block_whose_header_hash_is_not_its_contents_is_refused() {
        let mut tampered = chain_block(3);
        tampered.header.hash = HashType([9; 32]);
        assert!(matches!(
            screen_peer_block(&tampered),
            Err(ScreenRefusal::HashMismatch { block_id: 3, .. })
        ));
    }

    #[test]
    fn a_stuck_slot_is_counted_but_never_read_past() {
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
        let mut passes = vec![(Some(4), Some(3)); 5];
        passes.push((None, Some(3)));
        assert_eq!(
            run_stalls(&passes).stalled,
            Some((4, 5)),
            "the count survives a pass that never reached the stalled slot"
        );

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
        assert!(!alerts_at(0));
        assert!(!alerts_at(1));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES - 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES + 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES * 3));
    }

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
