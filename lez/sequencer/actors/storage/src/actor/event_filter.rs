use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use common::{HashType, transaction::TxEvents};
use lee_core::{BlockId, account::AccountId, program::TransactionEvent};

// Largest block span a single events range query may cover. Lives here so every surface
// that serves the query (RPC service, FFI) enforces the identical bound.
pub const MAX_EVENT_QUERY_BLOCK_SPAN: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EventFilter {
    Archival,
    Sources(HashMap<AccountId, SelectorFilter>),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SelectorFilter {
    All,
    Only(HashSet<[u8; 8]>),
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::Sources(HashMap::new())
    }
}

impl EventFilter {
    fn keeps(&self, event: &TransactionEvent) -> bool {
        match self {
            Self::Archival => true,
            Self::Sources(sources) => match sources.get(&event.account_id) {
                None => false,
                Some(SelectorFilter::All) => true,
                Some(SelectorFilter::Only(selectors)) => selectors.contains(&event.event.selector),
            },
        }
    }

    #[must_use]
    pub fn keeps_nothing(&self) -> bool {
        matches!(self, Self::Sources(sources) if sources.is_empty())
    }

    /// Whether every event in the requested `(program, selector)` domain is stored
    /// under this filter; `None` widens the dimension to "all".
    #[must_use]
    pub fn covers(&self, program_id: Option<AccountId>, selector: Option<[u8; 8]>) -> bool {
        match self {
            Self::Archival => true,
            Self::Sources(sources) => {
                let Some(program_id) = program_id else {
                    return false;
                };
                match sources.get(&program_id) {
                    None => false,
                    Some(SelectorFilter::All) => true,
                    Some(SelectorFilter::Only(selectors)) => {
                        selector.is_some_and(|selector| selectors.contains(&selector))
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn filter_block(&self, block_events: Vec<TxEvents>) -> Vec<TxEvents> {
        if matches!(self, Self::Archival) {
            return block_events;
        }
        block_events
            .into_iter()
            .filter_map(|mut group| {
                group.events.retain(|event| self.keeps(event));
                (!group.events.is_empty()).then_some(group)
            })
            .collect()
    }
}

/// Whether every event in the requested `(program, selector)` domain over
/// blocks `from..=to` was stored.
///
/// Each filter segment whose span intersects the range must cover the domain,
/// and the range must not precede the first segment.
#[must_use]
pub fn covered_over_range(
    segments: &[(EventFilter, BlockId)],
    from: BlockId,
    to: BlockId,
    program_id: Option<AccountId>,
    selector: Option<[u8; 8]>,
) -> bool {
    if to < from {
        return true;
    }
    let Some((_, first_from)) = segments.first() else {
        return false;
    };
    if from < *first_from {
        return false;
    }
    segments.iter().enumerate().all(|(i, (filter, seg_from))| {
        let seg_to = segments
            .get(i.saturating_add(1))
            .map_or(u64::MAX, |(_, next_from)| next_from.saturating_sub(1));
        *seg_from > to || seg_to < from || filter.covers(program_id, selector)
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Selector(pub [u8; 8]);

impl From<[u8; 8]> for Selector {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub block_id: BlockId,
    pub tx_index: u32,
    pub tx_hash: HashType,
    pub program_account_id: AccountId,
    pub selector: Selector,
    pub data: Vec<u8>,
}

impl EventRecord {
    #[must_use]
    pub fn matches_fields(
        &self,
        program_account_id: Option<AccountId>,
        selector: Option<Selector>,
    ) -> bool {
        program_account_id
            .is_none_or(|program_account_id| program_account_id == self.program_account_id)
            && selector.is_none_or(|selector| selector == self.selector)
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for conversions"
)]
impl EventRecord {
    // Not `From`: the orphan rule forbids implementing a foreign trait for `Vec<EventRecord>`.
    #[must_use]
    pub fn from_tx_events(block_id: BlockId, group: common::transaction::TxEvents) -> Vec<Self> {
        let common::transaction::TxEvents {
            tx_index,
            tx_hash,
            events,
        } = group;
        events
            .into_iter()
            .map(|event| Self {
                block_id,
                tx_index,
                tx_hash: tx_hash.into(),
                program_account_id: event.account_id.into(),
                selector: event.event.selector.into(),
                data: event.event.data,
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EventRangeError {
    FromPastTip { from: BlockId, tip: BlockId },
    ToPastTip { to: BlockId, tip: BlockId },
    Inverted { from: BlockId, to: BlockId },
    SpanExceeded { span: u64 },
}

pub fn resolve_event_block_range(
    from_block: BlockId,
    to_block: Option<BlockId>,
    tip: BlockId,
) -> Result<(BlockId, BlockId), EventRangeError> {
    if from_block > tip {
        return Err(EventRangeError::FromPastTip {
            from: from_block,
            tip,
        });
    }
    let to_block = to_block.unwrap_or(tip);
    if to_block > tip {
        return Err(EventRangeError::ToPastTip { to: to_block, tip });
    }
    if to_block < from_block {
        return Err(EventRangeError::Inverted {
            from: from_block,
            to: to_block,
        });
    }

    let span = to_block.saturating_sub(from_block).saturating_add(1);
    if span > MAX_EVENT_QUERY_BLOCK_SPAN {
        return Err(EventRangeError::SpanExceeded { span });
    }

    Ok((from_block, to_block))
}

#[cfg(test)]
mod tests {
    use common::HashType;
    use lee_core::program::ProgramEvent;

    use super::*;

    const PROGRAM_A: AccountId = AccountId::new([1; 32]);
    const PROGRAM_B: AccountId = AccountId::new([2; 32]);
    const SELECTOR_X: [u8; 8] = [1; 8];
    const SELECTOR_Y: [u8; 8] = [2; 8];

    fn event(account_id: AccountId, selector: [u8; 8]) -> TransactionEvent {
        TransactionEvent {
            account_id,
            event: ProgramEvent {
                selector,
                data: selector.to_vec(),
            },
        }
    }

    fn group(tx_index: u32, events: Vec<TransactionEvent>) -> TxEvents {
        TxEvents {
            tx_index,
            tx_hash: HashType([3; 32]),
            events,
        }
    }

    fn sources(entries: Vec<(AccountId, SelectorFilter)>) -> EventFilter {
        EventFilter::Sources(entries.into_iter().collect())
    }

    #[test]
    fn only_an_empty_source_set_keeps_nothing() {
        assert!(EventFilter::default().keeps_nothing());
        assert!(!EventFilter::Archival.keeps_nothing());
        assert!(!sources(vec![(PROGRAM_A, SelectorFilter::All)]).keeps_nothing());
    }

    #[test]
    fn archival_keeps_every_event() {
        let blocks = vec![group(
            0,
            vec![event(PROGRAM_A, SELECTOR_X), event(PROGRAM_B, SELECTOR_Y)],
        )];

        assert_eq!(EventFilter::Archival.filter_block(blocks.clone()), blocks);
    }

    #[test]
    fn default_keeps_nothing() {
        let blocks = vec![group(
            0,
            vec![event(PROGRAM_A, SELECTOR_X), event(PROGRAM_B, SELECTOR_Y)],
        )];

        assert_eq!(EventFilter::default().filter_block(blocks), vec![]);
    }

    #[test]
    fn program_wide_entry_keeps_all_its_selectors_only() {
        let filter = sources(vec![(PROGRAM_A, SelectorFilter::All)]);
        let blocks = vec![group(
            0,
            vec![
                event(PROGRAM_A, SELECTOR_X),
                event(PROGRAM_A, SELECTOR_Y),
                event(PROGRAM_B, SELECTOR_X),
            ],
        )];

        let expected = vec![group(
            0,
            vec![event(PROGRAM_A, SELECTOR_X), event(PROGRAM_A, SELECTOR_Y)],
        )];
        assert_eq!(filter.filter_block(blocks), expected);
    }

    #[test]
    fn selector_entry_keeps_only_listed_selectors() {
        let filter = sources(vec![(
            PROGRAM_A,
            SelectorFilter::Only(HashSet::from([SELECTOR_X])),
        )]);
        let blocks = vec![group(
            0,
            vec![event(PROGRAM_A, SELECTOR_X), event(PROGRAM_A, SELECTOR_Y)],
        )];

        let expected = vec![group(0, vec![event(PROGRAM_A, SELECTOR_X)])];
        assert_eq!(filter.filter_block(blocks), expected);
    }

    #[test]
    fn fully_filtered_group_is_dropped_while_mixed_group_survives() {
        let filter = sources(vec![(PROGRAM_A, SelectorFilter::All)]);
        let blocks = vec![
            group(0, vec![event(PROGRAM_B, SELECTOR_X)]),
            group(
                1,
                vec![event(PROGRAM_B, SELECTOR_X), event(PROGRAM_A, SELECTOR_Y)],
            ),
        ];

        let expected = vec![group(1, vec![event(PROGRAM_A, SELECTOR_Y)])];
        assert_eq!(filter.filter_block(blocks), expected);
    }

    #[test]
    fn archival_covers_any_domain() {
        for (program, selector) in [
            (None, None),
            (Some(PROGRAM_A), None),
            (Some(PROGRAM_A), Some(SELECTOR_X)),
        ] {
            assert!(EventFilter::Archival.covers(program, selector));
        }
    }

    #[test]
    fn default_covers_nothing() {
        for (program, selector) in [
            (None, None),
            (Some(PROGRAM_A), None),
            (Some(PROGRAM_A), Some(SELECTOR_X)),
        ] {
            assert!(!EventFilter::default().covers(program, selector));
        }
    }

    #[test]
    fn undeclared_or_unspecified_program_is_not_covered() {
        let filter = sources(vec![(PROGRAM_A, SelectorFilter::All)]);

        assert!(!filter.covers(Some(PROGRAM_B), Some(SELECTOR_X)));
        assert!(!filter.covers(None, Some(SELECTOR_X)));
        assert!(!filter.covers(None, None));
    }

    #[test]
    fn program_wide_entry_covers_its_whole_domain() {
        let filter = sources(vec![(PROGRAM_A, SelectorFilter::All)]);

        assert!(filter.covers(Some(PROGRAM_A), None));
        assert!(filter.covers(Some(PROGRAM_A), Some(SELECTOR_X)));
    }

    #[test]
    fn selector_entry_covers_only_listed_selectors() {
        let filter = sources(vec![(
            PROGRAM_A,
            SelectorFilter::Only(HashSet::from([SELECTOR_X])),
        )]);

        assert!(filter.covers(Some(PROGRAM_A), Some(SELECTOR_X)));
        assert!(!filter.covers(Some(PROGRAM_A), Some(SELECTOR_Y)));
        assert!(!filter.covers(Some(PROGRAM_A), None));
    }

    #[test]
    fn range_coverage_needs_history() {
        assert!(!covered_over_range(&[], 0, 10, None, None));
    }

    #[test]
    fn range_before_the_first_segment_is_not_covered() {
        let segments = [(EventFilter::Archival, 10)];

        assert!(!covered_over_range(&segments, 5, 15, None, None));
        assert!(covered_over_range(&segments, 10, 15, None, None));
    }

    #[test]
    fn every_segment_intersecting_the_range_must_cover_the_domain() {
        let segments = [
            (sources(vec![(PROGRAM_A, SelectorFilter::All)]), 0),
            (
                sources(vec![
                    (PROGRAM_A, SelectorFilter::All),
                    (PROGRAM_B, SelectorFilter::All),
                ]),
                100,
            ),
        ];

        // Program B is only declared from block 100 on.
        assert!(covered_over_range(
            &segments,
            100,
            200,
            Some(PROGRAM_B),
            None
        ));
        assert!(!covered_over_range(
            &segments,
            50,
            150,
            Some(PROGRAM_B),
            None
        ));
        assert!(!covered_over_range(
            &segments,
            99,
            99,
            Some(PROGRAM_B),
            None
        ));
        // Program A is covered by both eras.
        assert!(covered_over_range(
            &segments,
            50,
            150,
            Some(PROGRAM_A),
            None
        ));
        // The whole-domain query needs archival coverage in every era.
        assert!(!covered_over_range(&segments, 100, 200, None, None));
    }

    #[test]
    fn an_empty_range_is_covered_vacuously() {
        let segments = [(sources(vec![]), 0)];

        assert!(covered_over_range(&segments, 5, 4, Some(PROGRAM_A), None));
    }
}
