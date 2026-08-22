use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use common::transaction::TxEvents;
use lee_core::program::{ProgramId, TransactionEvent};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EventFilter {
    Archival,
    Sources(HashMap<ProgramId, SelectorFilter>),
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
            Self::Sources(sources) => match sources.get(&event.program_id) {
                None => false,
                Some(SelectorFilter::All) => true,
                Some(SelectorFilter::Only(selectors)) => selectors.contains(&event.event.selector),
            },
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

#[cfg(test)]
mod tests {
    use common::HashType;
    use lee_core::program::ProgramEvent;

    use super::*;

    const PROGRAM_A: ProgramId = [1; 8];
    const PROGRAM_B: ProgramId = [2; 8];
    const SELECTOR_X: [u8; 8] = [1; 8];
    const SELECTOR_Y: [u8; 8] = [2; 8];

    fn event(program_id: ProgramId, selector: [u8; 8]) -> TransactionEvent {
        TransactionEvent {
            program_id,
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

    fn sources(entries: Vec<(ProgramId, SelectorFilter)>) -> EventFilter {
        EventFilter::Sources(entries.into_iter().collect())
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
}
