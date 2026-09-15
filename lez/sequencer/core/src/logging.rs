//! Log lines for the follow and produce paths.
//!
//! Kept apart from the logic so the callers stay one line each.

use chain_state::AcceptOutcome;
use common::block::Block;
use log::{info, warn};
use logos_blockchain_zone_sdk::Slot;

use crate::block_publisher::MsgId;

/// `lo..=hi (n)` for a log line, flagged when the ids do not fill that range.
pub(crate) fn id_span(ids: &[u64]) -> String {
    match (ids.iter().min(), ids.iter().max()) {
        (Some(lo), Some(hi)) => {
            let span = hi.saturating_sub(*lo).saturating_add(1);
            let contiguous = u64::try_from(ids.len()).is_ok_and(|len| len == span);
            let gaps = if contiguous { "" } else { ", non-contiguous" };
            format!("{lo}..={hi} ({}{gaps})", ids.len())
        }
        _ => "none".to_owned(),
    }
}

pub(crate) fn block_ids(blocks: &[Block]) -> Vec<u64> {
    blocks.iter().map(|block| block.header.block_id).collect()
}

/// The pin — the channel entry the next publish chains on — as a log field.
pub(crate) fn pin_str(pin: Option<MsgId>) -> String {
    pin.map_or_else(|| "none".to_owned(), |msg| msg.to_string())
}

/// The L2 view of one update: decoded heights and the head they meet.
///
/// Counts, entry ids and the channel tip are zone-sdk's `ChannelUpdate` debug
/// line; this carries only what that cannot know.
pub(crate) fn log_update(
    orphaned: &[Block],
    adopted: &[Block],
    finalized: &[(Block, Slot)],
    head: Option<u64>,
) {
    info!(
        "Channel update: orphaned {}, adopted {}, finalized {}, head {head:?}",
        id_span(&block_ids(orphaned)),
        id_span(&block_ids(adopted)),
        id_span(
            &finalized
                .iter()
                .map(|(b, _)| b.header.block_id)
                .collect::<Vec<_>>()
        ),
    );
}

/// Adoptions that did not apply, with the pin they were left behind by.
pub(crate) fn log_parked(
    adopted: &[Block],
    outcomes: &[AcceptOutcome],
    head: Option<u64>,
    pin: Option<MsgId>,
) {
    for (block, outcome) in adopted.iter().zip(outcomes) {
        if let AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err) = outcome {
            warn!(
                "Adopted block {} did not apply, head stays at {head:?} with the pin at {}: {err}",
                block.header.block_id,
                pin_str(pin),
            );
        }
    }
}

pub(crate) fn log_rewind(before: Option<u64>, after: Option<u64>, pin: Option<MsgId>) {
    if let (Some(before), Some(after)) = (before, after)
        && after < before
    {
        warn!(
            "Head rewound from {before} to {after}, pin now {}",
            pin_str(pin)
        );
    }
}

/// Dropping the mark permits a second block at a height already inscribed, so
/// name the heights it frees: they are checkable on L1.
pub(crate) fn log_high_water_lowered(mark: Option<u64>, orphans_above_head: &[&Block]) {
    if let Some(mark) = mark {
        let ids: Vec<u64> = orphans_above_head
            .iter()
            .map(|block| block.header.block_id)
            .collect();
        warn!(
            "Lowering the published high water to {mark}, every height above it is writable \
             again; orphaned above the head and not re-adopted: {}",
            id_span(&ids),
        );
    }
}
