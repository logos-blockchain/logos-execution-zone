//! Log lines for the follow and produce paths.
//!
//! Kept apart from the logic so the callers stay one line each.

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
/// What the update reported, and what the derivation then did with it. The
/// two differ: the head comes from the channel chain, not from the delta.
pub(crate) fn log_update(
    orphaned: &[Block],
    finalized: &[(Block, Slot)],
    applied: &[Block],
    head: Option<u64>,
) {
    info!(
        "Channel update: orphaned {}, finalized {}, applied {}, head {head:?}",
        id_span(&block_ids(orphaned)),
        id_span(
            &finalized
                .iter()
                .map(|(b, _)| b.header.block_id)
                .collect::<Vec<_>>()
        ),
        id_span(&block_ids(applied)),
    );
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
