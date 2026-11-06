//! Log lines for the follow and produce paths.
//!
//! Kept apart from the logic so the callers stay one line each.

use chain_state::ChannelEntry;
use sequencer_bedrock_actor::protocol::{MsgId, ViewChange};
use tracing::{info, warn};

/// `lo..=hi (n)` for a log field, flagged when the ids do not fill that range.
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

/// The L2 view of one update: decoded heights and the head they meet.
///
/// Counts, entry ids and the channel tip are zone-sdk's `ChannelUpdate` debug
/// line; this carries only what that cannot know.
pub(crate) fn log_update(view: &ViewChange, finalized: &[ChannelEntry], head: Option<u64>) {
    let entry_ids = |entries: &mut dyn Iterator<Item = &ChannelEntry>| {
        id_span(
            &entries
                .filter_map(|entry| entry.block.as_ref())
                .map(|block| block.header.block_id)
                .collect::<Vec<_>>(),
        )
    };
    let finalized = entry_ids(&mut finalized.iter());
    match view {
        ViewChange::Extension(adopted) => info!(
            adopted = %entry_ids(&mut adopted.iter()),
            %finalized,
            head,
            "Channel update"
        ),
        ViewChange::Conflict {
            canonical,
            orphaned,
        } => info!(
            orphaned = %entry_ids(&mut orphaned.iter()),
            view = %entry_ids(&mut canonical.iter()),
            %finalized,
            head,
            "Channel conflict"
        ),
    }
}

pub(crate) fn log_rewind(before: Option<u64>, after: Option<u64>, pin: MsgId) {
    if let (Some(before), Some(after)) = (before, after)
        && after < before
    {
        warn!(before, after, %pin, "Head rewound");
    }
}
