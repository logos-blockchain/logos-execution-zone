//! Which full stake releases a block may hold: those whose removal config Bedrock reports final.

use std::{
    collections::{BTreeSet, HashSet},
    time::Duration,
};

use chain_state::{ChainState, ChannelEntry, L1Position, full_stake_releases};
use common::block::Block;
use kameo::actor::ActorRef;
use log::warn;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{FilterFinallyAbsent, MsgId, ViewChange},
};
use sequencer_stake_core::SequencerKey;
use tokio::sync::Mutex;

/// Pause between attempts at reading a verdict.
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The removal finality depth genesis set in `state`, `None` before genesis.
pub fn finality_depth(state: &lee::V03State) -> Option<u64> {
    crate::committee_discovery::channel_params(state).map(|params| params.finality_depth)
}

/// The keys `block`, landed at `at`, may release in full, read again until a read succeeds.
pub async fn finally_absent_keys<B: BedrockActorTrait>(
    bedrock_ref: &ActorRef<B>,
    at: L1Position,
    block: &Block,
    depth: Option<u64>,
) -> BTreeSet<SequencerKey> {
    let keys = full_stake_releases::finalize_unstake_keys(block);
    let Some(depth) = depth.filter(|_| !keys.is_empty()) else {
        return BTreeSet::new();
    };
    loop {
        let request = FilterFinallyAbsent {
            at,
            keys: keys.clone(),
            depth,
        };
        match bedrock_ref.ask(request).await {
            Ok(absent_keys) => return absent_keys,
            Err(err) => {
                warn!(
                    "Failed to read whether block {}'s stake releases are final, retrying: {err}",
                    block.header.block_id
                );
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// `finalized` and `view` with every entry's `finally_absent_keys` filled in, and those of the held
/// entries a finalized one chains on, which finalize with it.
pub async fn judged_update<B: BedrockActorTrait>(
    bedrock_ref: &ActorRef<B>,
    chain: &Mutex<ChainState>,
    finalized: &[ChannelEntry],
    view: &ViewChange,
) -> (
    Vec<ChannelEntry>,
    ViewChange,
    Vec<(MsgId, BTreeSet<SequencerKey>)>,
) {
    let (depth, held_ancestors) = {
        let chain = chain.lock().await;
        (
            finality_depth(chain.final_state()),
            held_entries_finalized_with(&chain, finalized),
        )
    };
    let mut held_finally_absent_keys = Vec::new();
    for entry in held_ancestors {
        if let Some(block) = &entry.block {
            // Its block is final, so the verdict depends on final blocks only.
            let at = L1Position::Msg {
                msg: entry.msg,
                parent: entry.parent,
            };
            let keys = finally_absent_keys(bedrock_ref, at, block, depth).await;
            held_finally_absent_keys.push((entry.msg, keys));
        }
    }
    let mut finalized = finalized.to_vec();
    let mut view = view.clone();
    let (ViewChange::Extension(view_entries)
    | ViewChange::Conflict {
        canonical: view_entries,
        ..
    }) = &mut view;
    for entry in finalized.iter_mut().chain(view_entries.iter_mut()) {
        if let Some(block) = &entry.block {
            entry.finally_absent_keys =
                finally_absent_keys(bedrock_ref, entry.l1_position, block, depth).await;
        }
    }
    (finalized, view, held_finally_absent_keys)
}

/// The held entries the chain will finalize along with `finalized` because one chains on them, in
/// place of a finalized report of their own.
fn held_entries_finalized_with(
    chain: &ChainState,
    finalized: &[ChannelEntry],
) -> Vec<ChannelEntry> {
    let finalized_msgs: HashSet<MsgId> = finalized.iter().map(|entry| entry.msg).collect();
    let mut seen = HashSet::new();
    finalized
        .iter()
        .flat_map(|entry| {
            chain
                .held_lineage(entry.parent)
                .into_iter()
                .take_while(|held| !finalized_msgs.contains(&held.msg))
        })
        .filter(|held| seen.insert(held.msg))
        .collect()
}

/// The fully pending keys a block built now may release, judged `2 * depth - 1` blocks under the
/// tip.
pub async fn producible_releases<B: BedrockActorTrait>(
    bedrock_ref: &ActorRef<B>,
    state: &lee::V03State,
) -> BTreeSet<SequencerKey> {
    let keys = full_stake_releases::fully_pending_keys(&full_stake_releases::stake_entries(state));
    let Some(depth) = finality_depth(state).filter(|_| !keys.is_empty()) else {
        return BTreeSet::new();
    };
    let depth = depth.saturating_mul(2).saturating_sub(1);
    bedrock_ref
        .ask(FilterFinallyAbsent {
            at: L1Position::Unknown,
            keys,
            depth,
        })
        .await
        .unwrap_or_else(|err| {
            warn!("Releasing no full stake this block: {err}");
            BTreeSet::new()
        })
}
