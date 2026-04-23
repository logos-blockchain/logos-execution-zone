use anyhow::{Context as _, Result};
use nssa::V03State;
use nssa_core::BlockId;
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
use url::Url;

/// Connects to a running sequencer at `url`, fetches a state snapshot, and deserializes it.
///
/// Returns `(forked_state, fork_block_id)`. The caller passes these to `run_forked` so the
/// local sequencer starts from the remote chain's current height and account state.
pub async fn fetch_fork_state(url: &Url) -> Result<(V03State, BlockId)> {
    let client = SequencerClientBuilder::default()
        .build(url.as_str())
        .with_context(|| format!("Failed to connect to remote sequencer at {url}"))?;

    let snapshot = client
        .get_state_snapshot()
        .await
        .with_context(|| format!("get_state_snapshot RPC failed against {url}"))?;

    let state = borsh::from_slice::<V03State>(&snapshot.state_bytes)
        .context("Failed to deserialize forked V03State from snapshot bytes")?;

    Ok((state, snapshot.block_id))
}
