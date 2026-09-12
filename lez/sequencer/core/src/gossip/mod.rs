//! Shared gossip-mesh state written by the core and read by the gossip
//! actor (`sequencer_gossip_actor`), which owns the mesh itself.

use std::collections::HashSet;

use tokio::sync::watch;

/// Keys the mesh accepts messages from, fed from the `sequencer_stake` config
/// by `refresh_committee`: the committee for slash approvals, every staked key
/// for channel-config messages.
pub type AccreditedKeys = HashSet<[u8; 32]>;

/// Written by `refresh_committee` on every head move.
pub type AccreditedKeysSender = watch::Sender<Option<AccreditedKeys>>;

/// Read by the gossip actor per inbound approval or config message.
pub type AccreditedKeysReceiver = watch::Receiver<Option<AccreditedKeys>>;

/// The mesh's accredited-key channel: `None` filters nothing, `Some` of an
/// empty set filters everything.
#[must_use]
pub fn accredited_keys_channel() -> (AccreditedKeysSender, AccreditedKeysReceiver) {
    watch::channel(None)
}
