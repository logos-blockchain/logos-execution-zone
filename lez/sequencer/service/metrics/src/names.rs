/// Label on every series a sequencer exports: its channel signing public key, in hex.
pub const SEQUENCER_LABEL: &str = "sequencer";

// Kameo's mailbox counters. Kameo names them, so a test in the service's
// `main.rs` pins these names against what the recorder actually renders.

/// Label on every kameo series: the actor's type name, module path included,
/// e.g. `sequencer_storage_actor::actor::StorageActor`.
pub const ACTOR_NAME_LABEL: &str = "actor_name";

/// Messages queued into the actor's mailbox.
pub const KAMEO_MESSAGES_SENT_TOTAL: &str = "kameo_messages_sent_total";

/// Messages the actor took off its mailbox.
pub const KAMEO_MESSAGES_RECEIVED_TOTAL: &str = "kameo_messages_received_total";

/// Lifecycle signals the actor took off its mailbox.
///
/// These are startup finished, stop, supervisor restart and callback. The
/// matching `sent` counter skips the ones kameo sends itself, startup
/// included, so only this side is complete.
pub const KAMEO_LIFECYCLE_RECEIVED_TOTAL: &str = "kameo_lifecycle_received_total";

/// Deaths of linked actors the actor took off its mailbox. Kameo never counts
/// the `sent` side of these.
pub const KAMEO_LINK_DIED_RECEIVED_TOTAL: &str = "kameo_link_died_received_total";

/// Messages the actor's mailbox holds before senders wait, `+Inf` for an
/// unbounded one. Labelled with [`ACTOR_NAME_LABEL`], like kameo's counters.
pub const ACTOR_MAILBOX_CAPACITY: &str = "actor_mailbox_capacity";
