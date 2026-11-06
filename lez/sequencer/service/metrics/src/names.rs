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

/// Time the actor spent handling one message, from taking it off the mailbox
/// to its handler returning. Labelled with [`ACTOR_NAME_LABEL`] and
/// [`MESSAGE_NAME_LABEL`].
pub const ACTOR_MESSAGE_HANDLING_TIME: &str = "actor_message_handling_time_seconds";

/// Label on [`ACTOR_MESSAGE_HANDLING_TIME`]: kameo's name for the message, by
/// default its type name with the module path, e.g.
/// `sequencer_storage_actor::messages::GetBlock`.
pub const MESSAGE_NAME_LABEL: &str = "message_name";

/// What the actor is doing, one of [`ActorState`]'s values.
pub const ACTOR_STATE: &str = "actor_state";

/// Unix time the actor last started; it changes on every restart.
pub const ACTOR_START_TIME: &str = "actor_start_time_seconds";

/// The values of [`ACTOR_STATE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorState {
    Stopped = 0,
    Running = 1,
    /// Stopped by its supervisor, to be started again.
    Restarting = 2,
    /// Stopped by a panic, an error, or the death of an actor linked to it.
    Failed = 3,
}

impl ActorState {
    pub const ALL: [Self; 4] = [Self::Stopped, Self::Running, Self::Restarting, Self::Failed];
}

impl From<ActorState> for u8 {
    #[expect(
        clippy::as_conversions,
        reason = "Reads the discriminant of a fieldless `repr(u8)` enum"
    )]
    fn from(state: ActorState) -> Self {
        state as Self
    }
}
