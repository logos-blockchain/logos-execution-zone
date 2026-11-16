//! Attributes of the spans the sequencer exports as traces. Every message an
//! actor handles roots a trace of its own, named after the actor and the
//! message, e.g. `ExecutorActor.ProduceBlock`.

/// Attribute of a handled message's span: the actor's type name, e.g.
/// `ExecutorActor`.
pub const ACTOR_ATTRIBUTE: &str = "actor";

/// Attribute of a handled message's span: what sent the message, as in
/// [`SENDER_LABEL`] but by type name, e.g. `ExecutorActor`, `rpc` or
/// [`NO_SENDER`].
///
/// [`SENDER_LABEL`]: crate::names::SENDER_LABEL
/// [`NO_SENDER`]: crate::names::NO_SENDER
pub const SENDER_ATTRIBUTE: &str = "sender";

/// Attribute of a handled message's span: the name of the trace the message
/// was sent from, e.g. `ExecutorActor.ProduceBlock` or `rpc.getBlock`; the
/// sender itself when sent outside any trace.
pub const CAUSE_ATTRIBUTE: &str = "cause";

/// Attribute of a handled message's span, for an actor that runs as one of
/// several of its type: which one, as in [`ACTOR_INSTANCE_LABEL`].
///
/// [`ACTOR_INSTANCE_LABEL`]: crate::names::ACTOR_INSTANCE_LABEL
pub const INSTANCE_ATTRIBUTE: &str = "instance";

/// Attribute of a handled message's span, sent by an actor that runs as one of
/// several of its type: which one, as [`INSTANCE_ATTRIBUTE`] says of the actor
/// handling it.
pub const SENDER_INSTANCE_ATTRIBUTE: &str = "sender_instance";

/// Attribute of every span: the sequencer, as in [`SEQUENCER_LABEL`]. Spans
/// exported before the sequencer knows its key go without.
///
/// [`SEQUENCER_LABEL`]: crate::names::SEQUENCER_LABEL
pub const SEQUENCER_ATTRIBUTE: &str = "sequencer";
