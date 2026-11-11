#![expect(
    clippy::cast_precision_loss,
    clippy::as_conversions,
    reason = "Mailbox capacities stay far below 2^52, so the f64 holds them exactly"
)]

use std::time::{Duration, SystemTime};

use metrics::{SharedString, Unit, gauge, histogram};

use crate::names::{self, ActorState};

/// Exports the mailbox capacity of the actor `actor_name` names; `None`, an
/// unbounded mailbox, goes out as infinity.
///
/// There is no `init()`: the series exist only once the actors do, and a zero
/// would claim a mailbox that holds nothing.
pub fn record_mailbox_capacity(actor_name: &'static str, capacity: Option<usize>) {
    let capacity = capacity.map_or(f64::INFINITY, |capacity| {
        u64::try_from(capacity).expect("Mailbox capacity should fit into u64") as f64
    });
    gauge!(
        description: "Messages the actor's mailbox holds before senders wait, +Inf if unbounded",
        unit: Unit::Count,
        names::ACTOR_MAILBOX_CAPACITY,
        names::ACTOR_NAME_LABEL => actor_name
    )
    .set(capacity);
}

pub fn record_message_handling_time(
    actor_name: impl Into<SharedString>,
    message_name: impl Into<SharedString>,
    sender: impl Into<SharedString>,
    duration: Duration,
) {
    histogram!(
        description: "Time an actor spent handling one message",
        unit: Unit::Seconds,
        names::ACTOR_MESSAGE_HANDLING_TIME,
        names::ACTOR_NAME_LABEL => actor_name,
        names::MESSAGE_NAME_LABEL => message_name,
        names::SENDER_LABEL => sender
    )
    .record(duration.as_secs_f64());
}

pub fn record_actor_state(actor_name: impl Into<SharedString>, state: ActorState) {
    gauge!(
        description: "What an actor is doing: 0 stopped, 1 running, 2 restarting, 3 failed",
        unit: Unit::Count,
        names::ACTOR_STATE,
        names::ACTOR_NAME_LABEL => actor_name
    )
    .set(f64::from(u8::from(state)));
}

pub fn record_actor_start_time(actor_name: impl Into<SharedString>, at: SystemTime) {
    let unix_time = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Actors start after 1970");
    gauge!(
        description: "Unix time an actor last started",
        unit: Unit::Seconds,
        names::ACTOR_START_TIME,
        names::ACTOR_NAME_LABEL => actor_name
    )
    .set(unix_time.as_secs_f64());
}
