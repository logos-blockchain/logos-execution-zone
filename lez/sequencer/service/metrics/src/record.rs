#![expect(
    clippy::cast_precision_loss,
    clippy::as_conversions,
    reason = "Mailbox capacities stay far below 2^52, so the f64 holds them exactly"
)]

use metrics::{Unit, gauge};

use crate::names;

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
