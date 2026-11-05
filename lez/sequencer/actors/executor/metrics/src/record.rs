use metrics::{Counter, Unit, counter, gauge};

use crate::names;

/// Initialize metrics.
pub fn init() {
    record_production_failed_attempts(0);
    record_turn_to_write(false);
    turns_to_write_total_counter().increment(0);
}

/// Consecutive production turns that failed outright. A sustained non-zero is a
/// node that cannot produce; every other signal looks like an idle one.
pub fn record_production_failed_attempts(attempts: u32) {
    gauge!(
        description: "Consecutive block production turns that failed",
        unit: Unit::Count,
        names::PRODUCTION_FAILED_ATTEMPTS
    )
    .set(f64::from(attempts));
}

/// Whether this sequencer may write to the channel right now.
pub fn record_turn_to_write(ours: bool) {
    gauge!(
        description: "1 while this sequencer holds the turn to write to the channel",
        unit: Unit::Count,
        names::TURN_TO_WRITE
    )
    .set(if ours { 1.0 } else { 0.0 });
}

fn turns_to_write_total_counter() -> Counter {
    counter!(
        description: "Number of turns to write to the channel this sequencer was given",
        unit: Unit::Count,
        names::TURNS_TO_WRITE_TOTAL
    )
}

pub fn increment_turns_to_write_total() {
    turns_to_write_total_counter().increment(1);
}
