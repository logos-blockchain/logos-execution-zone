use metrics::{Unit, gauge};

use crate::names;

/// Initialize metrics.
pub fn init() {
    record_publish_blocked_attempts(0);
    record_production_failed_attempts(0);
}

/// Consecutive production attempts skipped because the pin trails the tip. A
/// climbing value means the pin is stuck; alert on a sustained non-zero.
pub fn record_publish_blocked_attempts(attempts: u32) {
    gauge!(
        description: "Consecutive production attempts skipped because the channel pin trails the live tip",
        unit: Unit::Count,
        names::PUBLISH_BLOCKED_ATTEMPTS
    )
    .set(f64::from(attempts));
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
