use metrics::{Unit, gauge};

use crate::names;

/// Initialize metrics.
pub fn init() {
    record_production_failed_attempts(0);
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
