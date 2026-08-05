use metrics::{Counter, Unit, counter};

use crate::names;

pub fn init() {
    submitted_transactions_total_counter().increment(0);
    before_mempool_failed_transactions_total_counter().increment(0);
}

fn submitted_transactions_total_counter() -> Counter {
    counter!(
        description: "Number of transactions submitted",
        unit: Unit::Count,
        names::SUBMITTED_TRANSACTIONS_TOTAL
    )
}

pub fn increment_submitted_transactions_total() {
    submitted_transactions_total_counter().increment(1);
}

fn before_mempool_failed_transactions_total_counter() -> Counter {
    counter!(
        description: "Number of transactions that failed before reaching the mempool",
        unit: Unit::Count,
        names::BEFORE_MEMPOOL_FAILED_TRANSACTIONS_TOTAL
    )
}

pub fn increment_before_mempool_failed_transactions_total() {
    before_mempool_failed_transactions_total_counter().increment(1);
}
