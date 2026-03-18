//! Formatting utilities for the explorer.

/// Format timestamp to human-readable string.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "We need to convert milliseconds to seconds, and this is the most straightforward way to do it"
)]
pub fn format_timestamp(timestamp: u64) -> String {
    let seconds = timestamp / 1000;
    let datetime = chrono::DateTime::from_timestamp(
        i64::try_from(seconds).expect("Timestamp out of range"),
        0,
    )
    .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
