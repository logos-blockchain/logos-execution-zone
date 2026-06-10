use serde::{Deserialize, Serialize};

pub use oracle_price::{PriceAccount, SOURCE_TWAP as TWAP_SOURCE_ID};

mod tick_math;
pub use tick_math::{MAX_TICK, PRICE_SCALE, tick_to_price};

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    ReadTwap { window_ms: u64, max_age_ms: u64 },
}

#[must_use]
pub fn average_tick(newer_cumulative: i128, older_cumulative: i128, span: u64) -> i32 {
    let span = i128::from(span);

    i32::try_from((newer_cumulative - older_cumulative) / span).expect("Tick out of range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn average_tick_is_cumulative_delta_over_span() {
        assert_eq!(average_tick(1800, 0, 3), 600);
        assert_eq!(average_tick(-1800, 0, 3), -600);
    }
}
