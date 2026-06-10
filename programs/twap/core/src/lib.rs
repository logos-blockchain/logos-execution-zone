use serde::{Deserialize, Serialize};

pub use oracle_price::{PriceAccount, SOURCE_TWAP as TWAP_SOURCE_ID};

pub const PRICE_SCALE: u128 = 100_000_000;

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    ReadTwap { window_blocks: u64, max_age_blocks: u64 },
}

#[must_use]
pub fn average_tick(newer_cumulative: i128, older_cumulative: i128, span: u64) -> i32 {
    let span = i128::from(span);

    i32::try_from((newer_cumulative - older_cumulative) / span).expect("Tick out of range")
}

#[must_use]
pub fn tick_to_price(tick: i32) -> u128 {
    let ratio = 1.0001_f64.powi(tick);

    (ratio * PRICE_SCALE as f64) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_zero_is_unit_price() {
        assert_eq!(tick_to_price(0), PRICE_SCALE);
    }

    #[test]
    fn average_tick_is_cumulative_delta_over_span() {
        assert_eq!(average_tick(1800, 0, 3), 600);
        assert_eq!(average_tick(-1800, 0, 3), -600);
    }

    #[test]
    fn tick_to_price_matches_known_value() {
        let price = tick_to_price(600);

        assert!(
            (106_000_000..107_000_000).contains(&price),
            "1.0001^600 should be ~1.0618, got {price}"
        );
    }
}
