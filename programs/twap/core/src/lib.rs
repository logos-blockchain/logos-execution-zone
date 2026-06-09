use serde::{Deserialize, Serialize};

pub use oracle_price::{PriceAccount, SOURCE_TWAP as TWAP_SOURCE_ID};

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    ReadTwap { window_blocks: u64, max_age_blocks: u64 },
}
