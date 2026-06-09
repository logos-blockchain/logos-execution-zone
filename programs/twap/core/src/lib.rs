use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::Data;
use serde::{Deserialize, Serialize};

pub const TWAP_SOURCE_ID: u32 = 1;

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    ReadTwap { window_blocks: u64, max_age_blocks: u64 },
}

#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct PriceAccount {
    pub base_asset: [u8; 32],
    pub quote_asset: [u8; 32],
    pub price: u128,
    pub timestamp_ms: u64,
    pub source_id: u32,
    pub confidence: u128,
}

impl TryFrom<&Data> for PriceAccount {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&PriceAccount> for Data {
    fn from(price: &PriceAccount) -> Self {
        let mut data = Vec::with_capacity(std::mem::size_of_val(price));

        BorshSerialize::serialize(price, &mut data).expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Price account encoded data should fit into Data")
    }
}
