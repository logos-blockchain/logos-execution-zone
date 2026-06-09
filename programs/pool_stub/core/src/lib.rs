use borsh::{BorshDeserialize, BorshSerialize};
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::account::{AccountWithMetadata, Data};
use serde::{Deserialize, Serialize};

pub const CARDINALITY: usize = 16;
pub const MAX_TICK_DELTA: i32 = 9_116;

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    InitPool { tick: i32 },
    Observe { tick: i32 },
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct Observation {
    pub block: u64,
    pub tick_cumulative: i128,
}

#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct PoolAccount {
    pub last_tick: i32,
    pub last_block: u64,
    pub last_ts_ms: u64,
    pub index: u16,
    pub obs: Vec<Observation>,
}

impl TryFrom<&Data> for PoolAccount {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&PoolAccount> for Data {
    fn from(pool: &PoolAccount) -> Self {
        let mut data = Vec::with_capacity(std::mem::size_of_val(pool));

        BorshSerialize::serialize(pool, &mut data).expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Pool account encoded data should fit into Data")
    }
}

pub trait ClockExt {
    fn read_clock(&self) -> ClockAccountData;
}

impl ClockExt for AccountWithMetadata {
    fn read_clock(&self) -> ClockAccountData {
        assert_eq!(
            self.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
            "Not the system clock account"
        );

        ClockAccountData::from_bytes(self.account.data.as_ref())
    }
}
