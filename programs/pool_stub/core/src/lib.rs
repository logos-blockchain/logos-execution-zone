use borsh::{BorshDeserialize, BorshSerialize};
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, ClockAccountData};
use lee_core::{
    account::{AccountWithMetadata, Data},
    program::AccountPostState,
};
use serde::{Deserialize, Serialize};

pub const MAX_TICK_DELTA: i32 = 9_116;

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    InitPool { tick: i32, cardinality: u16 },
    Observe { tick: i32 },
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct Observation {
    pub timestamp: u64,
    pub tick_cumulative: i128,
}

#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct PoolAccount {
    pub last_tick: i32,
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

pub trait WithClock {
    fn with_clock(self, clock: AccountWithMetadata) -> Self;
}

impl WithClock for Vec<AccountPostState> {
    fn with_clock(mut self, clock: AccountWithMetadata) -> Self {
        assert_eq!(
            clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
            "Not the system clock account"
        );
        self.push(AccountPostState::new(clock.account));

        self
    }
}

#[must_use]
pub fn clamp_tick_delta(last_tick: i32, new_tick: i32) -> i32 {
    (new_tick - last_tick).clamp(-MAX_TICK_DELTA, MAX_TICK_DELTA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_is_clamped_to_max() {
        assert_eq!(clamp_tick_delta(0, 9_000_000), MAX_TICK_DELTA);
        assert_eq!(clamp_tick_delta(0, -9_000_000), -MAX_TICK_DELTA);
    }

    #[test]
    fn small_delta_passes_through() {
        assert_eq!(clamp_tick_delta(100, 250), 150);
    }
}
