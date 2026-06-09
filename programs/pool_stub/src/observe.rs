use clock_core::ClockAccountData;
use lee_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, Claim},
};
use pool_stub_core::{MAX_TICK_DELTA, Observation, PoolAccount};

#[must_use]
pub fn observe(
    pool: AccountWithMetadata,
    clock: AccountWithMetadata,
    tick: i32,
) -> Vec<AccountPostState> {
    let mut p = PoolAccount::try_from(&pool.account.data).expect("Invalid pool data");
    let now = ClockAccountData::from_bytes(clock.account.data.as_ref());

    if now.block_id <= p.last_block {
        return vec![];
    }

    let delta = (tick - p.last_tick).clamp(-MAX_TICK_DELTA, MAX_TICK_DELTA);
    let eff_tick = p.last_tick + delta;
    let blocks = i128::from(now.block_id - p.last_block);
    let prev = p.obs[p.index as usize].tick_cumulative;

    let next = (p.index as usize + 1) % p.obs.len();
    p.obs[next] = Observation {
        block: now.block_id,
        tick_cumulative: prev + i128::from(eff_tick) * blocks,
    };
    p.index = next as u16;
    p.last_tick = eff_tick;
    p.last_block = now.block_id;
    p.last_ts_ms = now.timestamp;

    let mut post = pool.account;
    post.data = Data::from(&p);

    vec![AccountPostState::new_claimed_if_default(post, Claim::Authorized)]
}
