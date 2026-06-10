use lee_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, Claim},
};
use pool_stub_core::{ClockExt, Observation, PoolAccount, WithClock, clamp_tick_delta};

#[must_use]
pub fn observe(
    pool: AccountWithMetadata,
    clock: AccountWithMetadata,
    tick: i32,
) -> Vec<AccountPostState> {
    let mut p = PoolAccount::try_from(&pool.account.data).expect("Invalid pool data");
    let now = clock.read_clock();
    let ts = now.timestamp;

    if ts <= p.last_ts_ms {
        return vec![AccountPostState::new(pool.account)].with_clock(clock);
    }

    let eff_tick = p.last_tick + clamp_tick_delta(p.last_tick, tick);

    if p.last_ts_ms == 0 {
        p.obs[0] = Observation {
            timestamp: ts,
            tick_cumulative: 0,
        };
        p.index = 0;
    } else {
        let dt = i128::from(ts - p.last_ts_ms);
        let prev = p.obs[p.index as usize].tick_cumulative;
        let next = (p.index as usize + 1) % p.obs.len();
        p.obs[next] = Observation {
            timestamp: ts,
            tick_cumulative: prev + i128::from(eff_tick) * dt,
        };
        p.index = next as u16;
    }

    p.last_tick = eff_tick;
    p.last_ts_ms = ts;

    let mut post = pool.account;
    post.data = Data::from(&p);

    vec![AccountPostState::new_claimed_if_default(post, Claim::Authorized)].with_clock(clock)
}
