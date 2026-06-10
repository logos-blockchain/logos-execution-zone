use lee_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, Claim},
};
use pool_stub_core::{ClockExt, Observation, PoolAccount, WithClock};
use twap_core::{PriceAccount, TWAP_SOURCE_ID, average_tick, tick_to_price};

#[must_use]
pub fn read_twap(
    pool: AccountWithMetadata,
    price_acc: AccountWithMetadata,
    clock: AccountWithMetadata,
    window_ms: u64,
    max_age_ms: u64,
) -> Vec<AccountPostState> {
    let p = PoolAccount::try_from(&pool.account.data).expect("Invalid pool data");
    let now = clock.read_clock();

    assert!(
        now.timestamp.saturating_sub(p.last_ts_ms) <= max_age_ms,
        "Stale price"
    );

    let newest = p.obs[p.index as usize].clone();
    let target = newest.timestamp.saturating_sub(window_ms);
    let older = oldest_at_or_before(&p, target);

    let span = newest.timestamp.saturating_sub(older.timestamp);
    assert!(span > 0, "Insufficient observations for window");

    let avg_tick = average_tick(newest.tick_cumulative, older.tick_cumulative, span);
    let price = tick_to_price(avg_tick);
    assert!(price > 0, "Invalid price");

    let mut out = PriceAccount::try_from(&price_acc.account.data).unwrap_or_default();
    out.price = price;
    out.timestamp_ms = now.timestamp;
    out.source_id = TWAP_SOURCE_ID;

    let mut post = price_acc.account;
    post.data = Data::from(&out);

    vec![
        AccountPostState::new(pool.account),
        AccountPostState::new_claimed_if_default(post, Claim::Authorized),
    ]
    .with_clock(clock)
}

fn oldest_at_or_before(p: &PoolAccount, target_ts: u64) -> Observation {
    p.obs
        .iter()
        .filter(|o| o.timestamp > 0 && o.timestamp <= target_ts)
        .max_by_key(|o| o.timestamp)
        .or_else(|| p.obs.iter().filter(|o| o.timestamp > 0).min_by_key(|o| o.timestamp))
        .cloned()
        .unwrap_or_default()
}
