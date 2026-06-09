use clock_core::ClockAccountData;
use lee_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, Claim},
};
use pool_stub_core::{Observation, PoolAccount};
use twap_core::{PriceAccount, TWAP_SOURCE_ID};

#[must_use]
pub fn read_twap(
    pool: AccountWithMetadata,
    clock: AccountWithMetadata,
    price_acc: AccountWithMetadata,
    window_blocks: u64,
    max_age_blocks: u64,
) -> Vec<AccountPostState> {
    let p = PoolAccount::try_from(&pool.account.data).expect("Invalid pool data");
    let now = ClockAccountData::from_bytes(clock.account.data.as_ref());

    assert!(
        now.block_id.saturating_sub(p.last_block) <= max_age_blocks,
        "Stale price"
    );

    let newest = p.obs[p.index as usize].clone();
    let target = newest.block.saturating_sub(window_blocks);
    let older = oldest_at_or_before(&p, target);

    let span = i128::from(newest.block.saturating_sub(older.block));
    assert!(span > 0, "Insufficient observations for window");

    let avg_tick = i32::try_from((newest.tick_cumulative - older.tick_cumulative) / span)
        .expect("Tick out of range");
    let price = tick_to_price(avg_tick);
    assert!(price > 0, "Invalid price");

    let mut out = PriceAccount::try_from(&price_acc.account.data).unwrap_or_default();
    out.price = price;
    out.timestamp_ms = now.timestamp;
    out.source_id = TWAP_SOURCE_ID;

    let mut post = price_acc.account;
    post.data = Data::from(&out);

    vec![AccountPostState::new_claimed_if_default(post, Claim::Authorized)]
}

fn oldest_at_or_before(p: &PoolAccount, target_block: u64) -> Observation {
    p.obs
        .iter()
        .filter(|o| o.block > 0 && o.block <= target_block)
        .max_by_key(|o| o.block)
        .or_else(|| p.obs.iter().filter(|o| o.block > 0).min_by_key(|o| o.block))
        .cloned()
        .unwrap_or_default()
}

fn tick_to_price(tick: i32) -> u128 {
    let ratio = 1.0001_f64.powi(tick);

    (ratio * 1e8) as u128
}
