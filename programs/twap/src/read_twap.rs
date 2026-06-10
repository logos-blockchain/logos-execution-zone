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
    window_blocks: u64,
    max_age_blocks: u64,
) -> Vec<AccountPostState> {
    let p = PoolAccount::try_from(&pool.account.data).expect("Invalid pool data");
    let now = clock.read_clock();

    assert!(
        now.block_id.saturating_sub(p.last_block) <= max_age_blocks,
        "Stale price"
    );

    let newest = p.obs[p.index as usize].clone();
    let target = newest.block.saturating_sub(window_blocks);
    let older = oldest_at_or_before(&p, target);

    let span = newest.block.saturating_sub(older.block);
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

fn oldest_at_or_before(p: &PoolAccount, target_block: u64) -> Observation {
    p.obs
        .iter()
        .filter(|o| o.block > 0 && o.block <= target_block)
        .max_by_key(|o| o.block)
        .or_else(|| p.obs.iter().filter(|o| o.block > 0).min_by_key(|o| o.block))
        .cloned()
        .unwrap_or_default()
}
