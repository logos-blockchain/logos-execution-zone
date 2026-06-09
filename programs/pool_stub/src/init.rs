use lee_core::{
    account::{AccountWithMetadata, Data},
    program::AccountPostState,
};
use pool_stub_core::{CARDINALITY, Observation, PoolAccount};

#[must_use]
pub fn init(pool: AccountWithMetadata, tick: i32) -> Vec<AccountPostState> {
    let pool_account = PoolAccount {
        last_tick: tick,
        last_block: 0,
        last_ts_ms: 0,
        index: 0,
        obs: vec![Observation::default(); CARDINALITY],
    };

    let mut post = pool.account;
    post.data = Data::from(&pool_account);

    vec![AccountPostState::new(post)]
}
