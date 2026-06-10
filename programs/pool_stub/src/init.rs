use lee_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, Claim},
};
use pool_stub_core::{Observation, PoolAccount};

#[must_use]
pub fn init(pool: AccountWithMetadata, tick: i32, cardinality: u16) -> Vec<AccountPostState> {
    let capacity = usize::from(cardinality.max(1));
    let pool_account = PoolAccount {
        last_tick: tick,
        last_ts_ms: 0,
        index: 0,
        obs: vec![Observation::default(); capacity],
    };

    let mut post = pool.account;
    post.data = Data::from(&pool_account);

    vec![AccountPostState::new_claimed_if_default(post, Claim::Authorized)]
}
