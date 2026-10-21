#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

//! A privacy-preserving transaction's fee surplus, refunded to a public target.

use anyhow::Result;
use integration_tests::{
    TestContext,
    config::{INITIAL_PRIVATE_BALANCES_FOR_WALLET, min_private_fee},
    private_mention, public_mention,
    utils::{account_balance, private_balance, send, sync_private},
};
use lee::AccountId;
use tokio::test;

/// The blocks of headroom the sends below reserve at.
const HEADROOM_BLOCKS: u64 = 5;

/// The reserve a send prices at the floor base fees after [`HEADROOM_BLOCKS`] full blocks.
fn reserve_at_floor() -> u128 {
    use fee_core::market::{
        BASE_FEE_EXEC_MAX, BASE_FEE_EXEC_MIN, BASE_FEE_STOR_MAX, BASE_FEE_STOR_MIN, D_EXEC, D_STOR,
        MAX_GAS_EXEC, MAX_GAS_STOR, TARGET_GAS_EXEC, TARGET_GAS_STOR, next_base_fee,
    };
    let climb = |base, max_gas, target, damping, lo, hi| {
        (0..HEADROOM_BLOCKS).fold(base, |fee, _| {
            next_base_fee(fee, max_gas, target, damping, lo, hi)
        })
    };
    fee_core::assess::private_fee_required(
        0,
        climb(
            BASE_FEE_EXEC_MIN,
            MAX_GAS_EXEC,
            TARGET_GAS_EXEC,
            D_EXEC,
            BASE_FEE_EXEC_MIN,
            BASE_FEE_EXEC_MAX,
        ),
        climb(
            BASE_FEE_STOR_MIN,
            MAX_GAS_STOR,
            TARGET_GAS_STOR,
            D_STOR,
            BASE_FEE_STOR_MIN,
            BASE_FEE_STOR_MAX,
        ),
    )
}

#[test]
async fn a_fee_refund_goes_to_the_public_target() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_public_accounts()[1];
    ctx.wallet_mut()
        .set_private_fee_headroom_blocks(HEADROOM_BLOCKS);
    ctx.wallet_mut().set_private_refund_target(Some(to));
    let reserve = reserve_at_floor();
    let surplus = reserve - min_private_fee();
    assert!(surplus > fee_core::market::MIN_PRIVATE_REFUND);
    let to_before = account_balance(&ctx, to).await?;

    send(&mut ctx, private_mention(from), public_mention(to), 100).await?;
    sync_private(&mut ctx).await?;

    // The deshield's recipient gets the amount and the surplus; nothing is left to claim.
    assert_eq!(account_balance(&ctx, to).await?, to_before + 100 + surplus);
    assert_eq!(
        private_balance(&ctx, from)?,
        INITIAL_PRIVATE_BALANCES_FOR_WALLET[0] - 100 - reserve
    );
    assert!(ctx.wallet_mut().owned_pending_messages().await?.is_empty());
    Ok(())
}
