#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use amm_core::{ExactInput, SwapRequest};
use anyhow::Result;
use integration_tests::{
    TestContext,
    amm::{
        PoolFixture, Trader, assert_dropped, assert_pool_and_vaults, fungible, private_holding,
        prove_swap, settle, spend_input, token_program_id,
    },
    restored_private_account, sync_private, wait_for_inclusion,
};
use lee::{
    Actor, PrivacyPreservingTransaction, privacy_preserving_transaction::circuit::ProgramCatalog,
};
use token_core::{Delivery, TokenHolding};
use tokio::test;

const SUPPLY: u128 = 10_000;
const AMOUNT_IN: u128 = 100;

// Spends the trader's private A note against no public state at all: nothing about the pool's
// reserves goes into the proof. The payout is cast rather than delivered, so the output account
// takes no part and the proof assumes nothing of public execution.
async fn prepare_swap(
    ctx: &TestContext,
    pool: &PoolFixture,
    trader: &Trader,
    min_amount_out: u128,
    seed: u8,
) -> Result<PrivacyPreservingTransaction> {
    let (spent, _) = spend_input(ctx, trader, seed).await?;
    prove_swap(
        pool,
        trader,
        AMOUNT_IN,
        SwapRequest::ExactInput(ExactInput {
            definition_id_out: pool.definition_b,
            min_amount_out,
            payout: trader.output,
            delivery: Delivery::Cast,
        }),
        vec![spent],
        vec![Vec::new()],
    )
}

// Exact-input swaps prepared while the pool sits at 1,000/1,000 settle later, unchanged, each for
// whatever the live curve quotes as long as that meets its minimum, and cast that quote to the
// trader as a pending token credit the trader receives privately afterwards. One whose minimum the
// live quote misses is refused without moving anything.
#[test]
async fn exact_inputs_prepared_at_one_price_settle_at_the_live_quote_and_cast_the_payout()
-> Result<()> {
    let mut ctx = TestContext::new().await?;
    let pool = PoolFixture::open(&mut ctx, SUPPLY).await?;
    let PoolFixture {
        holding_a,
        definition_a,
        definition_b,
        ..
    } = pool;

    let mut traders = Vec::new();
    for _ in 0..3 {
        traders.push(Trader::fund(&mut ctx, holding_a, AMOUNT_IN).await?);
    }

    // All three swaps are proven and recorded before the first settles; the second accepts less.
    let mut prepared = Vec::new();
    for ((trader, min_amount_out), seed) in traders.iter().zip([80, 70, 80]).zip(1..) {
        prepared.push(prepare_swap(&ctx, &pool, trader, min_amount_out, seed).await?);
    }
    assert_pool_and_vaults(&ctx, "prepared", &pool, 1_000, 1_000).await?;

    // Quotes 1000 * 100 / 1100 = 90 >= 80, then 910 * 100 / 1200 = 75 >= 70: the same kind of
    // prepared input settles at a different, still acceptable, live quote.
    settle(&ctx, &pool, "first swap", &prepared[0], 1_100, 910).await?;
    settle(&ctx, &pool, "second swap", &prepared[1], 1_200, 835).await?;

    // 835 * 100 / 1300 = 64 < 80: the live quote misses the third swap's minimum, so it is dropped
    // rather than included.
    assert_dropped(&ctx, &pool, "missed minimum", &prepared[2], 1_200, 835).await?;

    // Vault B's transfers cast the payouts: the node holds exactly the two token credits, pending
    // at the output accounts.
    let pending = ctx.wallet().get_pending_messages(0, 256).await?;
    assert_eq!(pending.len(), 2, "the node holds exactly the two payouts");
    for (record, (index, amount)) in pending.iter().zip([(0, 90), (1, 75)]) {
        assert_eq!(
            (record.body.source, record.body.to),
            (
                token_program_id(),
                Actor::new(traders[index].output, token_program_id())
            ),
            "trader {index}: the token program casts the payout to the output account"
        );
        assert_eq!(
            borsh::from_slice::<token_core::Message>(&record.body.message)?,
            token_core::Message::Credit {
                descriptor: fungible(definition_b),
                amount,
                notify: None,
            },
            "trader {index}: the payout is the live quote"
        );
    }

    for record in pending {
        let (received, _) = ctx
            .wallet()
            .receive_pending_message(
                record,
                None,
                None,
                &ProgramCatalog::from([(token_program_id(), programs::token())]),
            )
            .await?;
        wait_for_inclusion(&ctx, received).await?;
    }
    assert!(
        ctx.wallet().get_pending_messages(0, 256).await?.is_empty(),
        "receiving consumes the pending payouts"
    );

    sync_private(&mut ctx).await?;
    for (index, (input_left, received)) in
        [(0, 90), (0, 75), (AMOUNT_IN, 0)].into_iter().enumerate()
    {
        assert_eq!(
            private_holding(&ctx, traders[index].input)?,
            TokenHolding::Fungible {
                definition_id: definition_a,
                balance: input_left
            },
            "trader {index}: input note"
        );
        let output = restored_private_account(&ctx, traders[index].output, "trader output");
        if received == 0 {
            assert!(
                output.account.data.shard(token_program_id()).is_empty(),
                "trader {index}: a refused swap casts nothing to its output account"
            );
        } else {
            assert_eq!(
                private_holding(&ctx, traders[index].output)?,
                TokenHolding::Fungible {
                    definition_id: definition_b,
                    balance: received
                },
                "trader {index}: received payout"
            );
        }
    }

    Ok(())
}
