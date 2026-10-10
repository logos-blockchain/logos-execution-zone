#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::collections::BTreeSet;

use amm_core::SwapRequest;
use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext,
    amm::{
        PoolFixture, Prediction, Trader, assert_dropped, assert_pool_and_vaults, fungible,
        private_holding, prove_swap, settle, spend_input, token_program_id,
    },
    restored_private_account, sync_private, wait_for_inclusion,
};
use lee::{Actor, PrivacyPreservingTransaction, Publication};
use lee_core::{Commitment, Nullifier, PrivateAccountKind, program::PdaSeed};
use token_core::TokenHolding;
use tokio::test;
use wallet::{
    AccountIdentity,
    program_facades::amm::{Amm, Payout},
};

const SUPPLY: u128 = 10_000;
const AMOUNT_IN: u128 = 100;

// Spends the trader's private A note against no public state at all: nothing about the pool's
// reserves goes into the proof. The payout is cast rather than delivered, so the output account
// takes no part beyond the recovery binding its publication carries, and the proof assumes nothing
// of public execution.
async fn prepare_swap(
    ctx: &TestContext,
    pool: &PoolFixture,
    trader: &Trader,
    min_amount_out: u128,
    seed: u8,
) -> Result<PrivacyPreservingTransaction> {
    let (spent, _) = spend_input(ctx, trader, seed).await?;
    let (_, casts) = ctx.wallet().cast_destination(
        AccountIdentity::PrivateOwned(trader.output).select_program_actor_state(token_program_id()),
    )?;
    prove_swap(
        pool,
        trader,
        AMOUNT_IN,
        SwapRequest {
            definition_id_out: pool.definition_b,
            min_amount_out,
            payout: trader.output,
        },
        vec![spent],
        casts.recoveries,
        Prediction {
            cross_messages: vec![Vec::new()],
            cast_promotions: BTreeSet::new(),
        },
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

    // Vault B's transfers cast the payouts: exactly the two token credits are pending at the output
    // accounts.
    let pending = ctx.wallet_mut().owned_pending_messages().await?;
    assert_eq!(pending.len(), 2, "exactly the two payouts are pending");
    for (record, (index, amount)) in pending.iter().zip([(0, 90), (1, 75)]) {
        let Publication::Clear { body, .. } = &record.publication else {
            anyhow::bail!("a public vault's payout is published clear");
        };
        assert_eq!(
            (body.from.program_account_id, body.to),
            (
                token_program_id(),
                Actor::new(traders[index].output, token_program_id())
            ),
            "trader {index}: the token program casts the payout to the output account"
        );
        assert_eq!(
            borsh::from_slice::<token_core::Message>(&body.message)?,
            token_core::Message::Credit {
                descriptor: fungible(definition_b),
                amount,
                notify: None,
            },
            "trader {index}: the payout is the live quote"
        );
    }

    for record in pending {
        let (received, _) = ctx.wallet_mut().receive_pending_message(record).await?;
        wait_for_inclusion(&ctx, received).await?;
    }
    assert!(
        ctx.wallet_mut().owned_pending_messages().await?.is_empty(),
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
                output
                    .account
                    .data
                    .actor_state(token_program_id())
                    .is_empty(),
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

// A public exact-input swap proves only its payout's recovery binding and leaves the quote to live
// execution. The payout account is a private PDA under the recipient's keys, of which it holds no
// record: it finds each payout by opening its recovery note, records the PDA at its first receipt
// and follows it from there, and the second payout reuses the binding unproven.
#[test]
async fn a_public_exact_input_payout_reaches_an_account_its_recipient_discovers_by_key()
-> Result<()> {
    let mut ctx = TestContext::new().await?;
    let pool = PoolFixture::open(&mut ctx, SUPPLY).await?;
    let (recorded, _) = ctx.wallet_mut().create_new_account_private(None);
    let keys = restored_private_account(&ctx, recorded, "recipient keys")
        .key_chain
        .clone();
    let payout = AccountIdentity::PrivateForeign {
        npk: keys.nullifier_public_key,
        vpk: keys.viewing_public_key,
        kind: PrivateAccountKind::Pda {
            account_id: programs::amm_account_id(),
            seed: PdaSeed::new([7; 32]),
        },
    };
    let payout_id = payout.account_id();

    let mut notes = Vec::new();
    // Quotes 1000 * 100 / 1100 = 90, then 910 * 100 / 1200 = 75.
    for (amount, balance) in [(90, 90), (75, 165)] {
        let (swapped, _) = Amm(ctx.wallet())
            .send_swap(
                pool.pool_id,
                AccountIdentity::Public(pool.holding_a),
                payout.clone(),
                AMOUNT_IN,
                1,
                Payout::Live,
            )
            .await?;
        wait_for_inclusion(&ctx, swapped).await?;

        let [pending] = <[_; 1]>::try_from(ctx.wallet_mut().owned_pending_messages().await?)
            .map_err(|pending| anyhow::anyhow!("expected one payout, found {}", pending.len()))?;
        let Publication::Clear { body, recovery } = &pending.publication else {
            anyhow::bail!("a public swap's payout is published clear");
        };
        assert_eq!(body.to, Actor::new(payout_id, token_program_id()));
        assert_eq!(
            borsh::from_slice::<token_core::Message>(&body.message)?,
            token_core::Message::Credit {
                descriptor: fungible(pool.definition_b),
                amount,
                notify: None,
            },
            "the payout is the live quote"
        );
        notes.push(recovery.clone());
        let spent = Nullifier::for_message(
            &keys.private_key_holder.nullifier_secret_key(),
            &Commitment::for_message(body),
            pending.position,
        );

        let (received, _) = ctx.wallet_mut().receive_pending_message(pending).await?;
        wait_for_inclusion(&ctx, received).await?;
        // The receipt names neither the payout nor its position: the payout's nullifier, which
        // only the recipient's key derives, is one of its unlabelled private actions.
        let Some((LeeTransaction::PrivacyPreserving(receipt), _)) =
            ctx.wallet().get_transaction(received).await?
        else {
            anyhow::bail!("the payout's receipt must be a proven transaction");
        };
        assert!(
            receipt.message.execution.public_root.is_none()
                && receipt
                    .message
                    .execution
                    .private_actions
                    .iter()
                    .any(|action| action.nullifier == spent)
        );
        sync_private(&mut ctx).await?;
        assert_eq!(
            private_holding(&ctx, payout_id)?,
            TokenHolding::Fungible {
                definition_id: pool.definition_b,
                balance,
            }
        );
    }

    assert_eq!(
        notes[0], notes[1],
        "the second payout reuses the binding the first proved"
    );
    assert_eq!(
        ctx.wallet().get_recovery_binding(payout_id).await?,
        Some(notes[0].clone())
    );
    Ok(())
}
