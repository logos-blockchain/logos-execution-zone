#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use amm_core::{SwapOffer, SwapRequest};
use anyhow::Result;
use integration_tests::{
    TestContext,
    amm::{
        PoolFixture, Trader, assert_dropped, assert_pool_and_vaults, fungible, private_holding,
        prove_swap, settle, spend_input, token_program_id,
    },
    restored_private_account, sync_private, wait_for_inclusion,
};
use lee::{Actor, PrivacyPreservingTransaction};
use lee_core::{NullifierWitness, PrivateWitness, WitnessKind, program::Call};
use token_core::{Delivery, TokenHolding, expected_sends};
use tokio::test;
use wallet::{AccountIdentity, program_facades::amm::Amm};

const SUPPLY: u128 = 10_000;
const OFFER_IN: u128 = 100;
const OFFER_OUT: u128 = 75;

// Vault B's payout into the output note, the one delivery the proof assumes of public execution,
// made under the pool's grant of vault B: promised whatever the pool's price is at preparation.
fn payout_assumed(pool: &PoolFixture, trader: &Trader) -> Vec<lee::PublicCallAssumptions> {
    let vault_b = Actor::new(pool.vault_b, token_program_id());
    let payout = token_core::Message::Transfer {
        to: trader.output,
        descriptor: fungible(pool.definition_b),
        amount: OFFER_OUT,
        notify: None,
        delivery: Delivery::Call,
    };
    let (calls, casts) = expected_sends(vault_b, &payout);
    assert!(
        casts.is_empty(),
        "the token program's payout is an inline call"
    );
    vec![
        calls
            .into_iter()
            .map(
                |Call {
                     to,
                     message,
                     pda_seeds,
                 }| {
                    lee::Assumption {
                        envelope: lee::MessageEnvelope {
                            source: vault_b,
                            to,
                            message,
                        },
                        grants: vec![pool.vault_b],
                        pda_seeds,
                    }
                },
            )
            .collect(),
    ]
}

// Spends the trader's private A note and opens its private B holding, against no public state
// at all: nothing about the pool's reserves goes into the proof.
async fn prepare_offer(
    ctx: &TestContext,
    pool: &PoolFixture,
    trader: &Trader,
    seed: u8,
) -> Result<PrivacyPreservingTransaction> {
    let (spent, root) = spend_input(ctx, trader, seed).await?;
    let received = restored_private_account(ctx, trader.output, "trader output");
    prove_swap(
        pool,
        trader,
        OFFER_IN,
        SwapRequest::Offer(SwapOffer {
            definition_id_out: pool.definition_b,
            amount_out: OFFER_OUT,
            payout: trader.output,
        }),
        vec![
            spent,
            PrivateWitness {
                vpk: received.key_chain.viewing_public_key.clone(),
                random_seed: [seed.wrapping_add(128); 32],
                identifier: received.kind.identifier(),
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: received.key_chain.nullifier_public_key,
                    commitment_root: root,
                },
            },
        ],
        payout_assumed(pool, trader),
    )
}

// Offers prepared while the pool sits at 1,000/1,000 settle later, unchanged, against whatever
// the pool holds by then: each is accepted while the live curve can still afford it and pays
// exactly its fixed terms, and one it cannot afford is refused without moving anything, then
// settles as it stands once the price comes back.
#[test]
async fn offers_prepared_at_one_price_settle_against_the_live_pool() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let pool = PoolFixture::open(&mut ctx, SUPPLY).await?;
    let PoolFixture {
        holding_a,
        holding_b,
        definition_a,
        definition_b,
        ..
    } = pool;

    // Distinct traders, each with its own private note: the only contention is the pool's.
    let mut traders = Vec::new();
    for _ in 0..4 {
        traders.push(Trader::fund(&mut ctx, holding_a, OFFER_IN).await?);
    }

    // All three offers are proven and recorded before the first settles.
    let mut prepared = Vec::new();
    for (trader, seed) in traders.iter().take(3).zip(1..) {
        prepared.push(prepare_offer(&ctx, &pool, trader, seed).await?);
    }
    assert_pool_and_vaults(&ctx, "prepared", &pool, 1_000, 1_000).await?;

    // Quotes 1000 * 100 / 1100 = 90, then 925 * 100 / 1200 = 77; each offer pays exactly 75.
    settle(&ctx, &pool, "first offer", &prepared[0], 1_100, 925).await?;
    settle(&ctx, &pool, "second offer", &prepared[1], 1_200, 850).await?;

    // 850 * 100 / 1300 = 65 < 75: the pool cannot afford the third offer, so it is dropped rather
    // than included.
    assert_dropped(&ctx, &pool, "unaffordable offer", &prepared[2], 1_200, 850).await?;

    sync_private(&mut ctx).await?;
    for (index, (input_left, received)) in [(0, OFFER_OUT), (0, OFFER_OUT), (OFFER_IN, 0)]
        .into_iter()
        .enumerate()
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
                "trader {index}: a refused offer opens no output holding"
            );
        } else {
            assert_eq!(
                private_holding(&ctx, traders[index].output)?,
                TokenHolding::Fungible {
                    definition_id: definition_b,
                    balance: received
                },
                "trader {index}: fixed receipt"
            );
        }
    }

    // Move the price back in the offers' favour: 400 of B into 850/1200 quotes 1200 * 400 / 1250 =
    // 384 of A; the offer takes 300, leaving the pool at 900/1250.
    let (reversed, _) = Amm(ctx.wallet())
        .send_swap(
            pool.pool_id,
            AccountIdentity::Public(holding_b),
            AccountIdentity::Public(holding_a),
            400,
            300,
        )
        .await?;
    wait_for_inclusion(&ctx, reversed).await?;
    assert_pool_and_vaults(&ctx, "moved", &pool, 900, 1_250).await?;

    // Now 100 of A quotes 1250 * 100 / 1000 = 125 of B. The refused offer, resubmitted exactly as
    // it was recorded, settles for its fixed 75: its note was never spent.
    settle(&ctx, &pool, "retried offer", &prepared[2], 1_000, 1_175).await?;

    // 1175 * 100 / 1100 = 106 of B, but the fourth offer still pays exactly 75, through the
    // wallet's own private path.
    let (favoured, _) = Amm(ctx.wallet())
        .send_swap(
            pool.pool_id,
            AccountIdentity::PrivateOwned(traders[3].input),
            AccountIdentity::PrivateOwned(traders[3].output),
            OFFER_IN,
            OFFER_OUT,
        )
        .await?;
    wait_for_inclusion(&ctx, favoured).await?;
    assert_pool_and_vaults(&ctx, "favoured", &pool, 1_100, 1_100).await?;

    sync_private(&mut ctx).await?;
    for (index, trader) in traders.iter().enumerate().skip(2) {
        assert_eq!(
            private_holding(&ctx, trader.input)?,
            TokenHolding::Fungible {
                definition_id: definition_a,
                balance: 0
            },
            "trader {index}: input note"
        );
        assert_eq!(
            private_holding(&ctx, trader.output)?,
            TokenHolding::Fungible {
                definition_id: definition_b,
                balance: OFFER_OUT
            },
            "trader {index}: the receipt does not grow with the price"
        );
    }

    Ok(())
}
