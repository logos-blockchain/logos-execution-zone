#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::collections::HashMap;

use amm_core::Instruction;
use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext,
    amm::{PoolFixture, amm_program_id, assert_holdings, assert_pool_record, token_program_id},
    fetch_privacy_preserving_tx, new_account, private_mention, public_mention,
    restored_private_account, sync_private, token_send, verify_commitment_is_in_state,
    wait_for_inclusion, wait_until,
};
use lee::{
    AccountId, PrivacyPreservingTransaction, ProgramShardSelector, ProvingInput, execute_and_prove,
    privacy_preserving_transaction::{
        circuit::ProgramWithDependencies, message::Message, witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{NullifierWitness, PrivateWitness, WitnessKind};
use sequencer_service_rpc::RpcClient as _;
use token_core::TokenHolding;
use tokio::test;
use wallet::{AccountIdentity, program_facades::amm::Amm};

const SUPPLY: u128 = 10_000;
const OFFER_IN: u128 = 100;
const OFFER_OUT: u128 = 75;

struct Trader {
    input: AccountId,
    output: AccountId,
}

fn swap_instruction(pool: &PoolFixture) -> Result<Vec<u8>> {
    Ok(Program::serialize_instruction(Instruction::Swap {
        token_program_id: token_program_id(),
        definition_id_in: pool.definition_a,
        definition_id_out: pool.definition_b,
        amount_in: OFFER_IN,
        amount_out: OFFER_OUT,
    })?)
}

fn private_holding(ctx: &TestContext, account_id: AccountId) -> Result<TokenHolding> {
    let account = restored_private_account(ctx, account_id, "trader account").account;
    Ok(TokenHolding::try_from(
        account.data.shard(token_program_id()),
    )?)
}

// The pool record, and the vaults that back it exactly, since nothing else credits them here.
async fn assert_pool(
    ctx: &TestContext,
    step: &str,
    pool: &PoolFixture,
    a: u128,
    b: u128,
) -> Result<()> {
    assert_pool_record(ctx, step, pool.pool_id, (a, b, 1_000)).await?;
    assert_holdings(
        ctx,
        step,
        &[
            (pool.vault_a, pool.definition_a, a),
            (pool.vault_b, pool.definition_b, b),
        ],
    )
    .await
}

// Spends the trader's private A note and opens its private B holding, against no public state
// at all: nothing about the pool's reserves goes into the proof.
async fn prepare_offer(
    ctx: &TestContext,
    pool: &PoolFixture,
    trader: &Trader,
    seed: u8,
) -> Result<PrivacyPreservingTransaction> {
    let spent = restored_private_account(ctx, trader.input, "trader input");
    let received = restored_private_account(ctx, trader.output, "trader output");
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(trader.input)
        .context("the trader's input note is unknown to the wallet")?;
    let (proofs, root) = ctx.wallet().get_proofs_and_root(&[commitment]).await?;
    let membership_proof = proofs
        .into_iter()
        .next()
        .flatten()
        .context("the trader's input note is not on chain")?;
    let spent_keys = &spent.key_chain.private_key_holder;

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(pool.pool_id, amm_program_id()),
                ProgramShardSelector::new(pool.vault_a, token_program_id()),
                ProgramShardSelector::new(pool.vault_b, token_program_id()),
                ProgramShardSelector::new(trader.input, token_program_id()),
                ProgramShardSelector::new(trader.output, token_program_id()),
            ],
            private_witnesses: vec![
                PrivateWitness {
                    vpk: spent.key_chain.viewing_public_key.clone(),
                    random_seed: [seed; 32],
                    identifier: spent.kind.identifier(),
                    kind: WitnessKind::Regular {
                        ask: Some(spent_keys.authorization_secret_key),
                    },
                    nullifier: NullifierWitness::Update {
                        account: spent.account.clone(),
                        view_tag: 0,
                        nsk: spent_keys.nullifier_secret_key(),
                        membership_proof,
                    },
                },
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
            instruction_data: swap_instruction(pool)?,
            ..Default::default()
        },
        &ProgramWithDependencies::new(
            programs::amm(),
            amm_program_id(),
            HashMap::from([(token_program_id(), programs::token())]),
        ),
    )?;
    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    Ok(PrivacyPreservingTransaction::new(message, witness_set))
}

// Submits a prepared offer unchanged and requires exactly it to settle, leaving the pool at these
// reserves.
async fn settle(
    ctx: &TestContext,
    pool: &PoolFixture,
    step: &str,
    tx: &PrivacyPreservingTransaction,
    a: u128,
    b: u128,
) -> Result<()> {
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx.clone()))
        .await?;
    wait_for_inclusion(ctx, tx_hash).await?;
    assert_eq!(
        fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await,
        *tx,
        "{step}: the settled transaction is the one prepared at 1,000/1,000"
    );
    assert_pool(ctx, step, pool, a, b).await
}

async fn fund_trader(ctx: &mut TestContext, from: AccountId) -> Result<Trader> {
    let input = new_account(ctx, true, None).await?;
    let output = new_account(ctx, true, None).await?;
    token_send(ctx, public_mention(from), private_mention(input), OFFER_IN).await?;
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(input)
        .context("the funded note is unknown to the wallet")?;
    wait_until("the trader's note to be committed", || async {
        Ok(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await)
    })
    .await?;
    Ok(Trader { input, output })
}

// Offers prepared while the pool sits at 1,000/1,000 settle later, unchanged, against whatever
// the pool holds by then: each is accepted while the live curve can still afford it and pays
// exactly its fixed terms, and one it cannot afford is refused without moving anything, then
// settles as it stands once the price comes back.
#[test]
async fn offers_prepared_at_one_price_settle_against_the_live_pool() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let holding_lp = new_account(&mut ctx, false, None).await?;
    let pool = PoolFixture::create_tokens(&mut ctx, SUPPLY).await?;
    let PoolFixture {
        holding_a,
        holding_b,
        definition_a,
        definition_b,
        ..
    } = pool;

    let (created_pool, created) = Amm(ctx.wallet())
        .send_new_pool(
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            AccountIdentity::Public(holding_lp),
            1_000,
            1_000,
        )
        .await?;
    assert_eq!(
        created_pool, pool.pool_id,
        "the wallet creates the derived pool"
    );
    wait_for_inclusion(&ctx, created).await?;
    assert_pool(&ctx, "created", &pool, 1_000, 1_000).await?;

    // Distinct traders, each with its own private note: the only contention is the pool's.
    let mut traders = Vec::new();
    for _ in 0..4 {
        traders.push(fund_trader(&mut ctx, holding_a).await?);
    }

    // All three offers are proven and recorded before the first settles.
    let mut prepared = Vec::new();
    for (trader, seed) in traders.iter().take(3).zip(1..) {
        prepared.push(prepare_offer(&ctx, &pool, trader, seed).await?);
    }
    assert_pool(&ctx, "prepared", &pool, 1_000, 1_000).await?;

    // Quotes 1000 * 100 / 1100 = 90, then 925 * 100 / 1200 = 77; each offer pays exactly 75.
    settle(&ctx, &pool, "first offer", &prepared[0], 1_100, 925).await?;
    settle(&ctx, &pool, "second offer", &prepared[1], 1_200, 850).await?;

    // 850 * 100 / 1300 = 65 < 75: the pool cannot afford the third offer, so it is dropped rather
    // than included.
    let refused = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::PrivacyPreserving(prepared[2].clone()))
        .await?;
    let submitted_at = ctx.sequencer_client().get_last_block_id().await?;
    wait_until("two more blocks", || async {
        Ok(ctx.sequencer_client().get_last_block_id().await? >= submitted_at.saturating_add(2))
    })
    .await?;
    assert!(
        ctx.sequencer_client()
            .get_transaction(refused)
            .await?
            .is_none(),
        "an unaffordable offer must not be included"
    );
    assert_pool(&ctx, "refused", &pool, 1_200, 850).await?;

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
    assert_pool(&ctx, "moved", &pool, 900, 1_250).await?;

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
    assert_pool(&ctx, "favoured", &pool, 1_100, 1_100).await?;

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
