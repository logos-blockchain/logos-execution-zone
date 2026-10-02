#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use amm_core::{ExactInput, SwapRequest, swap_transfer};
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
    AccountId, Actor, PrivacyPreservingTransaction, ProvingInput, PublicExecutionContext,
    execute_and_prove_assuming,
    privacy_preserving_transaction::{
        circuit::ProgramCatalog, message::Message, witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{NullifierWitness, PrivateWitness, WitnessKind, execution_state::TransactionEntry};
use sequencer_service_rpc::RpcClient as _;
use token_core::{Delivery, TokenDescriptor, TokenHolding, TokenKind};
use tokio::test;
use wallet::{AccountIdentity, program_facades::amm::Amm};

const SUPPLY: u128 = 10_000;
const AMOUNT_IN: u128 = 100;
// The trader's input note pays into vault A and notifies the pool with the exact input; the payout
// is cast to the output account, which receives it later.
struct Trader {
    input: AccountId,
    output: AccountId,
}

const fn fungible(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

fn swap_message(pool: &PoolFixture, trader: &Trader, min_amount_out: u128) -> Result<Vec<u8>> {
    Ok(Program::serialize_message(swap_transfer(
        Actor::new(pool.pool_id, amm_program_id()),
        pool.vault_a,
        fungible(pool.definition_a),
        AMOUNT_IN,
        SwapRequest::ExactInput(ExactInput {
            definition_id_out: pool.definition_b,
            min_amount_out,
            payout: trader.output,
            delivery: Delivery::Cast,
        }),
    ))?)
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
    let spent = restored_private_account(ctx, trader.input, "trader input");
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(trader.input)
        .context("the trader's input note is unknown to the wallet")?;
    let (proofs, _) = ctx.wallet().get_proofs_and_root(&[commitment]).await?;
    let membership_proof = proofs
        .into_iter()
        .next()
        .flatten()
        .context("the trader's input note is not on chain")?;
    let spent_keys = &spent.key_chain.private_key_holder;

    let (output, proof) = execute_and_prove_assuming(
        ProvingInput {
            root: TransactionEntry::Call {
                to: Actor::new(trader.input, token_program_id()),
                message: swap_message(pool, trader, min_amount_out)?,
            },
            context: PublicExecutionContext::new(
                vec![
                    Actor::new(pool.pool_id, amm_program_id()),
                    Actor::new(pool.vault_a, token_program_id()),
                    Actor::new(pool.vault_b, token_program_id()),
                ],
                [],
            ),
            private_witnesses: vec![PrivateWitness {
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
            }],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
        },
        vec![Vec::new()],
        &ProgramCatalog::from([
            (amm_program_id(), programs::amm()),
            (token_program_id(), programs::token()),
        ]),
    )?;
    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    Ok(PrivacyPreservingTransaction::new(message, witness_set))
}

// Submits a prepared swap unchanged and requires exactly it to settle, leaving the pool at these
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
    token_send(ctx, public_mention(from), private_mention(input), AMOUNT_IN).await?;
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

// Exact-input swaps prepared while the pool sits at 1,000/1,000 settle later, unchanged, each for
// whatever the live curve quotes as long as that meets its minimum, and cast that quote to the
// trader as a pending token credit the trader receives privately afterwards. One whose minimum the
// live quote misses is refused without moving anything.
#[test]
async fn exact_inputs_prepared_at_one_price_settle_at_the_live_quote_and_cast_the_payout()
-> Result<()> {
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

    let (created_pool, created, _) = Amm(ctx.wallet())
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

    let mut traders = Vec::new();
    for _ in 0..3 {
        traders.push(fund_trader(&mut ctx, holding_a).await?);
    }

    // All three swaps are proven and recorded before the first settles; the second accepts less.
    let mut prepared = Vec::new();
    for ((trader, min_amount_out), seed) in traders.iter().zip([80, 70, 80]).zip(1..) {
        prepared.push(prepare_swap(&ctx, &pool, trader, min_amount_out, seed).await?);
    }
    assert_pool(&ctx, "prepared", &pool, 1_000, 1_000).await?;

    // Quotes 1000 * 100 / 1100 = 90 >= 80, then 910 * 100 / 1200 = 75 >= 70: the same kind of
    // prepared input settles at a different, still acceptable, live quote.
    settle(&ctx, &pool, "first swap", &prepared[0], 1_100, 910).await?;
    settle(&ctx, &pool, "second swap", &prepared[1], 1_200, 835).await?;

    // 835 * 100 / 1300 = 64 < 80: the live quote misses the third swap's minimum, so it is dropped
    // rather than included.
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
        "a swap whose minimum the live quote misses must not be included"
    );
    assert_pool(&ctx, "refused", &pool, 1_200, 835).await?;

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
