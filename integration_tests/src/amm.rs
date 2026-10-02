use amm_core::{
    PoolDefinition, SwapRequest, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda,
    swap_transfer,
};
use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use lee::{
    AccountId, Actor, PrivacyPreservingTransaction, ProvingInput, PublicCallAssumptions,
    PublicExecutionContext, execute_and_prove_assuming,
    privacy_preserving_transaction::{
        circuit::ProgramCatalog, message::Message, witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    CommitmentSetDigest, NullifierWitness, PrivateWitness, WitnessKind,
    execution_state::TransactionEntry,
};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    TestContext, fetch_privacy_preserving_tx, private_mention, public_mention,
    verify_commitment_is_in_state,
};
use token_core::{TokenDescriptor, TokenHolding, TokenKind};
use wallet::{AccountIdentity, program_facades::amm::Amm};

use crate::{
    create_token, get_account, new_account, restored_private_account, token_send,
    wait_for_inclusion, wait_until,
};

/// The reserve of each token a pool opened by [`PoolFixture::open`] starts with, which is also the
/// LP supply the opening mints.
const OPENING_RESERVE: u128 = 1_000;

/// Two fresh tokens, A and B, whose whole supply sits in the context's first two public accounts,
/// and the accounts of the pool they form under the built-in token program.
pub struct PoolFixture {
    pub holding_a: AccountId,
    pub holding_b: AccountId,
    pub definition_a: AccountId,
    pub definition_b: AccountId,
    pub pool_id: AccountId,
    pub vault_a: AccountId,
    pub vault_b: AccountId,
    pub lp_definition: AccountId,
}

impl PoolFixture {
    /// Creates tokens A and B with `supply` each and waits until both supplies land.
    pub async fn create_tokens(ctx: &mut TestContext, supply: u128) -> Result<Self> {
        let holding_a = ctx.existing_public_accounts()[0];
        let holding_b = ctx.existing_public_accounts()[1];
        let definition_a = new_account(ctx, false, None).await?;
        let definition_b = new_account(ctx, false, None).await?;
        create_token(
            ctx,
            public_mention(definition_a),
            public_mention(holding_a),
            "A",
            supply,
        )
        .await?;
        create_token(
            ctx,
            public_mention(definition_b),
            public_mention(holding_b),
            "B",
            supply,
        )
        .await?;
        let reader: &TestContext = ctx;
        for (holding_id, definition_id) in [(holding_a, definition_a), (holding_b, definition_b)] {
            wait_until("the token supply to land", || async {
                Ok(token_holding(reader, holding_id).await.ok()
                    == Some(TokenHolding::Fungible {
                        definition_id,
                        balance: supply,
                    }))
            })
            .await?;
        }

        let pool_id = compute_pool_pda(
            amm_program_id(),
            definition_a,
            definition_b,
            token_program_id(),
        );
        Ok(Self {
            holding_a,
            holding_b,
            definition_a,
            definition_b,
            pool_id,
            vault_a: compute_vault_pda(amm_program_id(), pool_id, definition_a),
            vault_b: compute_vault_pda(amm_program_id(), pool_id, definition_b),
            lp_definition: compute_liquidity_token_pda(amm_program_id(), pool_id),
        })
    }

    /// Creates tokens A and B with `supply` each and opens their pool through the wallet at
    /// 1,000/1,000, minting the LP tokens to a fresh public account.
    pub async fn open(ctx: &mut TestContext, supply: u128) -> Result<Self> {
        let holding_lp = new_account(ctx, false, None).await?;
        let pool = Self::create_tokens(ctx, supply).await?;
        let (created_pool, created, _) = Amm(ctx.wallet())
            .send_new_pool(
                AccountIdentity::Public(pool.holding_a),
                AccountIdentity::Public(pool.holding_b),
                AccountIdentity::Public(holding_lp),
                OPENING_RESERVE,
                OPENING_RESERVE,
            )
            .await?;
        assert_eq!(
            created_pool, pool.pool_id,
            "the wallet creates the derived pool"
        );
        wait_for_inclusion(ctx, created).await?;
        assert_pool_and_vaults(ctx, "created", &pool, OPENING_RESERVE, OPENING_RESERVE).await?;
        Ok(pool)
    }
}

/// A trader's private input note, which pays into vault A, and the private account its payout goes
/// to.
pub struct Trader {
    pub input: AccountId,
    pub output: AccountId,
}

impl Trader {
    /// Opens both private accounts and funds the input note with `amount` from `from`, waiting
    /// until the note is committed.
    pub async fn fund(ctx: &mut TestContext, from: AccountId, amount: u128) -> Result<Self> {
        let input = new_account(ctx, true, None).await?;
        let output = new_account(ctx, true, None).await?;
        token_send(ctx, public_mention(from), private_mention(input), amount).await?;
        let commitment = ctx
            .wallet()
            .get_private_account_commitment(input)
            .context("the funded note is unknown to the wallet")?;
        wait_until("the trader's note to be committed", || async {
            Ok(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await)
        })
        .await?;
        Ok(Self { input, output })
    }
}

/// The built-in token program's account.
#[must_use]
pub fn token_program_id() -> AccountId {
    programs::token_account_id()
}

/// The built-in AMM program's account.
#[must_use]
pub fn amm_program_id() -> AccountId {
    programs::amm_account_id()
}

/// A public account's token holding.
pub async fn token_holding(ctx: &TestContext, account_id: AccountId) -> Result<TokenHolding> {
    let account = get_account(ctx, account_id).await?;
    Ok(TokenHolding::try_from(
        account.data.shard(token_program_id()),
    )?)
}

/// Asserts each public holding is fungible, of the given definition and exactly the given balance.
pub async fn assert_holdings(
    ctx: &TestContext,
    step: &str,
    expected: &[(AccountId, AccountId, u128)],
) -> Result<()> {
    for &(holding_id, definition_id, balance) in expected {
        assert_eq!(
            token_holding(ctx, holding_id).await?,
            TokenHolding::Fungible {
                definition_id,
                balance
            },
            "{step}: holding {holding_id}"
        );
    }
    Ok(())
}

/// Asserts the pool is active and records exactly these reserves and LP supply.
pub async fn assert_pool_record(
    ctx: &TestContext,
    step: &str,
    pool_id: AccountId,
    (reserve_a, reserve_b, supply): (u128, u128, u128),
) -> Result<()> {
    let account = get_account(ctx, pool_id).await?;
    let pool = PoolDefinition::try_from(account.data.shard(amm_program_id()))?;
    assert!(pool.active, "{step}: the pool is inactive");
    assert_eq!(
        (pool.reserve_a, pool.reserve_b, pool.liquidity_pool_supply),
        (reserve_a, reserve_b, supply),
        "{step}: pool reserves and LP supply"
    );
    Ok(())
}

/// A fungible token of this definition.
#[must_use]
pub const fn fungible(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

/// A restored private account's token holding.
pub fn private_holding(ctx: &TestContext, account_id: AccountId) -> Result<TokenHolding> {
    let account = restored_private_account(ctx, account_id, "trader account").account;
    Ok(TokenHolding::try_from(
        account.data.shard(token_program_id()),
    )?)
}

/// Asserts a pool opened by [`PoolFixture::open`] records these reserves and its opening LP supply,
/// and that its vaults back them exactly, since nothing else credits them.
pub async fn assert_pool_and_vaults(
    ctx: &TestContext,
    step: &str,
    pool: &PoolFixture,
    reserve_a: u128,
    reserve_b: u128,
) -> Result<()> {
    assert_pool_record(
        ctx,
        step,
        pool.pool_id,
        (reserve_a, reserve_b, OPENING_RESERVE),
    )
    .await?;
    assert_holdings(
        ctx,
        step,
        &[
            (pool.vault_a, pool.definition_a, reserve_a),
            (pool.vault_b, pool.definition_b, reserve_b),
        ],
    )
    .await
}

/// The witness spending the trader's input note, and the commitment root its membership proof is
/// against.
pub async fn spend_input(
    ctx: &TestContext,
    trader: &Trader,
    seed: u8,
) -> Result<(PrivateWitness, CommitmentSetDigest)> {
    let spent = restored_private_account(ctx, trader.input, "trader input");
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
    Ok((
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
        root,
    ))
}

/// Proves the trader's input note paying `amount_in` into vault A with this swap request, against
/// no public state.
pub fn prove_swap(
    pool: &PoolFixture,
    trader: &Trader,
    amount_in: u128,
    request: SwapRequest,
    private_witnesses: Vec<PrivateWitness>,
    assumptions: Vec<PublicCallAssumptions>,
) -> Result<PrivacyPreservingTransaction> {
    let pool_actor = Actor::new(pool.pool_id, amm_program_id());
    let (output, proof) = execute_and_prove_assuming(
        ProvingInput {
            root: TransactionEntry::Call {
                to: Actor::new(trader.input, token_program_id()),
                message: Program::serialize_message(swap_transfer(
                    pool_actor,
                    pool.vault_a,
                    fungible(pool.definition_a),
                    amount_in,
                    request,
                ))?,
            },
            context: PublicExecutionContext::new(
                vec![
                    pool_actor,
                    Actor::new(pool.vault_a, token_program_id()),
                    Actor::new(pool.vault_b, token_program_id()),
                ],
                [],
            ),
            private_witnesses,
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
        },
        assumptions,
        &ProgramCatalog::from([
            (amm_program_id(), programs::amm()),
            (token_program_id(), programs::token()),
        ]),
    )?;
    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    Ok(PrivacyPreservingTransaction::new(message, witness_set))
}

/// Submits a prepared transaction unchanged and requires exactly it to settle, leaving the pool at
/// these reserves.
pub async fn settle(
    ctx: &TestContext,
    pool: &PoolFixture,
    step: &str,
    tx: &PrivacyPreservingTransaction,
    reserve_a: u128,
    reserve_b: u128,
) -> Result<()> {
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx.clone()))
        .await?;
    wait_for_inclusion(ctx, tx_hash).await?;
    assert_eq!(
        fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await,
        *tx,
        "{step}: the settled transaction is the one prepared"
    );
    assert_pool_and_vaults(ctx, step, pool, reserve_a, reserve_b).await
}

/// Submits a prepared transaction and requires it to be dropped rather than included, leaving the
/// pool at these reserves.
pub async fn assert_dropped(
    ctx: &TestContext,
    pool: &PoolFixture,
    step: &str,
    tx: &PrivacyPreservingTransaction,
    reserve_a: u128,
    reserve_b: u128,
) -> Result<()> {
    let dropped = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx.clone()))
        .await?;
    let submitted_at = ctx.sequencer_client().get_last_block_id().await?;
    wait_until("two more blocks", || async {
        Ok(ctx.sequencer_client().get_last_block_id().await? >= submitted_at.saturating_add(2))
    })
    .await?;
    assert!(
        ctx.sequencer_client()
            .get_transaction(dropped)
            .await?
            .is_none(),
        "{step}: the transaction must not be included"
    );
    assert_pool_and_vaults(ctx, step, pool, reserve_a, reserve_b).await
}
