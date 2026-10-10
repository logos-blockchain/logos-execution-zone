#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::collections::BTreeSet;

use anyhow::Result;
use integration_tests::{
    TestContext,
    amm::{PoolFixture, Trader, fungible, private_holding, token_program_id},
    sync_private, wait_for_inclusion,
};
use lee::{
    AccountId, Publication,
    error::{InvalidProgramBehaviorError, LeeError},
    privacy_preserving_transaction::circuit::ProgramCatalog,
    program::Program,
};
use lee_core::execution_state::ExecutionError;
use token_core::TokenHolding;
use tokio::test;
use wallet::{
    AccountIdentity, CastDelivery, CastPromotions, ExecutionFailureKind,
    program_facades::{CreditDelivery, token::Token},
};

const SUPPLY: u128 = 10_000;
const AMOUNT: u128 = 100;

// A private holder's token Cast to a private account leaves its proof sealed. The recipient's
// keys find it, the recipient receives it privately, and the wallet then lists it no more.
#[test]
async fn a_private_token_cast_is_sealed_and_received_by_its_recipient() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let PoolFixture {
        holding_a,
        definition_a,
        ..
    } = PoolFixture::create_tokens(&mut ctx, SUPPLY).await?;
    let trader = Trader::fund(&mut ctx, holding_a, AMOUNT).await?;

    let (sent, _) = Token(ctx.wallet())
        .transfer(
            AccountIdentity::PrivateOwned(trader.input),
            AccountIdentity::PrivateOwned(trader.output),
            AMOUNT,
            CreditDelivery::DeferredPrivate,
        )
        .await?;
    wait_for_inclusion(&ctx, sent).await?;

    assert_eq!(
        ctx.wallet().get_recovery_binding(trader.output).await?,
        None,
        "a sealed Cast binds nothing"
    );
    receive_sealed_transfer(&mut ctx, trader.output, definition_a).await
}

// A Cast back to the holder's own account, which the transaction witnesses, executes at once
// unless the selection lists only other candidates: then it is sealed for the holder to receive.
#[test]
async fn a_cast_to_a_witnessed_account_is_sealed_when_the_selection_lists_only_others() -> Result<()>
{
    let mut ctx = TestContext::new().await?;
    let PoolFixture {
        holding_a,
        definition_a,
        ..
    } = PoolFixture::create_tokens(&mut ctx, SUPPLY).await?;
    let trader = Trader::fund(&mut ctx, holding_a, AMOUNT).await?;
    let holder =
        AccountIdentity::PrivateOwned(trader.input).select_program_actor_state(token_program_id());
    let (_, casts) = ctx.wallet().seal_destination(holder.clone())?;

    let (sent, _) = ctx
        .wallet()
        .send_tx(
            vec![holder],
            0,
            Program::serialize_message(token_core::Message::Transfer {
                to: trader.input,
                descriptor: fungible(definition_a),
                amount: AMOUNT,
                notify: None,
            })?,
            &ProgramCatalog::from([(token_program_id(), programs::token())]),
            None,
            CastDelivery {
                promotions: CastPromotions {
                    listed_only: true,
                    ..CastPromotions::default()
                },
                ..casts
            },
        )
        .await?;
    wait_for_inclusion(&ctx, sent).await?;
    sync_private(&mut ctx).await?;

    assert_eq!(
        private_holding(&ctx, trader.input)?,
        TokenHolding::Fungible {
            definition_id: definition_a,
            balance: 0,
        },
        "the deferred credit has not reached the holder yet"
    );
    receive_sealed_transfer(&mut ctx, trader.input, definition_a).await
}

// An all-public send emits no private candidate, so a private selection on it is refused before
// anything is submitted.
#[test]
async fn a_private_selection_on_an_all_public_send_is_refused() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let PoolFixture {
        holding_a,
        definition_a,
        ..
    } = PoolFixture::create_tokens(&mut ctx, SUPPLY).await?;

    let Err(refusal) = ctx
        .wallet()
        .send_tx(
            vec![AccountIdentity::Public(holding_a).select_program_actor_state(token_program_id())],
            0,
            Program::serialize_message(token_core::Message::Transfer {
                to: holding_a,
                descriptor: fungible(definition_a),
                amount: AMOUNT,
                notify: None,
            })?,
            &ProgramCatalog::from([(token_program_id(), programs::token())]),
            None,
            CastDelivery {
                promotions: CastPromotions {
                    private: BTreeSet::from([0]),
                    ..CastPromotions::default()
                },
                ..CastDelivery::default()
            },
        )
        .await
    else {
        anyhow::bail!("a private selection on an all-public send must be refused");
    };

    assert!(matches!(
        refusal,
        ExecutionFailureKind::TransactionBuildError(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::Execution(ExecutionError::UnreachedCastPromotion {
                index: 0
            })
        ))
    ));
    Ok(())
}

// Receives the one transfer pending for the wallet, sealed to `to`, which then holds `AMOUNT`.
async fn receive_sealed_transfer(
    ctx: &mut TestContext,
    to: AccountId,
    definition_id: AccountId,
) -> Result<()> {
    let [pending] = <[_; 1]>::try_from(ctx.wallet_mut().owned_pending_messages().await?)
        .map_err(|pending| anyhow::anyhow!("expected one transfer, found {}", pending.len()))?;
    anyhow::ensure!(
        matches!(pending.publication, Publication::Sealed(_)),
        "a private holder's Cast to a private account is sealed"
    );
    assert_eq!(
        (pending.body.to.account_id, pending.recipient.account_id()),
        (to, to)
    );

    let (received, _) = ctx.wallet_mut().receive_pending_message(pending).await?;
    wait_for_inclusion(ctx, received).await?;
    sync_private(ctx).await?;

    assert_eq!(
        private_holding(ctx, to)?,
        TokenHolding::Fungible {
            definition_id,
            balance: AMOUNT,
        }
    );
    assert!(
        ctx.wallet_mut().owned_pending_messages().await?.is_empty(),
        "receiving spends the sealed transfer"
    );
    Ok(())
}
