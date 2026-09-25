#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use amm_core::Instruction;
use anyhow::Result;
use integration_tests::{
    TestContext, account_balance,
    amm::{PoolFixture, amm_program_id, assert_holdings, assert_pool_record, token_program_id},
    get_account, new_account, public_mention, send, wait_for_inclusion, wait_until,
};
use lee::{AccountId, program::Program};
use tokio::test;
use wallet::{
    AccountIdentity,
    program_facades::{amm::Amm, token::Token},
};

const SUPPLY: u128 = 10_000;
const FEE_FUNDS: u128 = 1_000_000_000_000;
const DONATION: u128 = 500;

async fn nonce(ctx: &TestContext, account_id: AccountId) -> Result<u128> {
    Ok(get_account(ctx, account_id).await?.nonce.0)
}

#[test]
async fn a_pool_round_trips_through_the_wallet_and_rejects_an_unaffordable_offer() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let funder = ctx.existing_public_accounts()[0];
    let holding_lp = new_account(&mut ctx, false, None).await?;
    // Accounts that are neither traders nor liquidity providers of this pool.
    let underfunded = new_account(&mut ctx, false, None).await?;
    let receiver = new_account(&mut ctx, false, None).await?;
    let donor = new_account(&mut ctx, false, None).await?;

    // Each of these signs alone somewhere below, so it pays that fee itself.
    for funded in [holding_lp, underfunded, donor] {
        send(
            &mut ctx,
            public_mention(funder),
            public_mention(funded),
            FEE_FUNDS,
        )
        .await?;
        wait_until("the fee funds to land", || async {
            Ok(account_balance(&ctx, funded).await? == FEE_FUNDS)
        })
        .await?;
    }
    let PoolFixture {
        holding_a,
        holding_b,
        definition_a,
        definition_b,
        pool_id,
        vault_a,
        vault_b,
        lp_definition,
    } = PoolFixture::create_tokens(&mut ctx, SUPPLY).await?;

    let amm = Amm(ctx.wallet());
    let token = Token(ctx.wallet());
    // Vault A holds its reserve plus whatever was donated to it; vault B holds exactly its
    // reserve, and the LP holding is the only one.
    let check = async |step: &str,
                       (a, b, lp): (u128, u128, u128),
                       (user_a, user_b): (u128, u128),
                       donated_a: u128| {
        assert_pool_record(&ctx, step, pool_id, (a, b, lp)).await?;
        assert_holdings(
            &ctx,
            step,
            &[
                (vault_a, definition_a, a + donated_a),
                (vault_b, definition_b, b),
                (holding_lp, lp_definition, lp),
                (holding_a, definition_a, user_a),
                (holding_b, definition_b, user_b),
            ],
        )
        .await
    };

    // A creation naming tokens A and B but funding each side from the other token's holding. The
    // AMM does not inspect the funding holdings; the token transfer child refuses the mismatch, so
    // the creation reverts while staying included and charged.
    let signers = [holding_a, holding_b, holding_lp];
    let mut nonces_before = Vec::new();
    for signer in signers {
        nonces_before.push(nonce(&ctx, signer).await?);
    }
    let mismatched = ctx
        .wallet()
        .send_pub_tx(
            vec![
                AccountIdentity::PublicNoSign(pool_id).select_program_shard(amm_program_id()),
                AccountIdentity::PublicNoSign(vault_a).select_program_shard(token_program_id()),
                AccountIdentity::PublicNoSign(vault_b).select_program_shard(token_program_id()),
                AccountIdentity::PublicNoSign(lp_definition)
                    .select_program_shard(token_program_id()),
                AccountIdentity::Public(holding_b).select_program_shard(token_program_id()),
                AccountIdentity::Public(holding_a).select_program_shard(token_program_id()),
                AccountIdentity::Public(holding_lp).select_program_shard(token_program_id()),
            ],
            Program::serialize_instruction(Instruction::NewDefinition {
                token_a_amount: 1_000,
                token_b_amount: 500,
                token_program_id: token_program_id(),
                definition_token_a_id: definition_a,
                definition_token_b_id: definition_b,
                pool_is_empty: true,
            })?,
            amm_program_id(),
        )
        .await?;
    wait_for_inclusion(&ctx, mismatched).await?;
    for (account_id, program_id) in [
        (pool_id, amm_program_id()),
        (vault_a, token_program_id()),
        (vault_b, token_program_id()),
        (lp_definition, token_program_id()),
        (holding_lp, token_program_id()),
    ] {
        assert!(
            get_account(&ctx, account_id)
                .await?
                .data
                .shard(program_id)
                .is_empty(),
            "mismatched: {account_id} gained no state"
        );
    }
    assert_holdings(
        &ctx,
        "mismatched",
        &[
            (holding_a, definition_a, SUPPLY),
            (holding_b, definition_b, SUPPLY),
        ],
    )
    .await?;
    for (signer, before) in signers.into_iter().zip(nonces_before) {
        assert_eq!(
            nonce(&ctx, signer).await?,
            before + 1,
            "mismatched: the creation was included and charged, not dropped"
        );
    }

    let (created_pool, created) = amm
        .send_new_pool(
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            AccountIdentity::Public(holding_lp),
            1_000,
            500,
        )
        .await?;
    assert_eq!(created_pool, pool_id, "the wallet creates the derived pool");
    wait_for_inclusion(&ctx, created).await?;
    // isqrt(1000 * 500) = 707 of LP.
    check("created", (1_000, 500, 707), (9_000, 9_500), 0).await?;

    // Up to 100 of each deposits 100 of A and 50 of B, minting 707 * 100 / 1000 = 70.
    let added = amm
        .send_add_liquidity(
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            AccountIdentity::Public(holding_lp),
            70,
            100,
            100,
        )
        .await?;
    wait_for_inclusion(&ctx, added).await?;
    check("added", (1_100, 550, 777), (8_900, 9_450), 0).await?;

    // 100 of A into 1100/550 quotes 550 * 100 / 1200 = 45 of B. The offer asks for 40, so it pays
    // exactly 40 and the pool keeps the other 5.
    let (sold_a, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            100,
            40,
        )
        .await?;
    wait_for_inclusion(&ctx, sold_a).await?;
    check("sold A", (1_200, 510, 777), (8_800, 9_490), 0).await?;

    // The reverse direction: 30 of B into 510/1200 quotes 1200 * 30 / 540 = 66 of A; the offer
    // takes 60.
    let (sold_b, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(holding_b),
            AccountIdentity::Public(holding_a),
            30,
            60,
        )
        .await?;
    wait_for_inclusion(&ctx, sold_b).await?;
    check("sold B", (1_140, 540, 777), (8_860, 9_460), 0).await?;

    // Burning 70 of 777 withdraws 1140 * 70 / 777 = 102 of A and 540 * 70 / 777 = 48 of B.
    let removed = amm
        .send_remove_liquidity(
            holding_a,
            holding_b,
            AccountIdentity::Public(holding_lp),
            70,
            102,
            48,
        )
        .await?;
    wait_for_inclusion(&ctx, removed).await?;
    check("removed", (1_038, 492, 707), (8_962, 9_508), 0).await?;

    // 100 of A into 1038/492 quotes 492 * 100 / 1138 = 43 of B, so an offer for 44 cannot be
    // afforded. The wallet builds it anyway: the pool decides at execution, where the charged
    // action reverts but stays included, keeping its fee and nonce and none of its effects.
    let (refused, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            100,
            44,
        )
        .await?;
    wait_for_inclusion(&ctx, refused).await?;
    check("refused", (1_038, 492, 707), (8_962, 9_508), 0).await?;

    for (recipient, amount) in [(underfunded, 10), (donor, DONATION)] {
        let funded = token
            .send_transfer_transaction(
                AccountIdentity::Public(holding_a),
                AccountIdentity::PublicNoSign(recipient),
                amount,
            )
            .await?;
        wait_for_inclusion(&ctx, funded).await?;
    }
    check("funded", (1_038, 492, 707), (8_452, 9_508), 0).await?;

    let underfunded_nonce = nonce(&ctx, underfunded).await?;
    let (unfunded, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(underfunded),
            AccountIdentity::Public(receiver),
            100,
            1,
        )
        .await?;
    wait_for_inclusion(&ctx, unfunded).await?;
    check("unfunded", (1_038, 492, 707), (8_452, 9_508), 0).await?;
    assert_holdings(&ctx, "unfunded", &[(underfunded, definition_a, 10)]).await?;
    assert!(
        get_account(&ctx, receiver)
            .await?
            .data
            .shard(token_program_id())
            .is_empty(),
        "unfunded: the reverted swap paid nothing out"
    );
    assert_eq!(
        nonce(&ctx, underfunded).await?,
        underfunded_nonce + 1,
        "unfunded: the swap was included and charged, not dropped"
    );

    let payer_nonce = nonce(&ctx, holding_a).await?;
    let (misdirected, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(underfunded),
            100,
            10,
        )
        .await?;
    wait_for_inclusion(&ctx, misdirected).await?;
    check("misdirected", (1_038, 492, 707), (8_452, 9_508), 0).await?;
    assert_holdings(&ctx, "misdirected", &[(underfunded, definition_a, 10)]).await?;
    assert_eq!(
        nonce(&ctx, holding_a).await?,
        payer_nonce + 1,
        "misdirected: the swap was included and charged, not dropped"
    );

    // A plain token transfer into vault A raises its balance but not the reserve the pool
    // accounts for.
    let donated = token
        .send_transfer_transaction(
            AccountIdentity::Public(donor),
            AccountIdentity::PublicNoSign(vault_a),
            DONATION,
        )
        .await?;
    wait_for_inclusion(&ctx, donated).await?;
    check("donated", (1_038, 492, 707), (8_452, 9_508), DONATION).await?;

    // Priced off the accounted 1038 of A, 100 more buys 43 of B; priced off the vault's 1538 it
    // would buy only 492 * 100 / 1638 = 30. The offer for exactly 43 settles, and the donation
    // stays in vault A outside the reserve.
    let (after_donation, _) = amm
        .send_swap(
            pool_id,
            AccountIdentity::Public(holding_a),
            AccountIdentity::Public(holding_b),
            100,
            43,
        )
        .await?;
    wait_for_inclusion(&ctx, after_donation).await?;
    check(
        "after donation",
        (1_138, 449, 707),
        (8_352, 9_551),
        DONATION,
    )
    .await?;

    Ok(())
}
