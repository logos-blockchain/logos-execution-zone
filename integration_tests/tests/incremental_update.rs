#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, new_account};
use lee::{privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program};
use tokio::test;
use wallet::AccountIdentity;

#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
    Transfer { amount: u128 },
}

#[derive(borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

/// End-to-end proof that `Incremental`/`Deferred` settlement works through the real wallet →
/// sequencer → settlement pipeline, not just in-process against a synthetic `V03State`.
///
/// Two *different* senders each transfer into the *same* shared receiver, submitted back-to-back
/// with no wait between them, so both are proven against the same pre-transfer receiver balance —
/// as if neither knew the other existed. The receiver is `PublicNoSign`: it never signs and so
/// never has a nonce to collide on, unlike the senders (each constrained only by their own,
/// independent nonce — a same-signer nonce collision would be ordinary replay protection working
/// as intended, not something `Deferred` claims to solve). Both credits must land, proving the
/// receiver's balance resolves against live state at settlement rather than one transfer's stale
/// view clobbering the other's.
#[test]
async fn concurrent_private_transfers_settle_against_live_state() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer_id = ctx.existing_public_accounts()[0];

    let program = test_programs::stripped_token();
    let header_id = new_account(&mut ctx, false, None).await?;
    let mut segment_ids = Vec::new();
    for _ in program
        .user_elf()
        .expect("valid ProgramBinary")
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }
    let program_account_id = wallet::program_facades::program_loader::ProgramLoader(ctx.wallet())
        .deploy(
            header_id,
            &segment_ids,
            program.elf().to_vec(),
            true,
            Some(payer_id),
        )
        .await?;

    let sender_1_id = new_account(&mut ctx, false, None).await?;
    let sender_2_id = new_account(&mut ctx, false, None).await?;
    let receiver_id = new_account(&mut ctx, false, None).await?;

    // Seed both senders via plain public transactions — cheaper than proving a
    // privacy-preserving one for a step that isn't what this test is about. Both co-sign with
    // the same `payer_id`, so each must settle (bumping the payer's nonce) before the next is
    // built, or the second races the first's stale payer nonce and never lands.
    for sender_id in [sender_1_id, sender_2_id] {
        ctx.wallet()
            .send_pub_tx_paid_by(
                vec![AccountIdentity::Public(sender_id)],
                Program::serialize_instruction(StrippedTokenInstruction::Initialize {
                    balance: 60,
                })
                .expect("instruction serializes"),
                program_account_id,
                Some(payer_id),
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    }

    let program_with_dependencies =
        ProgramWithDependencies::new(program, program_account_id, HashMap::new());

    for (sender_id, amount) in [(sender_1_id, 30_u128), (sender_2_id, 20)] {
        ctx.wallet()
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::Public(sender_id),
                    AccountIdentity::PublicNoSign(receiver_id),
                ],
                Program::serialize_instruction(StrippedTokenInstruction::Transfer { amount })
                    .expect("instruction serializes"),
                &program_with_dependencies,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let sender_1_final = get_account(&ctx, sender_1_id).await?;
    let sender_2_final = get_account(&ctx, sender_2_id).await?;
    let receiver_final = get_account(&ctx, receiver_id).await?;

    let sender_1_balance: TokenAccountData = borsh::from_slice(sender_1_final.data.as_ref())
        .expect("sender_1 data must decode as TokenAccountData");
    let sender_2_balance: TokenAccountData = borsh::from_slice(sender_2_final.data.as_ref())
        .expect("sender_2 data must decode as TokenAccountData");
    let receiver_balance: TokenAccountData = borsh::from_slice(receiver_final.data.as_ref())
        .expect("receiver data must decode as TokenAccountData");

    assert_eq!(sender_1_balance.balance, 30, "sender_1 must reflect its own debit (60 - 30)");
    assert_eq!(sender_2_balance.balance, 40, "sender_2 must reflect its own debit (60 - 20)");
    assert_eq!(
        receiver_balance.balance, 50,
        "receiver must reflect both deferred credits (30 + 20), not just whichever transfer \
         settled last"
    );

    Ok(())
}
