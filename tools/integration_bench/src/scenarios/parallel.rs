//! Parallel-fanout throughput scenario. N distinct senders each transfer one token
//! to one recipient. Submission is serialised through the single wallet but does
//! not wait for chain advance between submits, so all N txs land in the same
//! block (up to `max_num_tx_in_block`). Measures observed throughput.

use std::time::Instant;

use anyhow::{Result, bail};
use common::transaction::NSSATransaction;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{TestContext, public_mention};
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::token::TokenProgramAgnosticSubcommand,
};

use crate::harness::{BlockSize, ScenarioOutput, StepResult};

const PARALLEL_FANOUT_N: usize = 10;
const AMOUNT_PER_TRANSFER: u128 = 100;

pub async fn run(ctx: &mut TestContext) -> Result<ScenarioOutput> {
    let mut output = ScenarioOutput::new("parallel_fanout");

    // Setup: definition, master supply, N parallel supplies, N recipients.
    let def_id = new_public_account(ctx, &mut output, "create_acc_def").await?;
    let master_id = new_public_account(ctx, &mut output, "create_acc_master").await?;

    let mut senders = Vec::with_capacity(PARALLEL_FANOUT_N);
    for i in 0..PARALLEL_FANOUT_N {
        let id = new_public_account(ctx, &mut output, &format!("create_sender_{i:02}")).await?;
        senders.push(id);
    }
    let mut recipients = Vec::with_capacity(PARALLEL_FANOUT_N);
    for i in 0..PARALLEL_FANOUT_N {
        let id = new_public_account(ctx, &mut output, &format!("create_recipient_{i:02}")).await?;
        recipients.push(id);
    }

    // Mint full supply into master.
    let total_mint = u128::try_from(PARALLEL_FANOUT_N)
        .expect("usize fits u128")
        .saturating_mul(AMOUNT_PER_TRANSFER)
        .saturating_mul(10);
    output
        .step(ctx, "token_new_fungible", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::New {
                    definition_account_id: public_mention(def_id),
                    supply_account_id: public_mention(master_id),
                    name: "ParToken".to_owned(),
                    total_supply: total_mint,
                }),
            )
            .await
        })
        .await?;

    // Fund each sender from master. Serial; this is setup, not measured throughput.
    for (i, sender_id) in senders.iter().copied().enumerate() {
        output
            .step(ctx, format!("fund_sender_{i:02}"), async |ctx| {
                wallet::cli::execute_subcommand(
                    ctx.wallet_mut(),
                    Command::Token(TokenProgramAgnosticSubcommand::Send {
                        from: public_mention(master_id),
                        to: Some(public_mention(sender_id)),
                        to_npk: None,
                        to_vpk: None,
                        to_identifier: Some(0),
                        amount: AMOUNT_PER_TRANSFER * 5,
                    }),
                )
                .await
            })
            .await?;
    }

    // The measured phase: submit N transfers as fast as possible, do not wait
    // for chain advance between submits. The sequencer batches whatever lands in
    // its mempool before block_create_timeout. The burst step is captured
    // manually rather than via the `step()` helper because we need to time
    // submit-and-inclusion as two separate intervals over a synthesised batch
    // rather than per-tx.
    let pre_block_burst = ctx.sequencer_client().get_last_block_id().await?;
    let burst_started = Instant::now();

    // Submit all N back-to-back. Wallet serialises through `wallet_mut()`, but
    // each sender has its own nonce so there are no collisions.
    for (sender_id, recipient_id) in senders.iter().zip(recipients.iter()) {
        wallet::cli::execute_subcommand(
            ctx.wallet_mut(),
            Command::Token(TokenProgramAgnosticSubcommand::Send {
                from: public_mention(*sender_id),
                to: Some(public_mention(*recipient_id)),
                to_npk: None,
                to_vpk: None,
                to_identifier: Some(0),
                amount: AMOUNT_PER_TRANSFER,
            }),
        )
        .await?;
    }
    let all_submitted_at = Instant::now();
    let submit_duration = all_submitted_at.saturating_duration_since(burst_started);

    // Wait for the chain to advance by at least 2 blocks past pre_block_burst.
    // That guarantees the block holding our burst is sealed and applied.
    crate::harness::wait_for_chain_advance(ctx, pre_block_burst, 2).await?;
    let inclusion_done_at = Instant::now();
    let inclusion_after_submit = inclusion_done_at.saturating_duration_since(all_submitted_at);
    let burst_total = inclusion_done_at.saturating_duration_since(burst_started);

    eprintln!(
        "parallel_fanout: submitted {} txs in {:.3}s, inclusion in {:.3}s, total {:.3}s",
        senders.len(),
        submit_duration.as_secs_f64(),
        inclusion_after_submit.as_secs_f64(),
        burst_total.as_secs_f64(),
    );

    // Capture every block produced during the burst window. This is the
    // scenario where one block holds many txs, so block_bytes here is the
    // most representative L1-payload-equivalent measurement we have.
    let tip = ctx.sequencer_client().get_last_block_id().await?;
    let mut blocks: Vec<BlockSize> = Vec::new();
    for block_id in (pre_block_burst.saturating_add(1))..=tip {
        if let Some(block) = ctx.sequencer_client().get_block(block_id).await? {
            let block_bytes = borsh::to_vec(&block).map_or(0, |v| v.len());
            let mut sz = BlockSize {
                block_id,
                block_bytes,
                public_tx_bytes: Vec::new(),
                ppe_tx_bytes: Vec::new(),
                deploy_tx_bytes: Vec::new(),
            };
            for tx in &block.body.transactions {
                let n = borsh::to_vec(tx).map_or(0, |v| v.len());
                match tx {
                    NSSATransaction::Public(_) => sz.public_tx_bytes.push(n),
                    NSSATransaction::PrivacyPreserving(_) => sz.ppe_tx_bytes.push(n),
                    NSSATransaction::ProgramDeployment(_) => sz.deploy_tx_bytes.push(n),
                }
            }
            blocks.push(sz);
        }
    }

    // Synthesise a single summary "step" for the burst. Use the submit time
    // for `submit` and the inclusion-wait time for `inclusion`.
    let burst_step = StepResult {
        label: format!("burst_{}_transfers", senders.len()),
        submit: submit_duration,
        inclusion: Some(inclusion_after_submit),
        wallet_sync: None,
        total: burst_total,
        tx_hash: None,
        blocks,
    };
    output.push(burst_step);

    Ok(output)
}

async fn new_public_account(
    ctx: &mut TestContext,
    output: &mut ScenarioOutput,
    label: &str,
) -> Result<nssa::AccountId> {
    let ret = output
        .step(ctx, label, async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Account(AccountSubcommand::New(NewSubcommand::Public {
                    cci: None,
                    label: None,
                })),
            )
            .await
        })
        .await?;
    match ret {
        SubcommandReturnValue::RegisterAccount { account_id } => Ok(account_id),
        other => bail!("expected RegisterAccount, got {other:?}"),
    }
}
