#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext, account_balance, fetch_privacy_preserving_tx, funded_private_account, new_account,
    no_seal, private_balance, restored_private_account, sync_private, wait_for_inclusion,
    wait_until,
};
use lee::{
    AccountId, Actor, PrivacyPreservingTransaction, ProvingInput, PublicExecutionContext,
    Publication, RecipientEncryption, SenderPresentation, execute_and_prove_with_cross_messages,
    privacy_preserving_transaction::{
        circuit::ProgramCatalog, message::Message, witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    Commitment, Nullifier, NullifierWitness, PrivateAccountKind, PrivateWitness, RegularKey,
    RootCall, WitnessKind, execution_state::TransactionEntry, native_token, program::PdaSeed,
};
use sequencer_service_rpc::RpcClient as _;
use test_guest_core::{LIVE_PAYOUT_SEED, PayoutRequest, Script};
use tokio::test;
use wallet::{
    AccountIdentity,
    program_facades::{
        CreditDelivery, native_token_transfer::NativeTokenTransfer, program_loader::ProgramLoader,
    },
};

const AMOUNT_IN: u128 = 100;
const CUSTODY: u128 = 1_900;

// `scripted` runs the trader's private actor and `live_payout` the custody's public one.
struct Programs {
    scripted: AccountId,
    live_payout: AccountId,
}

/// The in-proof fee reserve of a trade, generous for the payout's guest cycles at the floor base
/// fees. The input note is presented canonically and unbound, so settlement keeps the surplus as
/// tip rather than refunding it, and a settled trade spends the note whole.
fn fee_reserve() -> u128 {
    fee_core::assess::private_fee_required(2_000_000, 8, 8)
}

// Deploys `program` immutably through the loader, paid by the context's first public account.
async fn deploy(ctx: &mut TestContext, program: &Program) -> Result<AccountId> {
    let payer = ctx.existing_public_accounts()[0];
    let header = new_account(ctx, false, None).await?;
    let mut segments = Vec::new();
    for _ in program
        .user_elf()?
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segments.push(new_account(ctx, false, None).await?);
    }
    ProgramLoader(ctx.wallet())
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

// The witness spending the trader's private input note.
async fn spend_input(ctx: &TestContext, input: AccountId, seed: u8) -> Result<PrivateWitness> {
    let spent = restored_private_account(ctx, input, "trader input");
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(input)
        .context("the trader's input note is unknown to the wallet")?;
    let (proofs, _, _) = ctx
        .wallet()
        .get_proofs_and_root(&[commitment], Vec::new())
        .await?;
    let membership_proof = proofs
        .into_iter()
        .next()
        .flatten()
        .context("the trader's input note is not on chain")?;
    Ok(PrivateWitness {
        vpk: spent.key_chain.viewing_public_key.clone(),
        random_seed: [seed; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(
            spent.key_chain.private_key_holder.authorization_secret_key,
        )),
        nullifier: NullifierWitness::Update {
            account: spent.account.clone(),
            membership_proof,
        },
        address_openings: BTreeSet::new(),
    })
}

// The trader's scripted actor deposits `AMOUNT_IN` from its private note into the custody, then
// asks the custody for its payout. The proof assumes nothing of public execution: the custody
// prices the payout off the balance it holds at settlement and sends it asynchronously, under the
// recovery binding the proof carries.
fn prove_trade(
    programs: &Programs,
    custody: AccountId,
    input: AccountId,
    witness: PrivateWitness,
    request: PayoutRequest,
    recoveries: Vec<RecipientEncryption>,
) -> Result<PrivacyPreservingTransaction> {
    let payer = Actor::new(custody, programs.live_payout);
    let script = Script::default()
        .send_sync(
            Actor::native_balance(input),
            &native_token::Message::Transfer {
                to: custody,
                amount: AMOUNT_IN,
            },
        )
        .send_sync(payer, &request);
    let (output, proof) = execute_and_prove_with_cross_messages(
        ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: Actor::new(input, programs.scripted),
                message: Program::serialize_message(script)?,
            }),
            // The fee inbox is declared so the reserve crosses to it rather than being published.
            public_context: PublicExecutionContext::new(
                [
                    payer,
                    Actor::native_balance(custody),
                    Actor::native_balance(system_accounts::fee_inbox_account_id()),
                ],
                [],
            ),
            private_witnesses: vec![witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries,
            private_promotions: BTreeSet::new(),
            fee: Some(lee_core::FeeTransfer {
                payer: input,
                recipient: system_accounts::fee_inbox_account_id(),
                amount: fee_reserve(),
                refund_to: None,
            }),
        },
        // One public segment each for the deposit and the request; neither sends anything back.
        vec![Vec::new(), Vec::new()],
        &ProgramCatalog::from([(programs.scripted, test_programs::scripted())]),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )?;
    let message = Message::from_circuit_output(BTreeMap::new(), output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    Ok(PrivacyPreservingTransaction::new(message, witness_set))
}

// Submits a prepared transaction unchanged and requires exactly it to settle, leaving the custody
// holding `custody_left`.
async fn settle(
    ctx: &TestContext,
    custody: AccountId,
    tx: &PrivacyPreservingTransaction,
    custody_left: u128,
) -> Result<()> {
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx.clone()))
        .await?;
    wait_for_inclusion(ctx, tx_hash).await?;
    assert_eq!(
        fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await,
        *tx,
        "the settled transaction is the one prepared"
    );
    assert_eq!(account_balance(ctx, custody).await?, custody_left);
    Ok(())
}

// Submits a prepared transaction and requires it to be dropped rather than included, leaving the
// custody holding `custody_left`.
async fn assert_dropped(
    ctx: &TestContext,
    custody: AccountId,
    tx: &PrivacyPreservingTransaction,
    custody_left: u128,
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
        "the transaction must not be included"
    );
    assert_eq!(account_balance(ctx, custody).await?, custody_left);
    Ok(())
}

// Trades proven while the custody holds 1,900 settle later, unchanged, each paying out a tenth of
// whatever the custody holds once the trade's deposit lands, and the custody sends that payout
// asynchronously as a pending native credit the trader receives privately afterwards. One whose
// minimum the live payout misses is refused without moving anything, its private deposit included.
#[test]
async fn trades_proven_at_one_custody_balance_pay_out_at_the_live_balance() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let programs = Programs {
        scripted: deploy(&mut ctx, &test_programs::scripted()).await?,
        live_payout: deploy(&mut ctx, &test_programs::live_payout()).await?,
    };
    let custody = AccountId::for_public_pda(&programs.live_payout, &LIVE_PAYOUT_SEED);
    let funder = ctx.existing_public_accounts()[0];
    let (funded, _) = NativeTokenTransfer(ctx.wallet())
        .transfer(
            AccountIdentity::Public(funder),
            AccountIdentity::PublicPda {
                program: programs.live_payout,
                seed: LIVE_PAYOUT_SEED,
            },
            CUSTODY,
            CreditDelivery::Automatic,
        )
        .await?;
    wait_for_inclusion(&ctx, funded).await?;

    // All three trades are proven before the first settles; the second accepts less.
    let mut traders = Vec::new();
    let mut prepared = Vec::new();
    for (min_payout, seed) in [200, 190, 200].into_iter().zip(1..) {
        let input = funded_private_account(&mut ctx, AMOUNT_IN + fee_reserve()).await?;
        let output = new_account(&mut ctx, true, None).await?;
        let (_, async_delivery) = ctx
            .wallet()
            .async_destination(AccountIdentity::PrivateOwned(output).balance())?;
        let witness = spend_input(&ctx, input, seed).await?;
        prepared.push(prove_trade(
            &programs,
            custody,
            input,
            witness,
            PayoutRequest {
                to: output,
                min_payout,
            },
            async_delivery.recoveries,
        )?);
        traders.push((input, output));
    }

    // A tenth of 1,900 + 100 is 200 >= 200, then of 1,800 + 100 is 190 >= 190: the same kind of
    // prepared trade settles at a different, still acceptable, live payout.
    settle(&ctx, custody, &prepared[0], 1_800).await?;
    settle(&ctx, custody, &prepared[1], 1_710).await?;

    // A tenth of 1,710 + 100 is 181 < 200: the live payout misses the third trade's minimum, so it
    // is dropped rather than included, and its recovery binding with it.
    assert_dropped(&ctx, custody, &prepared[2], 1_710).await?;
    assert_eq!(ctx.wallet().get_recovery_binding(traders[2].1).await?, None);

    // The custody's transfers send the payouts asynchronously: exactly the two credits are pending
    // at the output accounts.
    let pending = ctx.wallet_mut().owned_pending_messages().await?;
    assert_eq!(pending.len(), 2, "exactly the two payouts are pending");
    for (record, ((_, output), payout)) in pending.iter().zip(traders.iter().zip([200, 190])) {
        let Publication::Clear { body, .. } = &record.publication else {
            anyhow::bail!("a public custody's payout is published clear");
        };
        assert_eq!(
            (body.from, body.to),
            (
                Actor::native_balance(custody),
                Actor::native_balance(*output)
            ),
            "the custody sends the payout asynchronously to the output account"
        );
        assert_eq!(
            borsh::from_slice::<native_token::Message>(&body.message)?,
            native_token::Message::Credit(payout),
            "the payout is a tenth of the live balance"
        );
    }

    for record in pending {
        let (received, _) = ctx.wallet_mut().receive_pending_message(record).await?;
        wait_for_inclusion(&ctx, received).await?;
        // The receipts share a fee payer: the next one spends the note this one left.
        sync_private(&mut ctx).await?;
    }
    assert!(
        ctx.wallet_mut().owned_pending_messages().await?.is_empty(),
        "receiving consumes the pending payouts"
    );

    sync_private(&mut ctx).await?;
    for ((input, output), (input_left, received)) in
        traders
            .iter()
            .zip([(0, 200), (0, 190), (AMOUNT_IN + fee_reserve(), 0)])
    {
        assert_eq!(private_balance(&ctx, *input)?, input_left, "input note");
        assert_eq!(private_balance(&ctx, *output)?, received, "payout");
    }
    Ok(())
}

// A public transfer to a private PDA proves only the payout's recovery binding. The PDA is under
// the recipient's keys, of which it holds no record: it finds each payout by opening its recovery
// note, records the PDA at its first receipt and follows it from there, and the second payout
// reuses the binding unproven.
#[test]
async fn a_public_payout_reaches_a_private_pda_its_recipient_discovers_by_key() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let (recorded, _) = ctx.wallet_mut().create_new_account_private(None);
    let keys = restored_private_account(&ctx, recorded, "recipient keys")
        .key_chain
        .clone();
    let payout = AccountIdentity::PrivateForeign {
        npk: keys.nullifier_public_key,
        vpk: keys.viewing_public_key,
        kind: PrivateAccountKind::Pda {
            account_id: AccountId::new([4; 32]),
            seed: PdaSeed::new([7; 32]),
        },
    };
    let payout_id = payout.account_id();

    let mut notes = Vec::new();
    for (amount, balance) in [(90, 90), (75, 165)] {
        let (sent, _) = NativeTokenTransfer(ctx.wallet())
            .transfer(
                AccountIdentity::Public(sender),
                payout.clone(),
                amount,
                CreditDelivery::Automatic,
            )
            .await?;
        wait_for_inclusion(&ctx, sent).await?;

        let [pending] = <[_; 1]>::try_from(ctx.wallet_mut().owned_pending_messages().await?)
            .map_err(|pending| anyhow::anyhow!("expected one payout, found {}", pending.len()))?;
        let Publication::Clear { body, recovery } = &pending.publication else {
            anyhow::bail!("a public sender's payout is published clear");
        };
        assert_eq!(body.to, Actor::native_balance(payout_id));
        assert_eq!(
            borsh::from_slice::<native_token::Message>(&body.message)?,
            native_token::Message::Credit(amount)
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
        assert_eq!(private_balance(&ctx, payout_id)?, balance);
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
