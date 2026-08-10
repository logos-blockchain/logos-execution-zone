#![allow(
    clippy::print_stdout,
    reason = "this presentation binary intentionally reports each checked scenario"
)]

use anyhow::{Context as _, Result, ensure};
use cross_zone::cacp::{
    BedrockError, BedrockModel, ChannelParent, CounterpartySession, CrossZoneIntent,
    CustodialBondTerms, InitiatorSession, InscribeIntent, Phase, SubmissionResult, SubmittedBy,
    TimeoutOutcome, TwoZoneTopology, ZoneSequencer,
};
use lee::{AccountId, PrivateKey, PublicKey, PublicTransaction, V03State, public_transaction};
use logos_blockchain_core::mantle::{
    ops::{
        Op,
        channel::{ChannelId, MsgId},
    },
    traits::Hashable as _,
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;

const STAKE_AMOUNT: u128 = 1_000;

struct Fixture {
    key_a: Ed25519Key,
    key_b: Ed25519Key,
    intent: CrossZoneIntent,
    topology: TwoZoneTopology,
    parents: [ChannelParent; 2],
    lee_account_a: AccountId,
    lee_key_a: PrivateKey,
    lee_account_b: AccountId,
    lee_key_b: PrivateKey,
    bond_enforcer: AccountId,
    bond_enforcer_key: PrivateKey,
}

fn main() -> Result<()> {
    println!("CACP + externally enforced bond demo");
    println!("Scope: 1 Bedrock | 2 zones | 1 sequencer per zone | 2 ChannelInscribe ops");
    println!("Note: inscriptions carry data; LEZ public-account programs enforce the bond.\n");

    let fixture = fixture()?;
    happy_path(&fixture)?;
    counterparty_fallback(&fixture)?;
    safe_pre_phase_three_abort(&fixture)?;
    stale_parent_atomic_rejection(&fixture)?;
    public_account_stake_forfeiture(&fixture)?;

    println!("\nALL 5 CACP SCENARIOS PASSED");
    Ok(())
}

fn fixture() -> Result<Fixture> {
    let key_a = Ed25519Key::from_bytes(&[0xA1; 32]);
    let key_b = Ed25519Key::from_bytes(&[0xB2; 32]);
    let channel_a = ChannelId::from([1; 32]);
    let channel_b = ChannelId::from([2; 32]);
    let [lee_a, lee_b] =
        <[_; 2]>::try_from(testnet_initial_state::initial_pub_accounts_private_keys())
            .map_err(|_keys| anyhow::anyhow!("testnet must expose exactly two public accounts"))?;
    let bond_enforcer_key = PrivateKey::try_new([0xC3; 32])
        .map_err(|error| anyhow::anyhow!("invalid bond enforcer key: {error}"))?;
    let bond_enforcer = AccountId::from(&PublicKey::new_from_private_key(&bond_enforcer_key));
    let intent = CrossZoneIntent::new(
        [
            InscribeIntent {
                channel_id: channel_a,
                payload: b"zone-a inscription".to_vec(),
            },
            InscribeIntent {
                channel_id: channel_b,
                payload: b"zone-b inscription".to_vec(),
            },
        ],
        7,
    )?
    .with_custodial_bond(CustodialBondTerms {
        enforcer_account_id: bond_enforcer,
        stake_amount: STAKE_AMOUNT,
    })?;
    let topology = TwoZoneTopology::new(
        ZoneSequencer {
            channel_id: channel_a,
            public_key: key_a.public_key(),
        },
        ZoneSequencer {
            channel_id: channel_b,
            public_key: key_b.public_key(),
        },
        &intent,
    )?;
    let parents = [
        ChannelParent {
            channel_id: channel_a,
            parent: MsgId::from([3; 32]),
        },
        ChannelParent {
            channel_id: channel_b,
            parent: MsgId::from([4; 32]),
        },
    ];
    Ok(Fixture {
        key_a,
        key_b,
        intent,
        topology,
        parents,
        lee_account_a: lee_a.account_id,
        lee_key_a: lee_a.pub_sign_key,
        lee_account_b: lee_b.account_id,
        lee_key_b: lee_b.pub_sign_key,
        bond_enforcer,
        bond_enforcer_key,
    })
}

fn phase_three(fixture: &Fixture) -> Result<(InitiatorSession, CounterpartySession)> {
    let mut initiator = InitiatorSession::new(
        fixture.topology.clone(),
        fixture.intent.clone(),
        fixture.parents,
    )?;
    let mut counterparty = CounterpartySession::new(
        fixture.topology.clone(),
        fixture.intent.clone(),
        fixture.parents,
    )?;
    let accept = counterparty.receive_propose(&initiator.propose(), &fixture.key_b)?;
    let finalize = initiator.receive_accept(accept, &fixture.key_a)?;
    counterparty.receive_finalize(finalize)?;

    ensure!(initiator.phase() == Phase::SignaturesExchanged);
    ensure!(counterparty.phase() == Phase::SignaturesExchanged);
    Ok((initiator, counterparty))
}

fn happy_path(fixture: &Fixture) -> Result<()> {
    heading(1, "happy path");
    let (mut initiator, mut counterparty) = phase_three(fixture)?;
    let signed_tx = initiator
        .signed_tx()
        .context("initiator should hold the jointly signed transaction")?;
    let counterparty_hash = counterparty
        .signed_tx()
        .context("counterparty should hold the jointly signed transaction")?
        .hash();
    ensure!(signed_tx.hash() == counterparty_hash);
    ensure!(signed_tx.mantle_tx().ops().len() == 2);
    ensure!(
        signed_tx
            .mantle_tx()
            .ops()
            .iter()
            .all(|op| matches!(op, Op::ChannelInscribe(_)))
    );

    let mut bedrock = BedrockModel::new(fixture.parents);
    let result = bedrock.submit(signed_tx, SubmittedBy::Initiator)?;
    let SubmissionResult::Included(tx_hash) = result else {
        anyhow::bail!("the first submission must be included");
    };
    ensure!(bedrock.submitted_by(tx_hash) == Some(SubmittedBy::Initiator));
    initiator.mark_submitted()?;
    counterparty.mark_submitted()?;

    println!("  PROPOSE -> ACCEPT -> FINALIZE -> submit by Sequencer A");
    println!("  PASS: Bedrock included one joint tx with exactly two ChannelInscribe ops");
    Ok(())
}

fn counterparty_fallback(fixture: &Fixture) -> Result<()> {
    heading(
        2,
        "Phase 3 reached; Sequencer B performs fallback submission",
    );
    let (mut initiator, mut counterparty) = phase_three(fixture)?;
    let TimeoutOutcome::FallbackSubmission(signed_tx) = counterparty.on_timeout() else {
        anyhow::bail!("Sequencer B must retain fallback submission rights after Phase 3");
    };

    let mut bedrock = BedrockModel::new(fixture.parents);
    let SubmissionResult::Included(tx_hash) =
        bedrock.submit(&signed_tx, SubmittedBy::CounterpartyFallback)?
    else {
        anyhow::bail!("Sequencer B's first submission must be included");
    };
    ensure!(
        bedrock.submitted_by(tx_hash) == Some(SubmittedBy::CounterpartyFallback),
        "Bedrock must attribute inclusion to the fallback submitter"
    );
    let duplicate = bedrock.submit(&signed_tx, SubmittedBy::Initiator)?;
    ensure!(duplicate == SubmissionResult::AlreadyIncluded(tx_hash));
    counterparty.mark_submitted()?;
    initiator.mark_submitted()?;

    println!("  Sequencer A stalls after FINALIZE; B submits the identical signed tx");
    println!("  PASS: fallback included once; a later duplicate is idempotent");
    Ok(())
}

fn safe_pre_phase_three_abort(fixture: &Fixture) -> Result<()> {
    heading(3, "safe abort before Phase 3");
    let mut initiator = InitiatorSession::new(
        fixture.topology.clone(),
        fixture.intent.clone(),
        fixture.parents,
    )?;
    ensure!(initiator.on_timeout() == TimeoutOutcome::Aborted);
    ensure!(initiator.phase() == Phase::Aborted);
    ensure!(initiator.signed_tx().is_none());

    let proposer = InitiatorSession::new(
        fixture.topology.clone(),
        fixture.intent.clone(),
        fixture.parents,
    )?;
    let mut counterparty = CounterpartySession::new(
        fixture.topology.clone(),
        fixture.intent.clone(),
        fixture.parents,
    )?;
    counterparty.receive_propose(&proposer.propose(), &fixture.key_b)?;
    ensure!(counterparty.phase() == Phase::WaitingForFinalize);
    ensure!(counterparty.on_timeout() == TimeoutOutcome::Aborted);
    ensure!(counterparty.signed_tx().is_none());

    println!("  Tested timeout before ACCEPT and timeout while waiting for FINALIZE");
    println!("  PASS: no fully signed transaction exists, so no channel tip can advance");
    Ok(())
}

fn stale_parent_atomic_rejection(fixture: &Fixture) -> Result<()> {
    heading(4, "stale parent causes atomic rejection");
    let (initiator, _counterparty) = phase_three(fixture)?;
    let signed_tx = initiator
        .signed_tx()
        .context("Phase 3 should produce a jointly signed transaction")?;
    let current_parents = [
        ChannelParent {
            channel_id: fixture.parents[0].channel_id,
            parent: MsgId::from([0xCC; 32]),
        },
        fixture.parents[1],
    ];
    let mut bedrock = BedrockModel::new(current_parents);
    let before_a = bedrock.tip(fixture.parents[0].channel_id);
    let before_b = bedrock.tip(fixture.parents[1].channel_id);

    let error = bedrock
        .submit(signed_tx, SubmittedBy::Initiator)
        .expect_err("the stale parent must reject the whole transaction");
    ensure!(error == BedrockError::StaleParent);
    ensure!(bedrock.tip(fixture.parents[0].channel_id) == before_a);
    ensure!(bedrock.tip(fixture.parents[1].channel_id) == before_b);

    println!("  Zone A parent is stale when the joint tx reaches Bedrock");
    println!("  PASS: both inscriptions rejected; neither channel tip changed");
    Ok(())
}

fn public_account_stake_forfeiture(fixture: &Fixture) -> Result<()> {
    heading(5, "real public-account stakes; Sequencer A forfeits");
    let terms = fixture
        .intent
        .custodial_bond()
        .context("the CACP proposal must bind its external bond terms")?;
    ensure!(terms.enforcer_account_id == fixture.bond_enforcer);
    ensure!(terms.stake_amount == STAKE_AMOUNT);

    let mut state = testnet_initial_state::initial_state();
    let vault_id =
        vault_core::compute_vault_account_id(programs::vault().id(), fixture.bond_enforcer);
    let balance_a_before = state.get_account_by_id(fixture.lee_account_a).balance;
    let balance_b_before = state.get_account_by_id(fixture.lee_account_b).balance;
    let balance_a_after_deposit = balance_a_before
        .checked_sub(STAKE_AMOUNT)
        .context("Sequencer A must be able to fund its stake")?;
    let balance_b_after_deposit = balance_b_before
        .checked_sub(STAKE_AMOUNT)
        .context("Sequencer B must be able to fund its stake")?;
    let balance_b_after_forfeit = balance_b_before
        .checked_add(STAKE_AMOUNT)
        .context("Sequencer B's compensated balance must not overflow")?;
    let total_stake = STAKE_AMOUNT
        .checked_mul(2)
        .context("the combined stake must not overflow")?;

    apply_lee_tx(
        &mut state,
        &vault_deposit(
            fixture.lee_account_a,
            &fixture.lee_key_a,
            fixture.bond_enforcer,
            0,
            STAKE_AMOUNT,
        )?,
        1,
    )?;
    apply_lee_tx(
        &mut state,
        &vault_deposit(
            fixture.lee_account_b,
            &fixture.lee_key_b,
            fixture.bond_enforcer,
            0,
            STAKE_AMOUNT,
        )?,
        2,
    )?;

    ensure!(state.get_account_by_id(fixture.lee_account_a).balance == balance_a_after_deposit);
    ensure!(state.get_account_by_id(fixture.lee_account_b).balance == balance_b_after_deposit);
    ensure!(state.get_account_by_id(vault_id).balance == total_stake);

    let unauthorized = vault_claim(fixture.bond_enforcer, &fixture.lee_key_a, 0, total_stake)?;
    ensure!(
        state
            .transition_from_public_transaction(&unauthorized, 3, 3)
            .is_err(),
        "a sequencer must not be able to claim the external enforcer's vault"
    );
    ensure!(state.get_account_by_id(vault_id).balance == total_stake);

    apply_lee_tx(
        &mut state,
        &vault_claim(
            fixture.bond_enforcer,
            &fixture.bond_enforcer_key,
            0,
            total_stake,
        )?,
        4,
    )?;
    apply_lee_tx(
        &mut state,
        &native_transfer(
            fixture.bond_enforcer,
            &fixture.bond_enforcer_key,
            fixture.lee_account_b,
            1,
            total_stake,
        )?,
        5,
    )?;

    ensure!(state.get_account_by_id(vault_id).balance == 0);
    ensure!(state.get_account_by_id(fixture.bond_enforcer).balance == 0);
    ensure!(state.get_account_by_id(fixture.lee_account_a).balance == balance_a_after_deposit);
    ensure!(state.get_account_by_id(fixture.lee_account_b).balance == balance_b_after_forfeit);

    println!("  A and B each deposited {STAKE_AMOUNT} native units from signed public accounts");
    println!("  The LEZ vault rejected A's unauthorized claim");
    println!("  External resolver paid both stakes to B after A's attributed abort");
    println!("  PASS: A lost 1000; B gained 1000; escrow and resolver ended at zero");
    Ok(())
}

fn vault_deposit(
    sender: AccountId,
    signing_key: &PrivateKey,
    enforcer: AccountId,
    nonce: u128,
    amount: u128,
) -> Result<PublicTransaction> {
    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), enforcer);
    signed_lee_tx(
        programs::vault().id(),
        vec![sender, vault_id],
        nonce,
        vault_core::Instruction::Transfer {
            recipient_id: enforcer,
            amount,
        },
        signing_key,
    )
}

fn vault_claim(
    enforcer: AccountId,
    signing_key: &PrivateKey,
    nonce: u128,
    amount: u128,
) -> Result<PublicTransaction> {
    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), enforcer);
    signed_lee_tx(
        programs::vault().id(),
        vec![enforcer, vault_id],
        nonce,
        vault_core::Instruction::Claim { amount },
        signing_key,
    )
}

fn native_transfer(
    sender: AccountId,
    signing_key: &PrivateKey,
    recipient: AccountId,
    nonce: u128,
    amount: u128,
) -> Result<PublicTransaction> {
    signed_lee_tx(
        programs::authenticated_transfer().id(),
        vec![sender, recipient],
        nonce,
        authenticated_transfer_core::Instruction::Transfer { amount },
        signing_key,
    )
}

fn signed_lee_tx<I: serde::Serialize>(
    program_id: lee::ProgramId,
    account_ids: Vec<AccountId>,
    nonce: u128,
    instruction: I,
    signing_key: &PrivateKey,
) -> Result<PublicTransaction> {
    let message = public_transaction::Message::try_new(
        program_id,
        account_ids,
        vec![nonce.into()],
        instruction,
    )?;
    let witness = public_transaction::WitnessSet::for_message(&message, &[signing_key]);
    Ok(PublicTransaction::new(message, witness))
}

fn apply_lee_tx(state: &mut V03State, tx: &PublicTransaction, block_id: u64) -> Result<()> {
    state
        .transition_from_public_transaction(tx, block_id, block_id)
        .map_err(|error| anyhow::anyhow!("LEE rejected bond transaction: {error}"))
}

fn heading(number: u8, title: &str) {
    println!("[{number}/5] {title}");
}
