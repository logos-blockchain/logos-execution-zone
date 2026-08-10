#![allow(
    clippy::print_stdout,
    reason = "this presentation binary intentionally reports each checked scenario"
)]

use anyhow::{Context as _, Result, ensure};
use cross_zone::cacp::{
    BedrockError, BedrockModel, ChannelParent, CounterpartySession, CrossZoneIntent,
    InitiatorSession, InscribeIntent, Phase, SubmissionResult, SubmittedBy, TimeoutOutcome,
    TwoZoneTopology, ZoneSequencer,
};
use logos_blockchain_core::mantle::{
    ops::{
        Op,
        channel::{ChannelId, MsgId},
    },
    traits::Hashable as _,
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;

struct Fixture {
    key_a: Ed25519Key,
    key_b: Ed25519Key,
    intent: CrossZoneIntent,
    topology: TwoZoneTopology,
    parents: [ChannelParent; 2],
}

fn main() -> Result<()> {
    println!("CACP reference-model demo");
    println!("Scope: 1 Bedrock | 2 zones | 1 sequencer per zone | 2 ChannelInscribe ops");
    println!("Note: inscriptions carry data; they do not enforce stake custody or forfeiture.\n");

    let fixture = fixture()?;
    happy_path(&fixture)?;
    counterparty_fallback(&fixture)?;
    safe_pre_phase_three_abort(&fixture)?;
    stale_parent_atomic_rejection(&fixture)?;

    println!("\nALL 4 CACP SCENARIOS PASSED");
    Ok(())
}

fn fixture() -> Result<Fixture> {
    let key_a = Ed25519Key::from_bytes(&[0xA1; 32]);
    let key_b = Ed25519Key::from_bytes(&[0xB2; 32]);
    let channel_a = ChannelId::from([1; 32]);
    let channel_b = ChannelId::from([2; 32]);
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
    )?;
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

fn heading(number: u8, title: &str) {
    println!("[{number}/4] {title}");
}
