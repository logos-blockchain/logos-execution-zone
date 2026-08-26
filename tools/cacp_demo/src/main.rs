// Submission provenance and full references
//
// This source accompanies:
// Q. Jiang, “Costly Escalation in Cross-Zone Atomic Coordination: A Neutral-Zone Fee
// and Stake Mechanism for CACP,” MSc Emerging Digital Technologies dissertation,
// Department of Computer Science, University College London, 2026.
//
// The project specifications, platform specifications, and design literature are:
// [1] T. Lavaur, “[1.1.1] Cross-Channel Messaging,” The Logos Blockchain Project,
// specification version 1.1.1, 6 May 2026. [Online]. Available:
// https://nomos-tech.notion.site/1-1-1-Template-Cross-Channel-Messaging-33e261aa09df80b2a6aaca0e7cfd2ce7.
// [Accessed: 24 Aug. 2026].
// [3] T. Lavaur, “[1.5.0] Mantle,” The Logos Blockchain Project, specification version
// 1.5.0, 6 May 2026. [Online]. Available:
// https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85.
// [Accessed: 24 Aug. 2026].
// [4] Logos Blockchain Project, “LEE v0.3 Specifications,” Logos Improvement Proposal
// 237, Standards Track, raw status, 8 June 2026. [Online]. Available:
// https://lip.logos.co/blockchain/raw/lez/lee-v0.3-specifications.html.
// [Accessed: 24 Aug. 2026].
// [14] N. Asokan, M. Schunter, and M. Waidner, “Optimistic Protocols for Fair
// Exchange,” in Proc. 4th ACM Conference on Computer and Communications Security,
// pp. 7–17, 1997, doi: 10.1145/266420.266426.
// [15] N. Asokan, V. Shoup, and M. Waidner, “Optimistic Fair Exchange of Digital
// Signatures,” in Advances in Cryptology—EUROCRYPT 1998, pp. 591–606, 1998,
// doi: 10.1007/BFb0054156.
// [16] S. Dziembowski, L. Eckey, and S. Faust, “FairSwap: How to Fairly Exchange
// Digital Goods,” in Proc. 2018 ACM SIGSAC Conference on Computer and Communications
// Security, pp. 967–984, 2018, doi: 10.1145/3243734.3243857.
// [18] I. Bentov and R. Kumaresan, “How to Use Bitcoin to Design Fair Protocols,” in
// Advances in Cryptology—CRYPTO 2014, pp. 421–439, 2014,
// doi: 10.1007/978-3-662-44381-1_24.
// [23] Q. Jiang, “Specification for CACP: Cross-Zone Atomic Coordination Protocol,”
// University College London, project specification, 2026.
// [24] Q. Jiang, “LEZ CACP Costly Escalation Bond Protocol,” University College
// London, project specification, 2026.

#![allow(clippy::print_stdout, reason = "the demo reports verified scenarios")]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use cacp_bond_core::{
    AGREEMENT_VERSION, AgreementId, BondAgreement, BondState, Instruction as BondInstruction,
    MantleSignature, Settlement, burn_account_id, escrow_account_id, state_account_id,
};
use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use common::transaction::LeeTransaction;
use cross_zone::cacp::{
    CacpError, ChannelParent, CounterpartySession, CrossZoneIntent, Finalize, InitiatorSession,
    InscribeIntent, Phase, TimeoutOutcome, TwoZoneTopology, ZoneSequencer,
};
use lee::{AccountId, PrivateKey, PublicKey, PublicTransaction, public_transaction};
use logos_blockchain_codec::{BinaryDecodeExt as _, BinaryEncode as _};
use logos_blockchain_core::mantle::{
    SignedMantleTx,
    gas::GasCost,
    ops::{
        Op, OpProof,
        channel::{ChannelId, MsgId},
    },
    traits::Hashable as _,
    transactions::{
        MantleTxBuilder, OpsProofs, RawMantleTx, mantle_tx::MantleTx as _, states::Unverified,
    },
};
use logos_blockchain_http_api_common::bodies::wallet::fund::WalletFundRequestBody;
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkSignature};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    sequencer::FundingConfig,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{self, MultiNodeTestContextConfig, SequencerPartialConfig},
    setup::{SequencerSetup, sequencer_client},
};

const KEY_A: [u8; 32] = [0xA1; 32];
const KEY_B: [u8; 32] = [0xB2; 32];
const STAKE: u128 = 1_000;
const CHALLENGE_FEE: u128 = 100;
const RESPONSE_FEE: u128 = 100;
const WINDOW: u64 = 3;
const POLL: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(90);

struct LiveNetwork {
    _bond: TestContext,
    bond_client: SequencerClient,
    node: NodeHttpClient,
    _zone_a: sequencer_service::SequencerHandle,
    _zone_a_home: tempfile::TempDir,
    _zone_b: sequencer_service::SequencerHandle,
    _zone_b_home: tempfile::TempDir,
    key_a: Ed25519Key,
    key_b: Ed25519Key,
    account_a: AccountId,
    account_b: AccountId,
    lee_key_a: PrivateKey,
    lee_key_b: PrivateKey,
}

struct BondEvidence {
    agreement: BondAgreement,
    agreement_id: AgreementId,
    tx_hash: [u8; 32],
}

impl LiveNetwork {
    async fn start() -> Result<Self> {
        let bond = MultiZoneTestContextBuilder::default()
            .with_zone(
                ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                    .disable_indexer()
                    .from_scratch()
                    .with_sequencer_partial_config(SequencerPartialConfig {
                        // Live wallet initialization proves several transactions. A moderate
                        // interval preserves the shared Bedrock fee fixture before participant
                        // zones start.
                        block_create_timeout: Duration::from_secs(5),
                        ..SequencerPartialConfig::default()
                    }),
            )
            .build()
            .await
            .context("starting Bedrock and the neutral bond zone")?;
        let bedrock_addr = bond.bedrock_addr();
        let participant_config = SequencerPartialConfig {
            block_create_timeout: Duration::from_secs(60),
            ..SequencerPartialConfig::default()
        };
        let (zone_a, zone_a_home) = SequencerSetup::new(participant_config, bedrock_addr)
            .with_genesis(vec![])
            .with_channel_id(channel_a())
            .with_bedrock_signing_key(KEY_A)
            .setup()
            .await
            .context("starting participant-zone sequencer A")?;
        let (zone_b, zone_b_home) = SequencerSetup::new(participant_config, bedrock_addr)
            .with_genesis(vec![])
            .with_channel_id(channel_b())
            .with_bedrock_signing_key(KEY_B)
            .setup()
            .await
            .context("starting participant-zone sequencer B")?;
        let client_a = sequencer_client(zone_a.addr())?;
        let client_b = sequencer_client(zone_b.addr())?;
        ensure!(client_a.get_channel_id().await?.0 == *channel_a().as_ref());
        ensure!(client_b.get_channel_id().await?.0 == *channel_b().as_ref());

        let node_url = config::addr_to_url(config::UrlProtocol::Http, bedrock_addr)?;
        let node = NodeHttpClient::new(CommonHttpClient::new(None), node_url);
        wait_for_channel(&node, channel_a()).await?;
        wait_for_channel(&node, channel_b()).await?;

        let mut public_accounts = config::default_public_accounts_for_wallet();
        public_accounts
            .sort_by_key(|(key, _)| AccountId::from(&PublicKey::new_from_private_key(key)));
        let [(lee_key_a, _), (lee_key_b, _)] = <[_; 2]>::try_from(public_accounts)
            .map_err(|_error| anyhow::anyhow!("fixture must provide two public accounts"))?;
        let account_a = AccountId::from(&PublicKey::new_from_private_key(&lee_key_a));
        let account_b = AccountId::from(&PublicKey::new_from_private_key(&lee_key_b));
        let bond_client = bond.sequencer_client().clone();

        println!(
            "Started real HTTP services: Bedrock + sequencer A + sequencer B + neutral bond sequencer\n"
        );
        Ok(Self {
            _bond: bond,
            bond_client,
            node,
            _zone_a: zone_a,
            _zone_a_home: zone_a_home,
            _zone_b: zone_b,
            _zone_b_home: zone_b_home,
            key_a: Ed25519Key::from_bytes(&KEY_A),
            key_b: Ed25519Key::from_bytes(&KEY_B),
            account_a,
            account_b,
            lee_key_a,
            lee_key_b,
        })
    }

    async fn parents(&self) -> Result<[ChannelParent; 2]> {
        Ok([
            ChannelParent {
                channel_id: channel_a(),
                parent: channel_tip(&self.node, channel_a()).await?,
            },
            ChannelParent {
                channel_id: channel_b(),
                parent: channel_tip(&self.node, channel_b()).await?,
            },
        ])
    }

    fn intent(nonce: u64) -> Result<CrossZoneIntent> {
        Ok(CrossZoneIntent::new(
            [
                InscribeIntent {
                    channel_id: channel_a(),
                    payload: format!("CACP zone A / run {nonce}").into_bytes(),
                },
                InscribeIntent {
                    channel_id: channel_b(),
                    payload: format!("CACP zone B / run {nonce}").into_bytes(),
                },
            ],
            nonce,
        )?)
    }

    fn topology(&self, intent: &CrossZoneIntent) -> Result<TwoZoneTopology> {
        Ok(TwoZoneTopology::new(
            ZoneSequencer {
                channel_id: channel_a(),
                public_key: self.key_a.public_key(),
            },
            ZoneSequencer {
                channel_id: channel_b(),
                public_key: self.key_b.public_key(),
            },
            intent,
        )?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("CACP + protocol-enforced costly-escalation live demo");
    println!("1 local Bedrock | 2 participant zones | 1 neutral bond execution zone");
    println!(
        "The two business operations are ChannelInscribe; Bedrock may append one fee transfer.\n"
    );

    let network = LiveNetwork::start().await?;
    happy_path(&network, 1).await?;
    fallback_submission(&network, 2).await?;
    safe_abort(&network, 3).await?;
    stale_parent_rejection(&network, 4).await?;
    automatic_forfeiture(&network, 5).await?;

    println!("\nALL 5 LIVE CACP SCENARIOS PASSED");
    Ok(())
}

async fn funded_phase_three(
    network: &LiveNetwork,
    nonce: u64,
) -> Result<(InitiatorSession, CounterpartySession)> {
    let intent = LiveNetwork::intent(nonce)?;
    let topology = network.topology(&intent)?;
    let parents = network.parents().await?;
    let mut initiator = InitiatorSession::new(topology.clone(), intent.clone(), parents)?;
    let mut counterparty = CounterpartySession::new(topology, intent, parents)?;
    let raw = cross_zone::cacp::build_joint_tx(
        &initiator.propose().intent,
        &network.topology(&initiator.propose().intent)?,
        &parents,
    )?;
    let funded = fund_ops(&network.node, raw).await?;
    let transfer_proof = funded
        .1
        .context("Bedrock funding must append a fee-transfer proof")?;
    let accept = counterparty.receive_funded_propose(
        &initiator.propose(),
        funded.0,
        transfer_proof,
        &network.key_b,
    )?;
    let finalize = initiator.receive_accept(accept, &network.key_a)?;
    let substituted = substitute_transfer_fee_proof(&finalize)?;
    ensure!(
        counterparty.receive_finalize(substituted) == Err(CacpError::ProofMismatch),
        "B accepted a FINALIZE whose Transfer proof differs from the funded candidate"
    );
    counterparty.receive_finalize(finalize)?;
    ensure!(initiator.phase() == Phase::SignaturesExchanged);
    ensure!(counterparty.phase() == Phase::SignaturesExchanged);
    Ok((initiator, counterparty))
}

fn substitute_transfer_fee_proof(finalize: &Finalize) -> Result<Finalize> {
    let mut proofs = finalize
        .signed_tx
        .ops_proofs()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let Some(OpProof::ZkSig(original)) = proofs.get(2) else {
        anyhow::bail!("funded CACP transaction has no Transfer ZkSig proof");
    };
    let mut bytes = original.encode_to_vec();
    let first = bytes.first_mut().context("Transfer proof is empty")?;
    *first ^= 1;
    let (remaining, substituted) = ZkSignature::decode(&bytes)?;
    ensure!(remaining.is_empty());
    proofs[2] = OpProof::ZkSig(substituted);
    Ok(Finalize {
        signed_tx: SignedMantleTx::new(
            finalize.signed_tx.mantle_tx().clone(),
            OpsProofs::try_from(proofs)?,
        ),
    })
}

async fn happy_path(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(1, "happy path");
    let (mut a, mut b) = funded_phase_three(network, nonce).await?;
    let tx = a
        .signed_tx()
        .context("missing Phase-3 transaction")?
        .clone();
    assert_live_shape(&tx)?;
    let expected = inscription_tips(&tx)?;
    network.node.post_transaction(tx).await?;
    wait_for_tips(&network.node, expected).await?;
    a.mark_submitted()?;
    b.mark_submitted()?;
    println!(
        "  PASS: Sequencer A submitted; Bedrock advanced both participant channels atomically"
    );
    Ok(())
}

async fn fallback_submission(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(2, "Phase 3 fallback submission by Sequencer B");
    let (_a, mut b) = funded_phase_three(network, nonce).await?;
    let TimeoutOutcome::FallbackSubmission(tx) = b.on_timeout() else {
        anyhow::bail!("B did not retain the fully signed fallback transaction");
    };
    let expected = inscription_tips(&tx)?;
    network.node.post_transaction(tx).await?;
    wait_for_tips(&network.node, expected).await?;
    b.mark_submitted()?;
    println!(
        "  PASS: A stalled after Phase 3; B posted the identical transaction over Bedrock HTTP"
    );
    Ok(())
}

async fn safe_abort(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(3, "safe abort before Phase 3");
    let before = network.parents().await?;
    let intent = LiveNetwork::intent(nonce)?;
    let topology = network.topology(&intent)?;
    let mut a = InitiatorSession::new(topology, intent, before)?;
    ensure!(a.on_timeout() == TimeoutOutcome::Aborted);
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(network.parents().await? == before);
    println!(
        "  PASS: no fully signed tx was created or posted; both Bedrock tips stayed unchanged"
    );
    Ok(())
}

async fn stale_parent_rejection(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(4, "stale parent atomically rejects both inscriptions");
    let (a, _b) = funded_phase_three(network, nonce).await?;
    let stale_tx = a
        .signed_tx()
        .context("missing signed stale candidate")?
        .clone();
    let stale_expected = inscription_tips(&stale_tx)?;

    // Advance the live channel tips with another fully signed CACP transaction. This keeps the
    // setup valid for the current sequencer block format instead of injecting an arbitrary
    // inscription payload that the participant services cannot decode.
    let fresh_nonce = nonce.checked_add(10_000).context("fresh nonce overflow")?;
    let (fresh_a, _fresh_b) = funded_phase_three(network, fresh_nonce).await?;
    let fresh_tx = fresh_a
        .signed_tx()
        .context("missing signed fresh candidate")?
        .clone();
    let fresh_expected = inscription_tips(&fresh_tx)?;
    network.node.post_transaction(fresh_tx).await?;
    wait_for_tips(&network.node, fresh_expected).await?;

    let before_submit = network.parents().await?;
    network.node.post_transaction(stale_tx).await?;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let after = network.parents().await?;
    ensure!(
        after == before_submit,
        "a stale joint tx changed a channel tip"
    );
    ensure!(after[0].parent != stale_expected[0].1);
    ensure!(after[1].parent != stale_expected[1].1);
    println!("  PASS: after the parents changed, the old joint tx advanced neither A nor B");
    Ok(())
}

async fn automatic_forfeiture(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(5, "costly escalation fees and stake forfeiture");
    run_counterparty_response(network, nonce).await?;
    let initiator_response_nonce = nonce.checked_add(1).context("scenario nonce overflow")?;
    let counterparty_forfeit_nonce = nonce.checked_add(2).context("scenario nonce overflow")?;
    let initiator_forfeit_nonce = nonce.checked_add(3).context("scenario nonce overflow")?;
    run_initiator_response(network, initiator_response_nonce).await?;
    run_counterparty_forfeit(network, counterparty_forfeit_nonce).await?;
    run_initiator_forfeit(network, initiator_forfeit_nonce).await?;
    println!(
        "  PASS: valid responders paid the zone, neither participant profited, and unanswered challenges forfeited only stake"
    );
    Ok(())
}

async fn run_counterparty_response(network: &LiveNetwork, nonce: u64) -> Result<()> {
    let evidence = bond_evidence(network, nonce).await?;
    let balances_before = participant_balances(network).await?;
    let burn_before = burn_balance(network).await?;
    open_and_join_bond(network, &evidence).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::ChallengeAccept {
            agreement_id: evidence.agreement_id,
        },
    )
    .await?;
    let b_proof = counterparty_proof(network, &evidence);
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_b,
        BondInstruction::DiscloseAccept {
            agreement_id: evidence.agreement_id,
            proof: b_proof.clone(),
        },
    )
    .await?;
    ensure!(
        bond_state(network, evidence.agreement_id).await?.phase
            == cacp_bond_core::Phase::AwaitingFinalize
    );
    let a_proof = MantleSignature::new(network.key_a.sign_payload(&evidence.tx_hash).to_bytes());
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::Complete {
            agreement_id: evidence.agreement_id,
            initiator_proof: a_proof,
            counterparty_proof: b_proof,
        },
    )
    .await?;
    assert_escalation_balances(
        network,
        evidence.agreement_id,
        balances_before,
        burn_before,
        CHALLENGE_FEE,
        RESPONSE_FEE,
    )
    .await
}

async fn run_initiator_response(network: &LiveNetwork, nonce: u64) -> Result<()> {
    let evidence = bond_evidence(network, nonce).await?;
    let balances_before = participant_balances(network).await?;
    let burn_before = burn_balance(network).await?;
    open_and_join_bond(network, &evidence).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_b,
        BondInstruction::ChallengeFinalize {
            agreement_id: evidence.agreement_id,
            accept_proof: counterparty_proof(network, &evidence),
        },
    )
    .await?;
    let a_proof = MantleSignature::new(network.key_a.sign_payload(&evidence.tx_hash).to_bytes());
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::DiscloseFinalize {
            agreement_id: evidence.agreement_id,
            proof: a_proof,
        },
    )
    .await?;
    assert_escalation_balances(
        network,
        evidence.agreement_id,
        balances_before,
        burn_before,
        RESPONSE_FEE,
        CHALLENGE_FEE,
    )
    .await
}

async fn open_and_join_bond(network: &LiveNetwork, evidence: &BondEvidence) -> Result<()> {
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::Open {
            agreement: evidence.agreement.clone(),
        },
    )
    .await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_b,
        BondInstruction::Join {
            agreement_id: evidence.agreement_id,
        },
    )
    .await
}

async fn assert_escalation_balances(
    network: &LiveNetwork,
    agreement_id: AgreementId,
    before: (u128, u128),
    burn_before: u128,
    a_fee: u128,
    b_fee: u128,
) -> Result<()> {
    ensure!(bond_state(network, agreement_id).await?.settlement == Some(Settlement::Completed));
    let after = participant_balances(network).await?;
    ensure!(after.0 == before.0.checked_sub(a_fee).context("A fee underflow")?);
    ensure!(after.1 == before.1.checked_sub(b_fee).context("B fee underflow")?);
    let collected = a_fee.checked_add(b_fee).context("fee total overflow")?;
    ensure!(
        burn_balance(network).await?
            == burn_before
                .checked_add(collected)
                .context("burn sink overflow")?
    );
    ensure!(bond_escrow_balance(network, agreement_id).await? == 0);
    Ok(())
}

async fn run_counterparty_forfeit(network: &LiveNetwork, nonce: u64) -> Result<()> {
    // B creates and commits ACCEPT but deliberately does not deliver it to A.
    let evidence = bond_evidence(network, nonce).await?;
    let balances_before = participant_balances(network).await?;
    let burn_before = burn_balance(network).await?;
    open_and_join_bond(network, &evidence).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::ChallengeAccept {
            agreement_id: evidence.agreement_id,
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.agreement_id).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_a,
        BondInstruction::SettleTimeout {
            agreement_id: evidence.agreement_id,
        },
    )
    .await?;
    ensure!(
        bond_state(network, evidence.agreement_id).await?.settlement
            == Some(Settlement::CounterpartyForfeited)
    );
    let balances_after = participant_balances(network).await?;
    let expected_a = balances_before
        .0
        .checked_add(STAKE)
        .and_then(|amount| amount.checked_sub(CHALLENGE_FEE))
        .context("A forfeiture payout overflow")?;
    ensure!(balances_after.0 == expected_a);
    ensure!(balances_after.1.checked_add(STAKE) == Some(balances_before.1));
    ensure!(
        burn_balance(network).await?
            == burn_before
                .checked_add(CHALLENGE_FEE)
                .context("burn sink overflow")?
    );
    ensure!(bond_escrow_balance(network, evidence.agreement_id).await? == 0);
    Ok(())
}

async fn run_initiator_forfeit(network: &LiveNetwork, nonce: u64) -> Result<()> {
    // A receives B's ACCEPT and creates FINALIZE but deliberately withholds it.
    let evidence = bond_evidence(network, nonce).await?;
    let balances_before = participant_balances(network).await?;
    let burn_before = burn_balance(network).await?;
    open_and_join_bond(network, &evidence).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_b,
        BondInstruction::ChallengeFinalize {
            agreement_id: evidence.agreement_id,
            accept_proof: counterparty_proof(network, &evidence),
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.agreement_id).await?;
    submit_bond(
        network,
        evidence.agreement_id,
        &network.lee_key_b,
        BondInstruction::SettleTimeout {
            agreement_id: evidence.agreement_id,
        },
    )
    .await?;
    ensure!(
        bond_state(network, evidence.agreement_id).await?.settlement
            == Some(Settlement::InitiatorForfeited)
    );
    let balances_after = participant_balances(network).await?;
    ensure!(balances_after.0.checked_add(STAKE) == Some(balances_before.0));
    let expected_b = balances_before
        .1
        .checked_add(STAKE)
        .and_then(|amount| amount.checked_sub(CHALLENGE_FEE))
        .context("B forfeiture payout overflow")?;
    ensure!(balances_after.1 == expected_b);
    ensure!(
        burn_balance(network).await?
            == burn_before
                .checked_add(CHALLENGE_FEE)
                .context("burn sink overflow")?
    );
    ensure!(bond_escrow_balance(network, evidence.agreement_id).await? == 0);
    Ok(())
}

async fn bond_evidence(network: &LiveNetwork, nonce: u64) -> Result<BondEvidence> {
    let intent = LiveNetwork::intent(nonce)?;
    let topology = network.topology(&intent)?;
    let parents = network.parents().await?;
    let raw = cross_zone::cacp::build_joint_tx(&intent, &topology, &parents)?;
    let (funded_tx, funding_proof) = fund_ops(&network.node, raw).await?;
    funding_proof.context("bonded proposal requires its non-EdDSA fee proof")?;
    let hash = funded_tx.hash();
    let tx_hash = *hash.as_ref();
    let agreement = BondAgreement {
        version: AGREEMENT_VERSION,
        initiator: network.account_a,
        counterparty: network.account_b,
        tx_hash,
        initiator_mantle_key: network.key_a.public_key().to_bytes(),
        counterparty_mantle_key: network.key_b.public_key().to_bytes(),
        stake_amount: STAKE,
        challenge_fee: CHALLENGE_FEE,
        response_fee: RESPONSE_FEE,
        response_window_blocks: WINDOW,
    };
    let agreement_id = agreement.id(programs::cacp_bond().id());
    Ok(BondEvidence {
        agreement,
        agreement_id,
        tx_hash,
    })
}

fn counterparty_proof(network: &LiveNetwork, evidence: &BondEvidence) -> MantleSignature {
    MantleSignature::new(network.key_b.sign_payload(&evidence.tx_hash).to_bytes())
}

async fn submit_bond(
    network: &LiveNetwork,
    agreement_id: AgreementId,
    signer: &PrivateKey,
    instruction: BondInstruction,
) -> Result<()> {
    let state = state_account_id(programs::cacp_bond().id(), &agreement_id);
    let escrow = escrow_account_id(programs::cacp_bond().id(), &agreement_id);
    let nonce = network
        .bond_client
        .get_accounts_nonces(vec![network.account_a, network.account_b])
        .await?;
    let signer_id = AccountId::from(&PublicKey::new_from_private_key(signer));
    let signer_nonce = if signer_id == network.account_a {
        nonce[0]
    } else {
        nonce[1]
    };
    let mut accounts = vec![
        network.account_a,
        network.account_b,
        escrow,
        state,
        CLOCK_01_PROGRAM_ACCOUNT_ID,
    ];
    accounts.push(burn_account_id(programs::cacp_bond().id()));
    let message = public_transaction::Message::try_new(
        programs::cacp_bond().id(),
        accounts,
        vec![signer_nonce],
        instruction,
    )?;
    let witness = public_transaction::WitnessSet::for_message(&message, &[signer]);
    let hash = network
        .bond_client
        .send_transaction(LeeTransaction::Public(PublicTransaction::new(
            message, witness,
        )))
        .await?;
    wait_for_lee_tx(&network.bond_client, hash).await
}

async fn bond_state(network: &LiveNetwork, agreement_id: AgreementId) -> Result<BondState> {
    let account = network
        .bond_client
        .get_account(state_account_id(programs::cacp_bond().id(), &agreement_id))
        .await?;
    BondState::from_bytes(&account.data).context("decoding on-chain bond state")
}

async fn participant_balances(network: &LiveNetwork) -> Result<(u128, u128)> {
    Ok((
        network
            .bond_client
            .get_account_balance(network.account_a)
            .await?,
        network
            .bond_client
            .get_account_balance(network.account_b)
            .await?,
    ))
}

async fn burn_balance(network: &LiveNetwork) -> Result<u128> {
    network
        .bond_client
        .get_account_balance(burn_account_id(programs::cacp_bond().id()))
        .await
        .map_err(Into::into)
}

async fn bond_escrow_balance(network: &LiveNetwork, agreement_id: AgreementId) -> Result<u128> {
    network
        .bond_client
        .get_account_balance(escrow_account_id(programs::cacp_bond().id(), &agreement_id))
        .await
        .map_err(Into::into)
}

async fn wait_bond_deadline(network: &LiveNetwork, agreement_id: AgreementId) -> Result<()> {
    let deadline = bond_state(network, agreement_id).await?.expires_at_block;
    let wait = async {
        loop {
            if network.bond_client.get_last_block_id().await? >= deadline {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(TIMEOUT, wait)
        .await
        .context("waiting for bond deadline")?
}

async fn wait_for_lee_tx(client: &SequencerClient, hash: common::HashType) -> Result<()> {
    let wait = async {
        loop {
            if client.get_transaction(hash).await?.is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(TIMEOUT, wait)
        .await
        .context("waiting for bond transaction inclusion")?
}

async fn fund_ops(
    node: &NodeHttpClient,
    tx: RawMantleTx,
) -> Result<(RawMantleTx, Option<OpProof>)> {
    let tx_builder = MantleTxBuilder::new().extend_ops(tx.ops().iter().cloned())?;
    let funded = node
        .fund_tx(WalletFundRequestBody {
            tip: None,
            tx_builder,
            change_public_key: config::bedrock_funding_key(),
            funding_public_keys: vec![config::bedrock_funding_key()],
            max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
            priority_fee: FundingConfig::DEFAULT_PRIORITY_FEE,
        })
        .await?;
    Ok((funded.funded_tx, funded.transfer_proof))
}

fn assert_live_shape(tx: &SignedMantleTx<Unverified>) -> Result<()> {
    ensure!(tx.mantle_tx().ops().len() == 3);
    ensure!(
        tx.mantle_tx().ops()[..2]
            .iter()
            .all(|op| matches!(op, Op::ChannelInscribe(_)))
    );
    ensure!(matches!(tx.mantle_tx().ops()[2], Op::Transfer(_)));
    Ok(())
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "only inscriptions contribute channel tips"
)]
fn inscription_tips(tx: &SignedMantleTx<Unverified>) -> Result<[(ChannelId, MsgId); 2]> {
    let tips = tx
        .mantle_tx()
        .ops()
        .iter()
        .filter_map(|op| match op {
            Op::ChannelInscribe(inscription) => Some((inscription.channel_id, inscription.id())),
            _ => None,
        })
        .collect::<Vec<_>>();
    <[_; 2]>::try_from(tips).map_err(|_error| anyhow::anyhow!("expected exactly two inscriptions"))
}

async fn wait_for_channel(node: &NodeHttpClient, channel: ChannelId) -> Result<()> {
    let wait = async {
        loop {
            if node.channel_state(channel).await?.is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(TIMEOUT, wait)
        .await
        .context("waiting for participant channel")?
}

async fn channel_tip(node: &NodeHttpClient, channel: ChannelId) -> Result<MsgId> {
    node.channel_state(channel)
        .await?
        .map(|state| state.tip_message)
        .with_context(|| format!("Bedrock has no channel {channel:?}"))
}

async fn wait_for_tips(node: &NodeHttpClient, expected: [(ChannelId, MsgId); 2]) -> Result<()> {
    let wait = async {
        loop {
            if channel_tip(node, expected[0].0).await? == expected[0].1
                && channel_tip(node, expected[1].0).await? == expected[1].1
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(TIMEOUT, wait)
        .await
        .context("waiting for atomic Bedrock inclusion")?
}

fn heading(number: u8, title: &str) {
    println!("[{number}/5] {title}");
}

fn channel_a() -> ChannelId {
    ChannelId::from([0xA1; 32])
}

fn channel_b() -> ChannelId {
    ChannelId::from([0xB2; 32])
}
