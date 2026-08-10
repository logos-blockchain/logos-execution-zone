#![allow(clippy::print_stdout, reason = "the demo reports verified scenarios")]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use cacp_bond_core::{
    BondState, Instruction as BondInstruction, MantleSignature, Settlement, escrow_account_id,
    proof_commitment, state_account_id,
};
use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use common::transaction::LeeTransaction;
use cross_zone::cacp::{
    ChannelParent, CostlyAbortBondTerms, CounterpartySession, CrossZoneIntent, InitiatorSession,
    InscribeIntent, Phase, TimeoutOutcome, TwoZoneTopology, ZoneSequencer,
};
use lee::{AccountId, PrivateKey, PublicKey, PublicTransaction, public_transaction};
use logos_blockchain_core::mantle::{
    SignedMantleTx,
    gas::GasCost,
    ops::{
        Op, OpProof,
        channel::{
            ChannelId, MsgId,
            inscribe::{Inscription, InscriptionOp},
        },
    },
    traits::Hashable as _,
    transactions::{MantleTx, MantleTxBuilder, OpsProofs, states::Unverified},
};
use logos_blockchain_http_api_common::bodies::wallet::fund::WalletFundRequestBody;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    sequencer::FundingConfig,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    TestContext,
    config::{self, SequencerPartialConfig},
    setup::{SequencerSetup, sequencer_client},
};

const KEY_A: [u8; 32] = [0xA1; 32];
const KEY_B: [u8; 32] = [0xB2; 32];
const STAKE: u128 = 1_000;
const CHALLENGE_BOND: u128 = 100;
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

#[tokio::main]
async fn main() -> Result<()> {
    println!("CACP + protocol-enforced costly-abort live demo");
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

impl LiveNetwork {
    async fn start() -> Result<Self> {
        let bond = TestContext::builder()
            .disable_indexer()
            .from_scratch()
            .with_sequencer_partial_config(SequencerPartialConfig {
                // Live wallet initialization proves several transactions. A moderate interval
                // preserves the shared Bedrock fee fixture before participant zones start.
                block_create_timeout: Duration::from_secs(5),
                ..SequencerPartialConfig::default()
            })
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
            .map_err(|_| anyhow::anyhow!("fixture must provide two public accounts"))?;
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

    fn intent(&self, nonce: u64) -> Result<CrossZoneIntent> {
        CrossZoneIntent::new(
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
        )?
        .with_costly_abort_bond(CostlyAbortBondTerms {
            bond_zone: config::bedrock_channel_id(),
            bond_program_id: programs::cacp_bond().id(),
            stake_amount: STAKE,
            challenge_bond: CHALLENGE_BOND,
            response_window_blocks: WINDOW,
        })
        .map_err(Into::into)
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

async fn funded_phase_three(
    network: &LiveNetwork,
    nonce: u64,
) -> Result<(InitiatorSession, CounterpartySession)> {
    let intent = network.intent(nonce)?;
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
    counterparty.receive_finalize(finalize)?;
    ensure!(initiator.phase() == Phase::SignaturesExchanged);
    ensure!(counterparty.phase() == Phase::SignaturesExchanged);
    Ok((initiator, counterparty))
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
    let intent = network.intent(nonce)?;
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
    post_single_inscription(network, channel_a(), &network.key_a, b"advance A parent").await?;
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
    println!("  PASS: after A's parent changed, the old joint tx advanced neither A nor B");
    Ok(())
}

async fn automatic_forfeiture(network: &LiveNetwork, nonce: u64) -> Result<()> {
    heading(5, "program-enforced stake forfeiture");
    run_counterparty_forfeit(network, nonce).await?;
    run_initiator_forfeit(network, nonce + 1).await?;
    println!(
        "  PASS: both A-abort and B-abort paths were settled by cacp_bond with no resolver key"
    );
    Ok(())
}

async fn run_counterparty_forfeit(network: &LiveNetwork, nonce: u64) -> Result<()> {
    let evidence = bond_evidence(network, nonce).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_a,
        BondInstruction::Open {
            proposal_id: evidence.proposal,
            counterparty: network.account_b,
            initiator_mantle_key: network.key_a.public_key().to_bytes(),
            counterparty_mantle_key: network.key_b.public_key().to_bytes(),
            stake_amount: STAKE,
            challenge_bond: CHALLENGE_BOND,
            response_window_blocks: WINDOW,
        },
    )
    .await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_b,
        BondInstruction::Join {
            proposal_id: evidence.proposal,
            tx_hash: evidence.tx_hash,
            accept_commitment: proof_commitment(&evidence.b_proof),
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.proposal).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_a,
        BondInstruction::ChallengeAccept {
            proposal_id: evidence.proposal,
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.proposal).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_a,
        BondInstruction::SettleTimeout {
            proposal_id: evidence.proposal,
        },
    )
    .await?;
    ensure!(
        bond_state(network, evidence.proposal).await?.settlement
            == Some(Settlement::CounterpartyForfeited)
    );
    Ok(())
}

async fn run_initiator_forfeit(network: &LiveNetwork, nonce: u64) -> Result<()> {
    let evidence = bond_evidence(network, nonce).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_a,
        BondInstruction::Open {
            proposal_id: evidence.proposal,
            counterparty: network.account_b,
            initiator_mantle_key: network.key_a.public_key().to_bytes(),
            counterparty_mantle_key: network.key_b.public_key().to_bytes(),
            stake_amount: STAKE,
            challenge_bond: CHALLENGE_BOND,
            response_window_blocks: WINDOW,
        },
    )
    .await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_b,
        BondInstruction::Join {
            proposal_id: evidence.proposal,
            tx_hash: evidence.tx_hash,
            accept_commitment: proof_commitment(&evidence.b_proof),
        },
    )
    .await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_b,
        BondInstruction::DiscloseAccept {
            proposal_id: evidence.proposal,
            proof: evidence.b_proof,
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.proposal).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_b,
        BondInstruction::ChallengeFinalize {
            proposal_id: evidence.proposal,
        },
    )
    .await?;
    wait_bond_deadline(network, evidence.proposal).await?;
    submit_bond(
        network,
        evidence.proposal,
        &network.lee_key_b,
        BondInstruction::SettleTimeout {
            proposal_id: evidence.proposal,
        },
    )
    .await?;
    ensure!(
        bond_state(network, evidence.proposal).await?.settlement
            == Some(Settlement::InitiatorForfeited)
    );
    Ok(())
}

struct BondEvidence {
    proposal: [u8; 32],
    tx_hash: [u8; 32],
    b_proof: MantleSignature,
}

async fn bond_evidence(network: &LiveNetwork, nonce: u64) -> Result<BondEvidence> {
    let intent = network.intent(nonce)?;
    let tx = cross_zone::cacp::build_joint_tx(
        &intent,
        &network.topology(&intent)?,
        &network.parents().await?,
    )?;
    let hash = tx.hash();
    let tx_hash = *hash.as_ref();
    Ok(BondEvidence {
        proposal: intent.proposal_id().0,
        tx_hash,
        b_proof: MantleSignature::new(
            network
                .key_b
                .sign_payload(hash.as_signing_bytes().as_ref())
                .to_bytes(),
        ),
    })
}

async fn submit_bond(
    network: &LiveNetwork,
    proposal: [u8; 32],
    signer: &PrivateKey,
    instruction: BondInstruction,
) -> Result<()> {
    let state = state_account_id(programs::cacp_bond().id(), &proposal);
    let escrow = escrow_account_id(programs::cacp_bond().id(), &proposal);
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
    let message = public_transaction::Message::try_new(
        programs::cacp_bond().id(),
        vec![
            network.account_a,
            network.account_b,
            escrow,
            state,
            CLOCK_01_PROGRAM_ACCOUNT_ID,
        ],
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

async fn bond_state(network: &LiveNetwork, proposal: [u8; 32]) -> Result<BondState> {
    let account = network
        .bond_client
        .get_account(state_account_id(programs::cacp_bond().id(), &proposal))
        .await?;
    BondState::from_bytes(&account.data).context("decoding on-chain bond state")
}

async fn wait_bond_deadline(network: &LiveNetwork, proposal: [u8; 32]) -> Result<()> {
    let deadline = bond_state(network, proposal).await?.expires_at_block;
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

async fn fund_ops(node: &NodeHttpClient, tx: MantleTx) -> Result<(MantleTx, Option<OpProof>)> {
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

async fn post_single_inscription(
    network: &LiveNetwork,
    channel: ChannelId,
    key: &Ed25519Key,
    payload: &[u8],
) -> Result<()> {
    let parent = channel_tip(&network.node, channel).await?;
    let inscription = Inscription::try_from(payload.to_vec())?;
    let raw = MantleTxBuilder::new()
        .extend_ops([Op::ChannelInscribe(InscriptionOp {
            channel_id: channel,
            inscription,
            parent,
            signer: key.public_key(),
        })])?
        .build()?;
    let (tx, transfer_proof) = fund_ops(&network.node, raw).await?;
    let mut proofs: OpsProofs =
        OpProof::Ed25519Sig(key.sign_payload(tx.hash().as_signing_bytes().as_ref())).into();
    proofs.try_push(transfer_proof.context("missing fee proof")?)?;
    let signed = SignedMantleTx::new(tx, proofs);
    let expected = signed
        .mantle_tx()
        .ops()
        .iter()
        .find_map(|op| match op {
            Op::ChannelInscribe(inscription) => Some(inscription.id()),
            _ => None,
        })
        .context("missing inscription")?;
    network.node.post_transaction(signed).await?;
    wait_for_tip(&network.node, channel, expected).await
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
    <[_; 2]>::try_from(tips).map_err(|_| anyhow::anyhow!("expected exactly two inscriptions"))
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

async fn wait_for_tip(node: &NodeHttpClient, channel: ChannelId, expected: MsgId) -> Result<()> {
    let wait = async {
        loop {
            if channel_tip(node, channel).await? == expected {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::time::timeout(TIMEOUT, wait)
        .await
        .context("waiting for Bedrock inclusion")?
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
