use kameo::actor::Spawn as _;
use logos_blockchain_core::{
    crypto::ZkHash,
    mantle::{
        channel::{SlotTimeframe, SlotTimeout},
        ledger::{Inputs, NoteId, Outputs},
        ops::{
            channel::{ChannelId, MsgId, VerifiedChannelKeys, withdraw::ChannelWithdrawOp},
            transfer::TransferOp,
        },
    },
};

use super::*;

const CHANNEL: [u8; 32] = [1; 32];
const OWN_SECRET: [u8; 32] = [9; 32];
const PEER_SECRET: [u8; 32] = [8; 32];
/// A four-node committee: Bedrock asks three signatures of the next config.
const COMMITTEE: [[u8; 32]; 4] = [[1; 32], [2; 32], [3; 32], [4; 32]];

/// Stands in for the core, the only thing that can actually submit.
struct SubmitSink(mpsc::UnboundedSender<Submission>);

impl Actor for SubmitSink {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Error> {
        Ok(args)
    }
}

impl Message<SubmitConfig> for SubmitSink {
    type Reply = ();

    async fn handle(
        &mut self,
        SubmitConfig(submission): SubmitConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let _dontcare = self.0.send(*submission);
    }
}

fn key(secret: [u8; 32]) -> Ed25519Key {
    Ed25519Key::from_bytes(&secret)
}

/// Own key first, so this node sits at index 0 of the live committee.
fn live_keys() -> Vec<Ed25519PublicKey> {
    vec![key(OWN_SECRET).public_key(), key(PEER_SECRET).public_key()]
}

fn target() -> ConfigTarget {
    ConfigTarget {
        keys: live_keys(),
        parent: MsgId::root(),
        posting_timeframe: 300,
        posting_timeout: 25,
        configuration_threshold: 2,
        transfer_threshold: 1,
    }
}

/// The view every accredited node derives for itself each turn.
fn view(target: Option<ConfigTarget>) -> ChannelView {
    ChannelView {
        live_keys: live_keys(),
        required_signatures: 2,
        target,
    }
}

/// A transaction carrying exactly the config `target` asks for.
fn draft_tx(target: &ConfigTarget) -> Ops {
    let op = ChannelConfigOp {
        channel: ChannelId::from(CHANNEL),
        parent: target.parent,
        keys: VerifiedChannelKeys::try_from(target.keys.clone()).expect("a non-empty key list"),
        posting_timeframe: SlotTimeframe::from(target.posting_timeframe),
        posting_timeout: SlotTimeout::from(target.posting_timeout),
        configuration_threshold: target.configuration_threshold,
        transfer_threshold: target.transfer_threshold,
    };
    Ops::from([Op::ChannelConfig(op)])
}

fn actor(secret: [u8; 32]) -> ActorRef<ChannelConfigActor> {
    ChannelConfigActor::spawn(ChannelConfigActor::new(key(secret)))
}

async fn tell_view(actor: &ActorRef<ChannelConfigActor>, view: ChannelView) {
    actor
        .tell(view)
        .await
        .expect("the actor should accept a view");
}

async fn publisher(actor: &ActorRef<ChannelConfigActor>) -> mpsc::Receiver<Wire> {
    let (tx, rx) = mpsc::channel(64);
    actor
        .tell(SetPublisher(tx))
        .await
        .expect("the actor should accept a publisher");

    rx
}

/// `PEER_SECRET`'s signature over `tx`, at its index in the live list.
async fn peer_signs(actor: &ActorRef<ChannelConfigActor>, tx: &Ops) {
    let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
    actor
        .tell(Wire::Signature(Signature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        }))
        .await
        .expect("the actor should accept a signature");
}

/// The sink comes back too: the actor holds only a weak reference to it.
async fn submitter(
    actor: &ActorRef<ChannelConfigActor>,
) -> (ActorRef<SubmitSink>, mpsc::UnboundedReceiver<Submission>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let sink = SubmitSink::spawn(SubmitSink(tx));
    actor
        .tell(SetSubmitter(sink.clone().recipient().downgrade()))
        .await
        .expect("the actor should accept a submitter");

    (sink, rx)
}

/// The submission the actor sent, if any; it crosses a second mailbox, so
/// this waits for it.
async fn submitted(wakes: &mut mpsc::UnboundedReceiver<Submission>) -> Option<Submission> {
    tokio::time::timeout(std::time::Duration::from_secs(5), wakes.recv())
        .await
        .ok()
        .flatten()
}

/// Whether the actor stays quiet, which only a wait can tell.
async fn stays_quiet(wakes: &mut mpsc::UnboundedReceiver<Submission>) -> bool {
    tokio::time::timeout(std::time::Duration::from_millis(200), wakes.recv())
        .await
        .is_err()
}

async fn hold(actor: &ActorRef<ChannelConfigActor>, tx: Ops) {
    actor
        .tell(FundedTx {
            target: Box::new(target()),
            tx: Box::new(tx),
            accredited_keys: live_keys(),
            signing_threshold: 2,
        })
        .await
        .expect("the actor should accept a draft");
}

fn committee_keys() -> Vec<Ed25519PublicKey> {
    COMMITTEE
        .iter()
        .map(|secret| key(*secret).public_key())
        .collect()
}

fn committee_target() -> ConfigTarget {
    ConfigTarget {
        keys: committee_keys(),
        parent: MsgId::root(),
        posting_timeframe: 300,
        posting_timeout: 25,
        configuration_threshold: 4,
        transfer_threshold: 1,
    }
}

fn committee_view() -> ChannelView {
    ChannelView {
        live_keys: committee_keys(),
        required_signatures: 3,
        target: Some(committee_target()),
    }
}

/// The config `target` asks for, made unique to `proposer` the way funding
/// from each node's own wallet makes every proposer's transaction unique.
fn rival_tx(target: &ConfigTarget, proposer: u8) -> Ops {
    let mut tx = draft_tx(target);
    tx.try_push(Op::Transfer(TransferOp::new(
        Inputs::new([NoteId(ZkHash::from(u64::from(proposer)))]),
        Outputs::empty(),
    )))
    .expect("a second op fits");

    tx
}

/// Delivers everything each node published to its peers.
async fn route(nodes: &[ActorRef<ChannelConfigActor>], outbound: &mut [mpsc::Receiver<Wire>]) {
    let mut batch = Vec::new();
    for (from, rx) in outbound.iter_mut().enumerate() {
        while let Ok(message) = rx.try_recv() {
            batch.push((from, message));
        }
    }
    for (from, message) in batch {
        for (to, node) in nodes.iter().enumerate() {
            if to == from {
                continue;
            }
            node.ask(message.clone()).await.expect("a gossiped message");
        }
    }
}

/// Four proposers take turns, each funding its own draft, so a peer has to
/// sign every rival for one of them to reach the threshold.
#[tokio::test]
async fn rival_drafts_do_not_strand_the_committee() {
    let nodes: Vec<_> = COMMITTEE.iter().map(|secret| actor(*secret)).collect();
    let mut outbound = Vec::new();
    for node in &nodes {
        outbound.push(publisher(node).await);
    }

    let mut submitted = false;
    let mut ticks = 0;
    // Three full rotations; the state is fixed well before the end.
    for holder in (0..3).flat_map(|_| 0..COMMITTEE.len()) {
        ticks += 1;
        // Production reports on every node each tick, turn or not.
        for node in &nodes {
            node.ask(committee_view()).await.expect("a view");
        }

        match nodes[holder].ask(Propose).await.expect("a reply") {
            Action::Submit(_) => submitted = true,
            Action::Idle => {}
            Action::Build(target) => {
                let tx = rival_tx(&target, u8::try_from(holder).expect("four nodes"));
                nodes[holder]
                    .ask(FundedTx {
                        target,
                        tx: Box::new(tx),
                        accredited_keys: committee_keys(),
                        signing_threshold: 3,
                    })
                    .await
                    .expect("a draft");
                // A single-signer channel would land here; this one cannot.
                if matches!(
                    nodes[holder].ask(Propose).await.expect("a reply"),
                    Action::Submit(_)
                ) {
                    submitted = true;
                }
            }
        }
        // The draft out to the peers, then their signatures back.
        route(&nodes, &mut outbound).await;
        route(&nodes, &mut outbound).await;

        if submitted {
            break;
        }
    }

    assert!(submitted, "no draft ever reached the threshold");
    // Peers sign the first draft as soon as they see it, so its
    // proposer submits on its very next turn.
    assert_eq!(
        ticks,
        COMMITTEE.len() + 1,
        "the first draft was not the one submitted"
    );
}

#[test]
fn a_draft_survives_the_wire() {
    let sent = Wire::Draft(Draft {
        tx: Box::new(draft_tx(&target())),
    });
    let Some(Wire::Draft(got)) = Wire::decode(&sent.encode()) else {
        panic!("expected a draft back");
    };

    assert_eq!(got.tx.hash().0, draft_tx(&target()).hash().0);
}

#[test]
fn a_signature_survives_the_wire() {
    let tx = draft_tx(&target());
    let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
    let sent = Wire::Signature(Signature {
        tx_hash: tx.hash().0,
        signature: IndexedSignature::new(1, signature),
    });
    let Some(Wire::Signature(got)) = Wire::decode(&sent.encode()) else {
        panic!("expected a signature back");
    };

    assert_eq!(got.tx_hash, tx.hash().0);
    assert_eq!(got.signature, IndexedSignature::new(1, signature));
}

#[test]
fn junk_off_the_wire_is_not_a_message() {
    // A tag this build does not know, an empty frame, and a signature
    // frame too short to carry the hash it needs.
    assert!(Wire::decode(&[]).is_none());
    assert!(Wire::decode(&[99, 1, 2, 3]).is_none());
    assert!(Wire::decode(&[1, 0, 0]).is_none());
}

#[tokio::test]
async fn nothing_is_proposed_while_live_already_matches() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(None)).await;

    assert!(matches!(
        actor.ask(Propose).await.expect("a reply"),
        Action::Idle
    ));
}

#[tokio::test]
async fn a_target_with_no_draft_asks_for_one_to_be_built() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;

    let Action::Build(asked) = actor.ask(Propose).await.expect("a reply") else {
        panic!("expected a build request");
    };
    assert_eq!(*asked, target());
}

#[tokio::test]
async fn a_draft_alone_is_under_the_threshold() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;
    hold(&actor, draft_tx(&target())).await;

    assert!(
        matches!(outbound.recv().await, Some(Wire::Draft(_))),
        "a new draft should be announced"
    );
    assert!(
        matches!(actor.ask(Propose).await.expect("a reply"), Action::Idle),
        "one of two signatures is not enough to submit"
    );
}

/// Peers sign every copy of a draft they see, so one funding is one
/// announcement.
#[tokio::test]
async fn funding_a_draft_announces_it_once_and_answers_like_propose() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    let action = actor
        .ask(FundedTx {
            target: Box::new(target()),
            tx: Box::new(draft_tx(&target())),
            accredited_keys: live_keys(),
            signing_threshold: 2,
        })
        .await
        .expect("a reply");

    assert!(
        matches!(action, Action::Idle),
        "one of two signatures is not enough to submit"
    );
    assert!(
        matches!(outbound.recv().await, Some(Wire::Draft(_))),
        "the draft should be announced"
    );
    assert!(
        outbound.try_recv().is_err(),
        "funding should announce the draft exactly once"
    );
}

#[tokio::test]
async fn a_peer_signature_carries_the_draft_over_the_threshold() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let tx = draft_tx(&target());
    hold(&actor, tx.clone()).await;

    // The peer signs the same funded transaction, at its own index.
    let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
    actor
        .tell(Wire::Signature(Signature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        }))
        .await
        .expect("the actor should accept a signature");

    assert!(matches!(
        actor.ask(Propose).await.expect("a reply"),
        Action::Submit(_)
    ));
}

#[tokio::test]
async fn a_submission_carries_exactly_the_threshold_in_index_order() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let tx = draft_tx(&target());
    hold(&actor, tx.clone()).await;
    let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
    actor
        .tell(Wire::Signature(Signature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        }))
        .await
        .expect("the actor should accept a signature");

    let Action::Submit(submission) = actor.ask(Propose).await.expect("a reply") else {
        panic!("two of two signatures should submit");
    };

    assert_eq!(submission.tx_hash, tx.hash().0);
    let indices: Vec<u16> = submission
        .signatures
        .iter()
        .map(|indexed| indexed.channel_key_index)
        .collect();
    assert_eq!(indices, vec![0, 1]);
}

#[tokio::test]
async fn the_signature_that_meets_the_threshold_wakes_the_submitter() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let (_sink, mut wakes) = submitter(&actor).await;
    let tx = draft_tx(&target());
    hold(&actor, tx.clone()).await;

    // Our own signature is one of two, so there is nothing to submit yet.
    assert!(stays_quiet(&mut wakes).await);

    peer_signs(&actor, &tx).await;

    let submission = submitted(&mut wakes)
        .await
        .expect("the draft has its threshold and must not wait for a turn");
    assert_eq!(submission.tx_hash, tx.hash().0);
    let indices: Vec<u16> = submission
        .signatures
        .iter()
        .map(|indexed| indexed.channel_key_index)
        .collect();
    assert_eq!(indices, vec![0, 1]);
}

#[tokio::test]
async fn a_signature_short_of_the_threshold_does_not_wake_the_submitter() {
    // Three of four, so our own plus one peer is still short.
    let actor = actor(COMMITTEE[0]);
    tell_view(&actor, committee_view()).await;
    let (_sink, mut wakes) = submitter(&actor).await;
    let tx = draft_tx(&committee_target());
    actor
        .tell(FundedTx {
            target: Box::new(committee_target()),
            tx: Box::new(tx.clone()),
            accredited_keys: committee_keys(),
            signing_threshold: 3,
        })
        .await
        .expect("the actor should accept a draft");

    let signature = key(COMMITTEE[1]).sign_payload(tx.hash().as_signing_bytes().as_ref());
    actor
        .tell(Wire::Signature(Signature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        }))
        .await
        .expect("the actor should accept a signature");

    assert!(stays_quiet(&mut wakes).await);
}

#[tokio::test]
async fn a_signature_past_the_threshold_does_not_wake_the_submitter_again() {
    let actor = actor(COMMITTEE[0]);
    tell_view(&actor, committee_view()).await;
    let (_sink, mut wakes) = submitter(&actor).await;
    let tx = draft_tx(&committee_target());
    actor
        .tell(FundedTx {
            target: Box::new(committee_target()),
            tx: Box::new(tx.clone()),
            accredited_keys: committee_keys(),
            signing_threshold: 3,
        })
        .await
        .expect("the actor should accept a draft");

    // Ours plus two peers is the threshold; the fourth key is spare.
    for (index, secret) in [(1_u16, COMMITTEE[1]), (2, COMMITTEE[2]), (3, COMMITTEE[3])] {
        let signature = key(secret).sign_payload(tx.hash().as_signing_bytes().as_ref());
        actor
            .tell(Wire::Signature(Signature {
                tx_hash: tx.hash().0,
                signature: IndexedSignature::new(index, signature),
            }))
            .await
            .expect("the actor should accept a signature");
    }

    assert!(
        submitted(&mut wakes).await.is_some(),
        "the threshold was crossed"
    );
    assert!(
        stays_quiet(&mut wakes).await,
        "the spare signature changes nothing and must not wake it again"
    );
}

#[tokio::test]
async fn a_reset_draft_is_funded_again() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let tx = draft_tx(&target());
    hold(&actor, tx.clone()).await;
    peer_signs(&actor, &tx).await;

    actor.tell(Reset).await.expect("the actor should reset");

    let action = actor.ask(Propose).await.expect("a reply");
    assert!(
        matches!(action, Action::Build(_)),
        "the signatures covered a transaction the core has given up on"
    );
}

#[tokio::test]
async fn a_draft_funded_off_another_view_is_dropped() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    // zone-sdk chained the config on a tip this node does not see.
    let stale = ConfigTarget {
        parent: MsgId::from([7; 32]),
        ..target()
    };
    let action = actor
        .ask(FundedTx {
            target: Box::new(target()),
            tx: Box::new(draft_tx(&stale)),
            accredited_keys: live_keys(),
            signing_threshold: 2,
        })
        .await
        .expect("a reply");

    assert!(matches!(action, Action::Idle));
    assert!(
        outbound.try_recv().is_err(),
        "a draft that cannot land must not be announced"
    );
}

#[tokio::test]
async fn a_signature_that_does_not_verify_is_dropped() {
    let actor = actor(OWN_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let tx = draft_tx(&target());
    hold(&actor, tx.clone()).await;

    // Correctly signed by the peer, but over bytes that are not this
    // draft, then claimed against it.
    let signature = key(PEER_SECRET).sign_payload(&[0xAB; 32]);
    actor
        .tell(Wire::Signature(Signature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        }))
        .await
        .expect("the actor should accept a signature");

    assert!(
        matches!(actor.ask(Propose).await.expect("a reply"), Action::Idle),
        "a signature that does not verify must not count"
    );
}

#[tokio::test]
async fn a_peer_signs_the_config_it_wanted_anyway() {
    let actor = actor(PEER_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    actor
        .tell(Wire::Draft(Draft {
            tx: Box::new(draft_tx(&target())),
        }))
        .await
        .expect("the actor should accept a peer draft");

    assert!(matches!(outbound.recv().await, Some(Wire::Signature(_))));
}

#[tokio::test]
async fn a_peer_does_not_sign_a_config_it_did_not_ask_for() {
    let actor = actor(PEER_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    // Same shape, but installing a committee this node never derived.
    let mut rogue = target();
    rogue.keys = vec![key(PEER_SECRET).public_key()];
    actor
        .ask(Wire::Draft(Draft {
            tx: Box::new(draft_tx(&rogue)),
        }))
        .await
        .expect("the actor should accept a peer draft");

    assert!(
        outbound.try_recv().is_err(),
        "a peer is trusted for its signature, never for the config"
    );
}

#[tokio::test]
async fn every_matching_rival_draft_is_signed() {
    let actor = actor(PEER_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    // Three proposers funding the same config from their own wallets.
    for proposer in 0..3 {
        actor
            .tell(Wire::Draft(Draft {
                tx: Box::new(rival_tx(&target(), proposer)),
            }))
            .await
            .expect("the actor should accept a peer draft");
        assert!(
            matches!(outbound.recv().await, Some(Wire::Signature(_))),
            "rival {proposer} should have been signed"
        );
    }
}

/// The same signatures satisfy a withdraw sitting beside the config, so
/// what else the transaction carries has to be checked too.
#[tokio::test]
async fn a_draft_bundling_a_withdrawal_is_not_signed() {
    let actor = actor(PEER_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    let mut tx = draft_tx(&target());
    tx.try_push(Op::ChannelWithdraw(ChannelWithdrawOp {
        channel_id: ChannelId::from(CHANNEL),
        inputs: Inputs::new([NoteId(ZkHash::from(7_u64))]),
    }))
    .expect("a second op fits");
    actor
        .ask(Wire::Draft(Draft { tx: Box::new(tx) }))
        .await
        .expect("the actor should accept a peer draft");

    assert!(
        outbound.try_recv().is_err(),
        "the config is what we checked; we must not sign anything else"
    );
}

#[tokio::test]
async fn a_draft_carrying_two_configs_is_not_signed() {
    let actor = actor(PEER_SECRET);
    tell_view(&actor, view(Some(target()))).await;
    let mut outbound = publisher(&actor).await;

    let mut tx = draft_tx(&target());
    let Some(Op::ChannelConfig(config)) = tx.iter().next().cloned() else {
        unreachable!("the first op is the config")
    };
    tx.try_push(Op::ChannelConfig(config))
        .expect("a second op fits");
    actor
        .ask(Wire::Draft(Draft { tx: Box::new(tx) }))
        .await
        .expect("the actor should accept a peer draft");

    assert!(
        outbound.try_recv().is_err(),
        "a transaction must carry exactly one config to be signed"
    );
}
