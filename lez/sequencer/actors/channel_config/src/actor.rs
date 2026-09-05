use std::collections::BTreeMap;

use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
use log::{debug, warn};
use logos_blockchain_core::{
    mantle::{
        SignedMantleTx,
        ops::{
            Op, OpProof,
            channel::{Ed25519PublicKey, MsgId, config::ChannelConfigOp},
        },
        traits::Hashable as _,
        transactions::{OpsProofs, mantle_tx::MantleTx as _, mantle_tx::RawMantleTx},
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignature},
};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, Ed25519Signature};
use tokio::sync::mpsc;

use crate::{
    error::Error,
    protocol::{
        Candidate, ConfigTarget, Outbound, PeerCandidate, PeerSignature, Propose, Proposed, Report,
        SetPublisher,
    },
};

/// A candidate this node funded and is collecting signatures for.
struct Held {
    target: ConfigTarget,
    tx: RawMantleTx,
    /// The fee transfer's proof, reattached when the candidate is assembled.
    transfer_proof: Option<OpProof>,
    tx_hash: [u8; 32],
    /// Signatures by accredited-key index, so the choice below is ordered.
    signatures: BTreeMap<u16, Ed25519Signature>,
}

pub struct ChannelConfigActor {
    signing_key: Ed25519Key,
    own_key: Ed25519PublicKey,
    /// The live channel and the committee it should have, as of the last turn.
    report: Option<Report>,
    /// Our own candidate. Not persisted: a signature is only good for one
    /// funded transaction, and a restart funds a different one.
    candidate: Option<Held>,
    /// The candidate this node signed for a peer, and the tip it chained on.
    /// One signature per tip, so two rival configs never both carry ours.
    signed: Option<(MsgId, [u8; 32])>,
    publisher: Option<mpsc::Sender<Outbound>>,
}

impl ChannelConfigActor {
    #[must_use]
    pub fn new(signing_key: Ed25519Key) -> Self {
        let own_key = signing_key.public_key();

        Self {
            signing_key,
            own_key,
            report: None,
            candidate: None,
            signed: None,
            publisher: None,
        }
    }

    /// Best effort: without gossip this node only ever has its own signature.
    fn publish(&self, outbound: Outbound) {
        if let Some(publisher) = &self.publisher
            && publisher.try_send(outbound).is_err()
        {
            debug!("Dropped an outbound channel-config message");
        }
    }

    /// This node's index in the live accredited list, which is what a
    /// signature names.
    fn own_index(&self) -> Option<u16> {
        let report = self.report.as_ref()?;
        let index = report.live_keys.iter().position(|key| *key == self.own_key)?;

        u16::try_from(index).ok()
    }

    fn sign(&self, tx: &RawMantleTx) -> Ed25519Signature {
        self.signing_key
            .sign_payload(tx.hash().as_signing_bytes().as_ref())
    }
}

impl Actor for ChannelConfigActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Error> {
        Ok(args)
    }
}

impl Message<Report> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: Report, _ctx: &mut Context<Self, Self::Reply>) {
        // A candidate is bound to one target on one tip; either moving kills it.
        if self
            .candidate
            .as_ref()
            .is_some_and(|held| msg.target.as_ref() != Some(&held.target))
        {
            self.candidate = None;
        }
        // Signing memory is per tip: once a config lands, the next one is a
        // fresh decision rather than a rival of what we already signed.
        let parent = msg.target.as_ref().map(|target| target.parent);
        if self.signed.is_some_and(|(tip, _)| Some(tip) != parent) {
            self.signed = None;
        }
        self.report = Some(msg);
    }
}

impl Message<Propose> for ChannelConfigActor {
    type Reply = Proposed;

    async fn handle(&mut self, Propose: Propose, _ctx: &mut Context<Self, Self::Reply>) -> Proposed {
        let Some(report) = &self.report else {
            return Proposed::Idle;
        };
        let Some(target) = &report.target else {
            return Proposed::Idle;
        };
        let Some(held) = &self.candidate else {
            return Proposed::Build(Box::new(target.clone()));
        };
        if held.target != *target {
            return Proposed::Build(Box::new(target.clone()));
        }

        let required = usize::from(report.required_signatures);
        if held.signatures.len() < required {
            // Re-announce: a peer that was down when we first published still
            // has to see the candidate to sign it.
            self.publish(Outbound::Candidate(PeerCandidate {
                tx: Box::new(held.tx.clone()),
            }));

            return Proposed::Idle;
        }

        // Bedrock wants exactly the threshold, never more, so take the lowest
        // indices and leave the rest.
        let signatures: Vec<IndexedSignature> = held
            .signatures
            .iter()
            .take(required)
            .map(|(index, signature)| IndexedSignature::new(*index, *signature))
            .collect();
        let Ok(signatures) = signatures.try_into() else {
            warn!("Too many channel-config signatures to prove");
            return Proposed::Idle;
        };
        let Ok(proof) = ChannelMultiSigProof::try_new(signatures) else {
            warn!("Failed to assemble the channel-config multi-sig proof");
            return Proposed::Idle;
        };

        let mut ops_proofs: OpsProofs = OpProof::ChannelMultiSigProof(proof).into();
        if let Some(transfer_proof) = held.transfer_proof.clone()
            && ops_proofs.try_push(transfer_proof).is_err()
        {
            warn!("Too many operation proofs for the channel-config transaction");
            return Proposed::Idle;
        }

        Proposed::Submit(Box::new(SignedMantleTx::new(held.tx.clone(), ops_proofs)))
    }
}

impl Message<Candidate> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: Candidate, _ctx: &mut Context<Self, Self::Reply>) {
        let Candidate {
            target,
            tx,
            transfer_proof,
        } = msg;
        let Some(index) = self.own_index() else {
            warn!("Not in the live accredited list; dropping our channel-config candidate");
            return;
        };
        let signature = self.sign(&tx);
        let tx_hash = tx.hash().0;

        self.candidate = Some(Held {
            target: *target,
            tx: *tx.clone(),
            transfer_proof,
            tx_hash,
            signatures: BTreeMap::from([(index, signature)]),
        });
        self.publish(Outbound::Candidate(PeerCandidate { tx }));
    }
}

impl Message<PeerCandidate> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerCandidate, _ctx: &mut Context<Self, Self::Reply>) {
        // A peer is trusted for its signature, never for the config: sign only
        // what this node derived from finalized state for itself.
        let Some(report) = &self.report else {
            return;
        };
        let Some(target) = &report.target else {
            return;
        };
        let Some(op) = config_op(&msg.tx) else {
            return;
        };
        if !matches(target, op) {
            debug!("Ignoring a channel-config candidate that is not the config we want");
            return;
        }

        let tx_hash = msg.tx.hash().0;
        if let Some((_, signed)) = self.signed {
            if signed != tx_hash {
                warn!(
                    "Already signed a different channel config at this tip; ignoring {}",
                    hex::encode(tx_hash)
                );
            }
            return;
        }
        let Some(index) = self.own_index() else {
            return;
        };

        let signature = self.sign(&msg.tx);
        self.signed = Some((target.parent, tx_hash));
        self.publish(Outbound::Signature(PeerSignature {
            tx_hash,
            signature: IndexedSignature::new(index, signature),
        }));
    }
}

impl Message<PeerSignature> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerSignature, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(report) = &self.report else {
            return;
        };
        let Some(held) = &self.candidate else {
            return;
        };
        // Only good for the exact transaction it was signed over.
        if msg.tx_hash != held.tx_hash {
            return;
        }
        let index = msg.signature.channel_key_index;
        let Some(key) = report.live_keys.get(usize::from(index)) else {
            return;
        };
        if key
            .verify(
                held.tx.hash().as_signing_bytes().as_ref(),
                &msg.signature.signature,
            )
            .is_err()
        {
            debug!("Dropping a channel-config signature that does not verify");
            return;
        }

        if let Some(candidate) = &mut self.candidate {
            candidate.signatures.insert(index, msg.signature.signature);
        }
    }
}

impl Message<SetPublisher> for ChannelConfigActor {
    type Reply = ();

    async fn handle(
        &mut self,
        SetPublisher(publisher): SetPublisher,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        self.publisher = Some(publisher);
    }
}

/// The channel config a transaction would install, if it carries exactly one.
fn config_op(tx: &RawMantleTx) -> Option<&ChannelConfigOp> {
    let mut ops = tx.ops().iter().filter_map(|op| match op {
        Op::ChannelConfig(config) => Some(config),
        Op::ChannelInscribe(_)
        | Op::ChannelDeposit(_)
        | Op::ChannelWithdraw(_)
        | Op::ChannelTransfer(_)
        | Op::SDPDeclare(_)
        | Op::SDPWithdraw(_)
        | Op::SDPActive(_)
        | Op::LeaderClaim(_)
        | Op::Transfer(_)
        | Op::ClaimPowReward(_) => None,
    });
    let config = ops.next()?;

    ops.next().is_none().then_some(config)
}

/// Whether `op` installs exactly what this node wants installed.
fn matches(target: &ConfigTarget, op: &ChannelConfigOp) -> bool {
    op.parent == target.parent
        && op.keys.iter().eq(target.keys.iter())
        && u32::from(op.posting_timeframe.clone()) == target.posting_timeframe
        && u32::from(op.posting_timeout.clone()) == target.posting_timeout
        && op.configuration_threshold == target.configuration_threshold
        && op.transfer_threshold == target.transfer_threshold
}

#[cfg(test)]
mod tests {
    use kameo::actor::Spawn as _;
    use logos_blockchain_core::mantle::{
        channel::{SlotTimeframe, SlotTimeout},
        ops::channel::{ChannelId, config::Keys},
        transactions::Ops,
    };

    use super::*;

    const CHANNEL: [u8; 32] = [1; 32];
    const OWN_SECRET: [u8; 32] = [9; 32];
    const PEER_SECRET: [u8; 32] = [8; 32];

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

    /// The report every accredited node derives for itself each turn.
    fn report(target: Option<ConfigTarget>) -> Report {
        Report {
            live_keys: live_keys(),
            required_signatures: 2,
            target,
        }
    }

    /// A transaction carrying exactly the config `target` asks for.
    fn candidate_tx(target: &ConfigTarget) -> RawMantleTx {
        let op = ChannelConfigOp {
            channel: ChannelId::from(CHANNEL),
            parent: target.parent,
            keys: Keys::try_from(target.keys.clone()).expect("a non-empty key list"),
            posting_timeframe: SlotTimeframe::from(target.posting_timeframe),
            posting_timeout: SlotTimeout::from(target.posting_timeout),
            configuration_threshold: target.configuration_threshold,
            transfer_threshold: target.transfer_threshold,
        };
        let mut ops = Ops::default();
        ops.try_push(Op::ChannelConfig(op)).expect("one op fits");

        RawMantleTx(ops)
    }

    fn actor(secret: [u8; 32]) -> ActorRef<ChannelConfigActor> {
        ChannelConfigActor::spawn(ChannelConfigActor::new(key(secret)))
    }

    async fn tell_report(actor: &ActorRef<ChannelConfigActor>, report: Report) {
        actor
            .tell(report)
            .await
            .expect("the actor should accept a report");
    }

    async fn publisher(actor: &ActorRef<ChannelConfigActor>) -> mpsc::Receiver<Outbound> {
        let (tx, rx) = mpsc::channel(8);
        actor
            .tell(SetPublisher(tx))
            .await
            .expect("the actor should accept a publisher");

        rx
    }

    async fn hold(actor: &ActorRef<ChannelConfigActor>, tx: RawMantleTx) {
        actor
            .tell(Candidate {
                target: Box::new(target()),
                tx: Box::new(tx),
                transfer_proof: None,
            })
            .await
            .expect("the actor should accept a candidate");
    }

    #[test]
    fn a_candidate_survives_the_wire() {
        let sent = Outbound::Candidate(PeerCandidate {
            tx: Box::new(candidate_tx(&target())),
        });
        let Some(Outbound::Candidate(got)) = Outbound::decode(&sent.encode()) else {
            panic!("expected a candidate back");
        };

        assert_eq!(got.tx.hash().0, candidate_tx(&target()).hash().0);
    }

    #[test]
    fn a_signature_survives_the_wire() {
        let tx = candidate_tx(&target());
        let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
        let sent = Outbound::Signature(PeerSignature {
            tx_hash: tx.hash().0,
            signature: IndexedSignature::new(1, signature),
        });
        let Some(Outbound::Signature(got)) = Outbound::decode(&sent.encode()) else {
            panic!("expected a signature back");
        };

        assert_eq!(got.tx_hash, tx.hash().0);
        assert_eq!(got.signature, IndexedSignature::new(1, signature));
    }

    #[test]
    fn junk_off_the_wire_is_not_a_message() {
        // A tag this build does not know, an empty frame, and a signature
        // frame too short to carry the hash it needs.
        assert!(Outbound::decode(&[]).is_none());
        assert!(Outbound::decode(&[99, 1, 2, 3]).is_none());
        assert!(Outbound::decode(&[1, 0, 0]).is_none());
    }

    #[tokio::test]
    async fn nothing_is_proposed_while_live_already_matches() {
        let actor = actor(OWN_SECRET);
        tell_report(&actor, report(None)).await;

        assert!(matches!(
            actor.ask(Propose).await.expect("a reply"),
            Proposed::Idle
        ));
    }

    #[tokio::test]
    async fn a_target_with_no_candidate_asks_for_one_to_be_built() {
        let actor = actor(OWN_SECRET);
        tell_report(&actor, report(Some(target()))).await;

        let Proposed::Build(asked) = actor.ask(Propose).await.expect("a reply") else {
            panic!("expected a build request");
        };
        assert_eq!(*asked, target());
    }

    #[tokio::test]
    async fn a_candidate_alone_is_under_the_threshold() {
        let actor = actor(OWN_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let mut outbound = publisher(&actor).await;
        hold(&actor, candidate_tx(&target())).await;

        assert!(
            matches!(outbound.recv().await, Some(Outbound::Candidate(_))),
            "a new candidate should be announced"
        );
        assert!(
            matches!(actor.ask(Propose).await.expect("a reply"), Proposed::Idle),
            "one of two signatures is not enough to submit"
        );
    }

    #[tokio::test]
    async fn a_peer_signature_carries_the_candidate_over_the_threshold() {
        let actor = actor(OWN_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let tx = candidate_tx(&target());
        hold(&actor, tx.clone()).await;

        // The peer signs the same funded transaction, at its own index.
        let signature = key(PEER_SECRET).sign_payload(tx.hash().as_signing_bytes().as_ref());
        actor
            .tell(PeerSignature {
                tx_hash: tx.hash().0,
                signature: IndexedSignature::new(1, signature),
            })
            .await
            .expect("the actor should accept a signature");

        assert!(matches!(
            actor.ask(Propose).await.expect("a reply"),
            Proposed::Submit(_)
        ));
    }

    #[tokio::test]
    async fn a_signature_that_does_not_verify_is_dropped() {
        let actor = actor(OWN_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let tx = candidate_tx(&target());
        hold(&actor, tx.clone()).await;

        // Correctly signed by the peer, but over bytes that are not this
        // candidate, then claimed against it.
        let signature = key(PEER_SECRET).sign_payload(&[0xAB; 32]);
        actor
            .tell(PeerSignature {
                tx_hash: tx.hash().0,
                signature: IndexedSignature::new(1, signature),
            })
            .await
            .expect("the actor should accept a signature");

        assert!(
            matches!(actor.ask(Propose).await.expect("a reply"), Proposed::Idle),
            "a signature that does not verify must not count"
        );
    }

    #[tokio::test]
    async fn a_peer_signs_the_config_it_wanted_anyway() {
        let actor = actor(PEER_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let mut outbound = publisher(&actor).await;

        actor
            .tell(PeerCandidate {
                tx: Box::new(candidate_tx(&target())),
            })
            .await
            .expect("the actor should accept a peer candidate");

        assert!(matches!(
            outbound.recv().await,
            Some(Outbound::Signature(_))
        ));
    }

    #[tokio::test]
    async fn a_peer_does_not_sign_a_config_it_did_not_ask_for() {
        let actor = actor(PEER_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let mut outbound = publisher(&actor).await;

        // Same shape, but installing a committee this node never derived.
        let mut rogue = target();
        rogue.keys = vec![key(PEER_SECRET).public_key()];
        actor
            .tell(PeerCandidate {
                tx: Box::new(candidate_tx(&rogue)),
            })
            .await
            .expect("the actor should accept a peer candidate");

        assert!(
            outbound.try_recv().is_err(),
            "a peer is trusted for its signature, never for the config"
        );
    }

    #[tokio::test]
    async fn only_one_rival_candidate_is_signed_per_tip() {
        let actor = actor(PEER_SECRET);
        tell_report(&actor, report(Some(target()))).await;
        let mut outbound = publisher(&actor).await;

        actor
            .tell(PeerCandidate {
                tx: Box::new(candidate_tx(&target())),
            })
            .await
            .expect("the actor should accept a peer candidate");
        assert!(matches!(
            outbound.recv().await,
            Some(Outbound::Signature(_))
        ));

        // Another proposer funded its own transaction for the same config, so
        // the hash differs; signing both splits the committee's signatures
        // across two candidates and neither reaches the threshold.
        let mut rival = candidate_tx(&target());
        let Some(Op::ChannelConfig(config)) = rival.0.iter().next().cloned() else {
            unreachable!("the first op is the config")
        };
        rival
            .0
            .try_push(Op::ChannelConfig(config))
            .expect("a second op fits");
        actor
            .tell(PeerCandidate {
                tx: Box::new(rival),
            })
            .await
            .expect("the actor should accept a peer candidate");

        assert!(
            outbound.try_recv().is_err(),
            "a second signature at the same tip would split the committee"
        );
    }
}
