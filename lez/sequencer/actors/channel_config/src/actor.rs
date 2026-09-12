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
            channel::{Ed25519PublicKey, config::ChannelConfigOp},
        },
        traits::Hashable as _,
        transactions::{
            OpsProofs,
            mantle_tx::{MantleTx as _, RawMantleTx},
        },
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignature},
};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, Ed25519Signature};
use tokio::sync::mpsc;

use crate::{
    error::Error,
    protocol::{
        Action, ChannelView, ConfigTarget, Draft, FundedTx, Propose, SetPublisher, Signature, Wire,
    },
};

/// Mailbox depth to spawn the actor with.
///
/// A rotation where several nodes fund rivals puts one draft and one signature
/// per peer per rival on the topic, so the inbound burst grows with the square
/// of the committee; `try_send` drops past this, which costs one turn.
pub const MAILBOX_CAPACITY: usize = 256;

/// A draft this node funded and is collecting signatures for.
struct OwnDraft {
    target: ConfigTarget,
    tx: RawMantleTx,
    /// The fee transfer's proof, reattached when the draft is assembled.
    transfer_proof: Option<OpProof>,
    tx_hash: [u8; 32],
    /// Signatures by accredited-key index, so the choice below is ordered.
    signatures: BTreeMap<u16, Ed25519Signature>,
}

pub struct ChannelConfigActor {
    signing_key: Ed25519Key,
    own_key: Ed25519PublicKey,
    /// The live channel and the committee it should have, as of the last turn.
    view: Option<ChannelView>,
    /// Our own draft. Not persisted: a signature is only good for one funded
    /// transaction, and a restart funds a different one.
    draft: Option<OwnDraft>,
    publisher: Option<mpsc::Sender<Wire>>,
}

impl ChannelConfigActor {
    #[must_use]
    pub fn new(signing_key: Ed25519Key) -> Self {
        let own_key = signing_key.public_key();

        Self {
            signing_key,
            own_key,
            view: None,
            draft: None,
            publisher: None,
        }
    }

    /// Best effort: without gossip this node only ever has its own signature.
    fn publish(&self, outbound: Wire) {
        if let Some(publisher) = &self.publisher
            && publisher.try_send(outbound).is_err()
        {
            debug!("Dropped an outbound channel-config message");
        }
    }

    /// This node's index in the live accredited list, which is what a
    /// signature names.
    fn own_index(&self) -> Option<u16> {
        let view = self.view.as_ref()?;
        let index = view.live_keys.iter().position(|key| *key == self.own_key)?;

        u16::try_from(index).ok()
    }

    fn sign(&self, tx: &RawMantleTx) -> Ed25519Signature {
        self.signing_key
            .sign_payload(tx.hash().as_signing_bytes().as_ref())
    }

    /// What this turn owes the channel config, announcing the draft again if
    /// it is still short of signatures.
    fn next_action(&self) -> Action {
        let Some(view) = &self.view else {
            return Action::Idle;
        };
        let Some(target) = &view.target else {
            return Action::Idle;
        };
        let Some(draft) = &self.draft else {
            return Action::Build(Box::new(target.clone()));
        };
        if draft.target != *target {
            return Action::Build(Box::new(target.clone()));
        }

        let required = usize::from(view.required_signatures);
        if draft.signatures.len() < required {
            // Re-announce: a peer that was down when we first published still
            // has to see the draft to sign it.
            self.publish(Wire::Draft(Draft {
                tx: Box::new(draft.tx.clone()),
            }));

            return Action::Idle;
        }

        // Bedrock wants exactly the threshold, never more, so take the lowest
        // indices and leave the rest.
        let signatures: Vec<IndexedSignature> = draft
            .signatures
            .iter()
            .take(required)
            .map(|(index, signature)| IndexedSignature::new(*index, *signature))
            .collect();
        let Ok(signatures) = signatures.try_into() else {
            warn!("Too many channel-config signatures to prove");
            return Action::Idle;
        };
        let Ok(proof) = ChannelMultiSigProof::try_new(signatures) else {
            warn!("Failed to assemble the channel-config multi-sig proof");
            return Action::Idle;
        };

        let mut ops_proofs: OpsProofs = OpProof::ChannelMultiSigProof(proof).into();
        if let Some(transfer_proof) = draft.transfer_proof.clone()
            && ops_proofs.try_push(transfer_proof).is_err()
        {
            warn!("Too many operation proofs for the channel-config transaction");
            return Action::Idle;
        }

        Action::Submit(Box::new(SignedMantleTx::new(draft.tx.clone(), ops_proofs)))
    }

    /// A peer's draft, from gossip or from a direct send.
    fn on_peer_draft(&self, msg: &Draft) {
        // A peer is trusted for its signature, never for the config: sign only
        // what this node derived from finalized state for itself.
        let Some(view) = &self.view else {
            return;
        };
        let Some(target) = &view.target else {
            return;
        };
        let Some(op) = config_op(&msg.tx) else {
            return;
        };
        if !matches(target, op) {
            debug!("Ignoring a channel-config draft that is not the config we want");
            return;
        }

        let Some(index) = self.own_index() else {
            return;
        };

        // Rivals differ only in who funded them, and Bedrock lets one land, so
        // sign every one. Re-signing also replaces a signature lost on the way
        // back.
        let signature = self.sign(&msg.tx);
        self.publish(Wire::Signature(Signature {
            tx_hash: msg.tx.hash().0,
            signature: IndexedSignature::new(index, signature),
        }));
    }

    /// A peer's signature over the draft this node holds.
    fn on_peer_signature(&mut self, msg: &Signature) {
        let Some(view) = &self.view else {
            return;
        };
        let Some(draft) = &mut self.draft else {
            return;
        };
        // Only good for the exact transaction it was signed over.
        if msg.tx_hash != draft.tx_hash {
            return;
        }
        let index = msg.signature.channel_key_index;
        let Some(key) = view.live_keys.get(usize::from(index)) else {
            return;
        };
        if key
            .verify(
                draft.tx.hash().as_signing_bytes().as_ref(),
                &msg.signature.signature,
            )
            .is_err()
        {
            debug!("Dropping a channel-config signature that does not verify");
            return;
        }

        draft.signatures.insert(index, msg.signature.signature);
    }
}

impl Actor for ChannelConfigActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Error> {
        Ok(args)
    }
}

impl Message<ChannelView> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: ChannelView, _ctx: &mut Context<Self, Self::Reply>) {
        // A draft is bound to one target on one tip; either moving kills it.
        if self
            .draft
            .as_ref()
            .is_some_and(|draft| msg.target.as_ref() != Some(&draft.target))
        {
            self.draft = None;
        }
        self.view = Some(msg);
    }
}

impl Message<Propose> for ChannelConfigActor {
    type Reply = Action;

    async fn handle(&mut self, Propose: Propose, _ctx: &mut Context<Self, Self::Reply>) -> Action {
        self.next_action()
    }
}

impl Message<FundedTx> for ChannelConfigActor {
    type Reply = Action;

    /// Answers as [`Propose`] would, so a channel that needs only this node's
    /// signature submits on the same turn it funded.
    async fn handle(&mut self, msg: FundedTx, _ctx: &mut Context<Self, Self::Reply>) -> Action {
        let FundedTx {
            target,
            tx,
            transfer_proof,
        } = msg;
        let Some(index) = self.own_index() else {
            warn!("Not in the live accredited list; dropping our channel-config draft");
            return Action::Idle;
        };
        let signature = self.sign(&tx);
        let tx_hash = tx.hash().0;

        self.draft = Some(OwnDraft {
            target: *target,
            tx: *tx,
            transfer_proof,
            tx_hash,
            signatures: BTreeMap::from([(index, signature)]),
        });

        self.next_action()
    }
}

impl Message<Draft> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: Draft, _ctx: &mut Context<Self, Self::Reply>) {
        self.on_peer_draft(&msg);
    }
}

impl Message<Signature> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, msg: Signature, _ctx: &mut Context<Self, Self::Reply>) {
        self.on_peer_signature(&msg);
    }
}

impl Message<Wire> for ChannelConfigActor {
    type Reply = ();

    /// A gossiped message as it came off the wire, in the one shape gossip
    /// carries it.
    async fn handle(&mut self, msg: Wire, _ctx: &mut Context<Self, Self::Reply>) {
        match msg {
            Wire::Draft(draft) => self.on_peer_draft(&draft),
            Wire::Signature(signature) => self.on_peer_signature(&signature),
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

/// The channel config a transaction would install.
///
/// A signature covers the whole transaction, and the same signatures satisfy
/// any other op in it that takes a multi-sig proof, so a draft may carry
/// nothing beyond the config and the transfer that pays for it.
fn config_op(tx: &RawMantleTx) -> Option<&ChannelConfigOp> {
    let mut config = None;
    let mut funded = false;
    for op in tx.ops() {
        match op {
            Op::ChannelConfig(config_op) => {
                if config.replace(config_op).is_some() {
                    return None;
                }
            }
            // The fee the proposer's wallet added.
            Op::Transfer(_) => {
                if funded {
                    return None;
                }
                funded = true;
            }
            Op::ChannelInscribe(_)
            | Op::ChannelDeposit(_)
            | Op::ChannelWithdraw(_)
            | Op::ChannelTransfer(_)
            | Op::SDPDeclare(_)
            | Op::SDPWithdraw(_)
            | Op::SDPActive(_)
            | Op::LeaderClaim(_)
            | Op::ClaimPowReward(_) => return None,
        }
    }

    config
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
    use logos_blockchain_core::{
        crypto::ZkHash,
        mantle::{
            channel::{SlotTimeframe, SlotTimeout},
            ledger::{Inputs, NoteId, Outputs},
            ops::{
                channel::{ChannelId, MsgId, config::Keys, withdraw::ChannelWithdrawOp},
                transfer::TransferOp,
            },
            transactions::Ops,
        },
    };

    use super::*;

    const CHANNEL: [u8; 32] = [1; 32];
    const OWN_SECRET: [u8; 32] = [9; 32];
    const PEER_SECRET: [u8; 32] = [8; 32];
    /// A four-node committee: Bedrock asks three signatures of the next config.
    const COMMITTEE: [[u8; 32]; 4] = [[1; 32], [2; 32], [3; 32], [4; 32]];

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
    fn draft_tx(target: &ConfigTarget) -> RawMantleTx {
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

    async fn hold(actor: &ActorRef<ChannelConfigActor>, tx: RawMantleTx) {
        actor
            .tell(FundedTx {
                target: Box::new(target()),
                tx: Box::new(tx),
                transfer_proof: None,
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
    fn rival_tx(target: &ConfigTarget, proposer: u8) -> RawMantleTx {
        let mut tx = draft_tx(target);
        tx.0.try_push(Op::Transfer(TransferOp::new(
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
                match message.clone() {
                    Wire::Draft(draft) => {
                        node.ask(draft).await.expect("a peer draft");
                    }
                    Wire::Signature(signature) => {
                        node.ask(signature).await.expect("a peer signature");
                    }
                }
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
                            transfer_proof: None,
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
                transfer_proof: None,
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
            .tell(Signature {
                tx_hash: tx.hash().0,
                signature: IndexedSignature::new(1, signature),
            })
            .await
            .expect("the actor should accept a signature");

        assert!(matches!(
            actor.ask(Propose).await.expect("a reply"),
            Action::Submit(_)
        ));
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
            .tell(Signature {
                tx_hash: tx.hash().0,
                signature: IndexedSignature::new(1, signature),
            })
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
            .tell(Draft {
                tx: Box::new(draft_tx(&target())),
            })
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
            .ask(Draft {
                tx: Box::new(draft_tx(&rogue)),
            })
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
                .tell(Draft {
                    tx: Box::new(rival_tx(&target(), proposer)),
                })
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
        tx.0.try_push(Op::ChannelWithdraw(ChannelWithdrawOp {
            channel_id: ChannelId::from(CHANNEL),
            inputs: Inputs::new([NoteId(ZkHash::from(7_u64))]),
        }))
        .expect("a second op fits");
        actor
            .ask(Draft { tx: Box::new(tx) })
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
        let Some(Op::ChannelConfig(config)) = tx.0.iter().next().cloned() else {
            unreachable!("the first op is the config")
        };
        tx.0.try_push(Op::ChannelConfig(config))
            .expect("a second op fits");
        actor
            .ask(Draft { tx: Box::new(tx) })
            .await
            .expect("the actor should accept a peer draft");

        assert!(
            outbound.try_recv().is_err(),
            "a transaction must carry exactly one config to be signed"
        );
    }
}
