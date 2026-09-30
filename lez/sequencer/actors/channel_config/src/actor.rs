use std::collections::BTreeMap;

use kameo::{
    Actor,
    actor::{ActorRef, WeakRecipient},
    message::{Context, Message},
};
use log::{debug, warn};
use logos_blockchain_core::{
    mantle::{
        ops::{Op, channel::config::ChannelConfigOp},
        traits::Hashable as _,
        transactions::Ops,
    },
    proofs::channel_multi_sig_proof::IndexedSignature,
};
use logos_blockchain_key_management_system_service::keys::{
    Ed25519Key, Ed25519PublicKey, Ed25519Signature,
};
use tokio::sync::mpsc;

use crate::{
    error::Error,
    protocol::{
        Action, ChannelView, ConfigTarget, Draft, FundedTx, Propose, Reset, SetPublisher,
        SetSubmitter, Signature, Submission, SubmitConfig, Wire,
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
    tx: Ops,
    tx_hash: [u8; 32],
    /// Signatures by accredited-key index, so the choice below is ordered.
    signatures: BTreeMap<u16, Ed25519Signature>,
    /// Handed to the submitter already; a further signature changes nothing.
    submission_sent: bool,
}

pub struct ChannelConfigActor {
    signing_key: Ed25519Key,
    own_key: Ed25519PublicKey,
    /// The live channel and the committee it should have, as of the last turn.
    view: Option<ChannelView>,
    /// Our own draft. Not persisted: a signature is only good for one funded
    /// transaction, and a restart funds a different one.
    draft: Option<OwnDraft>,
    // TODO: Use messages instead of tokio's primitives.
    publisher: Option<mpsc::Sender<Wire>>,
    /// Sent the draft once it has its signatures.
    submitter: Option<WeakRecipient<SubmitConfig>>,
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
            submitter: None,
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

    /// Hands the core a draft to submit, reporting whether it arrived.
    ///
    /// Fire and forget on purpose: an `ask` here deadlocks, since the core
    /// asks this actor and a kameo handler blocks its own mailbox.
    fn send_submission(&self, submission: Box<Submission>) -> bool {
        let Some(submitter) = self.submitter.as_ref().and_then(WeakRecipient::upgrade) else {
            return false;
        };
        if let Err(err) = submitter.tell(SubmitConfig(submission)).try_send() {
            debug!("Dropped a signed channel config: {err}");
            return false;
        }

        true
    }

    /// This node's index in the live accredited list, which is what a
    /// signature names.
    fn own_index(&self) -> Option<u16> {
        let view = self.view.as_ref()?;
        let index = view.live_keys.iter().position(|key| *key == self.own_key)?;

        u16::try_from(index).ok()
    }

    fn sign(&self, tx: &Ops) -> Ed25519Signature {
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
        let signatures = draft
            .signatures
            .iter()
            .take(required)
            .map(|(index, signature)| IndexedSignature::new(*index, *signature))
            .collect();

        Action::Submit(Box::new(Submission {
            tx_hash: draft.tx_hash,
            signatures,
        }))
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
        let required = usize::from(view.required_signatures);
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
            .verify(&draft.tx_hash, &msg.signature.signature)
            .is_err()
        {
            debug!("Dropping a channel-config signature that does not verify");
            return;
        }

        let already_sent = draft.submission_sent;
        draft.signatures.insert(index, msg.signature.signature);
        // Only set on a submission that arrived, so a dropped send is retried
        // by the next signature rather than waiting for a turn to re-fund.
        if !already_sent
            && draft.signatures.len() >= required
            && let Action::Submit(submission) = self.next_action()
            && self.send_submission(submission)
            && let Some(in_flight) = &mut self.draft
        {
            in_flight.submission_sent = true;
        }
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
            accredited_keys,
            signing_threshold,
        } = msg;
        // zone-sdk picks the parent and indexes the signatures from its own
        // view, so a draft built off a different one would never land.
        let Some(view) = &self.view else {
            return Action::Idle;
        };
        // The target can move while funding is in flight, and a draft on the
        // one we asked for would no longer land.
        if view.target.as_ref() != Some(&*target) {
            debug!("The channel-config target moved while funding; dropping the draft");
            return Action::Idle;
        }
        if config_op(&tx).is_none_or(|op| !matches(&target, op))
            || accredited_keys != view.live_keys
            || signing_threshold != view.required_signatures
        {
            warn!("zone-sdk funded a channel-config draft off another view; dropping it");
            return Action::Idle;
        }
        let Some(index) = self.own_index() else {
            warn!("Not in the live accredited list; dropping our channel-config draft");
            return Action::Idle;
        };
        let signature = self.sign(&tx);
        let tx_hash = tx.hash().0;

        self.draft = Some(OwnDraft {
            target: *target,
            tx: *tx,
            tx_hash,
            signatures: BTreeMap::from([(index, signature)]),
            submission_sent: false,
        });

        self.next_action()
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

impl Message<SetSubmitter> for ChannelConfigActor {
    type Reply = ();

    async fn handle(
        &mut self,
        SetSubmitter(submitter): SetSubmitter,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        self.submitter = Some(submitter);
    }
}

impl Message<Reset> for ChannelConfigActor {
    type Reply = ();

    async fn handle(&mut self, Reset: Reset, _ctx: &mut Context<Self, Self::Reply>) {
        self.draft = None;
    }
}

/// The channel config a transaction would install.
///
/// A signature covers the whole transaction, and the same signatures satisfy
/// any other op in it that takes a multi-sig proof, so a draft may carry
/// nothing beyond the config and the transfer that pays for it.
fn config_op(tx: &Ops) -> Option<&ChannelConfigOp> {
    let mut config = None;
    let mut funded = false;
    for op in tx {
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
mod tests;
