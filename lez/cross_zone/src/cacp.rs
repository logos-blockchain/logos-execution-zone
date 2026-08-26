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

use std::collections::{HashMap, HashSet};

use bincode::Options as _;
use logos_blockchain_core::mantle::{
    SignedMantleTx,
    ops::{
        Op, OpProof,
        channel::{
            ChannelId, Ed25519PublicKey, MsgId,
            inscribe::{Inscription, InscriptionOp},
        },
    },
    traits::Hashable as _,
    transactions::{
        MantleTxBuilder, OpsProofs, RawMantleTx, TxHash, mantle_tx::MantleTx as _,
        states::Unverified,
    },
};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, Ed25519Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const INTENT_VERSION: u8 = 1;
pub const PARTICIPANT_COUNT: usize = 2;
pub const ACCEPT_CANDIDATE_DOMAIN: &[u8] = b"/CACP/AcceptCandidate/v1/";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InscribeIntent {
    pub channel_id: ChannelId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossZoneIntent {
    version: u8,
    operations: [InscribeIntent; PARTICIPANT_COUNT],
    nonce: u64,
}

impl CrossZoneIntent {
    pub fn new(
        mut operations: [InscribeIntent; PARTICIPANT_COUNT],
        nonce: u64,
    ) -> Result<Self, CacpError> {
        operations.sort_by(|left, right| left.channel_id.as_ref().cmp(right.channel_id.as_ref()));
        if operations[0].channel_id == operations[1].channel_id {
            return Err(CacpError::DuplicateChannel);
        }
        if operations
            .iter()
            .any(|operation| operation.payload.is_empty())
        {
            return Err(CacpError::EmptyInscription);
        }
        for operation in &operations {
            let _bounded: Inscription = operation
                .payload
                .clone()
                .try_into()
                .map_err(|_error| CacpError::InscriptionTooLarge)?;
        }
        Ok(Self {
            version: INTENT_VERSION,
            operations,
            nonce,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub const fn operations(&self) -> &[InscribeIntent; PARTICIPANT_COUNT] {
        &self.operations
    }

    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Fixed-field-order encoding used to identify one CACP proposal.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        for operation in &self.operations {
            bytes.extend_from_slice(operation.channel_id.as_ref());
            let payload_len = u64::try_from(operation.payload.len())
                .expect("an inscription length must fit in u64");
            bytes.extend_from_slice(&payload_len.to_le_bytes());
            bytes.extend_from_slice(&operation.payload);
        }
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    #[must_use]
    pub fn proposal_id(&self) -> ProposalId {
        ProposalId(Sha256::digest(self.canonical_bytes()).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProposalId(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneSequencer {
    pub channel_id: ChannelId,
    pub public_key: Ed25519PublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TwoZoneTopology {
    pub initiator: ZoneSequencer,
    pub counterparty: ZoneSequencer,
}

impl TwoZoneTopology {
    pub fn new(
        initiator: ZoneSequencer,
        counterparty: ZoneSequencer,
        intent: &CrossZoneIntent,
    ) -> Result<Self, CacpError> {
        if initiator.channel_id == counterparty.channel_id {
            return Err(CacpError::DuplicateChannel);
        }
        if initiator.public_key == counterparty.public_key {
            return Err(CacpError::DuplicateSequencer);
        }
        let participant_channels = [initiator.channel_id, counterparty.channel_id];
        if intent
            .operations
            .iter()
            .any(|operation| !participant_channels.contains(&operation.channel_id))
        {
            return Err(CacpError::TopologyMismatch);
        }
        Ok(Self {
            initiator,
            counterparty,
        })
    }

    fn sequencer_for(&self, channel_id: ChannelId) -> Option<&ZoneSequencer> {
        [&self.initiator, &self.counterparty]
            .into_iter()
            .find(|sequencer| sequencer.channel_id == channel_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelParent {
    pub channel_id: ChannelId,
    pub parent: MsgId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Propose {
    pub intent: CrossZoneIntent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accept {
    pub tx: RawMantleTx,
    pub counterparty_proof: Ed25519Signature,
    /// Proof for the optional Bedrock fee operation appended by the node wallet.
    pub funding_proof: Option<OpProof>,
}

impl Accept {
    pub fn candidate(&self) -> Result<AcceptCandidate, CacpError> {
        AcceptCandidate::new(self.tx.clone(), self.funding_proof.clone())
    }
}

/// The exact funded transaction and fee proof that A must be able to recover
/// before it can safely produce FINALIZE. The bond agreement separately binds
/// this transaction hash and B's verification key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptCandidate {
    pub tx: RawMantleTx,
    pub funding_proof: Option<OpProof>,
}

impl AcceptCandidate {
    pub fn new(tx: RawMantleTx, funding_proof: Option<OpProof>) -> Result<Self, CacpError> {
        let candidate = Self { tx, funding_proof };
        candidate.validate_shape()?;
        Ok(candidate)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CacpError> {
        self.validate_shape()?;
        let mut bytes = ACCEPT_CANDIDATE_DOMAIN.to_vec();
        bytes.extend_from_slice(self.tx.hash().as_ref());
        let body = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(self)
            .map_err(|_error| CacpError::InvalidAcceptCandidate)?;
        bytes.extend(body);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CacpError> {
        let body = bytes
            .strip_prefix(ACCEPT_CANDIDATE_DOMAIN)
            .ok_or(CacpError::InvalidAcceptCandidate)?;
        let (encoded_hash, body) = body
            .split_at_checked(32)
            .ok_or(CacpError::InvalidAcceptCandidate)?;
        let candidate: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(body)
            .map_err(|_error| CacpError::InvalidAcceptCandidate)?;
        candidate.validate_shape()?;
        if candidate.tx.hash().as_ref() != encoded_hash {
            return Err(CacpError::InvalidAcceptCandidate);
        }
        Ok(candidate)
    }

    fn validate_shape(&self) -> Result<(), CacpError> {
        let ops = self.tx.ops();
        let inscriptions_are_first = ops
            .get(..PARTICIPANT_COUNT)
            .is_some_and(|ops| ops.iter().all(|op| matches!(op, Op::ChannelInscribe(_))));
        let valid = match (ops.len(), &self.funding_proof) {
            (PARTICIPANT_COUNT, None) => inscriptions_are_first,
            (len, Some(OpProof::ZkSig(_))) if len == PARTICIPANT_COUNT + 1 => {
                inscriptions_are_first && matches!(ops.last(), Some(Op::Transfer(_)))
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(CacpError::InvalidAcceptCandidate)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finalize {
    pub signed_tx: SignedMantleTx<Unverified>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    WaitingForAccept,
    WaitingForFinalize,
    SignaturesExchanged,
    Submitted,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeoutOutcome {
    Aborted,
    FallbackSubmission(SignedMantleTx<Unverified>),
    NoAction,
}

pub struct InitiatorSession {
    topology: TwoZoneTopology,
    intent: CrossZoneIntent,
    parents: [ChannelParent; PARTICIPANT_COUNT],
    phase: Phase,
    signed_tx: Option<SignedMantleTx<Unverified>>,
}

impl InitiatorSession {
    pub fn new(
        topology: TwoZoneTopology,
        intent: CrossZoneIntent,
        parents: [ChannelParent; PARTICIPANT_COUNT],
    ) -> Result<Self, CacpError> {
        validate_parents(&intent, &parents)?;
        Ok(Self {
            topology,
            intent,
            parents,
            phase: Phase::WaitingForAccept,
            signed_tx: None,
        })
    }

    #[must_use]
    pub fn propose(&self) -> Propose {
        Propose {
            intent: self.intent.clone(),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub fn receive_accept(
        &mut self,
        accept: Accept,
        signing_key: &Ed25519Key,
    ) -> Result<Finalize, CacpError> {
        if self.phase != Phase::WaitingForAccept {
            return Err(CacpError::UnexpectedPhase);
        }
        require_key(signing_key, &self.topology.initiator)?;
        validate_joint_tx(&accept.tx, &self.intent, &self.topology, &self.parents)?;
        accept.candidate()?;

        let tx_hash = accept.tx.hash();
        self.topology
            .counterparty
            .public_key
            .verify(
                tx_hash.as_signing_bytes().as_ref(),
                &accept.counterparty_proof,
            )
            .map_err(|_error| CacpError::InvalidCounterpartyProof)?;

        let initiator_proof = signing_key.sign_payload(tx_hash.as_signing_bytes().as_ref());
        let proofs = proofs_in_operation_order(
            &accept.tx,
            &self.topology,
            initiator_proof,
            accept.counterparty_proof,
            accept.funding_proof.as_ref(),
        )?;
        let signed_tx = SignedMantleTx::new(accept.tx, proofs);
        signed_tx
            .clone()
            .preverify()
            .map_err(|_error| CacpError::InvalidSignedTransaction)?;

        self.phase = Phase::SignaturesExchanged;
        self.signed_tx = Some(signed_tx.clone());
        Ok(Finalize { signed_tx })
    }

    pub const fn on_timeout(&mut self) -> TimeoutOutcome {
        match self.phase {
            Phase::WaitingForAccept | Phase::WaitingForFinalize => {
                self.phase = Phase::Aborted;
                TimeoutOutcome::Aborted
            }
            Phase::SignaturesExchanged | Phase::Submitted | Phase::Aborted => {
                TimeoutOutcome::NoAction
            }
        }
    }

    pub fn mark_submitted(&mut self) -> Result<(), CacpError> {
        if self.phase != Phase::SignaturesExchanged {
            return Err(CacpError::UnexpectedPhase);
        }
        self.phase = Phase::Submitted;
        Ok(())
    }

    #[must_use]
    pub const fn signed_tx(&self) -> Option<&SignedMantleTx<Unverified>> {
        self.signed_tx.as_ref()
    }
}

pub struct CounterpartySession {
    topology: TwoZoneTopology,
    expected_intent: CrossZoneIntent,
    parents: [ChannelParent; PARTICIPANT_COUNT],
    phase: Phase,
    accepted_tx: Option<RawMantleTx>,
    accepted_counterparty_proof: Option<Ed25519Signature>,
    accepted_funding_proof: Option<OpProof>,
    signed_tx: Option<SignedMantleTx<Unverified>>,
}

impl CounterpartySession {
    pub fn new(
        topology: TwoZoneTopology,
        expected_intent: CrossZoneIntent,
        parents: [ChannelParent; PARTICIPANT_COUNT],
    ) -> Result<Self, CacpError> {
        validate_parents(&expected_intent, &parents)?;
        Ok(Self {
            topology,
            expected_intent,
            parents,
            phase: Phase::WaitingForAccept,
            accepted_tx: None,
            accepted_counterparty_proof: None,
            accepted_funding_proof: None,
            signed_tx: None,
        })
    }

    pub fn receive_propose(
        &mut self,
        propose: &Propose,
        signing_key: &Ed25519Key,
    ) -> Result<Accept, CacpError> {
        if self.phase != Phase::WaitingForAccept {
            return Err(CacpError::UnexpectedPhase);
        }
        if propose.intent != self.expected_intent {
            return Err(CacpError::IntentMismatch);
        }
        require_key(signing_key, &self.topology.counterparty)?;
        let tx = build_joint_tx(&propose.intent, &self.topology, &self.parents)?;
        let proof = signing_key.sign_payload(tx.hash().as_signing_bytes().as_ref());
        self.phase = Phase::WaitingForFinalize;
        self.accepted_tx = Some(tx.clone());
        self.accepted_counterparty_proof = Some(proof);
        self.accepted_funding_proof = None;
        Ok(Accept {
            tx,
            counterparty_proof: proof,
            funding_proof: None,
        })
    }

    /// Accepts a node-funded form of the joint transaction. The first two
    /// operations must be the exact CACP inscriptions; the only permitted
    /// additional operation is the final fee transfer supplied by Bedrock's
    /// wallet endpoint.
    pub fn receive_funded_propose(
        &mut self,
        propose: &Propose,
        funded_tx: RawMantleTx,
        funding_proof: OpProof,
        signing_key: &Ed25519Key,
    ) -> Result<Accept, CacpError> {
        if self.phase != Phase::WaitingForAccept {
            return Err(CacpError::UnexpectedPhase);
        }
        if propose.intent != self.expected_intent {
            return Err(CacpError::IntentMismatch);
        }
        require_key(signing_key, &self.topology.counterparty)?;
        validate_joint_tx(
            &funded_tx,
            &self.expected_intent,
            &self.topology,
            &self.parents,
        )?;
        if funded_tx.ops().len() != PARTICIPANT_COUNT + 1
            || !matches!(funded_tx.ops().last(), Some(Op::Transfer(_)))
        {
            return Err(CacpError::InvalidJointTransaction);
        }
        AcceptCandidate::new(funded_tx.clone(), Some(funding_proof.clone()))?;
        let proof = signing_key.sign_payload(funded_tx.hash().as_signing_bytes().as_ref());
        self.phase = Phase::WaitingForFinalize;
        self.accepted_tx = Some(funded_tx.clone());
        self.accepted_counterparty_proof = Some(proof);
        self.accepted_funding_proof = Some(funding_proof.clone());
        Ok(Accept {
            tx: funded_tx,
            counterparty_proof: proof,
            funding_proof: Some(funding_proof),
        })
    }

    pub fn receive_finalize(&mut self, finalize: Finalize) -> Result<(), CacpError> {
        if self.phase != Phase::WaitingForFinalize {
            return Err(CacpError::UnexpectedPhase);
        }
        let accepted_tx = self
            .accepted_tx
            .as_ref()
            .ok_or(CacpError::UnexpectedPhase)?;
        if finalize.signed_tx.mantle_tx() != accepted_tx {
            return Err(CacpError::TransactionMismatch);
        }
        self.validate_finalize_proofs(&finalize.signed_tx)?;
        finalize
            .signed_tx
            .clone()
            .preverify()
            .map_err(|_error| CacpError::InvalidSignedTransaction)?;
        self.phase = Phase::SignaturesExchanged;
        self.signed_tx = Some(finalize.signed_tx);
        Ok(())
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "only the two locked demo operation kinds may reach FINALIZE"
    )]
    fn validate_finalize_proofs(
        &self,
        signed_tx: &SignedMantleTx<Unverified>,
    ) -> Result<(), CacpError> {
        if signed_tx.ops_proofs().len() != signed_tx.mantle_tx().ops().len() {
            return Err(CacpError::ProofMismatch);
        }
        let counterparty_proof = self
            .accepted_counterparty_proof
            .ok_or(CacpError::UnexpectedPhase)?;
        for (operation, proof) in signed_tx.ops_with_proof() {
            match operation {
                Op::ChannelInscribe(inscription)
                    if inscription.channel_id == self.topology.initiator.channel_id =>
                {
                    if !matches!(proof, OpProof::Ed25519Sig(_)) {
                        return Err(CacpError::ProofMismatch);
                    }
                }
                Op::ChannelInscribe(inscription)
                    if inscription.channel_id == self.topology.counterparty.channel_id =>
                {
                    require_committed_proof(&OpProof::Ed25519Sig(counterparty_proof), proof)?;
                }
                Op::Transfer(_) => {
                    let expected = self
                        .accepted_funding_proof
                        .as_ref()
                        .ok_or(CacpError::ProofMismatch)?;
                    require_committed_proof(expected, proof)?;
                }
                _ => return Err(CacpError::ProofMismatch),
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub fn on_timeout(&mut self) -> TimeoutOutcome {
        match self.phase {
            Phase::WaitingForAccept | Phase::WaitingForFinalize => {
                self.phase = Phase::Aborted;
                TimeoutOutcome::Aborted
            }
            Phase::SignaturesExchanged => self
                .signed_tx
                .as_ref()
                .map_or(TimeoutOutcome::NoAction, |signed_tx| {
                    TimeoutOutcome::FallbackSubmission(signed_tx.clone())
                }),
            Phase::Submitted | Phase::Aborted => TimeoutOutcome::NoAction,
        }
    }

    pub fn mark_submitted(&mut self) -> Result<(), CacpError> {
        if self.phase != Phase::SignaturesExchanged {
            return Err(CacpError::UnexpectedPhase);
        }
        self.phase = Phase::Submitted;
        Ok(())
    }

    #[must_use]
    pub const fn signed_tx(&self) -> Option<&SignedMantleTx<Unverified>> {
        self.signed_tx.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmittedBy {
    Initiator,
    CounterpartyFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionResult {
    Included(TxHash),
    AlreadyIncluded(TxHash),
}

/// Atomic, in-memory model of the single Bedrock used by this demo.
pub struct BedrockModel {
    tips: HashMap<ChannelId, MsgId>,
    included: HashSet<TxHash>,
    submitters: HashMap<TxHash, SubmittedBy>,
}

impl BedrockModel {
    #[must_use]
    pub fn new(parents: [ChannelParent; PARTICIPANT_COUNT]) -> Self {
        Self {
            tips: parents
                .into_iter()
                .map(|parent| (parent.channel_id, parent.parent))
                .collect(),
            included: HashSet::new(),
            submitters: HashMap::new(),
        }
    }

    pub fn submit(
        &mut self,
        signed_tx: &SignedMantleTx<Unverified>,
        submitted_by: SubmittedBy,
    ) -> Result<SubmissionResult, BedrockError> {
        let tx_hash = signed_tx.hash();
        if self.included.contains(&tx_hash) {
            return Ok(SubmissionResult::AlreadyIncluded(tx_hash));
        }
        signed_tx
            .clone()
            .preverify()
            .map_err(|_error| BedrockError::InvalidProof)?;
        let ops = signed_tx.mantle_tx().ops();
        if ops.len() != PARTICIPANT_COUNT
            || ops
                .iter()
                .any(|operation| !matches!(operation, Op::ChannelInscribe(_)))
        {
            return Err(BedrockError::InvalidShape);
        }

        let mut next_tips = Vec::with_capacity(PARTICIPANT_COUNT);
        let mut seen = HashSet::new();
        for operation in ops {
            let Op::ChannelInscribe(inscription) = operation else {
                return Err(BedrockError::InvalidShape);
            };
            if !seen.insert(inscription.channel_id) {
                return Err(BedrockError::InvalidShape);
            }
            let current = self
                .tips
                .get(&inscription.channel_id)
                .ok_or(BedrockError::UnknownChannel)?;
            if *current != inscription.parent {
                return Err(BedrockError::StaleParent);
            }
            next_tips.push((inscription.channel_id, inscription.id()));
        }

        // Commit only after every operation has validated.
        for (channel_id, tip) in next_tips {
            self.tips.insert(channel_id, tip);
        }
        self.included.insert(tx_hash);
        self.submitters.insert(tx_hash, submitted_by);
        Ok(SubmissionResult::Included(tx_hash))
    }

    #[must_use]
    pub fn tip(&self, channel_id: ChannelId) -> Option<MsgId> {
        self.tips.get(&channel_id).copied()
    }

    #[must_use]
    pub fn submitted_by(&self, tx_hash: TxHash) -> Option<SubmittedBy> {
        self.submitters.get(&tx_hash).copied()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CacpError {
    #[error("the two zones must use distinct channels")]
    DuplicateChannel,
    #[error("the two zones must use distinct sequencer keys")]
    DuplicateSequencer,
    #[error("an inscription payload cannot be empty")]
    EmptyInscription,
    #[error("an inscription exceeds the Mantle bound")]
    InscriptionTooLarge,
    #[error("the intent does not match the fixed two-zone topology")]
    TopologyMismatch,
    #[error("a channel parent is missing")]
    MissingParent,
    #[error("the session is not in the required phase")]
    UnexpectedPhase,
    #[error("the proposal differs from the pre-agreed intent")]
    IntentMismatch,
    #[error("the accepting sequencer returned a different transaction")]
    TransactionMismatch,
    #[error("the supplied private key does not belong to this sequencer")]
    WrongSequencerKey,
    #[error("the counterparty signature is invalid")]
    InvalidCounterpartyProof,
    #[error(
        "the joint transaction must contain two inscriptions and at most one final fee transfer"
    )]
    InvalidJointTransaction,
    #[error("the fully signed transaction is invalid")]
    InvalidSignedTransaction,
    #[error("the final proofs differ from the proofs accepted during negotiation")]
    ProofMismatch,
    #[error("the ACCEPT candidate encoding or operation/proof shape is invalid")]
    InvalidAcceptCandidate,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BedrockError {
    #[error("the transaction is not exactly two ChannelInscribe operations")]
    InvalidShape,
    #[error("a ChannelInscribe signature is invalid")]
    InvalidProof,
    #[error("the transaction references a channel outside this demo")]
    UnknownChannel,
    #[error("at least one channel parent is stale")]
    StaleParent,
}

pub fn build_joint_tx(
    intent: &CrossZoneIntent,
    topology: &TwoZoneTopology,
    parents: &[ChannelParent; PARTICIPANT_COUNT],
) -> Result<RawMantleTx, CacpError> {
    validate_parents(intent, parents)?;
    let mut builder = MantleTxBuilder::new();
    for operation in intent.operations() {
        let sequencer = topology
            .sequencer_for(operation.channel_id)
            .ok_or(CacpError::TopologyMismatch)?;
        let parent = parents
            .iter()
            .find(|parent| parent.channel_id == operation.channel_id)
            .ok_or(CacpError::MissingParent)?;
        let inscription = operation
            .payload
            .clone()
            .try_into()
            .map_err(|_error| CacpError::InscriptionTooLarge)?;
        builder = builder
            .push_op(Op::ChannelInscribe(InscriptionOp {
                channel_id: operation.channel_id,
                inscription,
                parent: parent.parent,
                signer: sequencer.public_key,
            }))
            .map_err(|_error| CacpError::InvalidJointTransaction)?;
    }
    builder
        .build()
        .map_err(|_error| CacpError::InvalidJointTransaction)
}

fn validate_joint_tx(
    tx: &RawMantleTx,
    intent: &CrossZoneIntent,
    topology: &TwoZoneTopology,
    parents: &[ChannelParent; PARTICIPANT_COUNT],
) -> Result<(), CacpError> {
    let expected = build_joint_tx(intent, topology, parents)?;
    let expected_ops = expected.ops();
    let actual_ops = tx.ops();
    if actual_ops.len() < PARTICIPANT_COUNT || actual_ops.len() > PARTICIPANT_COUNT + 1 {
        return Err(CacpError::TransactionMismatch);
    }
    if actual_ops[..PARTICIPANT_COUNT] != expected_ops[..] {
        return Err(CacpError::TransactionMismatch);
    }
    if actual_ops.len() == PARTICIPANT_COUNT + 1
        && !matches!(actual_ops.last(), Some(Op::Transfer(_)))
    {
        return Err(CacpError::TransactionMismatch);
    }
    Ok(())
}

fn proofs_in_operation_order(
    tx: &RawMantleTx,
    topology: &TwoZoneTopology,
    initiator_proof: Ed25519Signature,
    counterparty_proof: Ed25519Signature,
    funding_proof: Option<&OpProof>,
) -> Result<OpsProofs, CacpError> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "only ChannelInscribe belongs in the locked demo scope"
    )]
    let proofs = tx
        .ops()
        .iter()
        .map(|operation| match operation {
            Op::ChannelInscribe(inscription)
                if inscription.channel_id == topology.initiator.channel_id =>
            {
                Ok(OpProof::Ed25519Sig(initiator_proof))
            }
            Op::ChannelInscribe(inscription)
                if inscription.channel_id == topology.counterparty.channel_id =>
            {
                Ok(OpProof::Ed25519Sig(counterparty_proof))
            }
            Op::Transfer(_) => funding_proof
                .cloned()
                .ok_or(CacpError::InvalidJointTransaction),
            _ => Err(CacpError::InvalidJointTransaction),
        })
        .collect::<Result<Vec<_>, _>>()?;
    OpsProofs::try_from(proofs).map_err(|_error| CacpError::InvalidJointTransaction)
}

fn require_committed_proof(expected: &OpProof, actual: &OpProof) -> Result<(), CacpError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CacpError::ProofMismatch)
    }
}

fn validate_parents(
    intent: &CrossZoneIntent,
    parents: &[ChannelParent; PARTICIPANT_COUNT],
) -> Result<(), CacpError> {
    if parents[0].channel_id == parents[1].channel_id {
        return Err(CacpError::DuplicateChannel);
    }
    if intent.operations.iter().any(|operation| {
        !parents
            .iter()
            .any(|parent| parent.channel_id == operation.channel_id)
    }) {
        return Err(CacpError::MissingParent);
    }
    Ok(())
}

fn require_key(key: &Ed25519Key, sequencer: &ZoneSequencer) -> Result<(), CacpError> {
    if key.public_key() == sequencer.public_key {
        Ok(())
    } else {
        Err(CacpError::WrongSequencerKey)
    }
}

#[cfg(test)]
mod tests {
    use logos_blockchain_codec::BinaryDecodeExt as _;
    use logos_blockchain_core::mantle::{
        NoteId,
        ledger::{Inputs, Outputs},
        ops::transfer::TransferOp,
    };
    use logos_blockchain_key_management_system_service::keys::ZkSignature;

    use super::*;

    const KEY_A: [u8; 32] = [0xA1; 32];
    const KEY_B: [u8; 32] = [0xB2; 32];

    struct Fixture {
        key_a: Ed25519Key,
        key_b: Ed25519Key,
        intent: CrossZoneIntent,
        topology: TwoZoneTopology,
        parents: [ChannelParent; PARTICIPANT_COUNT],
    }

    fn fixture() -> Fixture {
        let key_a = Ed25519Key::from_bytes(&KEY_A);
        let key_b = Ed25519Key::from_bytes(&KEY_B);
        let channel_a = ChannelId::from([1; 32]);
        let channel_b = ChannelId::from([2; 32]);
        let intent = CrossZoneIntent::new(
            [
                InscribeIntent {
                    channel_id: channel_b,
                    payload: b"zone-b-block".to_vec(),
                },
                InscribeIntent {
                    channel_id: channel_a,
                    payload: b"zone-a-block".to_vec(),
                },
            ],
            42,
        )
        .unwrap();
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
        )
        .unwrap();
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
        Fixture {
            key_a,
            key_b,
            intent,
            topology,
            parents,
        }
    }

    fn phase_three(fixture: &Fixture) -> (InitiatorSession, CounterpartySession, Finalize) {
        let mut initiator = InitiatorSession::new(
            fixture.topology.clone(),
            fixture.intent.clone(),
            fixture.parents,
        )
        .unwrap();
        let mut counterparty = CounterpartySession::new(
            fixture.topology.clone(),
            fixture.intent.clone(),
            fixture.parents,
        )
        .unwrap();
        let accept = counterparty
            .receive_propose(&initiator.propose(), &fixture.key_b)
            .unwrap();
        let finalize = initiator.receive_accept(accept, &fixture.key_a).unwrap();
        counterparty.receive_finalize(finalize.clone()).unwrap();
        (initiator, counterparty, finalize)
    }

    #[test]
    fn joint_transaction_has_only_two_channel_inscriptions() {
        let fixture = fixture();
        let tx = build_joint_tx(&fixture.intent, &fixture.topology, &fixture.parents).unwrap();
        assert_eq!(tx.ops().len(), 2);
        assert!(
            tx.ops()
                .iter()
                .all(|operation| matches!(operation, Op::ChannelInscribe(_)))
        );
    }

    #[test]
    fn happy_path_gives_both_sequencers_the_same_atomic_transaction() {
        let fixture = fixture();
        let (mut initiator, mut counterparty, finalize) = phase_three(&fixture);
        assert_eq!(initiator.signed_tx(), counterparty.signed_tx());

        let mut bedrock = BedrockModel::new(fixture.parents);
        let included = bedrock
            .submit(&finalize.signed_tx, SubmittedBy::Initiator)
            .unwrap();
        let SubmissionResult::Included(tx_hash) = included else {
            panic!("first submission must be included");
        };
        initiator.mark_submitted().unwrap();
        counterparty.mark_submitted().unwrap();
        assert_eq!(bedrock.submitted_by(tx_hash), Some(SubmittedBy::Initiator));
        assert_eq!(initiator.phase(), Phase::Submitted);
        assert_eq!(counterparty.phase(), Phase::Submitted);
        assert_ne!(
            bedrock.tip(fixture.topology.initiator.channel_id),
            Some(fixture.parents[0].parent)
        );
        assert_ne!(
            bedrock.tip(fixture.topology.counterparty.channel_id),
            Some(fixture.parents[1].parent)
        );
    }

    #[test]
    fn counterparty_fallback_submits_after_phase_three() {
        let fixture = fixture();
        let (_initiator, mut counterparty, _finalize) = phase_three(&fixture);
        let TimeoutOutcome::FallbackSubmission(signed_tx) = counterparty.on_timeout() else {
            panic!("post-Phase-3 timeout must trigger fallback submission");
        };
        let mut bedrock = BedrockModel::new(fixture.parents);
        let included = bedrock
            .submit(&signed_tx, SubmittedBy::CounterpartyFallback)
            .unwrap();
        let SubmissionResult::Included(tx_hash) = included else {
            panic!("fallback transaction must be included");
        };
        assert_eq!(
            bedrock.submitted_by(tx_hash),
            Some(SubmittedBy::CounterpartyFallback)
        );
        assert_eq!(
            bedrock.submit(&signed_tx, SubmittedBy::Initiator).unwrap(),
            SubmissionResult::AlreadyIncluded(tx_hash)
        );
    }

    #[test]
    fn timeout_before_phase_three_aborts_without_a_submittable_transaction() {
        let fixture = fixture();
        let mut initiator = InitiatorSession::new(
            fixture.topology.clone(),
            fixture.intent.clone(),
            fixture.parents,
        )
        .unwrap();
        assert_eq!(initiator.on_timeout(), TimeoutOutcome::Aborted);
        assert_eq!(initiator.phase(), Phase::Aborted);
        assert!(initiator.signed_tx().is_none());

        let mut counterparty =
            CounterpartySession::new(fixture.topology, fixture.intent, fixture.parents).unwrap();
        let _accept = counterparty
            .receive_propose(&initiator.propose(), &fixture.key_b)
            .unwrap();
        assert_eq!(counterparty.on_timeout(), TimeoutOutcome::Aborted);
        assert!(counterparty.signed_tx().is_none());
    }

    #[test]
    fn a_stale_parent_rejects_both_operations_atomically() {
        let fixture = fixture();
        let (_initiator, _counterparty, finalize) = phase_three(&fixture);
        let mut bedrock = BedrockModel::new([
            ChannelParent {
                parent: MsgId::from([9; 32]),
                ..fixture.parents[0]
            },
            fixture.parents[1],
        ]);
        let other_tip_before = bedrock.tip(fixture.parents[1].channel_id);
        assert_eq!(
            bedrock.submit(&finalize.signed_tx, SubmittedBy::Initiator),
            Err(BedrockError::StaleParent)
        );
        assert_eq!(bedrock.tip(fixture.parents[1].channel_id), other_tip_before);
    }

    #[test]
    fn proposal_id_is_canonical_over_channel_order() {
        let fixture = fixture();
        let reversed = CrossZoneIntent::new(
            [
                fixture.intent.operations()[1].clone(),
                fixture.intent.operations()[0].clone(),
            ],
            fixture.intent.nonce(),
        )
        .unwrap();
        assert_eq!(fixture.intent.proposal_id(), reversed.proposal_id());
    }

    #[test]
    fn substituted_transfer_fee_proof_is_rejected_by_receive_finalize() {
        let fixture = fixture();
        let mut initiator = InitiatorSession::new(
            fixture.topology.clone(),
            fixture.intent.clone(),
            fixture.parents,
        )
        .unwrap();
        let mut counterparty = CounterpartySession::new(
            fixture.topology.clone(),
            fixture.intent.clone(),
            fixture.parents,
        )
        .unwrap();
        let raw = build_joint_tx(&fixture.intent, &fixture.topology, &fixture.parents).unwrap();
        let mut note_bytes = [0_u8; 32];
        note_bytes[0] = 1;
        let (remaining, note_id) = NoteId::decode(&note_bytes).unwrap();
        assert!(remaining.is_empty());
        let funded_tx = MantleTxBuilder::new()
            .extend_ops(raw.ops().iter().cloned())
            .unwrap()
            .push_op(Op::Transfer(TransferOp::new(
                Inputs::new([note_id]),
                Outputs::empty(),
            )))
            .unwrap()
            .build()
            .unwrap();
        let accepted_funding_proof = zk_proof(1);
        let accept = counterparty
            .receive_funded_propose(
                &initiator.propose(),
                funded_tx,
                accepted_funding_proof.clone(),
                &fixture.key_b,
            )
            .unwrap();
        let candidate = accept.candidate().unwrap();
        assert_eq!(
            AcceptCandidate::from_bytes(&candidate.to_bytes().unwrap()).unwrap(),
            candidate
        );
        let finalize = initiator.receive_accept(accept, &fixture.key_a).unwrap();
        let mut substituted_proofs = finalize
            .signed_tx
            .ops_proofs()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        substituted_proofs[PARTICIPANT_COUNT] = zk_proof(2);
        let substituted = Finalize {
            signed_tx: SignedMantleTx::new(
                finalize.signed_tx.mantle_tx().clone(),
                OpsProofs::try_from(substituted_proofs).unwrap(),
            ),
        };

        assert_eq!(
            counterparty.receive_finalize(substituted),
            Err(CacpError::ProofMismatch)
        );
        assert_eq!(counterparty.receive_finalize(finalize), Ok(()));
        assert_eq!(
            require_committed_proof(&accepted_funding_proof, &accepted_funding_proof),
            Ok(())
        );
    }

    fn zk_proof(byte: u8) -> OpProof {
        let bytes = [byte; 128];
        let (remaining, signature) = ZkSignature::decode(&bytes).unwrap();
        assert!(remaining.is_empty());
        OpProof::ZkSig(signature)
    }
}
