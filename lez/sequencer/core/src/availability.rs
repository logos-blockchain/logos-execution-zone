//! A proof-bearing block's candidate, which its producer proposes before posting it, and the
//! approvals of the committee members that hold its proofs in Logos Storage and serve them.

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, ensure};
use borsh::{BorshDeserialize, BorshSerialize};
use chain_state::{
    ChainState,
    apply::{apply_block_to_state, validate_against_tip},
};
use common::{block::DigestedBlock, storage_cid::StorageCid};
use lee::privacy_preserving_transaction::circuit::ProofDigest;
use sequencer_bedrock_actor::protocol::Ed25519Key;
use sequencer_stake_core::{
    SequencerKey,
    ed25519_dalek::{Signature, VerifyingKey},
};
use tokio::sync::Mutex;

use crate::proof_objects::{Admission, ProofObjects};

/// How long an approval holds its candidate's proofs: for the block to land, and its chain entry
/// to hold them in turn.
const APPROVAL_PROMISE: Duration = Duration::from_mins(10);

/// What an approval is for: one candidate block of one producer's turn, on one parent, with its
/// proofs under the CIDs its inscription will name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct CandidateId {
    pub producer: SequencerKey,
    pub turn_start_slot: u64,
    pub parent: [u8; 32],
    pub candidate_hash: [u8; 32],
    pub locators: Vec<StorageCid>,
}

impl CandidateId {
    /// The bytes an approval of the candidate signs.
    #[must_use]
    pub fn approval_message(&self, channel_id: [u8; 32]) -> Vec<u8> {
        sequencer_stake_core::availability_approval_message(
            channel_id,
            self.producer,
            self.turn_start_slot,
            self.parent,
            self.candidate_hash,
            &self.locators,
        )
    }
}

/// A candidate block its producer asks the committee to approve.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Candidate {
    pub id: CandidateId,
    pub block: DigestedBlock,
}

impl Candidate {
    /// Whether `id` names this block: its recomputed hash, and one locator per proof.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.block.recompute_hash().0 == self.id.candidate_hash
            && self.block.header.hash.0 == self.id.candidate_hash
            && self.block.body.proofs().count() == self.id.locators.len()
    }
}

/// A committee member's signature that it holds and serves a candidate's proofs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AvailabilityApproval {
    pub candidate: CandidateId,
    pub signer: SequencerKey,
    pub signature: [u8; 64],
}

impl AvailabilityApproval {
    #[must_use]
    pub fn sign(candidate: CandidateId, channel_id: [u8; 32], key: &Ed25519Key) -> Self {
        let message = candidate.approval_message(channel_id);
        Self {
            candidate,
            signer: SequencerKey::new(key.public_key().to_bytes())
                .expect("a channel signing key is a sequencer key"),
            signature: key.sign_payload(&message).to_bytes(),
        }
    }

    /// Whether the signature is `signer`'s over the candidate.
    #[must_use]
    pub fn verify(&self, channel_id: [u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.signer.to_bytes()) else {
            return false;
        };
        key.verify_strict(
            &self.candidate.approval_message(channel_id),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

/// What the availability topic carries.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AvailabilityMessage {
    Candidate(Box<Candidate>),
    Approval(Box<AvailabilityApproval>),
}

/// Approves `candidate` once this node holds and serves its proofs.
///
/// The proofs are fetched whole, verified, and stored under exactly the CIDs the candidate names.
/// The block must extend this node's head and execute on it. The proofs are then held for
/// [`APPROVAL_PROMISE`], their records already persisted.
pub async fn approve_candidate(
    candidate: Candidate,
    chain: Arc<Mutex<ChainState>>,
    proof_objects: Arc<ProofObjects>,
    key: Ed25519Key,
    channel_id: [u8; 32],
) -> anyhow::Result<AvailabilityApproval> {
    let Candidate { id, block } = candidate;
    let mut proofs = Vec::with_capacity(id.locators.len());
    for (digest, locator) in block.body.proofs().zip(&id.locators) {
        let proof = proof_objects
            .fetch(*digest, *locator, Admission::Live, |_proof| true)
            .await?;
        ensure!(
            proof_objects.locator(digest) == Some(*locator),
            "a proof is stored under another CID than the candidate names"
        );
        proofs.push(proof);
    }
    let full = block
        .hydrate(|digest| {
            proofs
                .iter()
                .find(|proof| proof.digest() == *digest)
                .cloned()
        })
        .context("the fetched proofs do not hydrate the candidate")?;

    let (pin, tip, mut state) = {
        let chain = chain.lock().await;
        (chain.pin(), chain.head_tip(), chain.head_state().clone())
    };
    ensure!(
        <[u8; 32]>::from(pin) == id.parent,
        "the candidate does not extend this node's head"
    );
    tokio::task::spawn_blocking(move || {
        validate_against_tip(tip.as_ref(), &full)?;
        apply_block_to_state(&full, &mut state)
    })
    .await
    .context("the candidate's execution did not finish")?
    .context("the candidate does not execute on this node's head")?;

    let held: Vec<ProofDigest> = block.body.proofs().copied().collect();
    for digest in &held {
        proof_objects.hold(*digest);
    }
    tokio::spawn(async move {
        tokio::time::sleep(APPROVAL_PROMISE).await;
        for digest in &held {
            proof_objects.release(digest);
        }
    });
    Ok(AvailabilityApproval::sign(id, channel_id, &key))
}
