//! A proof-bearing block's candidate, which its producer proposes before posting it, and the
//! approvals of the committee members that hold its proofs in Logos Storage and serve them.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context as _, ensure};
use borsh::{BorshDeserialize, BorshSerialize};
use chain_state::{
    ChainState,
    apply::{apply_judged_block_to_state, validate_against_tip},
};
use common::{block::DigestedBlock, storage_cid::StorageCid};
use kameo::actor::ActorRef;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, Ed25519Key},
};
use sequencer_stake_core::{
    SequencerKey,
    ed25519_dalek::{Signature, VerifyingKey},
};
use sharding_pool_actor::ShardingPoolActor;
use tokio::sync::Mutex;

use crate::{
    proof_objects::{Admission, ProofObjects, until},
    release_finality,
};

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
/// The block must extend this node's head, checked before anything is fetched. Its proofs are
/// fetched whole, verified, and stored under exactly the CIDs it names; it must then execute on
/// the head as the fold would judge it. The proofs are held for [`APPROVAL_PROMISE`], persisted
/// before the approval is signed.
pub async fn approve_candidate<B: BedrockActorTrait>(
    candidate: Candidate,
    chain: Arc<Mutex<ChainState>>,
    proof_objects: Arc<ProofObjects>,
    key: Ed25519Key,
    bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
    channel_id: ChannelId,
) -> anyhow::Result<AvailabilityApproval> {
    let Candidate { id, block } = candidate;
    ensure!(
        <[u8; 32]>::from(chain.lock().await.pin()) == id.parent,
        "the candidate does not extend this node's head"
    );
    let mut proofs = BTreeMap::new();
    for (digest, locator) in block.body.proofs().zip(&id.locators) {
        if !proofs.contains_key(digest) {
            let proof = proof_objects
                .fetch(*digest, *locator, Admission::Live, |_proof| true)
                .await?;
            proofs.insert(*digest, proof);
        }
        ensure!(
            proof_objects.locator(digest) == Some(*locator),
            "a proof is stored under another CID than the candidate names"
        );
    }
    let full = block
        .hydrate(|digest| proofs.get(digest).cloned())
        .context("the fetched proofs do not hydrate the candidate")?;

    let (pin, tip, mut state) = {
        let chain = chain.lock().await;
        (chain.pin(), chain.head_tip(), chain.head_state().clone())
    };
    ensure!(
        <[u8; 32]>::from(pin) == id.parent,
        "the candidate does not extend this node's head"
    );
    let releasable =
        release_finality::producible_releases(&bedrock_pool_ref, channel_id, &state).await;
    tokio::task::spawn_blocking(move || {
        validate_against_tip(tip.as_ref(), &full)?;
        apply_judged_block_to_state(&full, &mut state, Some(&releasable))
    })
    .await
    .context("the candidate's execution did not finish")?
    .context("the candidate does not execute on this node's head")?;

    for digest in proofs.keys() {
        proof_objects.hold(digest, until(APPROVAL_PROMISE)).await?;
    }
    Ok(AvailabilityApproval::sign(id, *channel_id.as_ref(), &key))
}

#[cfg(test)]
mod tests {
    use common::{storage_cid::STORAGE_CID_PREFIX, test_utils};

    use super::*;

    const CHANNEL: [u8; 32] = [1; 32];

    fn key(seed: u8) -> Ed25519Key {
        Ed25519Key::from_bytes(&[seed; 32])
    }

    fn sequencer_key(seed: u8) -> SequencerKey {
        SequencerKey::new(key(seed).public_key().to_bytes()).unwrap()
    }

    fn candidate() -> Candidate {
        let block = test_utils::produce_dummy_block(1, None, Vec::new()).digested();
        Candidate {
            id: CandidateId {
                producer: sequencer_key(1),
                turn_start_slot: 60,
                parent: [2; 32],
                candidate_hash: block.header.hash.0,
                locators: Vec::new(),
            },
            block,
        }
    }

    #[test]
    fn an_approval_verifies_for_its_candidate_only() {
        let approval = AvailabilityApproval::sign(candidate().id, CHANNEL, &key(2));

        assert!(approval.verify(CHANNEL));
        assert!(!approval.verify([9; 32]));
        for changed in [
            CandidateId {
                turn_start_slot: 61,
                ..candidate().id
            },
            CandidateId {
                parent: [3; 32],
                ..candidate().id
            },
            CandidateId {
                producer: sequencer_key(3),
                ..candidate().id
            },
            CandidateId {
                locators: vec![
                    StorageCid::try_from([&STORAGE_CID_PREFIX[..], &[0; 32]].concat().as_slice())
                        .unwrap(),
                ],
                ..candidate().id
            },
        ] {
            assert!(
                !AvailabilityApproval {
                    candidate: changed,
                    ..approval.clone()
                }
                .verify(CHANNEL)
            );
        }
    }

    #[test]
    fn an_approval_is_no_slash_approval() {
        let id = candidate().id;
        let message = id.approval_message(CHANNEL);

        assert!(message.starts_with(&sequencer_stake_core::AVAILABILITY_APPROVAL_DOMAIN));
        assert_ne!(
            sequencer_stake_core::AVAILABILITY_APPROVAL_DOMAIN,
            sequencer_stake_core::SLASH_APPROVAL_DOMAIN
        );
    }

    #[test]
    fn a_candidate_names_its_own_block_with_a_locator_per_proof() {
        assert!(candidate().is_consistent());
        assert!(
            !Candidate {
                id: CandidateId {
                    candidate_hash: [7; 32],
                    ..candidate().id
                },
                ..candidate()
            }
            .is_consistent()
        );
        assert!(
            !Candidate {
                id: CandidateId {
                    locators: vec![
                        StorageCid::try_from(
                            [&STORAGE_CID_PREFIX[..], &[0; 32]].concat().as_slice()
                        )
                        .unwrap(),
                    ],
                    ..candidate().id
                },
                ..candidate()
            }
            .is_consistent()
        );
    }
}
