//! Committee approvals of `system_upgrader` changes, collected until a threshold of them lets the
//! producer build the change.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};
use lee_core::BlockId;
use sequencer_stake_core::{SequencerKey, SequencerStakeConfig, slash_approval_threshold};
use system_upgrader_core::{Approval, Proposal, SignedApproval};

type ByProposal = BTreeMap<Proposal, BTreeMap<SequencerKey, Approval>>;

/// Verified approvals, by proposal and signer. A signer's newer approval of the same proposal
/// replaces its older one.
#[derive(Debug, Default)]
pub struct SystemApprovals {
    by_proposal: ByProposal,
    /// Changed since the last [`SystemApprovals::take_changed`].
    changed: bool,
}

/// How the pool is persisted, versioned so a later layout can still read this one.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum PersistedApprovals {
    V1(ByProposal),
}

impl SystemApprovals {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&PersistedApprovals::V1(self.by_proposal.clone()))
            .expect("approvals serialize")
    }

    /// `None` if `bytes` doesn't decode as a persisted pool.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let PersistedApprovals::V1(by_proposal) = borsh::from_slice(bytes).ok()?;
        Some(Self {
            by_proposal,
            changed: false,
        })
    }

    /// Whether the pool changed since the last call, so it needs persisting.
    pub const fn take_changed(&mut self) -> bool {
        let changed = self.changed;
        self.changed = false;
        changed
    }

    /// Keeps `signed` if it is a valid approval, by an accredited member of `committee`, still
    /// usable at `next_block`.
    pub fn add(
        &mut self,
        signed: SignedApproval,
        committee: &SequencerStakeConfig,
        next_block: BlockId,
    ) -> Result<()> {
        let SignedApproval { proposal, approval } = signed;
        let channel_id = committee
            .channel_id
            .context("the committee config has no channel id")?;
        ensure!(
            approval.valid_until >= next_block,
            "the approval expired at block {}",
            approval.valid_until
        );
        ensure!(
            committee.is_accredited_committee_member(&approval.signer),
            "the signer is not an accredited committee member"
        );
        ensure!(
            approval.verify(channel_id, &proposal),
            "the approval's signature does not verify"
        );
        self.by_proposal
            .entry(proposal)
            .or_default()
            .insert(approval.signer, approval);
        self.changed = true;
        Ok(())
    }

    /// Every proposal a threshold of `committee` approves at `block_id`, each with a threshold's
    /// worth of approvals: those that expire last, so the change stays valid longest. Drops the
    /// approvals that have expired.
    pub fn ready(
        &mut self,
        committee: &SequencerStakeConfig,
        block_id: BlockId,
    ) -> Vec<(Proposal, Vec<Approval>)> {
        let before: usize = self.by_proposal.values().map(BTreeMap::len).sum();
        self.by_proposal.retain(|_, approvals| {
            approvals.retain(|_, approval| approval.valid_until >= block_id);
            !approvals.is_empty()
        });
        let after: usize = self.by_proposal.values().map(BTreeMap::len).sum();
        self.changed |= after != before;
        let threshold = slash_approval_threshold(committee.accredited_committee_members_count());
        self.by_proposal
            .iter()
            .filter_map(|(proposal, approvals)| {
                let mut usable: Vec<Approval> = approvals
                    .values()
                    .filter(|approval| committee.is_accredited_committee_member(&approval.signer))
                    .cloned()
                    .collect();
                if usable.len() < threshold {
                    return None;
                }
                usable.sort_by_key(|approval| std::cmp::Reverse(approval.valid_until));
                usable.truncate(threshold);
                Some((*proposal, usable))
            })
            .collect()
    }

    /// Forgets `proposal`, once its change has been included or has failed.
    pub fn remove(&mut self, proposal: &Proposal) {
        self.changed |= self.by_proposal.remove(proposal).is_some();
    }
}

#[cfg(test)]
mod tests {
    use lee_core::account::AccountId;
    use sequencer_stake_core::{
        ChannelParams, SequencerEntry,
        ed25519_dalek::{Signer as _, SigningKey},
    };
    use system_upgrader_core::{SystemProgramName, approval_message};

    use super::*;

    const CHANNEL_ID: [u8; 32] = [5; 32];

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sequencer_key(seed: u8) -> SequencerKey {
        SequencerKey::new(key(seed).verifying_key().to_bytes()).unwrap()
    }

    /// Three accredited members (seeds 1 to 3), so two approvals meet the threshold.
    fn committee() -> SequencerStakeConfig {
        SequencerStakeConfig {
            channel_params: Some(ChannelParams {
                minimum_sequencer_stake: 1,
                posting_timeframe: 1,
                posting_timeout: 2,
                exit_delay: 1,
            }),
            channel_id: Some(CHANNEL_ID),
            entries: (1..=3)
                .map(|seed| {
                    (
                        sequencer_key(seed),
                        SequencerEntry {
                            account_id: AccountId::new([seed; 32]),
                            total_staked: 10,
                            total_pending_unstake: 0,
                        },
                    )
                })
                .collect(),
        }
    }

    fn proposal() -> Proposal {
        Proposal::Schedule {
            name: SystemProgramName::new(b"clock"),
            first_segment: AccountId::new([9; 32]),
            from_height: 50,
        }
    }

    fn signed(seed: u8, valid_until: BlockId) -> SignedApproval {
        let proposal = proposal();
        SignedApproval {
            proposal,
            approval: Approval {
                signer: sequencer_key(seed),
                valid_until,
                signature: key(seed)
                    .sign(&approval_message(CHANNEL_ID, &proposal, valid_until))
                    .to_bytes()
                    .to_vec(),
            },
        }
    }

    #[test]
    fn a_proposal_is_ready_once_a_threshold_approves() {
        let mut pool = SystemApprovals::default();
        pool.add(signed(1, 20), &committee(), 1).unwrap();
        assert!(pool.ready(&committee(), 1).is_empty(), "one of two");

        pool.add(signed(2, 30), &committee(), 1).unwrap();
        let ready = pool.ready(&committee(), 1);
        let [(ready_proposal, approvals)] = ready.as_slice() else {
            panic!("expected one ready proposal, got {ready:?}");
        };
        assert_eq!(*ready_proposal, proposal());
        assert_eq!(approvals.len(), 2);
    }

    #[test]
    fn a_threshold_of_the_approvals_that_expire_last_is_used() {
        let mut pool = SystemApprovals::default();
        for (seed, valid_until) in [(1, 20), (2, 40), (3, 30)] {
            pool.add(signed(seed, valid_until), &committee(), 1)
                .unwrap();
        }

        let ready = pool.ready(&committee(), 1);
        let signers: Vec<SequencerKey> = ready[0].1.iter().map(|a| a.signer).collect();
        assert_eq!(signers, vec![sequencer_key(2), sequencer_key(3)]);
    }

    #[test]
    fn expired_approvals_are_dropped() {
        let mut pool = SystemApprovals::default();
        pool.add(signed(1, 20), &committee(), 1).unwrap();
        pool.add(signed(2, 10), &committee(), 1).unwrap();

        assert!(
            pool.ready(&committee(), 11).is_empty(),
            "one approval expired at 10"
        );
    }

    #[test]
    fn the_pool_round_trips_through_its_bytes() {
        let mut pool = SystemApprovals::default();
        pool.add(signed(1, 20), &committee(), 1).unwrap();
        pool.add(signed(2, 30), &committee(), 1).unwrap();
        assert!(pool.take_changed());
        assert!(!pool.take_changed(), "taking clears it");

        let mut restored = SystemApprovals::from_bytes(&pool.to_bytes()).unwrap();
        assert_eq!(restored.ready(&committee(), 1), pool.ready(&committee(), 1));
    }

    #[test]
    fn invalid_approvals_are_refused() {
        let mut pool = SystemApprovals::default();
        let outsider = signed(9, 20);
        assert!(
            pool.add(outsider, &committee(), 1).is_err(),
            "not accredited"
        );

        let mut forged = signed(1, 20);
        forged.approval.valid_until = 21;
        assert!(pool.add(forged, &committee(), 1).is_err(), "bad signature");

        assert!(
            pool.add(signed(1, 20), &committee(), 21).is_err(),
            "already expired"
        );
    }
}
