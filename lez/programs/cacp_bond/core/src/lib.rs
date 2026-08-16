use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

pub type ProposalId = [u8; 32];
pub type MantleTxHash = [u8; 32];
pub type Commitment = [u8; 32];
pub const ACCEPT_CANDIDATE_DOMAIN: &[u8] = b"/CACP/AcceptCandidate/v1/";
pub type MantlePublicKey = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MantleSignature(pub Vec<u8>);

impl MantleSignature {
    #[must_use]
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes.to_vec())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

const STATE_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CacpBondState/0000000/";
const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CacpBondEscrow/000000/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    Open {
        proposal_id: ProposalId,
        counterparty: AccountId,
        expected_tx_hash: MantleTxHash,
        expected_accept_candidate_commitment: Commitment,
        initiator_mantle_key: MantlePublicKey,
        stake_amount: u128,
        challenge_bond: u128,
        response_window_blocks: u64,
    },
    Join {
        proposal_id: ProposalId,
        tx_hash: MantleTxHash,
        accept_candidate_commitment: Commitment,
        counterparty_mantle_key: MantlePublicKey,
        accept_commitment: Commitment,
    },
    ChallengeAccept {
        proposal_id: ProposalId,
    },
    DiscloseAccept {
        proposal_id: ProposalId,
        accept_candidate: Vec<u8>,
        proof: MantleSignature,
    },
    ChallengeFinalize {
        proposal_id: ProposalId,
        accept_candidate: Vec<u8>,
        accept_proof: MantleSignature,
    },
    DiscloseFinalize {
        proposal_id: ProposalId,
        proof: MantleSignature,
    },
    Complete {
        proposal_id: ProposalId,
        initiator_proof: MantleSignature,
        counterparty_proof: MantleSignature,
    },
    SettleTimeout {
        proposal_id: ProposalId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Phase {
    AwaitingCounterparty,
    AwaitingAccept,
    AcceptChallenged,
    AwaitingFinalize,
    FinalizeChallenged,
    Settled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Settlement {
    Completed,
    CounterpartyDidNotEngage,
    ExpiredWithoutChallenge,
    InitiatorForfeited,
    CounterpartyForfeited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutPayout {
    RefundInitiatorStake,
    RefundBothStakes,
    AwardEscrowToInitiator,
    AwardEscrowToCounterparty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutResolution {
    pub settlement: Settlement,
    pub payout: TimeoutPayout,
}

/// Defines an exit for every non-terminal phase. Quiet-window expiry never
/// decides who withheld an off-chain message; it simply refunds both stakes.
/// Forfeiture is possible only after an explicit on-chain challenge expires.
#[must_use]
pub const fn timeout_resolution(phase: Phase) -> Option<TimeoutResolution> {
    match phase {
        Phase::AwaitingCounterparty => Some(TimeoutResolution {
            settlement: Settlement::CounterpartyDidNotEngage,
            payout: TimeoutPayout::RefundInitiatorStake,
        }),
        Phase::AwaitingAccept | Phase::AwaitingFinalize => Some(TimeoutResolution {
            settlement: Settlement::ExpiredWithoutChallenge,
            payout: TimeoutPayout::RefundBothStakes,
        }),
        Phase::AcceptChallenged => Some(TimeoutResolution {
            settlement: Settlement::CounterpartyForfeited,
            payout: TimeoutPayout::AwardEscrowToInitiator,
        }),
        Phase::FinalizeChallenged => Some(TimeoutResolution {
            settlement: Settlement::InitiatorForfeited,
            payout: TimeoutPayout::AwardEscrowToCounterparty,
        }),
        Phase::Settled => None,
    }
}

#[must_use]
pub const fn can_challenge_accept(phase: Phase) -> bool {
    matches!(phase, Phase::AwaitingAccept)
}

#[must_use]
pub const fn can_challenge_finalize(phase: Phase) -> bool {
    matches!(phase, Phase::AwaitingAccept | Phase::AwaitingFinalize)
}

#[must_use]
pub const fn can_disclose_accept(phase: Phase) -> bool {
    matches!(phase, Phase::AcceptChallenged)
}

#[must_use]
pub const fn can_disclose_finalize(phase: Phase) -> bool {
    matches!(phase, Phase::FinalizeChallenged)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondState {
    pub proposal_id: ProposalId,
    pub initiator: AccountId,
    pub counterparty: AccountId,
    pub initiator_mantle_key: MantlePublicKey,
    pub counterparty_mantle_key: Option<MantlePublicKey>,
    pub stake_amount: u128,
    pub challenge_bond: u128,
    pub response_window_blocks: u64,
    pub expires_at_block: u64,
    pub tx_hash: MantleTxHash,
    pub accept_candidate_commitment: Commitment,
    pub accept_commitment: Option<Commitment>,
    pub phase: Phase,
    pub settlement: Option<Settlement>,
}

impl BondState {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("CACP bond state serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

#[must_use]
pub fn state_account_id(program_id: ProgramId, proposal_id: &ProposalId) -> AccountId {
    AccountId::for_public_pda(&program_id, &state_seed(proposal_id))
}

#[must_use]
pub fn escrow_account_id(program_id: ProgramId, proposal_id: &ProposalId) -> AccountId {
    AccountId::for_public_pda(&program_id, &escrow_seed(proposal_id))
}

#[must_use]
pub fn state_seed(proposal_id: &ProposalId) -> PdaSeed {
    derived_seed(&STATE_SEED_DOMAIN, proposal_id)
}

#[must_use]
pub fn escrow_seed(proposal_id: &ProposalId) -> PdaSeed {
    derived_seed(&ESCROW_SEED_DOMAIN, proposal_id)
}

#[must_use]
pub fn proof_commitment(proof: &MantleSignature) -> Commitment {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    Impl::hash_bytes(proof.as_bytes())
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

#[must_use]
pub fn accept_candidate_commitment(candidate: &[u8]) -> Commitment {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    Impl::hash_bytes(candidate)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

/// The candidate bytes start with a versioned domain and the Mantle tx hash,
/// allowing the guest to bind opaque, recoverable transaction/proof bytes to
/// the same transaction that both parties staked on.
#[must_use]
pub fn valid_accept_candidate(candidate: &[u8], expected_tx_hash: &MantleTxHash) -> bool {
    let hash_start = ACCEPT_CANDIDATE_DOMAIN.len();
    let hash_end = hash_start + expected_tx_hash.len();
    candidate.starts_with(ACCEPT_CANDIDATE_DOMAIN)
        && candidate.get(hash_start..hash_end) == Some(expected_tx_hash)
        && candidate.len() > hash_end
}

/// Rejects encodings that cannot be used as Ed25519 verification keys, as
/// well as small-order keys that must not identify a CACP participant.
#[must_use]
pub fn valid_mantle_key(bytes: &MantlePublicKey) -> bool {
    VerifyingKey::from_bytes(bytes).is_ok_and(|key| !key.is_weak())
}

fn derived_seed(domain: &[u8; 32], proposal_id: &ProposalId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(domain);
    bytes[32..].copy_from_slice(proposal_id);
    let seed = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_pdas_are_stable_and_separate() {
        let program_id = [7; 8];
        let proposal = [3; 32];
        assert_eq!(
            state_account_id(program_id, &proposal),
            state_account_id(program_id, &proposal)
        );
        assert_ne!(
            state_account_id(program_id, &proposal),
            escrow_account_id(program_id, &proposal)
        );
        assert_ne!(
            state_account_id(program_id, &proposal),
            state_account_id(program_id, &[4; 32])
        );
    }

    #[test]
    fn malformed_or_weak_mantle_keys_are_rejected_at_registration() {
        let valid_basepoint = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        assert!(valid_mantle_key(&valid_basepoint));
        let non_canonical_y = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(!valid_mantle_key(&non_canonical_y));
        assert!(!valid_mantle_key(&[0; 32]));
    }

    #[test]
    fn accept_candidate_is_bound_to_its_transaction_and_exact_bytes() {
        let tx_hash = [7_u8; 32];
        let mut candidate = ACCEPT_CANDIDATE_DOMAIN.to_vec();
        candidate.extend_from_slice(&tx_hash);
        candidate.extend_from_slice(b"canonical funded transaction and fee proof");
        assert!(valid_accept_candidate(&candidate, &tx_hash));

        let commitment = accept_candidate_commitment(&candidate);
        candidate.push(0);
        assert_ne!(accept_candidate_commitment(&candidate), commitment);
        assert!(!valid_accept_candidate(&candidate, &[8_u8; 32]));
    }

    #[test]
    fn every_live_phase_has_a_timeout_exit() {
        for phase in [
            Phase::AwaitingCounterparty,
            Phase::AwaitingAccept,
            Phase::AcceptChallenged,
            Phase::AwaitingFinalize,
            Phase::FinalizeChallenged,
        ] {
            assert!(
                timeout_resolution(phase).is_some(),
                "missing exit for {phase:?}"
            );
        }
        assert_eq!(timeout_resolution(Phase::Settled), None);
    }

    #[test]
    fn only_expired_challenges_can_forfeit_stake() {
        assert_eq!(
            timeout_resolution(Phase::AwaitingAccept),
            Some(TimeoutResolution {
                settlement: Settlement::ExpiredWithoutChallenge,
                payout: TimeoutPayout::RefundBothStakes,
            })
        );
        assert_eq!(
            timeout_resolution(Phase::AwaitingFinalize),
            Some(TimeoutResolution {
                settlement: Settlement::ExpiredWithoutChallenge,
                payout: TimeoutPayout::RefundBothStakes,
            })
        );
        assert_eq!(
            timeout_resolution(Phase::AcceptChallenged)
                .expect("challenge must resolve")
                .settlement,
            Settlement::CounterpartyForfeited
        );
        assert_eq!(
            timeout_resolution(Phase::FinalizeChallenged)
                .expect("challenge must resolve")
                .settlement,
            Settlement::InitiatorForfeited
        );
    }

    #[test]
    fn disclosure_is_never_a_routine_confirmation() {
        assert!(can_challenge_accept(Phase::AwaitingAccept));
        assert!(can_challenge_finalize(Phase::AwaitingAccept));
        assert!(!can_disclose_accept(Phase::AwaitingAccept));
        assert!(!can_disclose_finalize(Phase::AwaitingFinalize));
        assert!(can_disclose_accept(Phase::AcceptChallenged));
        assert!(can_disclose_finalize(Phase::FinalizeChallenged));
    }
}
