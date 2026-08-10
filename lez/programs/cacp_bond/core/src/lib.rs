use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

pub type ProposalId = [u8; 32];
pub type MantleTxHash = [u8; 32];
pub type Commitment = [u8; 32];
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
        initiator_mantle_key: MantlePublicKey,
        counterparty_mantle_key: MantlePublicKey,
        stake_amount: u128,
        challenge_bond: u128,
        response_window_blocks: u64,
    },
    Join {
        proposal_id: ProposalId,
        tx_hash: MantleTxHash,
        accept_commitment: Commitment,
    },
    ChallengeAccept {
        proposal_id: ProposalId,
    },
    DiscloseAccept {
        proposal_id: ProposalId,
        proof: MantleSignature,
    },
    ChallengeFinalize {
        proposal_id: ProposalId,
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
    InitiatorForfeited,
    CounterpartyForfeited,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondState {
    pub proposal_id: ProposalId,
    pub initiator: AccountId,
    pub counterparty: AccountId,
    pub initiator_mantle_key: MantlePublicKey,
    pub counterparty_mantle_key: MantlePublicKey,
    pub stake_amount: u128,
    pub challenge_bond: u128,
    pub response_window_blocks: u64,
    pub expires_at_block: u64,
    pub tx_hash: Option<MantleTxHash>,
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
}
