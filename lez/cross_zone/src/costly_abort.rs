use cacp_bond_core::{Instruction, escrow_account_id, state_account_id};
use lee::{AccountId, ProgramId};

use crate::cacp::{CostlyAbortBondTerms, ProposalId};

/// Deterministic address binding between one CACP proposal and its neutral-zone
/// bond state/escrow accounts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondAccounts {
    pub state: AccountId,
    pub escrow: AccountId,
}

#[must_use]
pub fn bond_accounts(program_id: ProgramId, proposal_id: ProposalId) -> BondAccounts {
    BondAccounts {
        state: state_account_id(program_id, &proposal_id.0),
        escrow: escrow_account_id(program_id, &proposal_id.0),
    }
}

/// Builds the opening instruction from terms already committed by both CACP
/// participants. Execution transfers the initiator's real public-account stake
/// into the program-controlled escrow.
#[must_use]
pub fn open_instruction(
    proposal_id: ProposalId,
    counterparty: AccountId,
    initiator_mantle_key: [u8; 32],
    counterparty_mantle_key: [u8; 32],
    terms: CostlyAbortBondTerms,
) -> Instruction {
    Instruction::Open {
        proposal_id: proposal_id.0,
        counterparty,
        initiator_mantle_key,
        counterparty_mantle_key,
        stake_amount: terms.stake_amount,
        challenge_bond: terms.challenge_bond,
        response_window_blocks: terms.response_window_blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_blockchain_core::mantle::ops::channel::ChannelId;

    #[test]
    fn proposal_has_separate_program_owned_state_and_escrow() {
        let accounts = bond_accounts([7; 8], ProposalId([3; 32]));
        assert_ne!(accounts.state, accounts.escrow);
    }

    #[test]
    fn open_instruction_uses_committed_terms() {
        let terms = CostlyAbortBondTerms {
            bond_zone: ChannelId::from([9; 32]),
            bond_program_id: [7; 8],
            stake_amount: 1_000,
            challenge_bond: 100,
            response_window_blocks: 4,
        };
        let instruction = open_instruction(
            ProposalId([3; 32]),
            AccountId::new([2; 32]),
            [0xA1; 32],
            [0xB2; 32],
            terms,
        );
        assert!(matches!(
            instruction,
            Instruction::Open {
                stake_amount: 1_000,
                challenge_bond: 100,
                response_window_blocks: 4,
                ..
            }
        ));
    }
}
