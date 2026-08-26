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

use cacp_bond_core::{
    AgreementId, BondAgreement, Instruction, burn_account_id, escrow_account_id, state_account_id,
};
use lee::{AccountId, ProgramId};

/// Deterministic address binding between one executable bond agreement and its
/// neutral-zone state, escrow, and protocol-fixed burn sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondAccounts {
    pub state: AccountId,
    pub escrow: AccountId,
    pub burn: AccountId,
}

#[must_use]
pub fn bond_accounts(program_id: ProgramId, agreement_id: AgreementId) -> BondAccounts {
    BondAccounts {
        state: state_account_id(program_id, &agreement_id),
        escrow: escrow_account_id(program_id, &agreement_id),
        burn: burn_account_id(program_id),
    }
}

/// The guest recomputes the agreement ID from this complete value at Open,
/// preventing the initiator from pairing an honest ID with different fees.
#[must_use]
pub const fn open_instruction(agreement: BondAgreement) -> Instruction {
    Instruction::Open { agreement }
}

/// B's authorized Join transaction signs this recomputed agreement ID, which
/// binds B to every executable stake, fee, key, and timeout field.
#[must_use]
pub fn join_instruction(program_id: ProgramId, agreement: &BondAgreement) -> Instruction {
    Instruction::Join {
        agreement_id: agreement.id(program_id),
    }
}

#[cfg(test)]
mod tests {
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;

    use super::*;

    fn agreement() -> BondAgreement {
        BondAgreement {
            version: cacp_bond_core::AGREEMENT_VERSION,
            initiator: AccountId::new([1; 32]),
            counterparty: AccountId::new([2; 32]),
            tx_hash: [3; 32],
            initiator_mantle_key: Ed25519Key::from_bytes(&[4; 32]).public_key().to_bytes(),
            counterparty_mantle_key: Ed25519Key::from_bytes(&[5; 32]).public_key().to_bytes(),
            stake_amount: 1_000,
            challenge_fee: 100,
            response_fee: 80,
            response_window_blocks: 4,
        }
    }

    #[test]
    fn agreement_has_separate_state_escrow_and_fixed_burn_accounts() {
        let accounts = bond_accounts([7; 8], agreement().id([7; 8]));
        assert_ne!(accounts.state, accounts.escrow);
        assert_ne!(accounts.state, accounts.burn);
        assert_ne!(accounts.escrow, accounts.burn);
    }

    #[test]
    fn open_and_join_use_the_same_complete_agreement() {
        let agreement = agreement();
        let expected_id = agreement.id([7; 8]);
        let Instruction::Open { agreement: opened } = open_instruction(agreement.clone()) else {
            panic!("expected Open instruction");
        };
        assert_eq!(opened, agreement);
        assert_eq!(
            join_instruction([7; 8], &opened),
            Instruction::Join {
                agreement_id: expected_id
            }
        );
    }

    #[test]
    fn join_does_not_authorize_terms_changed_after_off_chain_review() {
        let agreed = agreement();
        let signed_join = join_instruction([7; 8], &agreed);
        let mut malicious_open = agreed;
        malicious_open.response_fee = 1_000_000;

        assert_ne!(
            signed_join,
            join_instruction([7; 8], &malicious_open),
            "changing the response fee must require a different authorized Join"
        );
    }
}
