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

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

pub const AGREEMENT_VERSION: u8 = 1;
pub const AGREEMENT_DOMAIN: &[u8] = b"/CACP/BondAgreement/v1/";
pub const BURN_POLICY_VERSION: u8 = 1;
const BURN_SEED_DOMAIN: &[u8] = b"/LEZ/v0.3/CacpBondBurn/v1/";
const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CacpBondEscrow/000000/";
const STATE_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CacpBondState/0000000/";

pub type AgreementId = [u8; 32];
pub type MantlePublicKey = [u8; 32];
pub type MantleTxHash = [u8; 32];

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

/// The complete executable agreement. Both participants can derive the same
/// ID before either stake is locked, and the guest recomputes that ID at Open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BondAgreement {
    pub version: u8,
    pub initiator: AccountId,
    pub counterparty: AccountId,
    pub tx_hash: MantleTxHash,
    pub initiator_mantle_key: MantlePublicKey,
    pub counterparty_mantle_key: MantlePublicKey,
    pub stake_amount: u128,
    pub challenge_fee: u128,
    pub response_fee: u128,
    pub response_window_blocks: u64,
}

impl BondAgreement {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.version == AGREEMENT_VERSION
            && self.initiator != self.counterparty
            && self.initiator_mantle_key != self.counterparty_mantle_key
            && valid_mantle_key(&self.initiator_mantle_key)
            && valid_mantle_key(&self.counterparty_mantle_key)
            && self.stake_amount > 0
            && self.challenge_fee > 0
            && self.response_fee > 0
            && self.response_window_blocks > 0
            && self.participant_deposit().is_some()
    }

    /// Each party prepays every fee it could owe in the longest live path.
    #[must_use]
    pub fn participant_deposit(&self) -> Option<u128> {
        self.stake_amount
            .checked_add(self.challenge_fee)?
            .checked_add(self.response_fee)
    }

    #[must_use]
    pub const fn fee_reserve(&self) -> Option<u128> {
        self.challenge_fee.checked_add(self.response_fee)
    }

    #[must_use]
    pub fn id(&self, program_id: ProgramId) -> AgreementId {
        agreement_id(program_id, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    Open {
        agreement: BondAgreement,
    },
    Join {
        agreement_id: AgreementId,
    },
    ChallengeAccept {
        agreement_id: AgreementId,
    },
    DiscloseAccept {
        agreement_id: AgreementId,
        proof: MantleSignature,
    },
    ChallengeFinalize {
        agreement_id: AgreementId,
        accept_proof: MantleSignature,
    },
    DiscloseFinalize {
        agreement_id: AgreementId,
        proof: MantleSignature,
    },
    Complete {
        agreement_id: AgreementId,
        initiator_proof: MantleSignature,
        counterparty_proof: MantleSignature,
    },
    SettleTimeout {
        agreement_id: AgreementId,
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

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondState {
    pub agreement_id: AgreementId,
    pub agreement: BondAgreement,
    pub expires_at_block: u64,
    pub initiator_fees_burned: u128,
    pub counterparty_fees_burned: u128,
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

    #[must_use]
    pub const fn fees_burned(&self, initiator: bool) -> u128 {
        if initiator {
            self.initiator_fees_burned
        } else {
            self.counterparty_fees_burned
        }
    }

    #[must_use]
    pub fn participant_refund(&self, initiator: bool) -> Option<u128> {
        self.agreement
            .participant_deposit()?
            .checked_sub(self.fees_burned(initiator))
    }

    #[must_use]
    pub fn remaining_fee_reserve(&self, initiator: bool) -> Option<u128> {
        self.agreement
            .fee_reserve()?
            .checked_sub(self.fees_burned(initiator))
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

/// Completion is free only while no escalation is active. Once challenged,
/// the challenged party must use the matching disclosure instruction and pay
/// the configured response fee.
#[must_use]
pub const fn can_complete(phase: Phase) -> bool {
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

/// Defines an exit for every non-terminal phase.
///
/// Quiet-window expiry never decides who withheld an off-chain message; it
/// simply refunds both stakes. Forfeiture is possible only after an explicit
/// on-chain challenge expires.
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
pub fn agreement_id(program_id: ProgramId, agreement: &BondAgreement) -> AgreementId {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(AGREEMENT_DOMAIN);
    bytes.push(agreement.version);
    bytes.push(BURN_POLICY_VERSION);
    for word in program_id {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(agreement.initiator.as_ref());
    bytes.extend_from_slice(agreement.counterparty.as_ref());
    bytes.extend_from_slice(&agreement.tx_hash);
    bytes.extend_from_slice(&agreement.initiator_mantle_key);
    bytes.extend_from_slice(&agreement.counterparty_mantle_key);
    bytes.extend_from_slice(&agreement.stake_amount.to_le_bytes());
    bytes.extend_from_slice(&agreement.challenge_fee.to_le_bytes());
    bytes.extend_from_slice(&agreement.response_fee.to_le_bytes());
    bytes.extend_from_slice(&agreement.response_window_blocks.to_le_bytes());
    Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

#[must_use]
pub fn state_account_id(program_id: ProgramId, agreement_id: &AgreementId) -> AccountId {
    AccountId::for_public_pda(&program_id, &state_seed(agreement_id))
}

#[must_use]
pub fn escrow_account_id(program_id: ProgramId, agreement_id: &AgreementId) -> AccountId {
    AccountId::for_public_pda(&program_id, &escrow_seed(agreement_id))
}

#[must_use]
pub fn burn_account_id(program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&program_id, &burn_seed())
}

#[must_use]
pub fn state_seed(agreement_id: &AgreementId) -> PdaSeed {
    derived_seed(&STATE_SEED_DOMAIN, agreement_id)
}

#[must_use]
pub fn escrow_seed(agreement_id: &AgreementId) -> PdaSeed {
    derived_seed(&ESCROW_SEED_DOMAIN, agreement_id)
}

#[must_use]
pub fn burn_seed() -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    PdaSeed::new(
        Impl::hash_bytes(BURN_SEED_DOMAIN)
            .as_bytes()
            .try_into()
            .unwrap_or_else(|_| unreachable!()),
    )
}

/// Rejects encodings that cannot be used as Ed25519 verification keys, as
/// well as small-order keys that must not identify a CACP participant.
#[must_use]
pub fn valid_mantle_key(bytes: &MantlePublicKey) -> bool {
    VerifyingKey::from_bytes(bytes).is_ok_and(|key| !key.is_weak())
}

fn derived_seed(domain: &[u8; 32], agreement_id: &AgreementId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(domain);
    bytes[32..].copy_from_slice(agreement_id);
    let seed = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn agreement() -> BondAgreement {
        BondAgreement {
            version: AGREEMENT_VERSION,
            initiator: AccountId::new([1; 32]),
            counterparty: AccountId::new([2; 32]),
            tx_hash: [3; 32],
            initiator_mantle_key: SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
            counterparty_mantle_key: SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
            stake_amount: 1_000,
            challenge_fee: 100,
            response_fee: 80,
            response_window_blocks: 4,
        }
    }

    #[test]
    fn agreement_pdas_and_fixed_burn_sink_are_stable_and_separate() {
        let program_id = [7; 8];
        let agreement = agreement();
        let agreement_id = agreement.id(program_id);
        assert_eq!(
            state_account_id(program_id, &agreement_id),
            state_account_id(program_id, &agreement_id)
        );
        assert_ne!(
            state_account_id(program_id, &agreement_id),
            escrow_account_id(program_id, &agreement_id)
        );
        assert_ne!(
            burn_account_id(program_id),
            escrow_account_id(program_id, &agreement_id)
        );
        assert_ne!(
            state_account_id(program_id, &agreement_id),
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
    fn agreement_id_binds_every_executable_term() {
        let program_id = [7; 8];
        let agreed = agreement();
        let expected = agreed.id(program_id);

        let mut variants = Vec::new();
        let mut changed_stake = agreed.clone();
        changed_stake.stake_amount += 1;
        variants.push(changed_stake);
        let mut changed_challenge_fee = agreed.clone();
        changed_challenge_fee.challenge_fee += 1;
        variants.push(changed_challenge_fee);
        let mut changed_response_fee = agreed.clone();
        changed_response_fee.response_fee += 1;
        variants.push(changed_response_fee);
        let mut changed_window = agreed.clone();
        changed_window.response_window_blocks += 1;
        variants.push(changed_window);
        let mut changed_tx = agreed.clone();
        changed_tx.tx_hash[0] ^= 1;
        variants.push(changed_tx);
        let mut changed_counterparty = agreed.clone();
        changed_counterparty.counterparty = AccountId::new([9; 32]);
        variants.push(changed_counterparty);

        assert!(agreed.is_valid());
        assert!(
            variants
                .iter()
                .all(|variant| variant.id(program_id) != expected)
        );
        assert_ne!(agreed.id([8; 8]), expected);
    }

    #[test]
    fn participants_prefund_stake_and_both_possible_fees() {
        let agreed = agreement();
        assert_eq!(agreed.fee_reserve(), Some(180));
        assert_eq!(agreed.participant_deposit(), Some(1_180));

        let mut invalid = agreed;
        invalid.response_fee = u128::MAX;
        assert!(!invalid.is_valid());
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

    #[test]
    fn completion_cannot_bypass_an_active_escalation_fee() {
        assert!(can_complete(Phase::AwaitingAccept));
        assert!(can_complete(Phase::AwaitingFinalize));
        assert!(!can_complete(Phase::AcceptChallenged));
        assert!(!can_complete(Phase::FinalizeChallenged));
    }
}
