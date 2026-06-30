use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentSetDigest, Identifier, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey,
    account::{Account, AccountWithMetadata, PrivateAddressPlaintext},
    encryption::{EncryptedAccountData, ViewingPublicKey},
    program::{BlockValidityWindow, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow},
};

#[derive(Serialize, Deserialize)]
pub struct PrivacyPreservingCircuitInput {
    /// Outputs of the program execution.
    pub program_outputs: Vec<ProgramOutput>,
    /// One entry per `pre_state`, in the same order as the program's `pre_states`.
    /// Length must equal the number of `pre_states` derived from `program_outputs`.
    /// The guest's `private_pda_by_position` and `private_pda_bound_positions`
    /// rely on this position alignment.
    pub account_identities: Vec<InputAccountIdentity>,
    /// Program ID.
    pub program_id: ProgramId,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from `program_outputs` and emits no
    /// commitment, ciphertext, or nullifier.
    Public,
    /// Init of an authorized standalone private account: no membership proof. The `pre_state`
    /// must be `Account::default()`. The `account_id` is derived as
    /// `PrivateAddressPlaintext::new(NullifierPublicKey::from(nsk), vpk, identifier).account_id()`
    /// and matched against `pre_state.account_id`.
    PrivateAuthorizedInit {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        nsk: NullifierSecretKey,
        identifier: Identifier,
    },
    /// Update of an authorized standalone private account: existing on-chain commitment, with
    /// membership proof.
    PrivateAuthorizedUpdate {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
    },
    /// Init of a standalone private account the caller does not own (e.g. a recipient who
    /// doesn't yet exist on chain). No `nsk`, no membership proof.
    PrivateUnauthorized {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        npk: NullifierPublicKey,
        identifier: Identifier,
    },
    /// Init of a private PDA, unauthorized. The npk-to-account_id binding is proven upstream
    /// via `Claim::Pda(seed)` or a caller's `pda_seeds` match. The identifier diversifies the
    /// PDA within the `(program_id, seed, npk)` family.
    PrivatePdaInit {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        npk: NullifierPublicKey,
        identifier: Identifier,
        /// When `Some((seed, authority_program_id))`, the circuit binds this position via the
        /// external derivation check
        /// `PrivateAddressPlaintext::new(npk, vpk,
        /// identifier).pda_account_id(authority_program_id, seed) == pre_state.account_id`
        /// rather than requiring a `Claim::Pda` or caller `pda_seeds` to establish the
        /// binding. The `pre_state` must have `is_authorized == false`.
        seed: Option<(PdaSeed, ProgramId)>,
    },
    /// Update of an existing private PDA, with membership proof. `npk` is derived
    /// from `nsk`. Authorization may be established upstream by a caller `pda_seeds` match or a
    /// previously-seen authorization in a chained call.
    PrivatePdaUpdate {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
        /// When `Some((seed, authority_program_id))`, the circuit binds this position via the
        /// external derivation check
        /// `PrivateAddressPlaintext::new(npk, vpk,
        /// identifier).pda_account_id(authority_program_id, seed) == pre_state.account_id`
        /// rather than requiring a caller `pda_seeds` to establish the binding. The
        /// `pre_state` must have `is_authorized == false`.
        seed: Option<(PdaSeed, ProgramId)>,
    },
}

impl InputAccountIdentity {
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    #[must_use]
    pub const fn is_private_pda(&self) -> bool {
        matches!(
            self,
            Self::PrivatePdaInit { .. } | Self::PrivatePdaUpdate { .. }
        )
    }

    #[must_use]
    pub fn private_pda_address(&self) -> Option<PrivateAddressPlaintext<'_>> {
        match self {
            Self::PrivatePdaInit {
                npk,
                vpk,
                identifier,
                ..
            } => Some(PrivateAddressPlaintext::new(*npk, vpk, *identifier)),
            Self::PrivatePdaUpdate {
                nsk,
                vpk,
                identifier,
                ..
            } => Some(PrivateAddressPlaintext::new(
                NullifierPublicKey::from(nsk),
                vpk,
                *identifier,
            )),
            Self::Public
            | Self::PrivateAuthorizedInit { .. }
            | Self::PrivateAuthorizedUpdate { .. }
            | Self::PrivateUnauthorized { .. } => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PrivacyPreservingCircuitOutput {
    pub public_pre_states: Vec<AccountWithMetadata>,
    pub public_post_states: Vec<Account>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
}

#[cfg(feature = "host")]
impl PrivacyPreservingCircuitOutput {
    /// Serializes the circuit output to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&risc0_zkvm::serde::to_vec(&self).unwrap()).to_vec()
    }
}

#[cfg(feature = "host")]
#[cfg(test)]
mod tests {
    use risc0_zkvm::serde::from_slice;

    use super::*;
    use crate::{
        Commitment, Nullifier,
        account::{Account, AccountId, AccountWithMetadata, Nonce},
        encryption::{Ciphertext, EphemeralPublicKey},
    };

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_is_compatible_with_from_slice() {
        let output = PrivacyPreservingCircuitOutput {
            public_pre_states: vec![
                AccountWithMetadata::new(
                    Account {
                        program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                        balance: 12_345_678_901_234_567_890,
                        data: b"test data".to_vec().try_into().unwrap(),
                        nonce: Nonce(0xFFFF_FFFF_FFFF_FFFE),
                    },
                    true,
                    AccountId::new([0; 32]),
                ),
                AccountWithMetadata::new(
                    Account {
                        program_owner: [9, 9, 9, 8, 8, 8, 7, 7],
                        balance: 123_123_123_456_456_567_112,
                        data: b"test data".to_vec().try_into().unwrap(),
                        nonce: Nonce(9_999_999_999_999_999_999_999),
                    },
                    false,
                    AccountId::new([1; 32]),
                ),
            ],
            public_post_states: vec![Account {
                program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                balance: 100,
                data: b"post state data".to_vec().try_into().unwrap(),
                nonce: Nonce(0xFFFF_FFFF_FFFF_FFFF),
            }],
            encrypted_private_post_states: vec![EncryptedAccountData {
                ciphertext: Ciphertext(vec![255, 255, 1, 1, 2, 2]),
                epk: EphemeralPublicKey(vec![9, 9, 9]),
                view_tag: 42,
            }],
            new_commitments: vec![Commitment::new(
                &AccountId::new([1; 32]),
                &Account::default(),
            )],
            new_nullifiers: vec![(
                Nullifier::for_account_update(
                    &Commitment::new(&AccountId::new([2; 32]), &Account::default()),
                    &[1; 32],
                ),
                [0xab; 32],
            )],
            block_validity_window: (1..).into(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
