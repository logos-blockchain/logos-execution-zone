use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationPublicKey, AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier,
    MembershipProof, Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::{EncryptedAccountData, ViewingPublicKey},
    program::{BlockValidityWindow, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow},
};

#[derive(Serialize, Deserialize)]
pub struct PrivacyPreservingCircuitInput {
    /// Outputs of the program execution.
    pub program_outputs: Vec<ProgramOutput>,
    /// One entry per `pre_state`, in the same order as the program's `pre_states`.
    /// Length must equal the number of `pre_states` derived from `program_outputs`.
    /// The guest's `private_pda_bound_positions` relies on this position alignment.
    pub account_identities: Vec<InputAccountIdentity>,
    /// Program ID.
    pub program_id: ProgramId,
}

#[derive(Serialize, Deserialize, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "Private carries the ML-KEM viewing key and dominates; boxing it would add a guest heap allocation per witness, and the footprint matches the pre-refactor enum"
)]
pub enum InputAccountIdentity {
    /// Public (transparent) account. The guest reads pre/post state from `program_outputs` and
    /// emits no commitment, ciphertext, or nullifier.
    Public,
    Private(PrivateWitness),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateWitness {
    pub vpk: ViewingPublicKey,
    pub random_seed: [u8; 32],
    pub identifier: Identifier,
    pub kind: PrivateKind,
    pub nullifier: NullifierWitness,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PrivateKind {
    Regular { auth: AuthWitness },
    Pda { seed: Option<(PdaSeed, ProgramId)> },
}

#[derive(Serialize, Deserialize, Clone)]
pub enum AuthWitness {
    Held(AuthorizationSecretKey),
    Public(AuthorizationPublicKey),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum NullifierWitness {
    Init {
        npk: NullifierPublicKey,
        commitment_root: CommitmentSetDigest,
    },
    Update {
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
}

impl NullifierWitness {
    #[must_use]
    pub fn npk(&self) -> NullifierPublicKey {
        match self {
            Self::Init { npk, .. } => *npk,
            Self::Update { nsk, .. } => NullifierPublicKey::from(nsk),
        }
    }
}

impl AuthWitness {
    fn apk(&self) -> AuthorizationPublicKey {
        match self {
            Self::Held(ask) => AuthorizationPublicKey::from(ask),
            Self::Public(apk) => *apk,
        }
    }
}

impl PrivateWitness {
    fn regular_id(&self, auth: &AuthWitness) -> AccountId {
        AccountId::for_regular_private_account(
            &self.nullifier.npk(),
            &auth.apk(),
            &self.vpk,
            self.identifier,
        )
    }

    fn pda_id(&self, program_id: &ProgramId, seed: &PdaSeed) -> AccountId {
        AccountId::for_private_pda(
            program_id,
            seed,
            &self.nullifier.npk(),
            &self.vpk,
            self.identifier,
        )
    }
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
            Self::Private(PrivateWitness {
                kind: PrivateKind::Pda { .. },
                ..
            })
        )
    }

    #[must_use]
    pub fn regular_account_id(&self) -> Option<AccountId> {
        match self {
            Self::Private(
                witness @ PrivateWitness {
                    kind: PrivateKind::Regular { auth },
                    ..
                },
            ) => Some(witness.regular_id(auth)),
            Self::Public | Self::Private(_) => None,
        }
    }

    #[must_use]
    pub fn pda_account_id(&self, program_id: &ProgramId, seed: &PdaSeed) -> Option<AccountId> {
        match self {
            Self::Public => Some(AccountId::for_public_pda(program_id, seed)),
            Self::Private(
                witness @ PrivateWitness {
                    kind: PrivateKind::Pda { .. },
                    ..
                },
            ) => Some(witness.pda_id(program_id, seed)),
            Self::Private(_) => None,
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
