use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    program::{
        BlockValidityWindow, PdaSeed, ProgramData, ProgramId, ProgramOutput,
        TimestampValidityWindow,
    },
};

/// A claim that `account_id`'s program account currently has a given `image_id`.
///
/// Supplied by the prover as circuit input (untrusted), used inside the circuit for
/// `env::verify` in place of a `Deploy`-created program's address (which, unlike a legacy
/// program's, doesn't encode its image id), and echoed unchanged into the circuit's output —
/// the circuit never interprets *how* a claim was authenticated, only its `image_id()`.
/// Anchoring the claim to real chain state is **not** enforced inside the circuit — it's enforced
/// by the sequencer, which independently reconstructs every claim before accepting the proof.
#[derive(Serialize, Deserialize, Clone, Copy, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub enum ProgramImageClaim {
    /// Anchored against real, live public chain state (`V03State::get_program(account_id)`). A
    /// side effect of this, for now: every publicly-anchored program invoked anywhere in a
    /// private transaction's call graph is publicly visible via this claim list.
    Public {
        account_id: AccountId,
        image_id: ProgramId,
    },
    /// Anchored against a private commitment mirroring a permanently-immutable program's
    /// finalized `ProgramData`, via `program_loader_core::immutable_mirror_commitment`. Only ever
    /// exists for a program whose `update_auth` became permanently `None`; the sequencer's
    /// reconstruction proves membership (`V03State::get_proof_for_commitment`) instead of doing a
    /// public lookup, so which program this is stays hidden unless the caller chooses to reveal
    /// it.
    Private {
        account_id: AccountId,
        program_data: ProgramData,
    },
}

impl ProgramImageClaim {
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        match self {
            Self::Public { account_id, .. } | Self::Private { account_id, .. } => *account_id,
        }
    }

    #[must_use]
    pub const fn image_id(&self) -> ProgramId {
        match self {
            Self::Public { image_id, .. } => *image_id,
            Self::Private { program_data, .. } => program_data.current_image_id,
        }
    }
}

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
    pub dummy_inputs: Vec<DummyInput>,
    /// Real `image_id`s for every `Deploy`-created program invoked in the call graph, keyed by
    /// account id. See [`ProgramImageClaim`].
    pub program_image_claims: Vec<ProgramImageClaim>,
}

#[derive(Serialize, Deserialize, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "Private carries the ML-KEM viewing key and dominates; boxing it would add a guest heap allocation per witness, and the footprint matches the pre-refactor enum"
)]
pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from `program_outputs` and emits no
    /// commitment, ciphertext, or nullifier.
    Public,
    Private(PrivateWitness),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateWitness {
    pub vpk: ViewingPublicKey,
    pub random_seed: [u8; 32],
    pub identifier: Identifier,
    pub kind: WitnessKind,
    pub nullifier: NullifierWitness,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum WitnessKind {
    /// Standalone private account. The `account_id` is derived as
    /// `AccountId::for_regular_private_account(&npk, vpk, identifier)` and matched against
    /// `pre_state.account_id`. An honest authorized account's `npk` for Id computation gets
    /// derived from the supplied `ask`.
    Regular { ask: Option<AuthorizationSecretKey> },
    /// Private PDA. The npk-to-account_id binding is proven upstream via `Claim::Pda(seed)` or a
    /// caller's `pda_seeds` match. The identifier diversifies the PDA within the
    /// `(program_account_id, seed, npk)` family: `AccountId::for_private_pda` uses it as the 4th
    /// input.
    Pda {
        /// When `Some((authority_account_id, seed))`, the circuit binds this position via the
        /// external derivation check
        /// `AccountId::for_private_pda(authority_account_id, seed, npk, vpk, identifier) ==
        /// pre_state.account_id` rather than requiring a `Claim::Pda` or caller
        /// `pda_seeds` to establish the binding.
        binding: Option<(AccountId, PdaSeed)>,
    },
}

#[derive(Serialize, Deserialize, Clone)]
pub enum NullifierWitness {
    /// Init of a private account: no membership proof. The `pre_state` must be
    /// `Account::default()`. `npk` is supplied directly, so the caller need not own the account
    /// (e.g. a recipient who doesn't yet exist on chain).
    Init {
        npk: NullifierPublicKey,
        commitment_root: CommitmentSetDigest,
    },
    /// Update of a private account: existing on-chain commitment, with membership proof. `npk`
    /// is derived from `nsk`.
    Update {
        view_tag: ViewTag,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
}

/// A struct containing necessary data for dummy nullifier and
/// commitment generation.
#[derive(Serialize, Deserialize)]
pub struct DummyInput {
    /// The seed used for generating the dummy nullifier.
    pub nullifier_seed: [u8; 32],
    /// The seed used for generating the dummy commitment.
    pub commitment_seed: [u8; 32],
    /// The dummy ciphertext, epk, and view tag.
    pub note: EncryptedAccountData,
    /// The dummy root.
    pub commitment_root: CommitmentSetDigest,
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
                kind: WitnessKind::Pda { .. },
                ..
            })
        )
    }

    #[must_use]
    pub fn npk_vpk_if_private_pda(
        &self,
    ) -> Option<(NullifierPublicKey, ViewingPublicKey, Identifier)> {
        match self {
            Self::Private(PrivateWitness {
                vpk,
                identifier,
                kind: WitnessKind::Pda { .. },
                nullifier,
                ..
            }) => Some((nullifier.npk(), vpk.clone(), *identifier)),
            Self::Public | Self::Private(_) => None,
        }
    }
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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, Default, PartialEq, Eq)
)]
pub struct PrivateAction {
    pub nullifier: Nullifier,
    pub root: CommitmentSetDigest,
    // IMPORTANT: The commitment in the action is not necessarily connected
    // to the nullifier in content. That is, the commitment's plaintext is
    // not necessarily the updated account state of the nullifier's plaintext.
    pub commitment: Commitment,
    pub encrypted_post_state: EncryptedAccountData,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PublicAction {
    pub pre: AccountWithMetadata,
    pub post: Account,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq, Default))]
pub struct PrivacyPreservingCircuitOutput {
    pub public_actions: Vec<PublicAction>,
    pub private_actions: Vec<PrivateAction>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    /// Unchanged echo of [`PrivacyPreservingCircuitInput::program_image_claims`] — what the
    /// receipt actually commits to, so the sequencer can check it against real chain state.
    pub program_image_claims: Vec<ProgramImageClaim>,
}

#[cfg(any(feature = "host", test))]
impl PrivacyPreservingCircuitOutput {
    #[must_use]
    pub fn commitments(&self) -> Vec<Commitment> {
        self.private_actions
            .iter()
            .map(|action| action.commitment)
            .collect()
    }

    #[must_use]
    pub fn nullifiers(&self) -> Vec<(Nullifier, CommitmentSetDigest)> {
        self.private_actions
            .iter()
            .map(|action| (action.nullifier, action.root))
            .collect()
    }
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
            public_actions: vec![
                PublicAction {
                    pre: AccountWithMetadata::new(
                        Account {
                            program_owner: [1, 2, 3, 4, 5, 6, 7, 8].into(),
                            balance: 12_345_678_901_234_567_890,
                            data: b"test data".to_vec().try_into().unwrap(),
                            nonce: Nonce(0xFFFF_FFFF_FFFF_FFFE),
                        },
                        true,
                        AccountId::new([0; 32]),
                    ),
                    post: Account {
                        program_owner: [1, 2, 3, 4, 5, 6, 7, 8].into(),
                        balance: 100,
                        data: b"post state data".to_vec().try_into().unwrap(),
                        nonce: Nonce(0xFFFF_FFFF_FFFF_FFFF),
                    },
                },
                PublicAction {
                    pre: AccountWithMetadata::new(
                        Account {
                            program_owner: [9, 9, 9, 8, 8, 8, 7, 7].into(),
                            balance: 123_123_123_456_456_567_112,
                            data: b"test data".to_vec().try_into().unwrap(),
                            nonce: Nonce(9_999_999_999_999_999_999_999),
                        },
                        false,
                        AccountId::new([1; 32]),
                    ),
                    post: Account {
                        program_owner: [2, 3, 4, 5, 6, 7, 8, 9].into(),
                        balance: 200,
                        data: b"post state data 2".to_vec().try_into().unwrap(),
                        nonce: Nonce(0xFFFF_FFFF_FFFF_FFFD),
                    },
                },
            ],
            private_actions: vec![PrivateAction {
                nullifier: Nullifier::for_account_update(
                    &Commitment::new(&AccountId::new([2; 32]), &Account::default()),
                    &[1; 32],
                ),
                root: [0xab; 32],
                commitment: Commitment::new(&AccountId::new([1; 32]), &Account::default()),
                encrypted_post_state: EncryptedAccountData {
                    ciphertext: Ciphertext(vec![255, 255, 1, 1, 2, 2]),
                    epk: EphemeralPublicKey(vec![9, 9, 9]),
                    view_tag: 42,
                },
            }],
            block_validity_window: (1..).into(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: vec![ProgramImageClaim::Public {
                account_id: AccountId::new([3; 32]),
                image_id: [4; 8],
            }],
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
