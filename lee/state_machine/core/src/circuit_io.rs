use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId},
    compute_digest_for_path,
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    execution_state::{Assumption, Boundary, Declared, RootCall},
    program::{
        BlockValidityWindow, PdaSeed, ProgramHeader, ProgramId, TimestampValidityWindow,
        Transition, immutable_mirror_commitment,
    },
};

/// `circuit_io` is shared by host and guest, so this can't live in the host-only `error` module.
#[derive(Debug, thiserror::Error)]
#[error("an undisclosed program claim requires an immutable header")]
pub struct UndisclosedHeaderNotImmutable;

/// Untrusted circuit input claiming a program's real `image_id`, used for `env::verify` in place
/// of a header's address.
///
/// Both variants are publicly deployed; `Undisclosed` just doesn't reveal which one, proving
/// membership in-circuit instead.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum ProgramImageWitness {
    /// `image_id` is disclosed on the resulting claim.
    Disclosed {
        account_id: AccountId,
        image_id: ProgramId,
    },
    /// Deployed at an immutable header, not disclosed on the resulting claim.
    Undisclosed {
        account_id: AccountId,
        program_header: ProgramHeader,
        membership_proof: MembershipProof,
    },
}

impl ProgramImageWitness {
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        match self {
            Self::Disclosed { account_id, .. } | Self::Undisclosed { account_id, .. } => {
                *account_id
            }
        }
    }

    #[must_use]
    pub const fn image_id(&self) -> ProgramId {
        match self {
            Self::Disclosed { image_id, .. } => *image_id,
            Self::Undisclosed { program_header, .. } => program_header.image_id,
        }
    }

    /// # Errors
    /// Returns an error if `Self::Undisclosed`'s header isn't immutable.
    pub fn to_claim(&self) -> Result<ProgramImageClaim, UndisclosedHeaderNotImmutable> {
        Ok(match self {
            Self::Disclosed {
                account_id,
                image_id,
            } => ProgramImageClaim::Disclosed {
                account_id: *account_id,
                image_id: *image_id,
            },
            Self::Undisclosed {
                account_id,
                program_header,
                membership_proof,
            } => {
                if !program_header.immutable {
                    return Err(UndisclosedHeaderNotImmutable);
                }
                let commitment = immutable_mirror_commitment(*account_id, program_header);
                ProgramImageClaim::Undisclosed {
                    root: compute_digest_for_path(&commitment, membership_proof),
                }
            }
        })
    }
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub enum ProgramImageClaim {
    Disclosed {
        account_id: AccountId,
        image_id: ProgramId,
    },
    /// Some immutable header's mirrored commitment is a member of `root`.
    Undisclosed { root: CommitmentSetDigest },
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct ShadowProgramWitness {
    pub image_id: ProgramId,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PrivacyPreservingCircuitInput {
    pub root: RootCall,
    pub declared: Declared,
    /// One witness for each private account used by the transaction.
    pub private_witnesses: Vec<PrivateWitness>,
    pub dummy_inputs: Vec<DummyInput>,
    /// Minimum length of each note the guest encrypts, capped at `MAX_CIPHERTEXT_PADDING`.
    /// `dummy_inputs` carry their own ciphertexts and are checked against it, not padded.
    pub ciphertext_padding: Option<u32>,
    /// Real `image_id`s for every address-deployed program invoked in the call graph, keyed by
    /// account id.
    pub program_image_witnesses: Vec<ProgramImageWitness>,
    /// Identities of every shadow program invoked in the call graph.
    pub shadow_program_witnesses: Vec<ShadowProgramWitness>,
    pub turns: Vec<Transition>,
    pub assumed: Vec<Vec<Assumption>>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrivateWitness {
    pub vpk: ViewingPublicKey,
    pub random_seed: [u8; 32],
    pub identifier: Identifier,
    pub kind: WitnessKind,
    pub nullifier: NullifierWitness,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum WitnessKind {
    /// Standalone private account. The `account_id` is derived as
    /// `AccountId::for_regular_private_account(&npk, vpk, identifier)` and matched against
    /// the addressed actor's `account_id`. An honest authorized account's `npk` for Id computation
    /// gets derived from the supplied `ask`.
    Regular { ask: Option<AuthorizationSecretKey> },
    /// A private PDA with its authority's account ID and seed.
    Pda { binding: (AccountId, PdaSeed) },
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum NullifierWitness {
    /// Initializes a private account without a membership proof.
    Init {
        npk: NullifierPublicKey,
        commitment_root: CommitmentSetDigest,
    },
    /// Update of a private account: existing on-chain commitment, with membership proof. `npk`
    /// is derived from `nsk`.
    Update {
        account: Account,
        view_tag: ViewTag,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
}

/// A struct containing necessary data for dummy nullifier and
/// commitment generation.
#[derive(BorshSerialize, BorshDeserialize)]
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

impl PrivateWitness {
    #[must_use]
    pub const fn is_pda(&self) -> bool {
        matches!(self.kind, WitnessKind::Pda { .. })
    }

    #[must_use]
    pub const fn pda_binding(&self) -> Option<(AccountId, PdaSeed)> {
        match self.kind {
            WitnessKind::Pda { binding } => Some(binding),
            WitnessKind::Regular { .. } => None,
        }
    }

    /// Derives the account ID from this witness.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        let npk = self.nullifier.npk();
        match self.kind {
            WitnessKind::Regular { .. } => {
                AccountId::for_regular_private_account(&npk, &self.vpk, self.identifier)
            }
            WitnessKind::Pda {
                binding: (program, seed),
            } => AccountId::for_private_pda(&program, &seed, &npk, &self.vpk, self.identifier),
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

#[derive(BorshSerialize, BorshDeserialize)]
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

#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq, Default))]
pub struct PrivacyPreservingCircuitOutput {
    pub declared: Declared,
    pub boundary: Boundary,
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
    /// Serializes the circuit output to the exact journal byte sequence the circuit guest commits.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::to_borsh_frame(self)
    }
}

#[cfg(feature = "host")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Commitment, Nullifier,
        account::{Account, AccountId, Actor},
        encryption::{Ciphertext, EphemeralPublicKey},
        execution_state::{Output, ScheduleOp},
        program::Origin,
    };

    fn pinned_statement() -> (Declared, Boundary) {
        let public = Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32]));
        let private = Actor::new(AccountId::new([9; 32]), AccountId::new([8; 32]));
        (
            Declared {
                public_actors: vec![public],
                authorized_accounts: vec![AccountId::new([7; 32])],
            },
            Boundary {
                outputs: vec![Output {
                    to: public,
                    message: b"o".to_vec(),
                    origin: Origin::Program(private.program_account_id),
                    grants: Vec::new(),
                    pda_seeds: Vec::new(),
                }],
                assumptions: vec![Assumption {
                    from: public,
                    to: private,
                    message: b"a".to_vec(),
                    grants: Vec::new(),
                    pda_seeds: Vec::new(),
                }],
                schedule: vec![
                    ScheduleOp::CallPublic,
                    ScheduleOp::EnterPrivate,
                    ScheduleOp::LeavePrivate,
                    ScheduleOp::ReturnPublic,
                ],
            },
        )
    }

    #[test]
    fn a_circuit_output_journal_has_a_pinned_layout() {
        let (declared, boundary) = pinned_statement();
        let output = PrivacyPreservingCircuitOutput {
            declared,
            boundary,
            private_actions: Vec::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: Vec::new(),
        };

        let expected: Vec<u8> = [
            &[127, 1, 0, 0][..], // frame length: the 383 bytes below
            &[1, 0, 0, 0],       // declared.public_actors: one actor
            &[5; 32],
            &[6; 32],
            &[1, 0, 0, 0], // declared.authorized_accounts: one account
            &[7; 32],
            &[1, 0, 0, 0], // boundary.outputs: one output
            &[5; 32],      // to
            &[6; 32],
            &[1, 0, 0, 0], // message
            b"o",
            &[1], // origin: Origin::Program
            &[8; 32],
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[1, 0, 0, 0], // boundary.assumptions: one assumption
            &[5; 32],      // from
            &[6; 32],
            &[9; 32], // to
            &[8; 32],
            &[1, 0, 0, 0], // message
            b"a",
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[4, 0, 0, 0], // boundary.schedule: four ops
            &[0, 1, 2, 3],
            &[0, 0, 0, 0], // private_actions: none
            &[0, 0],       // block_validity_window: from None, to None
            &[0, 0],       // timestamp_validity_window: from None, to None
            &[0, 0, 0, 0], // program_image_claims: none
        ]
        .concat();

        assert_eq!(output.to_bytes(), expected);
    }

    #[test]
    fn schedule_op_tags_follow_declaration_order() {
        for (op, tag) in [
            (ScheduleOp::CallPublic, 0),
            (ScheduleOp::EnterPrivate, 1),
            (ScheduleOp::LeavePrivate, 2),
            (ScheduleOp::ReturnPublic, 3),
        ] {
            assert_eq!(borsh::to_vec(&op).unwrap(), [tag]);
        }
    }

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_round_trips_via_borsh_frame() {
        let output = PrivacyPreservingCircuitOutput {
            declared: Declared::default(),
            boundary: Boundary::default(),
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
            program_image_claims: vec![ProgramImageClaim::Disclosed {
                account_id: AccountId::new([3; 32]),
                image_id: [4; 8],
            }],
        };
        let bytes = output.to_bytes();
        let decoded: PrivacyPreservingCircuitOutput = borsh::from_slice(
            crate::from_frame(&bytes).expect("self-produced frame is well-formed"),
        )
        .unwrap();
        assert_eq!(output, decoded);
    }

    #[test]
    fn private_witness_account_id_matches_its_derivation() {
        let npk = NullifierPublicKey([3; 32]);
        let vpk = ViewingPublicKey::from_seed(&[1; 32], &[2; 32]);
        let identifier = Identifier::new([77; 32]);
        let witness = |kind| PrivateWitness {
            vpk: vpk.clone(),
            random_seed: [4; 32],
            identifier,
            kind,
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: [5; 32],
            },
        };
        let program = AccountId::new([6; 32]);
        let seed = PdaSeed::new([7; 32]);

        let regular = witness(WitnessKind::Regular { ask: None });
        assert!(!regular.is_pda());
        assert_eq!(
            regular.account_id(),
            AccountId::for_regular_private_account(&npk, &vpk, identifier)
        );

        let pda = witness(WitnessKind::Pda {
            binding: (program, seed),
        });
        assert!(pda.is_pda());
        assert_eq!(
            pda.account_id(),
            AccountId::for_private_pda(&program, &seed, &npk, &vpk, identifier)
        );
    }
}
