use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId, Actor},
    compute_digest_for_path,
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    execution_state::{Boundary, Delivery, PublicExecutionContext, TransactionEntry},
    program::{
        BlockValidityWindow, MessageBody, MessageRef, PdaSeed, ProgramHeader, ProgramId, Response,
        StoredMessage, TimestampValidityWindow, immutable_mirror_commitment,
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

/// Inputs for proving a transaction's private part.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProvingInput {
    pub root: TransactionEntry<StoredMessage>,
    pub context: PublicExecutionContext,
    /// One witness for each private account used by the transaction.
    pub private_witnesses: Vec<PrivateWitness>,
    pub dummy_inputs: Vec<DummyInput>,
    /// Minimum length of each note the guest encrypts, capped at `MAX_CIPHERTEXT_PADDING`.
    /// `dummy_inputs` carry their own ciphertexts and are checked against it, not padded.
    pub ciphertext_padding: Option<u32>,
}

impl ProvingInput {
    #[must_use]
    pub fn private_root(&self) -> Option<TransactionEntry<StoredMessage>> {
        (!self.root_is_public()).then(|| self.root.clone())
    }

    #[must_use]
    pub fn entry(&self) -> Option<TransactionEntry<MessageRef>> {
        match &self.root {
            TransactionEntry::Call { to, message } => {
                self.root_is_public().then(|| TransactionEntry::Call {
                    to: *to,
                    message: message.clone(),
                })
            }
            TransactionEntry::Cast(record) => Some(TransactionEntry::Cast(record.reference())),
        }
    }

    fn root_is_public(&self) -> bool {
        self.context.actors.contains(&self.root.destination())
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PrivacyPreservingCircuitInput {
    pub input: ProvingInput,
    /// Real `image_id`s for every address-deployed program invoked in the call graph, keyed by
    /// account id.
    pub program_image_witnesses: Vec<ProgramImageWitness>,
    /// Identities of every shadow program invoked in the call graph.
    pub shadow_program_witnesses: Vec<ShadowProgramWitness>,
    pub responses: Vec<Response>,
    pub predicted_crossings: Vec<Vec<Delivery<Actor>>>,
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
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, PartialEq, Eq, Default)
)]
pub struct PrivacyPreservingCircuitOutput {
    pub context: PublicExecutionContext,
    pub boundary: Boundary,
    pub casts: Vec<MessageBody>,
    /// How the transaction starts, as far as the proof reveals it: `None` for a private call.
    pub entry: Option<TransactionEntry<MessageRef>>,
    pub private_actions: Vec<PrivateAction>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    /// Claims derived from [`PrivacyPreservingCircuitInput::program_image_witnesses`] — what the
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
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        Commitment, Nullifier,
        account::{Account, AccountId, Actor},
        encryption::{Ciphertext, EphemeralPublicKey},
        execution_state::{BoundaryStep, Delivery},
        program::{MessageBody, MessageDigest, MessageEnvelope},
    };

    fn pinned_statement() -> (PublicExecutionContext, Boundary) {
        let public = Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32]));
        let private = Actor::new(AccountId::new([9; 32]), AccountId::new([8; 32]));
        (
            PublicExecutionContext {
                actors: vec![public],
                authorized_accounts: BTreeSet::from([AccountId::new([7; 32])]),
            },
            vec![
                BoundaryStep::EnterPublic(Delivery {
                    envelope: MessageEnvelope {
                        source: private.program_account_id,
                        to: public,
                        message: b"o".to_vec(),
                    },
                    grants: BTreeSet::new(),
                    pda_seeds: Vec::new(),
                }),
                BoundaryStep::EnterPrivate(Delivery {
                    envelope: MessageEnvelope {
                        source: public,
                        to: private,
                        message: b"a".to_vec(),
                    },
                    grants: BTreeSet::new(),
                    pda_seeds: Vec::new(),
                }),
                BoundaryStep::ExitPrivate,
                BoundaryStep::ExitPublic,
            ],
        )
    }

    #[test]
    fn a_circuit_output_journal_has_a_pinned_layout() {
        let (context, boundary) = pinned_statement();
        let output = PrivacyPreservingCircuitOutput {
            context,
            boundary,
            casts: Vec::new(),
            entry: None,
            private_actions: Vec::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: Vec::new(),
        };

        let expected: Vec<u8> = [
            &[123, 1, 0, 0][..], // frame length: the 379 bytes below
            &[1, 0, 0, 0],       // context.actors: one actor
            &[5; 32],
            &[6; 32],
            &[1, 0, 0, 0], // context.authorized_accounts: one account
            &[7; 32],
            &[4, 0, 0, 0], // boundary: four steps
            &[0],          // BoundaryStep::EnterPublic
            &[8; 32],      // source: the calling program
            &[5; 32],      // to
            &[6; 32],
            &[1, 0, 0, 0], // message
            b"o",
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[1],          // BoundaryStep::EnterPrivate
            &[5; 32],      // from
            &[6; 32],
            &[9; 32], // to
            &[8; 32],
            &[1, 0, 0, 0], // message
            b"a",
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[2],          // BoundaryStep::ExitPrivate
            &[3],          // BoundaryStep::ExitPublic
            &[0, 0, 0, 0], // casts: none
            &[0],          // entry: None
            &[0, 0, 0, 0], // private_actions: none
            &[0, 0],       // block_validity_window: from None, to None
            &[0, 0],       // timestamp_validity_window: from None, to None
            &[0, 0, 0, 0], // program_image_claims: none
        ]
        .concat();

        assert_eq!(output.to_bytes(), expected);
    }

    #[test]
    fn a_circuit_output_journal_with_a_received_entry_has_a_pinned_layout() {
        let public = Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32]));
        let output = PrivacyPreservingCircuitOutput {
            context: PublicExecutionContext {
                actors: vec![public],
                authorized_accounts: BTreeSet::new(),
            },
            boundary: Vec::new(),
            casts: vec![MessageBody {
                source: AccountId::new([8; 32]),
                to: Actor::new(AccountId::new([3; 32]), AccountId::new([4; 32])),
                message: b"p".to_vec(),
            }],
            entry: Some(TransactionEntry::Cast(MessageRef {
                sequence: 9,
                digest: MessageDigest::new([7; 32]),
            })),
            private_actions: Vec::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: Vec::new(),
        };

        let expected: Vec<u8> = [
            &[243, 0, 0, 0][..], // frame length: the 243 bytes below
            &[1, 0, 0, 0],       // context.actors: one actor
            &[5; 32],
            &[6; 32],
            &[0, 0, 0, 0], // context.authorized_accounts: none
            &[0, 0, 0, 0], // boundary: no steps
            &[1, 0, 0, 0], // casts: one message
            &[8; 32],      // source
            &[3; 32],      // to
            &[4; 32],
            &[1, 0, 0, 0], // message
            b"p",
            &[1],                                              // entry: Some
            &[1],                                              // TransactionEntry::Cast
            &[9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // sequence
            &[7; 32],                                          // digest
            &[0, 0, 0, 0],                                     // private_actions: none
            &[0, 0],                                           /* block_validity_window: from
                                                                * None, to None */
            &[0, 0],       // timestamp_validity_window: from None, to None
            &[0, 0, 0, 0], // program_image_claims: none
        ]
        .concat();

        assert_eq!(output.to_bytes(), expected);
    }

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_round_trips_via_borsh_frame() {
        let output = PrivacyPreservingCircuitOutput {
            context: PublicExecutionContext::default(),
            boundary: Boundary::default(),
            casts: Vec::new(),
            entry: None,
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
