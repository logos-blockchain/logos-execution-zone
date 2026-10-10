use std::{borrow::Cow, collections::BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, InvalidMembershipProof,
    MembershipProof, Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId, Actor, Nonce},
    compute_digest_for_path,
    encryption::{EncryptedNote, ViewingPublicKey},
    execution_state::{Boundary, PredictedCrossMessages, PublicExecutionContext, TransactionEntry},
    program::{
        MessageBody, MessageData, PdaSeed, PrivateAccountKind, ProgramHeader, ProgramId, Response,
        ValidityWindows, immutable_mirror_commitment,
    },
    recovery::{RecipientEncryption, RecoveryBinding},
    sealing::SealedCast,
};

/// `circuit_io` is shared by host and guest, so this can't live in the host-only `error` module.
#[derive(Debug, thiserror::Error)]
pub enum InvalidProgramImageWitness {
    #[error("an undisclosed program claim requires an immutable header")]
    MutableHeader,
    #[error(transparent)]
    Membership(#[from] InvalidMembershipProof),
}

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
    /// Returns an error if `Self::Undisclosed`'s header isn't immutable or its membership proof's
    /// position does not fit its path.
    pub fn to_claim(&self) -> Result<ProgramImageClaim, InvalidProgramImageWitness> {
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
                membership_proof: (position, path),
            } => {
                if !program_header.immutable {
                    return Err(InvalidProgramImageWitness::MutableHeader);
                }
                let commitment = immutable_mirror_commitment(*account_id, program_header);
                ProgramImageClaim::Undisclosed {
                    root: compute_digest_for_path(&commitment, *position, path)?,
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
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct MessageWitness {
    pub body: MessageBody,
    pub position: u64,
    pub rho: Option<[u8; 32]>,
    pub path: Vec<[u8; 32]>,
    pub filler: DummyOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RootCall {
    pub to: Actor,
    pub message: MessageData,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidMessageEvidence {
    #[error("A received message's position does not fit its membership path")]
    NoncanonicalPosition,
    #[error("A privately received message must reach a witnessed private account")]
    UnwitnessedDestination,
}

/// Inputs for proving a transaction's private part.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProvingInput {
    pub root: TransactionEntry<MessageWitness>,
    pub context: PublicExecutionContext,
    /// One witness for each private account used by the transaction.
    pub private_witnesses: Vec<PrivateWitness>,
    pub dummy_inputs: Vec<DummyInput>,
    /// Minimum length of each note the guest encrypts, capped at `MAX_CIPHERTEXT_PADDING`.
    /// `dummy_inputs` carry their own ciphertexts and are checked against it, not padded.
    pub ciphertext_padding: Option<u32>,
    pub recoveries: Vec<RecipientEncryption>,
    pub private_cast_promotions: BTreeSet<u64>,
}

impl ProvingInput {
    #[must_use]
    pub fn public_root(&self) -> Option<RootCall> {
        match &self.root {
            TransactionEntry::Call(call) => {
                self.context.runs_publicly(call.to).then(|| call.clone())
            }
            TransactionEntry::Cast(_) => None,
        }
    }
}

impl MessageWitness {
    /// # Errors
    /// Returns an error if a received message's evidence does not fit it.
    pub fn spend(
        &self,
        witnesses: &[PrivateWitness],
    ) -> Result<(Nullifier, CommitmentSetDigest), InvalidMessageEvidence> {
        let to = self.body.to;
        let commitment = self.rho.as_ref().map_or_else(
            || Commitment::for_message(&self.body),
            |rho| Commitment::for_sealed_message(&self.body, rho),
        );
        let root = compute_digest_for_path(&commitment, self.position, &self.path)
            .map_err(|InvalidMembershipProof| InvalidMessageEvidence::NoncanonicalPosition)?;
        let receiver = witnesses
            .iter()
            .find(|witness| {
                let account_id = witness.account_id();
                account_id == to.account_id
                    || witness
                        .openings
                        .iter()
                        .any(|opening| account_id.blinded(opening) == to.account_id)
            })
            .ok_or(InvalidMessageEvidence::UnwitnessedDestination)?;
        Ok((
            Nullifier::for_message(&receiver.kind.nsk(), &commitment, self.position),
            root,
        ))
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
    /// Per private transition: Calls other than replies to `input.from`, then every Cast, in
    /// their respective vector orders before descendants execute. Call replies preserve the
    /// reached address and consume no entry. Public emissions consume none. Missing or surplus
    /// entries are rejected.
    pub sender_presentations: Vec<SenderPresentation>,
    /// One per durable Cast of private execution, in the order it publishes them.
    pub cast_seals: Vec<RecipientEncryption>,
    pub predicted_cross_messages: PredictedCrossMessages,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrivateWitness {
    pub vpk: ViewingPublicKey,
    pub random_seed: [u8; 32],
    pub kind: WitnessKind,
    pub nullifier: NullifierWitness,
    pub openings: BTreeSet<[u8; 32]>,
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub enum SenderPresentation {
    Canonical,
    Blinded([u8; 32]),
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum WitnessKind {
    /// Standalone private account. The `account_id` is derived as
    /// `AccountId::for_regular_private_account(&npk, vpk)` from the key's `npk` and matched
    /// against the addressed actor's `account_id`.
    Regular(RegularKey),
    /// A private PDA with its authority's account ID and seed, held by `nsk`.
    Pda {
        nsk: NullifierSecretKey,
        binding: (AccountId, PdaSeed),
    },
}

/// The key a regular private account's witness holds: an authorization key also authorizes the
/// account's spending, a nullifier key only proves control of its state.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum RegularKey {
    Authorized(AuthorizationSecretKey),
    Nullifying(NullifierSecretKey),
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum NullifierWitness {
    /// Initializes a private account from the fixed empty predecessor, which needs no membership
    /// proof, anchored at a known commitment-set root.
    Init {
        commitment_root: CommitmentSetDigest,
    },
    /// Update of a private account: existing on-chain commitment, with membership proof.
    Update {
        account: Account,
        membership_proof: MembershipProof,
    },
}

/// A struct containing necessary data for dummy nullifier and
/// commitment generation.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct DummyInput {
    /// The seed used for generating the dummy nullifier.
    pub nullifier_seed: [u8; 32],
    /// The dummy root.
    pub commitment_root: CommitmentSetDigest,
    /// The dummy commitment and note.
    pub output: DummyOutput,
}

/// The output of an action that creates no account state: a dummy commitment and note.
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct DummyOutput {
    /// The seed used for generating the dummy commitment.
    pub commitment_seed: [u8; 32],
    /// The dummy ciphertext and epk.
    pub note: EncryptedNote,
}

#[cfg(any(feature = "host", test))]
impl Default for DummyOutput {
    fn default() -> Self {
        Self {
            commitment_seed: [0; 32],
            note: EncryptedNote {
                epk: crate::EphemeralPublicKey(vec![0; crate::ML_KEM_768_CIPHERTEXT_LEN]),
                ..EncryptedNote::default()
            },
        }
    }
}

impl PrivateWitness {
    #[must_use]
    pub const fn is_pda(&self) -> bool {
        matches!(self.kind, WitnessKind::Pda { .. })
    }

    #[must_use]
    pub const fn pda_binding(&self) -> Option<(AccountId, PdaSeed)> {
        match self.kind {
            WitnessKind::Pda { binding, .. } => Some(binding),
            WitnessKind::Regular(_) => None,
        }
    }

    /// Derives the account ID from this witness.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        let npk = NullifierPublicKey::from(&self.kind.nsk());
        AccountId::for_private_account(&npk, &self.vpk, &self.kind.account_kind())
    }

    /// The state this witness's transition starts from: the fixed empty account when it
    /// initializes.
    #[must_use]
    pub(crate) fn predecessor(&self) -> Cow<'_, Account> {
        match &self.nullifier {
            NullifierWitness::Init { .. } => Cow::Owned(Account::default()),
            NullifierWitness::Update { account, .. } => Cow::Borrowed(account),
        }
    }

    /// The nullifier this witness's transition spends, the commitment-set root anchoring it, and
    /// the nonce its successor takes. An initialization spends its fixed predecessor's nullifier
    /// like any update; only that predecessor may omit membership.
    pub fn transition(
        &self,
    ) -> Result<(Nullifier, CommitmentSetDigest, Nonce), InvalidMembershipProof> {
        let nsk = self.kind.nsk();
        let predecessor = self.predecessor();
        let commitment = Commitment::new(&self.account_id(), &predecessor);
        let root = match &self.nullifier {
            NullifierWitness::Init { commitment_root } => *commitment_root,
            NullifierWitness::Update {
                membership_proof: (position, path),
                ..
            } => compute_digest_for_path(&commitment, *position, path)?,
        };
        Ok((
            Nullifier::for_account_update(&commitment, &nsk),
            root,
            predecessor.nonce.private_account_nonce_increment(&nsk),
        ))
    }
}

impl WitnessKind {
    /// The nullifier key holding the witnessed account.
    #[must_use]
    pub fn nsk(&self) -> NullifierSecretKey {
        match self {
            Self::Regular(key) => key.nsk(),
            Self::Pda { nsk, .. } => *nsk,
        }
    }

    /// Whether the witness authorizes its account's spending.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Regular(RegularKey::Authorized(_)))
    }

    #[must_use]
    pub const fn account_kind(&self) -> PrivateAccountKind {
        match *self {
            Self::Regular(_) => PrivateAccountKind::Regular,
            Self::Pda {
                binding: (account_id, seed),
                ..
            } => PrivateAccountKind::Pda { account_id, seed },
        }
    }
}

impl RegularKey {
    /// The nullifier key this key holds: derived from an authorization key.
    #[must_use]
    pub fn nsk(&self) -> NullifierSecretKey {
        match self {
            Self::Authorized(ask) => NullifierSecretKey::from(ask),
            Self::Nullifying(nsk) => *nsk,
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
    pub encrypted_post_state: EncryptedNote,
}

#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, PartialEq, Eq, Default)
)]
pub struct PrivacyPreservingCircuitOutput {
    pub context: PublicExecutionContext,
    pub execution: ProvenExecution,
}

#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, PartialEq, Eq, Default)
)]
pub struct ProvenExecution {
    pub boundary: Boundary,
    pub casts: Vec<SealedCast>,
    pub recovery_bindings: Vec<RecoveryBinding>,
    /// How the transaction starts, as far as the proof reveals it: a public Call, or `None` for a
    /// private Call or a received message, whose spend is an ordinary private action.
    pub public_root: Option<RootCall>,
    pub private_actions: Vec<PrivateAction>,
    pub validity: ValidityWindows,
    /// Claims derived from [`PrivacyPreservingCircuitInput::program_image_witnesses`] — what the
    /// receipt actually commits to, so the sequencer can check it against real chain state.
    pub program_image_claims: Vec<ProgramImageClaim>,
}

#[cfg(any(feature = "host", test))]
impl ProvenExecution {
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
        Commitment, EncryptedNote, Nullifier, SealedCast,
        account::{Account, AccountId, Actor},
        encryption::{Ciphertext, EphemeralPublicKey},
        execution_state::{BoundaryStep, Delivery},
        program::{MessageBody, MessageEnvelope},
    };

    const NSK: NullifierSecretKey = [0; 32];

    // The private account `NSK` controls, reachable at its own address and at the alias its one
    // opening blinds.
    fn receiver() -> PrivateWitness {
        PrivateWitness {
            vpk: ViewingPublicKey::from_seed(&[1; 32], &[2; 32]),
            random_seed: [3; 32],
            kind: WitnessKind::Regular(RegularKey::Nullifying(NSK)),
            nullifier: NullifierWitness::Init {
                commitment_root: [5; 32],
            },
            openings: BTreeSet::from([[6; 32]]),
        }
    }

    fn body(to: Actor) -> MessageBody {
        MessageBody {
            from: Actor::new(AccountId::new([9; 32]), AccountId::new([10; 32])),
            to,
            message: b"m".to_vec(),
        }
    }

    fn path() -> Vec<[u8; 32]> {
        vec![[11; 32], [12; 32]]
    }

    fn received(to: Actor, position: u64, rho: Option<[u8; 32]>) -> MessageWitness {
        MessageWitness {
            body: body(to),
            position,
            rho,
            path: path(),
            filler: DummyOutput::default(),
        }
    }

    fn proving(
        root: TransactionEntry<MessageWitness>,
        context: PublicExecutionContext,
    ) -> ProvingInput {
        ProvingInput {
            root,
            context,
            private_witnesses: vec![receiver()],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_cast_promotions: BTreeSet::new(),
        }
    }

    #[test]
    fn a_circuit_output_journal_has_a_pinned_layout() {
        let public = Actor::new(AccountId::new([0; 32]), AccountId::new([1; 32]));
        let private = Actor::new(AccountId::new([2; 32]), AccountId::new([3; 32]));
        let output = PrivacyPreservingCircuitOutput {
            context: PublicExecutionContext {
                actors: BTreeSet::from([public]),
                authorized_accounts: BTreeSet::from([AccountId::new([4; 32])]),
                cast_promotions: BTreeSet::from([5]),
            },
            execution: ProvenExecution {
                boundary: vec![
                    BoundaryStep::PrivateToPublic(Delivery {
                        envelope: MessageEnvelope {
                            from: private,
                            to: public,
                            message: vec![6],
                        },
                        inherited_authorizations: BTreeSet::from([AccountId::new([7; 32])]),
                        inherits_entry_authorizations: false,
                        pda_seeds: BTreeSet::from([PdaSeed::new([8; 32])]),
                    }),
                    BoundaryStep::PublicToPrivate(Delivery {
                        envelope: MessageEnvelope {
                            from: public,
                            to: private,
                            message: vec![9],
                        },
                        inherited_authorizations: BTreeSet::new(),
                        inherits_entry_authorizations: true,
                        pda_seeds: BTreeSet::new(),
                    }),
                    BoundaryStep::EndPrivateSubtree,
                    BoundaryStep::EndPublicSubtree,
                ],
                casts: vec![SealedCast {
                    commitment: Commitment::from_byte_array([10; 32]),
                    note: EncryptedNote {
                        ciphertext: Ciphertext(vec![11; 3]),
                        epk: EphemeralPublicKey(vec![12; 2]),
                    },
                }],
                recovery_bindings: vec![RecoveryBinding {
                    address: AccountId::new([13; 32]),
                    note: EncryptedNote {
                        ciphertext: Ciphertext(vec![14; 3]),
                        epk: EphemeralPublicKey(vec![15; 2]),
                    },
                }],
                public_root: Some(RootCall {
                    to: public,
                    message: vec![16; 2],
                }),
                private_actions: vec![PrivateAction {
                    nullifier: Nullifier::from_byte_array([17; 32]),
                    root: [18; 32],
                    commitment: Commitment::from_byte_array([19; 32]),
                    encrypted_post_state: EncryptedNote {
                        ciphertext: Ciphertext(vec![20; 3]),
                        epk: EphemeralPublicKey(vec![21; 2]),
                    },
                }],
                validity: ValidityWindows {
                    blocks: (22..).into(),
                    timestamps: (..23).into(),
                },
                program_image_claims: vec![
                    ProgramImageClaim::Disclosed {
                        account_id: AccountId::new([24; 32]),
                        image_id: [25; 8],
                    },
                    ProgramImageClaim::Undisclosed { root: [26; 32] },
                ],
            },
        };

        let expected: Vec<u8> = [
            &[108, 3, 0, 0][..], // frame length: the 876 bytes below
            &[1, 0, 0, 0],       // context.actors: one actor
            &[0; 32],
            &[1; 32],
            &[1, 0, 0, 0], // context.authorized_accounts: one account
            &[4; 32],
            &[1, 0, 0, 0], // context.cast_promotions: one selected Cast
            &[5, 0, 0, 0, 0, 0, 0, 0],
            &[4, 0, 0, 0], // boundary: four steps
            &[0],          // BoundaryStep::PrivateToPublic
            &[2; 32],      // from
            &[3; 32],
            &[0; 32], // to
            &[1; 32],
            &[1, 0, 0, 0], // message
            &[6],
            &[1, 0, 0, 0], // inherited_authorizations: one account
            &[7; 32],
            &[0],          // inherits_entry_authorizations: false
            &[1, 0, 0, 0], // pda_seeds: one seed
            &[8; 32],
            &[1],     // BoundaryStep::PublicToPrivate
            &[0; 32], // from
            &[1; 32],
            &[2; 32], // to
            &[3; 32],
            &[1, 0, 0, 0], // message
            &[9],
            &[0, 0, 0, 0], // inherited_authorizations: none
            &[1],          // inherits_entry_authorizations: true
            &[0, 0, 0, 0], // pda_seeds: none
            &[2],          // BoundaryStep::EndPrivateSubtree
            &[3],          // BoundaryStep::EndPublicSubtree
            &[1, 0, 0, 0], // casts: one sealed Cast
            &[10; 32],     // commitment
            &[3, 0, 0, 0], // note.ciphertext
            &[11; 3],
            &[2, 0, 0, 0], // note.epk
            &[12; 2],
            &[1, 0, 0, 0], // recovery_bindings: one binding
            &[13; 32],     // address
            &[3, 0, 0, 0], // note.ciphertext
            &[14; 3],
            &[2, 0, 0, 0], // note.epk
            &[15; 2],
            &[1],     // public_root: Some
            &[0; 32], // to
            &[1; 32],
            &[2, 0, 0, 0], // message
            &[16; 2],
            &[1, 0, 0, 0], // private_actions: one action
            &[17; 32],     // nullifier
            &[18; 32],     // root
            &[19; 32],     // commitment
            &[3, 0, 0, 0], // encrypted_post_state.ciphertext
            &[20; 3],
            &[2, 0, 0, 0], // encrypted_post_state.epk
            &[21; 2],
            &[1], // validity.blocks.from: Some
            &[22, 0, 0, 0, 0, 0, 0, 0],
            &[0], // validity.blocks.to: None
            &[0], // validity.timestamps.from: None
            &[1], // validity.timestamps.to: Some
            &[23, 0, 0, 0, 0, 0, 0, 0],
            &[2, 0, 0, 0],            // program_image_claims: two claims
            &[0],                     // ProgramImageClaim::Disclosed
            &[24; 32],                // account_id
            &[25, 0, 0, 0].repeat(8), // image_id: eight little-endian words
            &[1],                     // ProgramImageClaim::Undisclosed
            &[26; 32],                // root
        ]
        .concat();

        assert_eq!(output.to_bytes(), expected);
        assert_eq!(
            crate::to_borsh_frame(&(&output.context, &output.execution)),
            expected
        );
        let decoded: PrivacyPreservingCircuitOutput =
            borsh::from_slice(crate::from_frame(&expected).expect("the frame is well-formed"))
                .unwrap();
        assert_eq!(decoded, output);
    }

    #[test]
    fn private_witness_account_id_matches_its_derivation() {
        let nsk = [3; 32];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1; 32], &[2; 32]);
        let witness = |kind| PrivateWitness {
            vpk: vpk.clone(),
            random_seed: [4; 32],
            kind,
            nullifier: NullifierWitness::Init {
                commitment_root: [5; 32],
            },
            openings: BTreeSet::new(),
        };
        let program = AccountId::new([6; 32]);
        let seed = PdaSeed::new([7; 32]);

        let regular = witness(WitnessKind::Regular(RegularKey::Nullifying(nsk)));
        assert!(!regular.is_pda());
        assert_eq!(
            regular.account_id(),
            AccountId::for_regular_private_account(&npk, &vpk)
        );

        let pda = witness(WitnessKind::Pda {
            nsk,
            binding: (program, seed),
        });
        assert!(pda.is_pda());
        assert_eq!(
            pda.account_id(),
            AccountId::for_private_pda(&program, &seed, &npk, &vpk)
        );
    }

    #[test]
    fn a_private_witness_has_a_pinned_layout() {
        let account = Account::default();
        let authorized = PrivateWitness {
            kind: WitnessKind::Regular(RegularKey::Authorized(AuthorizationSecretKey([2; 32]))),
            nullifier: NullifierWitness::Update {
                account: account.clone(),
                membership_proof: (4, vec![[11; 32]]),
            },
            ..receiver()
        };
        let pda = PrivateWitness {
            kind: WitnessKind::Pda {
                nsk: NSK,
                binding: (AccountId::new([7; 32]), PdaSeed::new([8; 32])),
            },
            openings: BTreeSet::new(),
            ..receiver()
        };
        let vpk = receiver().vpk;

        let expected_authorized: Vec<u8> = [
            &[160, 4, 0, 0][..], // vpk: 1184 bytes
            vpk.to_bytes(),
            &[3; 32], // random_seed
            &[0, 0],  // kind: Regular(Authorized)
            &[2; 32],
            &[1], // nullifier: Update, with no view tag
            &*borsh::to_vec(&account).unwrap(),
            &[4, 0, 0, 0, 0, 0, 0, 0], // membership_proof: leaf index
            &[1, 0, 0, 0],
            &[11; 32],
            &[1, 0, 0, 0], // openings: one
            &[6; 32],
        ]
        .concat();
        let expected_pda: Vec<u8> = [
            &[160, 4, 0, 0][..], // vpk: 1184 bytes
            vpk.to_bytes(),
            &[3; 32], // random_seed
            &[1],     // kind: Pda
            &NSK,
            &[7; 32], // binding
            &[8; 32],
            &[0], // nullifier: Init
            &[5; 32],
            &[0, 0, 0, 0], // openings: none
        ]
        .concat();

        assert_eq!(borsh::to_vec(&authorized).unwrap(), expected_authorized);
        assert_eq!(borsh::to_vec(&pda).unwrap(), expected_pda);
    }

    #[test]
    fn an_initialization_spends_its_empty_predecessors_update_nullifier_whatever_its_anchor() {
        let account_id = receiver().account_id();
        let initialization = (
            Nullifier::for_account_update(&Commitment::new(&account_id, &Account::default()), &NSK),
            Nonce::default().private_account_nonce_increment(&NSK),
        );
        assert_eq!(
            Nullifier::for_account_initialization(&account_id, &NSK),
            initialization.0
        );

        for (anchor, witness) in [
            ([5; 32], receiver()),
            (
                [10; 32],
                PrivateWitness {
                    random_seed: [9; 32],
                    nullifier: NullifierWitness::Init {
                        commitment_root: [10; 32],
                    },
                    openings: BTreeSet::new(),
                    ..receiver()
                },
            ),
        ] {
            let (nullifier, root, nonce) = witness.transition().unwrap();
            assert_eq!((nullifier, nonce), initialization);
            assert_eq!(root, anchor);
        }

        let account = Account {
            nonce: Nonce(7),
            ..Account::default()
        };
        let commitment = Commitment::new(&account_id, &account);
        let update = PrivateWitness {
            nullifier: NullifierWitness::Update {
                account,
                membership_proof: (0, path()),
            },
            ..receiver()
        };
        assert_eq!(
            update.transition(),
            Ok((
                Nullifier::for_account_update(&commitment, &NSK),
                compute_digest_for_path(&commitment, 0, &path()).unwrap(),
                Nonce(7).private_account_nonce_increment(&NSK),
            ))
        );
    }

    #[test]
    fn a_received_message_is_nullified_with_its_receiving_witnesss_key() {
        let private = Actor::new(receiver().account_id(), AccountId::new([8; 32]));
        let other = PrivateWitness {
            kind: WitnessKind::Regular(RegularKey::Nullifying([13; 32])),
            openings: BTreeSet::new(),
            ..receiver()
        };
        let commitment = Commitment::for_message(&body(private));

        assert_eq!(
            received(private, 3, None)
                .spend(&[other, receiver()])
                .unwrap(),
            (
                Nullifier::for_message(&NSK, &commitment, 3),
                compute_digest_for_path(&commitment, 3, &path()).unwrap(),
            )
        );
    }

    #[test]
    fn a_proof_discloses_only_a_public_call_root_and_spends_a_received_message_privately() {
        let public = Actor::new(AccountId::new([7; 32]), AccountId::new([8; 32]));
        let private = Actor::new(receiver().account_id(), AccountId::new([8; 32]));
        let alias = Actor::new(
            private.account_id.blinded(&[6; 32]),
            private.program_account_id,
        );
        let context = PublicExecutionContext::new(vec![public], []);
        let call = |to| {
            TransactionEntry::Call(RootCall {
                to,
                message: b"m".to_vec(),
            })
        };

        assert_eq!(
            proving(call(public), context.clone()).public_root(),
            Some(RootCall {
                to: public,
                message: b"m".to_vec(),
            })
        );
        assert_eq!(proving(call(private), context.clone()).public_root(), None);
        for to in [private, alias] {
            let commitment = Commitment::for_message(&body(to));

            assert_eq!(
                proving(
                    TransactionEntry::Cast(received(to, 3, None)),
                    context.clone()
                )
                .public_root(),
                None
            );
            assert_eq!(
                received(to, 3, None).spend(&[receiver()]).unwrap(),
                (
                    Nullifier::for_message(&NSK, &commitment, 3),
                    compute_digest_for_path(&commitment, 3, &path()).unwrap(),
                )
            );
        }
    }

    #[test]
    fn an_account_or_program_membership_position_must_fit_its_path() {
        for (position, fits) in [(3, true), (7, false)] {
            let account = PrivateWitness {
                nullifier: NullifierWitness::Update {
                    account: Account::default(),
                    membership_proof: (position, path()),
                },
                ..receiver()
            };
            let program = ProgramImageWitness::Undisclosed {
                account_id: AccountId::new([13; 32]),
                program_header: ProgramHeader {
                    image_id: [14; 8],
                    program_first_segment: AccountId::new([15; 32]),
                    immutable: true,
                },
                membership_proof: (position, path()),
            };

            assert_eq!(account.transition().is_ok(), fits);
            assert_eq!(program.to_claim().is_ok(), fits);
        }
    }

    #[test]
    fn a_received_message_whose_evidence_does_not_fit_it_is_not_spent() {
        let private = Actor::new(receiver().account_id(), AccountId::new([8; 32]));
        let commitment = Commitment::for_message(&body(private));
        // A bit above the path's depth would reach the same root but spend another nullifier.
        assert!(compute_digest_for_path(&commitment, 3, &path()).is_ok());
        assert_eq!(
            compute_digest_for_path(&commitment, 7, &path()),
            Err(InvalidMembershipProof)
        );
        assert_ne!(
            Nullifier::for_message(&NSK, &commitment, 3),
            Nullifier::for_message(&NSK, &commitment, 7)
        );
        let stranger = Actor::new(AccountId::new([14; 32]), AccountId::new([8; 32]));

        for (case, witness, refusal) in [
            (
                "a position above its path",
                received(private, 7, None),
                InvalidMessageEvidence::NoncanonicalPosition,
            ),
            (
                "an address no witness reaches",
                received(stranger, 3, None),
                InvalidMessageEvidence::UnwitnessedDestination,
            ),
        ] {
            assert_eq!(
                witness.spend(&[receiver()]).unwrap_err().to_string(),
                refusal.to_string(),
                "{case}"
            );
        }
    }

    #[test]
    fn a_sealed_message_is_spent_under_its_randomness() {
        let private = Actor::new(receiver().account_id(), AccountId::new([8; 32]));
        let rho = [13; 32];
        let commitment = Commitment::for_sealed_message(&body(private), &rho);

        assert_eq!(
            received(private, 3, Some(rho))
                .spend(&[receiver()])
                .unwrap(),
            (
                Nullifier::for_message(&NSK, &commitment, 3),
                compute_digest_for_path(&commitment, 3, &path()).unwrap(),
            )
        );
    }
}
