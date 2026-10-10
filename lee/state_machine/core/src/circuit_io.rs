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
    use super::*;
    use crate::{
        Commitment, Nullifier,
        account::{Account, AccountId},
        encryption::{Ciphertext, EphemeralPublicKey},
    };

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_round_trips_via_borsh_frame() {
        let touched = AccountId::new([8; 32]);
        let also_touched = AccountId::new([9; 32]);
        let output = PrivacyPreservingCircuitOutput {
            public_actions: vec![
                PublicAction {
                    account_id: AccountId::new([0; 32]),
                    is_authorized: true,
                    effects: vec![
                        DeferredPublicEffect {
                            program_account_id: touched,
                            shard_program_account_id: touched,
                            data: b"post state data".to_vec(),
                        },
                        DeferredPublicEffect {
                            program_account_id: touched,
                            shard_program_account_id: also_touched,
                            data: b"fresh record".to_vec(),
                        },
                    ],
                },
                PublicAction {
                    account_id: AccountId::new([1; 32]),
                    is_authorized: false,
                    effects: Vec::new(),
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
