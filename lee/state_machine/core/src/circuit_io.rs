use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId},
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    execution_state::{PublicResolution, RootCall},
    program::{
        BlockValidityWindow, PdaSeed, ProgramId, ProgramOutput, ResolveOutput,
        TimestampValidityWindow,
    },
};

/// A claim that `account_id`'s program account currently has `image_id`.
///
/// Supplied by the prover as circuit input (untrusted). The circuit uses it for `env::verify` in
/// place of a legacy-bijection lookup — an address-deployed program's account doesn't encode its
/// image id — and echoes it unchanged into the circuit's output. The circuit itself does **not**
/// check `image_id` against `account_id`; the sequencer does, independently, against real chain
/// state (`V03State::get_program_image_id`) before accepting the proof. Side effect for now:
/// every program invoked in a private transaction's call graph is publicly visible via this claim
/// list.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct ProgramImageClaim {
    pub account_id: AccountId,
    pub image_id: ProgramId,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PrivacyPreservingCircuitInput {
    pub root: RootCall,
    /// One witness for each private account used by the transaction.
    pub private_witnesses: Vec<PrivateWitness>,
    pub dummy_inputs: Vec<DummyInput>,
    /// Real `image_id`s for every address-deployed program invoked in the call graph, keyed by
    /// account id. See [`ProgramImageClaim`].
    pub program_image_claims: Vec<ProgramImageClaim>,
    /// One entry per scheduled call, in traversal order.
    pub calls: Vec<ProvenCall>,
}

/// One scheduled call's transcript: its planner output, and the resolutions of the private
/// effects that planner emitted, in effect order.
///
/// Native-token plans and resolutions are recomputed from the protocol's own implementation, so
/// they carry no receipt and occupy no slot in `private_resolutions`.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct ProvenCall {
    pub plan: ProgramOutput,
    pub private_resolutions: Vec<ResolveOutput>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrivateWitness {
    pub account: Account,
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
    /// the handle's `account_id`. An honest authorized account's `npk` for Id computation gets
    /// derived from the supplied `ask`.
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

/// A public account's root-authorization bit and the effects the execution deferred to
/// settlement, in the order its traversal emitted them.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PublicAction {
    pub account_id: AccountId,
    pub is_authorized: bool,
    pub resolutions: Vec<PublicResolution>,
}

#[derive(BorshSerialize, BorshDeserialize)]
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
                    resolutions: vec![
                        PublicResolution::Apply {
                            program_account_id: touched,
                            shard_program_account_id: touched,
                            data: b"post state data".to_vec(),
                        },
                        PublicResolution::Apply {
                            program_account_id: touched,
                            shard_program_account_id: also_touched,
                            data: b"fresh record".to_vec(),
                        },
                    ],
                },
                PublicAction {
                    account_id: AccountId::new([1; 32]),
                    is_authorized: false,
                    resolutions: Vec::new(),
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
            program_image_claims: vec![ProgramImageClaim {
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
        let identifier: Identifier = 77;
        let witness = |kind| PrivateWitness {
            account: Account::default(),
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
