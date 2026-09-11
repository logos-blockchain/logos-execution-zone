use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{Account, AccountId, AccountWithMetadata, BalanceDiff, Data},
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    program::{BlockValidityWindow, PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow},
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
    /// Outputs of the program execution.
    pub program_outputs: Vec<ProgramOutput>,
    /// One entry per `pre_state`, in the same order as the program's `pre_states`.
    /// Length must equal the number of `pre_states` derived from `program_outputs`.
    /// The guest's `private_pda_by_position` and `private_pda_bound_positions`
    /// rely on this position alignment.
    pub account_identities: Vec<InputAccountIdentity>,
    /// The top-level call's own dispatch address.
    pub program_account_id: AccountId,
    pub dummy_inputs: Vec<DummyInput>,
    /// `account_id`s the top-level call was invoked with. Every one must still appear somewhere
    /// in the final accumulated pre-states, or the guest rejects — catches a chained call
    /// silently dropping an account from its own output.
    pub initial_pre_states: Vec<AccountId>,
    /// Real `image_id`s for every address-deployed program invoked in the call graph, keyed by
    /// account id. See [`ProgramImageClaim`].
    pub program_image_claims: Vec<ProgramImageClaim>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Private carries the ML-KEM viewing key and dominates; boxing it would add a guest heap allocation per witness, and the footprint matches the pre-refactor enum"
)]
pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from `program_outputs` and emits no
    /// commitment, ciphertext, or nullifier. Whether a given touch ends up `Bound` or `Deferred`
    /// is never declared here — it's inferred per diff from whether the executing program
    /// implements `CallKind::Incremental` (see `ExecutionState`'s per-account accumulation).
    Public,
    Private(PrivateWitness),
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
    /// `pre_state.account_id`. An honest authorized account's `npk` for Id computation gets
    /// derived from the supplied `ask`.
    Regular { ask: Option<AuthorizationSecretKey> },
    /// Private PDA. The npk-to-account_id binding is proven upstream via the `binding` below or a
    /// caller's `pda_seeds` match. The identifier diversifies the PDA within the
    /// `(program_account_id, seed, npk)` family: `AccountId::for_private_pda` uses it as the 4th
    /// input.
    Pda {
        /// When `Some((authority_account_id, seed))`, the circuit binds this position via the
        /// external derivation check
        /// `AccountId::for_private_pda(authority_account_id, seed, npk, vpk, identifier) ==
        /// pre_state.account_id` rather than requiring a caller's `pda_seeds` to establish the
        /// binding.
        binding: Option<(AccountId, PdaSeed)>,
    },
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
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

/// One pending, unresolved update to a `Deferred` account's `data`.
///
/// Everything settlement needs to replay `CallKind::Incremental` for real, host-side, against
/// live state. A `Deferred` account carries a list of these (see `PublicAction::Deferred`), one
/// per touch by a program that implements `Incremental`, applied in order at settlement.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct DeferredResolution {
    /// The program whose ELF resolves this account's `post_data` via `CallKind::Incremental` —
    /// not necessarily the touched account itself (mirrors `resolve_diff`'s own distinction
    /// between `executing_account_id` and `diff.pre_state.account_id`).
    pub executing_account_id: AccountId,
    pub caller_account_id: Option<AccountId>,
    pub post_balance_diff: BalanceDiff,
    pub post_data: Option<Data>,
}

/// A public account's outcome for one privacy-preserving execution.
///
/// `Bound` and `Deferred` are never declared by a caller — every touch is classified per diff, by
/// whether the program producing it implements `CallKind::Incremental`; a `Deferred`-eligible
/// touch that later shares an account with a `Bound`-forced one folds into `Bound` for the rest
/// of the execution (see `ExecutionState`'s accumulation logic).
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub enum PublicAction {
    /// Resolved in-circuit, part of what the proof attests to — `pre` anchors the proof's
    /// validity to that exact starting value, checked against live state at settlement.
    Bound {
        pre: AccountWithMetadata,
        post: Account,
    },
    /// Unresolved — no `pre` at all, deliberately: a `Deferred` account's value was never tied
    /// to any specific starting state in the first place, so there's nothing to anchor or check
    /// against live state at settlement. `resolutions` are replayed in order, each against
    /// whatever the account actually holds when it's applied.
    Deferred {
        account_id: AccountId,
        resolutions: Vec<DeferredResolution>,
    },
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
        account::{Account, AccountId, AccountWithMetadata, Nonce},
        encryption::{Ciphertext, EphemeralPublicKey},
    };

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_round_trips_via_borsh_frame() {
        let output = PrivacyPreservingCircuitOutput {
            public_actions: vec![
                PublicAction::Bound {
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
                PublicAction::Bound {
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
                PublicAction::Deferred {
                    account_id: AccountId::new([5; 32]),
                    resolutions: vec![
                        DeferredResolution {
                            executing_account_id: AccountId::new([6; 32]),
                            caller_account_id: None,
                            post_balance_diff: BalanceDiff::Add(5),
                            post_data: Some(b"delta 1".to_vec().try_into().unwrap()),
                        },
                        DeferredResolution {
                            executing_account_id: AccountId::new([6; 32]),
                            caller_account_id: Some(AccountId::new([7; 32])),
                            post_balance_diff: BalanceDiff::Sub(2),
                            post_data: None,
                        },
                    ],
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
}
