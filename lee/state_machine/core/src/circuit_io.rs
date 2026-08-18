use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    Nullifier, NullifierPublicKey, NullifierSecretKey,
    account::{AccountId, AccountWithMetadata, Data},
    encryption::{EncryptedAccountData, ViewTag, ViewingPublicKey},
    program::{
        AccountDiffOutput, BlockValidityWindow, PdaSeed, ProgramId, ProgramOutput,
        TimestampValidityWindow,
    },
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
    pub dummy_inputs: Vec<DummyInput>,
    /// The materialized `data` result for every `AccountDiff` with `diff_data.is_some()`
    /// encountered across `program_outputs`, in the same order the circuit visits them (the
    /// same account/chained-call traversal order `account_identities` aligns to). The host
    /// proves each one via `Program::prove_update_from_diff` and adds the resulting receipt as
    /// an `env_builder` assumption; the circuit reconstructs the expected
    /// `UpdateFromDiffOutput{pre_state, diff_data, data}` journal from `pre_state` (known from
    /// the pre-state), `diff_data` (known from the diff), and this `data`, then checks it via
    /// `env::verify` — so this value is untrusted input, made trustworthy only by that check.
    pub update_from_diff_results: Vec<Data>,
    /// The accounts this transaction claims are signers. `is_authorized` for every account is
    /// *derived* from membership in this single list — never accepted as an independent
    /// per-account witness — and the list itself is committed to the output so the sequencer can
    /// cross-check it against real signatures. Without that, a prover could satisfy
    /// claim-eligibility's authorization check for an account it never actually controls.
    pub signer_account_ids: Vec<AccountId>,
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
    /// `(program_id, seed, npk)` family: `AccountId::for_private_pda` uses it as the 4th input.
    /// An init is unauthorized; on an update, authorization may be established upstream by a
    /// caller `pda_seeds` match or a previously-seen authorization in a chained call.
    Pda {
        /// When `Some((authority_program_id, seed))`, the circuit binds this position via the
        /// external derivation check
        /// `AccountId::for_private_pda(authority_program_id, seed, npk, vpk, identifier) ==
        /// pre_state.account_id` rather than requiring a `Claim::Pda` or caller
        /// `pda_seeds` to establish the binding. The `pre_state` must have `is_authorized
        /// == false`.
        binding: Option<(ProgramId, PdaSeed)>,
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

/// One call's raw, unaggregated diff to a public account.
///
/// Deliberately not collapsed into one diff per account: `AccountDiff` has no "combine two
/// diffs" operation, especially for `diff_data`, which only composes by being applied in
/// sequence. The sequencer replays these one at a time against its own live state — never
/// trusting anything the circuit internally materialized for a public account, which is why the
/// account's *value* (as opposed to its diffs) never appears here.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct PublicDiff {
    pub account_id: AccountId,
    /// Carried alongside the diff because the sequencer's replay-time authorization re-check
    /// (and PDA claim resolution) needs to know which program produced it — the same role
    /// `chained_call.program_id` plays in the public-transaction path's live materialize loop.
    pub executing_program_id: ProgramId,
    pub diff: AccountDiffOutput,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq, Default))]
pub struct PrivacyPreservingCircuitOutput {
    /// What the circuit witnessed as each public account's pre-state — deliberately *not*
    /// reconciled against live sequencer state. Used only to verify the proof is internally
    /// consistent (see `check_privacy_preserving_circuit_proof_is_valid`); materialization uses
    /// live state instead, via `public_diffs`, which is what actually avoids tying this
    /// transaction's validity to a specific public-account snapshot.
    pub public_pre_states: Vec<AccountWithMetadata>,
    pub public_diffs: Vec<PublicDiff>,
    pub private_actions: Vec<PrivateAction>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    /// Committed so the sequencer can verify every account this circuit treated as authorized
    /// really did sign the transaction — see `PrivacyPreservingCircuitInput::signer_account_ids`.
    pub signer_account_ids: Vec<AccountId>,
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
        account::{Account, AccountDiff, AccountId, AccountWithMetadata, BalanceDiff, Nonce},
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
            public_diffs: vec![
                PublicDiff {
                    account_id: AccountId::new([0; 32]),
                    executing_program_id: [1, 2, 3, 4, 5, 6, 7, 8],
                    diff: AccountDiffOutput::new(AccountDiff {
                        id: AccountId::new([0; 32]),
                        diff_balance: BalanceDiff::Add(100),
                        diff_data: Some(b"post state data".to_vec()),
                    }),
                },
                PublicDiff {
                    account_id: AccountId::new([1; 32]),
                    executing_program_id: [2, 3, 4, 5, 6, 7, 8, 9],
                    diff: AccountDiffOutput::new(AccountDiff {
                        id: AccountId::new([1; 32]),
                        diff_balance: BalanceDiff::Sub(200),
                        diff_data: Some(b"post state data 2".to_vec()),
                    }),
                },
            ],
            signer_account_ids: vec![AccountId::new([0; 32])],
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
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
