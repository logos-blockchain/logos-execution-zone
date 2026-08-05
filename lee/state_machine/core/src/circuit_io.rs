use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentSetDigest, Identifier, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey,
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
    /// The accounts this transaction claims are signers. `is_authorized` for every account is
    /// *derived* from membership in this single list — never accepted as an independent
    /// per-account witness — and the list itself is committed to the output so the sequencer can
    /// cross-check it against real signatures. Without that, a prover could satisfy
    /// claim-eligibility's authorization check for an account it never actually controls.
    pub signer_account_ids: Vec<AccountId>,
    /// Claimed `Data` results for each `diff_data.is_some()` materialization the circuit needs,
    /// consumed in the same order `validate_and_sync_states` encounters them. Flat rather than
    /// keyed by account, because the same account can be materialized more than once within one
    /// chain. Each entry is only trusted once `env::verify` confirms a real
    /// `UpdateFromDiffOutput` receipt exists binding it to the exact `pre_state`/`diff_data` the
    /// circuit already knows for that step.
    pub update_from_diff_results: Vec<Data>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from `program_outputs` and emits no
    /// commitment, ciphertext, or nullifier.
    Public,
    /// Init of an authorized standalone private account: no membership proof. The `pre_state`
    /// must be `Account::default()`. The `account_id` is derived as
    /// `AccountId::for_regular_private_account(&NullifierPublicKey::from(nsk), vpk, identifier)`
    /// and matched against `pre_state.account_id`.
    PrivateAuthorizedInit {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        nsk: NullifierSecretKey,
        identifier: Identifier,
        commitment_root: CommitmentSetDigest,
    },
    /// Update of an authorized standalone private account: existing on-chain commitment, with
    /// membership proof.
    PrivateAuthorizedUpdate {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        view_tag: ViewTag,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
    },
    /// Init of a standalone private account the caller does not own (e.g. a recipient who
    /// doesn't yet exist on chain). No `nsk`, no membership proof.
    PrivateForeignInit {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        npk: NullifierPublicKey,
        identifier: Identifier,
        commitment_root: CommitmentSetDigest,
    },
    /// Init of a private PDA, unauthorized. The npk-to-account_id binding is proven upstream
    /// via `Claim::Pda(seed)` or a caller's `pda_seeds` match. The identifier diversifies the
    /// PDA within the `(program_id, seed, npk)` family: `AccountId::for_private_pda` uses it
    /// as the 4th input.
    PrivatePdaInit {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        npk: NullifierPublicKey,
        identifier: Identifier,
        commitment_root: CommitmentSetDigest,
        /// When `Some((seed, authority_program_id))`, the circuit binds this position via the
        /// external derivation check
        /// `AccountId::for_private_pda(authority_program_id, seed, npk, vpk, identifier) ==
        /// pre_state.account_id` rather than requiring a `Claim::Pda` or caller
        /// `pda_seeds` to establish the binding. The `pre_state` must have `is_authorized
        /// == false`.
        seed: Option<(PdaSeed, ProgramId)>,
    },
    /// Update of an existing private PDA, with membership proof. `npk` is derived
    /// from `nsk`. Authorization may be established upstream by a caller `pda_seeds` match or a
    /// previously-seen authorization in a chained call.
    PrivatePdaUpdate {
        vpk: ViewingPublicKey,
        random_seed: [u8; 32],
        view_tag: ViewTag,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
        identifier: Identifier,
        /// When `Some((seed, authority_program_id))`, the circuit binds this position via the
        /// external derivation check
        /// `AccountId::for_private_pda(authority_program_id, seed, npk, vpk, identifier) ==
        /// pre_state.account_id` rather than requiring a caller `pda_seeds` to establish
        /// the binding. The `pre_state` must have `is_authorized == false`.
        seed: Option<(PdaSeed, ProgramId)>,
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
            Self::PrivatePdaInit { .. } | Self::PrivatePdaUpdate { .. }
        )
    }

    #[must_use]
    pub fn npk_vpk_if_private_pda(
        &self,
    ) -> Option<(NullifierPublicKey, ViewingPublicKey, Identifier)> {
        match self {
            Self::PrivatePdaInit {
                npk,
                vpk,
                identifier,
                ..
            } => Some((*npk, vpk.clone(), *identifier)),
            Self::PrivatePdaUpdate {
                nsk,
                vpk,
                identifier,
                ..
            } => Some((NullifierPublicKey::from(nsk), vpk.clone(), *identifier)),
            Self::Public
            | Self::PrivateAuthorizedInit { .. }
            | Self::PrivateAuthorizedUpdate { .. }
            | Self::PrivateForeignInit { .. } => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq, Default))]
pub struct PrivacyPreservingCircuitOutput {
    pub public_pre_states: Vec<AccountWithMetadata>,
    /// Raw, per-call, unaggregated diffs for public accounts — `(account_id,
    /// executing_program_id, diff)` triples, one per call that touched a public account, in
    /// processing order. Deliberately not collapsed into one diff per account
    /// (`AccountDiffOutput`/`AccountDiff` have no "combine two diffs" operation, especially for
    /// `diff_data`, which only composes by being applied in sequence). The sequencer replays
    /// these one at a time against its own live state — never trusting anything the circuit
    /// internally materialized for a public account, which is why the account's *value* (as
    /// opposed to its diffs) never appears in this output. `executing_program_id` is carried
    /// alongside each diff because the sequencer's replay-time authorization re-check (and PDA
    /// claim resolution) needs to know which program produced it — the same role
    /// `chained_call.program_id` plays in the public-transaction path's live materialize loop.
    pub public_diffs: Vec<(AccountId, ProgramId, AccountDiffOutput)>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    /// Committed so the sequencer can verify every account this circuit treated as authorized
    /// really did sign the transaction — see `PrivacyPreservingCircuitInput::signer_account_ids`.
    pub signer_account_ids: Vec<AccountId>,
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
            public_diffs: vec![(
                AccountId::new([1; 32]),
                [1, 2, 3, 4, 5, 6, 7, 8],
                AccountDiffOutput::new(AccountDiff {
                    id: AccountId::new([1; 32]),
                    diff_balance: BalanceDiff::Add(100),
                    diff_data: Some(b"post state data".to_vec()),
                }),
            )],
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
            signer_account_ids: vec![AccountId::new([0; 32])],
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
