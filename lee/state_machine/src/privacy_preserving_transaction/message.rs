use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Commitment, CommitmentSetDigest, Nullifier, PrivacyPreservingCircuitOutput,
    account::{AccountWithMetadata, Nonce},
    program::{AccountDiffOutput, BlockValidityWindow, ProgramId, TimestampValidityWindow},
};
pub use lee_core::{EncryptedAccountData, ViewTag};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::LeeError};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";

#[derive(Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub public_account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    /// What the circuit witnessed as each public account's pre-state — deliberately *not*
    /// reconciled against live sequencer state. Used only to verify the proof is internally
    /// consistent (see `check_privacy_preserving_circuit_proof_is_valid`); materialization uses
    /// live state instead, via `public_diffs` below, which is what actually avoids tying this
    /// transaction's validity to a specific public-account snapshot.
    pub public_pre_states: Vec<AccountWithMetadata>,
    /// Raw, per-call, unaggregated diffs for public accounts. See
    /// `PrivacyPreservingCircuitOutput::public_diffs`.
    pub public_diffs: Vec<(AccountId, ProgramId, AccountDiffOutput)>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    /// The accounts the circuit claims are signers — cross-checked by the sequencer against real
    /// signatures. See `PrivacyPreservingCircuitOutput::signer_account_ids`.
    pub signer_account_ids: Vec<AccountId>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexDigest<'arr>(&'arr [u8; 32]);
        impl std::fmt::Debug for HexDigest<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }
        let nullifiers: Vec<_> = self
            .new_nullifiers
            .iter()
            .map(|(n, d)| (n, HexDigest(d)))
            .collect();
        f.debug_struct("Message")
            .field("public_account_ids", &self.public_account_ids)
            .field("nonces", &self.nonces)
            .field("public_pre_states", &self.public_pre_states)
            .field("public_diffs", &self.public_diffs)
            .field(
                "encrypted_private_post_states",
                &self.encrypted_private_post_states,
            )
            .field("new_commitments", &self.new_commitments)
            .field("new_nullifiers", &nullifiers)
            .field("block_validity_window", &self.block_validity_window)
            .field("timestamp_validity_window", &self.timestamp_validity_window)
            .field("signer_account_ids", &self.signer_account_ids)
            .finish()
    }
}

impl Message {
    pub fn try_from_circuit_output(
        public_account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        output: PrivacyPreservingCircuitOutput,
    ) -> Result<Self, LeeError> {
        Ok(Self {
            public_account_ids,
            nonces,
            public_pre_states: output.public_pre_states,
            public_diffs: output.public_diffs,
            encrypted_private_post_states: output.encrypted_private_post_states,
            new_commitments: output.new_commitments,
            new_nullifiers: output.new_nullifiers,
            block_validity_window: output.block_validity_window,
            signer_account_ids: output.signer_account_ids,
            timestamp_validity_window: output.timestamp_validity_window,
        })
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let msg = self.to_bytes();
        let mut bytes = Vec::with_capacity(
            PREFIX
                .len()
                .checked_add(msg.len())
                .expect("length overflow"),
        );
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&msg);

        Sha256::digest(bytes).into()
    }

    /// Ensure that the commitments, nullifiers, and ciphertexts agree.
    pub fn validate_note_lengths(&self) -> Result<usize, LeeError> {
        let count = self.new_nullifiers.len();
        if self.new_commitments.len() != count || self.encrypted_private_post_states.len() != count
        {
            return Err(LeeError::InvalidInput(format!(
                "Note vectors disagree in length with {count} nullifiers, {} commitments, and {} ciphertexts",
                self.new_commitments.len(),
                self.encrypted_private_post_states.len(),
            )));
        }
        Ok(count)
    }
}

#[cfg(test)]
pub mod tests {
    use lee_core::{
        Commitment, EncryptionScheme, EphemeralSecretKey, Nullifier, NullifierPublicKey,
        PrivateAccountKind, SharedSecretKey,
        account::{Account, AccountId, Nonce},
        encryption::ViewingPublicKey,
        program::{BlockValidityWindow, TimestampValidityWindow},
    };
    use sha2::{Digest as _, Sha256};

    use super::{EncryptedAccountData, Message, PREFIX};

    #[must_use]
    pub fn message_for_tests() -> Message {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let npk1 = NullifierPublicKey::from(&nsk1);
        let npk2 = NullifierPublicKey::from(&nsk2);
        let vpk = ViewingPublicKey::from_seed(&[7; 32], &[8; 32]);

        let public_account_ids = vec![AccountId::new([1; 32])];

        let nonces = vec![1_u128.into(), 2_u128.into(), 3_u128.into()];

        let public_pre_states = Vec::new();
        let public_diffs = Vec::new();

        let encrypted_private_post_states = Vec::new();

        let account_id2 = lee_core::account::AccountId::for_regular_private_account(&npk2, &vpk, 0);
        let new_commitments = vec![Commitment::new(&account_id2, &account2)];

        let account_id1 = lee_core::account::AccountId::for_regular_private_account(&npk1, &vpk, 0);
        let old_commitment = Commitment::new(&account_id1, &account1);
        let new_nullifiers = vec![(
            Nullifier::for_account_update(&old_commitment, &nsk1),
            [0; 32],
        )];

        Message {
            public_account_ids,
            nonces,
            public_pre_states,
            public_diffs,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            signer_account_ids: Vec::new(),
        }
    }

    #[test]
    fn validate_note_lengths_accepts_matching_and_rejects_mismatched() {
        assert_eq!(Message::default().validate_note_lengths().unwrap(), 0);

        let mismatched = Message {
            new_commitments: vec![Commitment::new(
                &AccountId::new([0; 32]),
                &Account::default(),
            )],
            ..Default::default()
        };
        assert!(mismatched.validate_note_lengths().is_err());
    }

    #[test]
    fn hash_privacy_pinned() {
        let msg = Message {
            public_account_ids: vec![AccountId::new([42_u8; 32])],
            nonces: vec![Nonce(5)],
            public_pre_states: vec![],
            public_diffs: vec![],
            encrypted_private_post_states: vec![],
            new_commitments: vec![],
            new_nullifiers: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            signer_account_ids: vec![],
        };

        let public_account_ids_bytes: &[u8] = &[42_u8; 32];
        let nonces_bytes: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // all remaining vec fields are empty: u32 len=0
        let empty_vec_bytes: &[u8] = &[0_u8; 4];
        // validity windows: unbounded = {from: None (0_u8), to: None (0_u8)}
        let unbounded_window_bytes: &[u8] = &[0_u8; 2];

        let expected_borsh_vec: Vec<u8> = [
            &[1_u8, 0, 0, 0], // public_account_ids
            public_account_ids_bytes,
            nonces_bytes,
            empty_vec_bytes,        // public_pre_states
            empty_vec_bytes,        // public_diffs
            empty_vec_bytes,        // encrypted_private_post_states
            empty_vec_bytes,        // new_commitments
            empty_vec_bytes,        // new_nullifiers
            unbounded_window_bytes, // block_validity_window
            unbounded_window_bytes, // timestamp_validity_window
            empty_vec_bytes,        // signer_account_ids
        ]
        .concat();
        let expected_borsh: &[u8] = &expected_borsh_vec;

        assert_eq!(
            borsh::to_vec(&msg).unwrap(),
            expected_borsh,
            "`privacy_preserving_transaction::hash()`: expected borsh order has changed"
        );

        let mut preimage = Vec::with_capacity(PREFIX.len() + expected_borsh.len());
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(expected_borsh);
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            msg.hash(),
            expected_hash,
            "`privacy_preserving_transaction::hash()`: serialization has changed"
        );
    }

    #[test]
    fn encrypted_account_data_constructor() {
        let npk = NullifierPublicKey::from(&[1; 32]);
        let vpk = ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]);
        let account = Account::default();
        let account_id = lee_core::account::AccountId::for_regular_private_account(&npk, &vpk, 0);
        let nullifier = Nullifier::for_account_initialization(&account_id);
        let (shared_secret, epk) =
            SharedSecretKey::encapsulate_deterministic(&vpk, &EphemeralSecretKey([0_u8; 32]));
        let ciphertext = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Regular(0),
            &shared_secret,
            &nullifier,
        );
        let encrypted_account_data =
            EncryptedAccountData::new(ciphertext.clone(), &npk, &vpk, epk.clone());

        let expected_view_tag = {
            let mut hasher = Sha256::new();
            hasher.update(b"/LEE/v0.3/ViewTag/");
            hasher.update(npk.to_byte_array());
            hasher.update(vpk.to_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            digest[0]
        };

        assert_eq!(encrypted_account_data.ciphertext, ciphertext);
        assert_eq!(encrypted_account_data.epk, epk);
        assert_eq!(
            encrypted_account_data.view_tag,
            EncryptedAccountData::compute_view_tag(&npk, &vpk)
        );
        assert_eq!(encrypted_account_data.view_tag, expected_view_tag);
    }
}
