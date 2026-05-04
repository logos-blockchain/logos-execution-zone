use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    Commitment, CommitmentSetDigest, Nullifier, NullifierPublicKey, PrivacyPreservingCircuitOutput,
    account::{Account, Nonce},
    encryption::{Ciphertext, EphemeralPublicKey, ViewingPublicKey},
    program::{BlockValidityWindow, TimestampValidityWindow},
};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::NssaError};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";

pub type ViewTag = u8;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EncryptedAccountData {
    pub ciphertext: Ciphertext,
    pub epk: EphemeralPublicKey,
    pub view_tag: ViewTag,
}

impl EncryptedAccountData {
    fn new(
        ciphertext: Ciphertext,
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        epk: EphemeralPublicKey,
    ) -> Self {
        let view_tag = Self::compute_view_tag(npk, vpk);
        Self {
            ciphertext,
            epk,
            view_tag,
        }
    }

    /// Computes the tag as the first byte of SHA256("/LEE/v0.3/ViewTag/" || Npk || vpk).
    #[must_use]
    pub fn compute_view_tag(npk: &NullifierPublicKey, vpk: &ViewingPublicKey) -> ViewTag {
        let mut hasher = Sha256::new();
        hasher.update(b"/LEE/v0.3/ViewTag/");
        hasher.update(npk.to_byte_array());
        hasher.update(vpk.to_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        digest[0]
    }
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub public_account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub public_post_states: Vec<Account>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
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
            .field("public_post_states", &self.public_post_states)
            .field(
                "encrypted_private_post_states",
                &self.encrypted_private_post_states,
            )
            .field("new_commitments", &self.new_commitments)
            .field("new_nullifiers", &nullifiers)
            .field("block_validity_window", &self.block_validity_window)
            .field("timestamp_validity_window", &self.timestamp_validity_window)
            .finish()
    }
}

impl Message {
    pub fn try_from_circuit_output(
        public_account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        public_keys: Vec<(NullifierPublicKey, ViewingPublicKey, EphemeralPublicKey)>,
        output: PrivacyPreservingCircuitOutput,
    ) -> Result<Self, NssaError> {
        if public_keys.len() != output.ciphertexts.len() {
            return Err(NssaError::InvalidInput(
                "Ephemeral public keys and ciphertexts length mismatch".into(),
            ));
        }

        let encrypted_private_post_states = output
            .ciphertexts
            .into_iter()
            .zip(public_keys)
            .map(|(ciphertext, (npk, vpk, epk))| {
                EncryptedAccountData::new(ciphertext, &npk, &vpk, epk)
            })
            .collect();
        Ok(Self {
            public_account_ids,
            nonces,
            public_post_states: output.public_post_states,
            encrypted_private_post_states,
            new_commitments: output.new_commitments,
            new_nullifiers: output.new_nullifiers,
            block_validity_window: output.block_validity_window,
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
}

#[cfg(test)]
pub mod tests {
    use nssa_core::{
        Commitment, EncryptionScheme, Nullifier, NullifierPublicKey, PrivateAccountKind,
        SharedSecretKey,
        account::{Account, AccountId, Nonce},
        encryption::{EphemeralPublicKey, ViewingPublicKey},
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

        let public_account_ids = vec![AccountId::new([1; 32])];

        let nonces = vec![1_u128.into(), 2_u128.into(), 3_u128.into()];

        let public_post_states = vec![Account::default()];

        let encrypted_private_post_states = Vec::new();

        let account_id2 = nssa_core::account::AccountId::from((&npk2, 0));
        let new_commitments = vec![Commitment::new(&account_id2, &account2)];

        let account_id1 = nssa_core::account::AccountId::from((&npk1, 0));
        let old_commitment = Commitment::new(&account_id1, &account1);
        let new_nullifiers = vec![(
            Nullifier::for_account_update(&old_commitment, &nsk1),
            [0; 32],
        )];

        Message {
            public_account_ids,
            nonces,
            public_post_states,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        }
    }

    #[test]
    fn hash_privacy_pinned() {
        let msg = Message {
            public_account_ids: vec![AccountId::new([42_u8; 32])],
            nonces: vec![Nonce(5)],
            public_post_states: vec![],
            encrypted_private_post_states: vec![],
            new_commitments: vec![],
            new_nullifiers: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };

        let public_account_ids_bytes: &[u8] = &[42_u8; 32];
        let nonces_bytes: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // all remaining vec fields are empty: u32 len=0
        let empty_vec_bytes: &[u8] = &[0_u8; 4];
        // validity windows: unbounded = {from: None (0u8), to: None (0u8)}
        let unbounded_window_bytes: &[u8] = &[0_u8; 2];

        let expected_borsh_vec: Vec<u8> = [
            &[1_u8, 0, 0, 0], // public_account_ids
            public_account_ids_bytes,
            nonces_bytes,
            empty_vec_bytes,        // public_post_state
            empty_vec_bytes,        // encrypted_private_post_states
            empty_vec_bytes,        // new_commitments
            empty_vec_bytes,        // new_nullifiers
            unbounded_window_bytes, // block_validity_window
            unbounded_window_bytes, // timestamp_validity_window
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
        let vpk = ViewingPublicKey::from_scalar([2; 32]);
        let account = Account::default();
        let account_id = nssa_core::account::AccountId::from((&npk, 0));
        let commitment = Commitment::new(&account_id, &account);
        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &vpk);
        let epk = EphemeralPublicKey::from_scalar(esk);
        let ciphertext = EncryptionScheme::encrypt(&account, &PrivateAccountKind::Account(0), &shared_secret, &commitment, 2);
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
