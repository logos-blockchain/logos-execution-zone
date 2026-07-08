use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Commitment, CommitmentSetDigest, Nullifier, PrivacyPreservingCircuitOutput, PrivateAction,
    account::{Account, Nonce},
    program::{BlockValidityWindow, TimestampValidityWindow},
};
pub use lee_core::{EncryptedAccountData, ViewTag};
use sha2::{Digest as _, Sha256};

use crate::AccountId;

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PublicActionWithID {
    pub account_id: AccountId,
    pub post_state: Account,
}

#[derive(Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub public_actions: Vec<PublicActionWithID>,
    pub nonces: Vec<Nonce>,
    pub private_actions: Vec<PrivateAction>,
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
        let private_actions: Vec<_> = self
            .private_actions
            .iter()
            .map(|a| {
                (
                    &a.nullifier,
                    HexDigest(&a.root),
                    &a.commitment,
                    &a.encrypted_post_state,
                )
            })
            .collect();
        f.debug_struct("Message")
            .field("public_actions", &self.public_actions)
            .field("nonces", &self.nonces)
            .field("private_actions", &private_actions)
            .field("block_validity_window", &self.block_validity_window)
            .field("timestamp_validity_window", &self.timestamp_validity_window)
            .finish()
    }
}

impl Message {
    #[must_use]
    pub fn from_circuit_output(nonces: Vec<Nonce>, output: PrivacyPreservingCircuitOutput) -> Self {
        let public_actions = output
            .public_actions
            .into_iter()
            .map(|action| PublicActionWithID {
                account_id: action.pre.account_id,
                post_state: action.post,
            })
            .collect();
        Self {
            public_actions,
            nonces,
            private_actions: output.private_actions,
            block_validity_window: output.block_validity_window,
            timestamp_validity_window: output.timestamp_validity_window,
        }
    }

    #[must_use]
    pub fn commitments(&self) -> Vec<Commitment> {
        self.private_actions
            .iter()
            .map(|action| action.commitment.clone())
            .collect()
    }

    #[must_use]
    pub fn nullifiers(&self) -> Vec<(Nullifier, CommitmentSetDigest)> {
        self.private_actions
            .iter()
            .map(|action| (action.nullifier, action.root))
            .collect()
    }

    #[must_use]
    pub fn public_account_ids(&self) -> Vec<AccountId> {
        self.public_actions
            .iter()
            .map(|action| action.account_id)
            .collect()
    }

    #[must_use]
    pub fn public_post_states(&self) -> Vec<Account> {
        self.public_actions
            .iter()
            .map(|action| action.post_state.clone())
            .collect()
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
    use lee_core::{
        Commitment, EncryptionScheme, EphemeralPublicKey, EphemeralSecretKey, Nullifier,
        NullifierPublicKey, PrivateAccountKind, PrivateAction, SharedSecretKey,
        account::{Account, AccountId, Nonce},
        encryption::{Ciphertext, ViewingPublicKey},
        program::{BlockValidityWindow, TimestampValidityWindow},
    };
    use sha2::{Digest as _, Sha256};

    use super::{EncryptedAccountData, Message, PREFIX, PublicActionWithID};

    #[must_use]
    pub fn message_for_tests() -> Message {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let npk1 = NullifierPublicKey::from(&nsk1);
        let npk2 = NullifierPublicKey::from(&nsk2);
        let vpk = ViewingPublicKey::from_seed(&[7; 32], &[8; 32]);

        let nonces = vec![1_u128.into(), 2_u128.into(), 3_u128.into()];

        let account_id2 = lee_core::account::AccountId::for_regular_private_account(&npk2, &vpk, 0);
        let commitment = Commitment::new(&account_id2, &account2);

        let account_id1 = lee_core::account::AccountId::for_regular_private_account(&npk1, &vpk, 0);
        let old_commitment = Commitment::new(&account_id1, &account1);
        let nullifier = Nullifier::for_account_update(&old_commitment, &nsk1);

        Message {
            public_actions: vec![PublicActionWithID {
                account_id: AccountId::new([1; 32]),
                post_state: Account::default(),
            }],
            nonces,
            private_actions: vec![PrivateAction {
                nullifier,
                root: [0; 32],
                commitment,
                encrypted_post_state: EncryptedAccountData {
                    ciphertext: Ciphertext::from_inner(vec![]),
                    epk: EphemeralPublicKey(vec![]),
                    view_tag: 0,
                },
            }],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        }
    }

    #[test]
    fn hash_privacy_pinned() {
        let msg = Message {
            public_actions: vec![],
            nonces: vec![Nonce(5)],
            private_actions: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };

        // empty vec fields: u32 len=0
        let public_actions_bytes: &[u8] = &[0, 0, 0, 0];
        let nonces_bytes: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let private_actions_bytes: &[u8] = &[0, 0, 0, 0];
        // validity windows: unbounded = {from: None (0_u8), to: None (0_u8)}
        let unbounded_window_bytes: &[u8] = &[0, 0];

        let expected_borsh_vec: Vec<u8> = [
            public_actions_bytes,
            nonces_bytes,
            private_actions_bytes,
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
