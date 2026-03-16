use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    Commitment, CommitmentSetDigest, Nullifier, NullifierPublicKey, PrivacyPreservingCircuitOutput,
    account::{Account, Nonce},
    encryption::{Ciphertext, EphemeralPublicKey, ViewingPublicKey},
};
use sha2::{Digest, Sha256};

use crate::{AccountId, error::NssaError};

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
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        epk: EphemeralPublicKey,
    ) -> Self {
        let view_tag = Self::compute_view_tag(npk, vpk);
        Self {
            ciphertext,
            epk,
            view_tag,
        }
    }

    /// Computes the tag as the first byte of SHA256("/NSSA/v0.2/ViewTag/" || Npk || vpk)
    pub fn compute_view_tag(npk: NullifierPublicKey, vpk: ViewingPublicKey) -> ViewTag {
        let mut hasher = Sha256::new();
        hasher.update(b"/NSSA/v0.2/ViewTag/");
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
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexDigest<'a>(&'a [u8; 32]);
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
                EncryptedAccountData::new(ciphertext, npk, vpk, epk)
            })
            .collect();
        Ok(Self {
            public_account_ids,
            nonces,
            public_post_states: output.public_post_states,
            encrypted_private_post_states,
            new_commitments: output.new_commitments,
            new_nullifiers: output.new_nullifiers,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use nssa_core::{
        Commitment, EncryptionScheme, Nullifier, NullifierPublicKey, SharedSecretKey,
        account::Account,
        encryption::{EphemeralPublicKey, ViewingPublicKey},
    };
    use sha2::{Digest, Sha256};

    use crate::{
        AccountId,
        privacy_preserving_transaction::message::{EncryptedAccountData, Message},
    };

    pub fn message_for_tests() -> Message {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let npk1 = NullifierPublicKey::from(&nsk1);
        let npk2 = NullifierPublicKey::from(&nsk2);

        let public_account_ids = vec![AccountId::new([1; 32])];

        let nonces = vec![1, 2, 3];

        let public_post_states = vec![Account::default()];

        let encrypted_private_post_states = Vec::new();

        let new_commitments = vec![Commitment::new(&npk2, &account2)];

        let old_commitment = Commitment::new(&npk1, &account1);
        let new_nullifiers = vec![(
            Nullifier::for_account_update(&old_commitment, &nsk1),
            [0; 32],
        )];

        Message {
            public_account_ids: public_account_ids.clone(),
            nonces: nonces.clone(),
            public_post_states: public_post_states.clone(),
            encrypted_private_post_states: encrypted_private_post_states.clone(),
            new_commitments: new_commitments.clone(),
            new_nullifiers: new_nullifiers.clone(),
        }
    }

    #[test]
    fn test_encrypted_account_data_constructor() {
        let npk = NullifierPublicKey::from(&[1; 32]);
        let vpk = ViewingPublicKey::from_scalar([2; 32]);
        let account = Account::default();
        let commitment = Commitment::new(&npk, &account);
        let esk = [3; 32];
        let shared_secret = SharedSecretKey::new(&esk, &vpk);
        let epk = EphemeralPublicKey::from_scalar(esk);
        let ciphertext = EncryptionScheme::encrypt(&account, &shared_secret, &commitment, 2);
        let encrypted_account_data =
            EncryptedAccountData::new(ciphertext.clone(), npk.clone(), vpk.clone(), epk.clone());

        let expected_view_tag = {
            let mut hasher = Sha256::new();
            hasher.update(b"/NSSA/v0.2/ViewTag/");
            hasher.update(npk.to_byte_array());
            hasher.update(vpk.to_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            digest[0]
        };

        assert_eq!(encrypted_account_data.ciphertext, ciphertext);
        assert_eq!(encrypted_account_data.epk, epk);
        assert_eq!(
            encrypted_account_data.view_tag,
            EncryptedAccountData::compute_view_tag(npk, vpk)
        );
        assert_eq!(encrypted_account_data.view_tag, expected_view_tag);
    }
}
