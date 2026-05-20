use borsh::{BorshDeserialize, BorshSerialize};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit as _, StreamCipher as _},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "host")]
pub use shared_key_derivation::{EphemeralPublicKey, ViewingPublicKey};

use crate::{Commitment, account::Account, program::PrivateAccountKind};
#[cfg(feature = "host")]
pub mod shared_key_derivation;

pub type Scalar = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct SharedSecretKey(pub [u8; 32]);

pub struct EncryptionScheme;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Clone, PartialEq, Eq))]
pub struct Ciphertext(pub(crate) Vec<u8>);

#[cfg(any(feature = "host", test))]
impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        let hex: String = self.0.iter().fold(String::new(), |mut acc, b| {
            write!(acc, "{b:02x}").expect("writing to string should not fail");
            acc
        });
        write!(f, "Ciphertext({hex})")
    }
}

impl EncryptionScheme {
    #[must_use]
    pub fn encrypt(
        account: &Account,
        kind: &PrivateAccountKind,
        shared_secret: &SharedSecretKey,
        commitment: &Commitment,
        output_index: u32,
    ) -> Ciphertext {
        // Plaintext: PrivateAccountKind::HEADER_LEN bytes header || account bytes.
        // Both variants produce the same header length — see PrivateAccountKind::to_header_bytes.
        let mut buffer = kind.to_header_bytes().to_vec();
        buffer.extend_from_slice(&account.to_bytes());
        Self::symmetric_transform(&mut buffer, shared_secret, commitment, output_index);
        Ciphertext(buffer)
    }

    fn symmetric_transform(
        buffer: &mut [u8],
        shared_secret: &SharedSecretKey,
        commitment: &Commitment,
        output_index: u32,
    ) {
        let key = Self::kdf(shared_secret, commitment, output_index);
        let mut cipher = ChaCha20::new(&key.into(), &[0; 12].into());
        cipher.apply_keystream(buffer);
    }

    fn kdf(
        shared_secret: &SharedSecretKey,
        commitment: &Commitment,
        output_index: u32,
    ) -> [u8; 32] {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(b"LEE/v0.2/KDF-SHA256/");
        bytes.extend_from_slice(&shared_secret.0);
        bytes.extend_from_slice(&commitment.to_byte_array());
        bytes.extend_from_slice(&output_index.to_le_bytes());

        Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap()
    }

    #[cfg(feature = "host")]
    #[expect(
        clippy::print_stdout,
        reason = "This is the current way to debug things. TODO: fix later"
    )]
    #[must_use]
    pub fn decrypt(
        ciphertext: &Ciphertext,
        shared_secret: &SharedSecretKey,
        commitment: &Commitment,
        output_index: u32,
    ) -> Option<(PrivateAccountKind, Account)> {
        use std::io::Cursor;
        let mut buffer = ciphertext.0.clone();
        Self::symmetric_transform(&mut buffer, shared_secret, commitment, output_index);

        if buffer.len() < PrivateAccountKind::HEADER_LEN {
            return None;
        }
        let header: &[u8; PrivateAccountKind::HEADER_LEN] =
            buffer[..PrivateAccountKind::HEADER_LEN].try_into().unwrap();
        let kind = PrivateAccountKind::from_header_bytes(header)?;

        let mut cursor = Cursor::new(&buffer[PrivateAccountKind::HEADER_LEN..]);
        Account::from_cursor(&mut cursor)
            .inspect_err(|err| {
                println!(
                    "Failed to decode {ciphertext:?} \n
                      with secret {:?} ,\n
                      commitment {commitment:?} ,\n
                      and output_index {output_index} ,\n
                      with error {err:?}",
                    shared_secret.0
                );
            })
            .ok()
            .map(|account| (kind, account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::{Account, AccountId},
        program::PdaSeed,
    };

    #[test]
    fn encrypt_same_length_for_account_and_pda() {
        let account = Account::default();
        let secret = SharedSecretKey([0_u8; 32]);
        let commitment = crate::Commitment::new(&AccountId::new([0_u8; 32]), &Account::default());

        let account_ct = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Regular(42),
            &secret,
            &commitment,
            0,
        );
        let pda_ct = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Pda {
                program_id: [1_u32; 8],
                seed: PdaSeed::new([2_u8; 32]),
                identifier: 42,
            },
            &secret,
            &commitment,
            0,
        );

        assert_eq!(account_ct.0.len(), pda_ct.0.len());
    }

    /// Verifies the full account-note pipeline: ML-KEM-768 encapsulation/decapsulation
    /// feeds the correct shared secret into the SHA-256 KDF and ChaCha20 round-trip.
    #[cfg(feature = "host")]
    #[test]
    fn kem_to_chacha20_round_trip() {
        let d = [1_u8; 32];
        let r = [2_u8; 32];
        let vpk = shared_key_derivation::ViewingPublicKey::from_seed(&d, &r);

        let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
        let receiver_ss = SharedSecretKey::decapsulate(&epk, &d, &r);

        let account = Account {
            program_owner: [12_u32; 8],
            balance: 999,
            ..Account::default()
        };
        let kind = PrivateAccountKind::Regular(0);
        let commitment = crate::Commitment::new(&AccountId::new([7_u8; 32]), &account);

        let ct = EncryptionScheme::encrypt(&account, &kind, &sender_ss, &commitment, 0);
        let (decoded_kind, decoded_account) =
            EncryptionScheme::decrypt(&ct, &receiver_ss, &commitment, 0)
                .expect("decryption must succeed with correct shared secret");

        assert_eq!(decoded_account, account);
        assert_eq!(decoded_kind, kind);

        // Wrong shared secret must not decrypt correctly.
        let wrong_ss = SharedSecretKey([0_u8; 32]);
        let bad = EncryptionScheme::decrypt(&ct, &wrong_ss, &commitment, 0);
        assert!(
            bad.is_none() || bad.is_some_and(|(_, a)| a.balance != 999),
            "wrong shared secret must not produce the correct plaintext"
        );
    }
}
