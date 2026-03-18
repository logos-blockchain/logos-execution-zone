use borsh::{BorshDeserialize, BorshSerialize};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit as _, StreamCipher as _},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "host")]
pub use shared_key_derivation::{EphemeralPublicKey, EphemeralSecretKey, ViewingPublicKey};

use crate::{Commitment, account::Account};
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
        shared_secret: &SharedSecretKey,
        commitment: &Commitment,
        output_index: u32,
    ) -> Ciphertext {
        let mut buffer = account.to_bytes();
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

        bytes.extend_from_slice(b"NSSA/v0.2/KDF-SHA256/");
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
    ) -> Option<Account> {
        use std::io::Cursor;
        let mut buffer = ciphertext.0.clone();
        Self::symmetric_transform(&mut buffer, shared_secret, commitment, output_index);

        let mut cursor = Cursor::new(buffer.as_slice());
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
    }
}
