use borsh::{BorshDeserialize, BorshSerialize};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit as _, StreamCipher as _},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "host")]
pub use shared_key_derivation::{EphemeralPublicKey, EphemeralSecretKey, ViewingPublicKey};

use crate::{
    Commitment, Identifier,
    account::Account,
    program::{PdaSeed, ProgramId},
};
#[cfg(feature = "host")]
pub mod shared_key_derivation;

pub type Scalar = [u8; 32];

/// Discriminates the type of private account a ciphertext belongs to, carrying the data needed
/// to reconstruct the account's [`AccountId`] on the receiver side.
///
/// [`AccountId`]: crate::account::AccountId
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateAccountKind {
    Regular(Identifier),
    Pda {
        program_id: ProgramId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}

impl PrivateAccountKind {
    ///   Regular(ident):                  0x00 || ident (16 LE) || [0u8; 64]
    ///   Pda { program_id, seed, ident }: 0x01 || program_id (32 LE) || seed (32) || ident (16 LE)
    pub const HEADER_LEN: usize = 81;

    #[must_use]
    pub fn identifier(&self) -> Identifier {
        match self {
            Self::Regular(identifier) => *identifier,
            Self::Pda { identifier, .. } => *identifier,
        }
    }

    #[must_use]
    pub fn to_header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut bytes = [0u8; Self::HEADER_LEN];
        match self {
            Self::Regular(identifier) => {
                bytes[0] = 0x00;
                bytes[1..17].copy_from_slice(&identifier.to_le_bytes());
                // bytes[17..81] are zero padding
            }
            Self::Pda { program_id, seed, identifier } => {
                bytes[0] = 0x01;
                for (i, &word) in program_id.iter().enumerate() {
                    bytes[1 + i * 4..1 + (i + 1) * 4].copy_from_slice(&word.to_le_bytes());
                }
                bytes[33..65].copy_from_slice(seed.as_bytes());
                bytes[65..81].copy_from_slice(&identifier.to_le_bytes());
            }
        }
        bytes
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub fn from_header_bytes(bytes: &[u8; Self::HEADER_LEN]) -> Option<Self> {
        match bytes[0] {
            0x00 => {
                let identifier = Identifier::from_le_bytes(bytes[1..17].try_into().unwrap());
                Some(Self::Regular(identifier))
            }
            0x01 => {
                let mut program_id = [0u32; 8];
                for (i, word) in program_id.iter_mut().enumerate() {
                    *word = u32::from_le_bytes(
                        bytes[1 + i * 4..1 + (i + 1) * 4].try_into().unwrap(),
                    );
                }
                let seed = PdaSeed::new(bytes[33..65].try_into().unwrap());
                let identifier = Identifier::from_le_bytes(bytes[65..81].try_into().unwrap());
                Some(Self::Pda { program_id, seed, identifier })
            }
            _ => None,
        }
    }
}

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
    use crate::account::{Account, AccountId};

    #[test]
    fn encrypt_same_length_for_account_and_pda() {
        let account = Account::default();
        let secret = SharedSecretKey([0u8; 32]);
        let commitment = crate::Commitment::new(&AccountId::new([0u8; 32]), &Account::default());

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
                program_id: [1u32; 8],
                seed: PdaSeed::new([2u8; 32]),
                identifier: 42,
            },
            &secret,
            &commitment,
            0,
        );

        assert_eq!(account_ct.0.len(), pda_ct.0.len());
    }
}
