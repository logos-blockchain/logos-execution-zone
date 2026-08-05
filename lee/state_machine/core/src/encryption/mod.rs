use borsh::{BorshDeserialize, BorshSerialize};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit as _, StreamCipher as _},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
pub use shared_key_derivation::{MlKem768EncapsulationKey, ViewingPublicKey};

use crate::{Nullifier, account::Account, program::PrivateAccountKind};
pub mod shared_key_derivation;

/// Length in bytes of an ML-KEM-768 ciphertext (the `EphemeralPublicKey` payload).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

pub type Scalar = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct EphemeralSecretKey(pub [u8; 32]);

impl EphemeralSecretKey {
    /// Derives an ephemeral secret key from OS randomness and account-specific values.
    ///
    /// For updates, `nonce` carries `nsk`-derived entropy, making `esk` strong even
    /// with a compromised RNG. For inits, `nonce` is deterministic, so `random_seed`
    /// is the sole entropy source.
    #[must_use]
    pub fn new(
        account_id: &crate::account::AccountId,
        random_seed: &[u8; 32],
        nonce: &crate::account::Nonce,
    ) -> Self {
        const PREFIX: &[u8; 14] = b"/LEE/v0.3/esk/";
        let mut input = [0_u8; 14 + 32 + 32 + 16];
        input[0..14].copy_from_slice(PREFIX);
        input[14..46].copy_from_slice(account_id.value());
        input[46..78].copy_from_slice(random_seed);
        input[78..94].copy_from_slice(&nonce.0.to_le_bytes());
        Self(Impl::hash_bytes(&input).as_bytes().try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct SharedSecretKey(pub [u8; 32]);

/// The ML-KEM-768 ciphertext produced during encapsulation; transmitted on-wire in place of the
/// former ECDH ephemeral public key. Always `ML_KEM_768_CIPHERTEXT_LEN` (1088) bytes.
#[derive(
    Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize,
)]
pub struct EphemeralPublicKey(pub Vec<u8>);

pub struct EncryptionScheme;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Clone, Default, PartialEq, Eq))]
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

pub type ViewTag = u8;

/// Encrypted private-account note for one output.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, Default, PartialEq, Eq)
)]
pub struct EncryptedAccountData {
    pub ciphertext: Ciphertext,
    pub epk: EphemeralPublicKey,
    pub view_tag: ViewTag,
}

impl EncryptedAccountData {
    #[must_use]
    pub fn compute_view_tag(npk: &crate::NullifierPublicKey, vpk: &ViewingPublicKey) -> ViewTag {
        const PREFIX: &[u8; 18] = b"/LEE/v0.3/ViewTag/";
        let mut bytes = [0_u8; 18 + 32 + ViewingPublicKey::LEN];
        bytes[0..18].copy_from_slice(PREFIX);
        bytes[18..50].copy_from_slice(&npk.to_byte_array());
        bytes[50..].copy_from_slice(vpk.to_bytes());
        Impl::hash_bytes(&bytes).as_bytes()[0]
    }
}

#[cfg(feature = "host")]
impl EncryptedAccountData {
    #[must_use]
    pub fn new(
        ciphertext: Ciphertext,
        npk: &crate::NullifierPublicKey,
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
}

impl EncryptionScheme {
    #[must_use]
    pub fn encrypt(
        account: &Account,
        kind: &PrivateAccountKind,
        shared_secret: &SharedSecretKey,
        nullifier: &Nullifier,
    ) -> Ciphertext {
        // Plaintext: PrivateAccountKind::HEADER_LEN bytes header || account bytes.
        // Both variants produce the same header length — see PrivateAccountKind::to_header_bytes.
        let mut buffer = kind.to_header_bytes().to_vec();
        buffer.extend_from_slice(&account.to_bytes());
        Self::symmetric_transform(&mut buffer, shared_secret, nullifier);
        Ciphertext(buffer)
    }

    fn symmetric_transform(
        buffer: &mut [u8],
        shared_secret: &SharedSecretKey,
        nullifier: &Nullifier,
    ) {
        let key = Self::kdf(shared_secret, nullifier);
        let mut cipher = ChaCha20::new(&key.into(), &[0; 12].into());
        cipher.apply_keystream(buffer);
    }

    fn kdf(shared_secret: &SharedSecretKey, nullifier: &Nullifier) -> [u8; 32] {
        const PREFIX: &[u8; 20] = b"LEE/v0.3/KDF-SHA256/";
        let mut bytes = [0_u8; 20 + 32 + 32];
        bytes[0..20].copy_from_slice(PREFIX);
        bytes[20..52].copy_from_slice(&shared_secret.0);
        bytes[52..84].copy_from_slice(&nullifier.to_byte_array());

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
        nullifier: &Nullifier,
    ) -> Option<(PrivateAccountKind, Account)> {
        use std::io::Cursor;
        let mut buffer = ciphertext.0.clone();
        Self::symmetric_transform(&mut buffer, shared_secret, nullifier);

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
                      nullifier {nullifier:?} ,\n
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
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([0_u8; 32]));

        let account_ct = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Regular(42),
            &secret,
            &nullifier,
        );
        let pda_ct = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Pda {
                program_id: [1_u32; 8],
                seed: PdaSeed::new([2_u8; 32]),
                identifier: 42,
            },
            &secret,
            &nullifier,
        );

        assert_eq!(account_ct.0.len(), pda_ct.0.len());
    }

    /// Verifies the full account-note pipeline: ML-KEM-768 encapsulation/decapsulation
    /// feeds the correct shared secret into the SHA-256 KDF and `ChaCha20` round-trip.
    #[cfg(feature = "host")]
    #[test]
    fn kem_to_chacha20_round_trip() {
        let d = [1_u8; 32];
        let z = [2_u8; 32];
        let vpk = shared_key_derivation::ViewingPublicKey::from_seed(&d, &z);

        let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
        let receiver_ss = SharedSecretKey::decapsulate(&epk, &d, &z).unwrap();

        let account = Account {
            program_owner: [12_u32; 8],
            balance: 999,
            ..Account::default()
        };
        let kind = PrivateAccountKind::Regular(0);
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([7_u8; 32]));

        let ct = EncryptionScheme::encrypt(&account, &kind, &sender_ss, &nullifier);
        let (decoded_kind, decoded_account) =
            EncryptionScheme::decrypt(&ct, &receiver_ss, &nullifier)
                .expect("decryption must succeed with correct shared secret");

        assert_eq!(decoded_account, account);
        assert_eq!(decoded_kind, kind);

        // Wrong shared secret must not decrypt correctly.
        let wrong_ss = SharedSecretKey([0_u8; 32]);
        let bad_via_ss = EncryptionScheme::decrypt(&ct, &wrong_ss, &nullifier);
        assert!(
            bad_via_ss.is_none() || bad_via_ss.is_some_and(|(_, a)| a.balance != 999),
            "wrong shared secret must not produce the correct plaintext"
        );

        // Wrong nullifier must not decrypt correctly.
        let wrong_nullifier = Nullifier::for_account_initialization(&AccountId::new([9; 32]));
        let bad_via_nlf = EncryptionScheme::decrypt(&ct, &receiver_ss, &wrong_nullifier);
        assert!(
            bad_via_nlf.is_none() || bad_via_nlf.is_some_and(|(_, a)| a.balance != 999),
            "wrong nullifier must not produce the correct plaintext"
        );
    }

    #[test]
    fn esk_is_deterministic() {
        let account_id = AccountId::new([1_u8; 32]);
        let random_seed = [2_u8; 32];
        let nonce = crate::account::Nonce(42);
        let esk1 = EphemeralSecretKey::new(&account_id, &random_seed, &nonce);
        let esk2 = EphemeralSecretKey::new(&account_id, &random_seed, &nonce);
        assert_eq!(esk1.0, esk2.0);
    }

    #[test]
    fn esk_differs_for_different_account_id() {
        let random_seed = [2_u8; 32];
        let nonce = crate::account::Nonce(42);
        let esk_a = EphemeralSecretKey::new(&AccountId::new([0_u8; 32]), &random_seed, &nonce);
        let esk_b = EphemeralSecretKey::new(&AccountId::new([1_u8; 32]), &random_seed, &nonce);
        assert_ne!(esk_a.0, esk_b.0);
    }

    #[test]
    fn esk_differs_for_different_random_seed() {
        let account_id = AccountId::new([1_u8; 32]);
        let nonce = crate::account::Nonce(42);
        let esk_a = EphemeralSecretKey::new(&account_id, &[0_u8; 32], &nonce);
        let esk_b = EphemeralSecretKey::new(&account_id, &[1_u8; 32], &nonce);
        assert_ne!(esk_a.0, esk_b.0);
    }

    #[test]
    fn esk_differs_for_different_nonce() {
        let account_id = AccountId::new([1_u8; 32]);
        let random_seed = [2_u8; 32];
        let esk_a = EphemeralSecretKey::new(&account_id, &random_seed, &crate::account::Nonce(0));
        let esk_b = EphemeralSecretKey::new(&account_id, &random_seed, &crate::account::Nonce(1));
        assert_ne!(esk_a.0, esk_b.0);
    }
}
