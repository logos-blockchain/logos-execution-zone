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

/// Upper bound on a requested note pad.
///
/// Keeps a prover from inflating its own transaction into a whole block at the flat
/// private-transaction storage fee. Plaintexts longer than this are unaffected, the pad is only
/// a floor.
pub const MAX_CIPHERTEXT_PADDING: u32 = 8 * 1024;

const ACCOUNT_KEY_DOMAIN: &[u8; 20] = b"LEE/v0.3/KDF-SHA256/";
const MAX_KEY_DOMAIN_LEN: usize = 29;

pub type Scalar = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct EphemeralSecretKey(pub [u8; 32]);

impl EphemeralSecretKey {
    /// Derives an ephemeral secret key from OS randomness and account-specific values.
    ///
    /// `nonce` carries `nsk`-derived entropy for every transition, an initialization's included,
    /// making `esk` strong even with a compromised RNG.
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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, Clone, Default, PartialEq, Eq)
)]
pub struct EncryptedNote {
    pub ciphertext: Ciphertext,
    pub epk: EphemeralPublicKey,
}

impl EncryptionScheme {
    /// Encrypts a note: the `kind` header followed by the account bytes, under a keystream keyed
    /// by the shared secret and the nullifier.
    ///
    /// `pad_to_len` is a floor: shorter plaintexts are zero-extended to it before encryption,
    /// longer ones keep their own length. Decryption needs no counterpart, `Account` bytes are
    /// length-prefixed. Pass `None` off the note path, where the ciphertext is never published
    /// and its length carries nothing.
    ///
    /// # Panics
    ///
    /// If `pad_to_len` exceeds [`MAX_CIPHERTEXT_PADDING`].
    #[must_use]
    pub fn encrypt(
        account: &Account,
        kind: &PrivateAccountKind,
        shared_secret: &SharedSecretKey,
        nullifier: &Nullifier,
        pad_to_len: Option<u32>,
    ) -> Ciphertext {
        // Plaintext: PrivateAccountKind::HEADER_LEN bytes header || account bytes.
        // Both variants produce the same header length — see PrivateAccountKind::to_header_bytes.
        let mut buffer = kind.to_header_bytes().to_vec();
        buffer.extend_from_slice(&account.to_bytes());
        pad_to_floor(&mut buffer, pad_to_len);
        apply_keystream(
            &mut buffer,
            ACCOUNT_KEY_DOMAIN,
            shared_secret,
            &nullifier.to_byte_array(),
        );
        Ciphertext(buffer)
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub fn decrypt(
        ciphertext: &Ciphertext,
        shared_secret: &SharedSecretKey,
        nullifier: &Nullifier,
    ) -> Option<(PrivateAccountKind, Account)> {
        use std::io::Cursor;
        let mut buffer = ciphertext.0.clone();
        apply_keystream(
            &mut buffer,
            ACCOUNT_KEY_DOMAIN,
            shared_secret,
            &nullifier.to_byte_array(),
        );

        if buffer.len() < PrivateAccountKind::HEADER_LEN {
            return None;
        }
        let header: &[u8; PrivateAccountKind::HEADER_LEN] =
            buffer[..PrivateAccountKind::HEADER_LEN].try_into().unwrap();
        let kind = PrivateAccountKind::from_header_bytes(header)?;

        let mut cursor = Cursor::new(&buffer[PrivateAccountKind::HEADER_LEN..]);
        Account::from_cursor(&mut cursor)
            .ok()
            .map(|account| (kind, account))
    }
}

pub(crate) fn note_key(
    domain: &[u8],
    shared_secret: &SharedSecretKey,
    binding: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = [0_u8; MAX_KEY_DOMAIN_LEN + 32 + 32];
    let (head, tail) = preimage.split_at_mut(domain.len());
    head.copy_from_slice(domain);
    let (secret, tail) = tail.split_at_mut(32);
    secret.copy_from_slice(&shared_secret.0);
    tail[..32].copy_from_slice(binding);
    let len = domain
        .len()
        .checked_add(64)
        .expect("a key domain fits the preimage");
    Impl::hash_bytes(&preimage[..len])
        .as_bytes()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

pub(crate) fn apply_keystream(
    buffer: &mut [u8],
    domain: &[u8],
    shared_secret: &SharedSecretKey,
    binding: &[u8; 32],
) {
    ChaCha20::new(
        &note_key(domain, shared_secret, binding).into(),
        &[0; 12].into(),
    )
    .apply_keystream(buffer);
}

pub(crate) fn pad_to_floor(buffer: &mut Vec<u8>, pad_to_len: Option<u32>) {
    if let Some(pad_to_len) = pad_to_len {
        assert!(
            pad_to_len <= MAX_CIPHERTEXT_PADDING,
            "ciphertext padding exceeds the maximum"
        );
        let pad_to_len = usize::try_from(pad_to_len).expect("pad length fits in usize");
        if pad_to_len > buffer.len() {
            buffer.resize(pad_to_len, 0);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Identifier,
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
            &PrivateAccountKind::Regular(Identifier::new([42; 32])),
            &secret,
            &nullifier,
            None,
        );
        let pda_ct = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Pda {
                account_id: AccountId::new([1_u8; 32]),
                seed: PdaSeed::new([2_u8; 32]),
                identifier: Identifier::new([42; 32]),
            },
            &secret,
            &nullifier,
            None,
        );

        assert_eq!(account_ct.0.len(), pda_ct.0.len());
    }

    fn account_with_data(data_len: usize) -> Account {
        Account::default().with_shard(
            AccountId::new([8_u8; 32]),
            vec![7_u8; data_len].try_into().expect("data fits"),
        )
    }

    fn plaintext_len(account: &Account) -> u32 {
        let len = PrivateAccountKind::HEADER_LEN
            .checked_add(account.to_bytes().len())
            .expect("plaintext length fits in usize");
        u32::try_from(len).expect("plaintext length fits in u32")
    }

    #[test]
    fn encrypt_pads_short_plaintext_to_requested_length() {
        let secret = SharedSecretKey([0_u8; 32]);
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([0_u8; 32]));
        let kind = PrivateAccountKind::Regular(Identifier::ZERO);

        for data_len in [0, 10, 100, 300] {
            let account = account_with_data(data_len);
            let base = plaintext_len(&account);
            // exact fit (no-op), one byte over (tightest pad), and a loose pad
            for delta in [0, 1, 1000] {
                let pad = base.saturating_add(delta);
                let ct = EncryptionScheme::encrypt(&account, &kind, &secret, &nullifier, Some(pad));
                assert_eq!(
                    ct.as_bytes().len(),
                    usize::try_from(pad).expect("pad fits in usize"),
                    "data_len {data_len}, pad {pad}"
                );
            }
        }
    }

    #[test]
    fn encrypt_leaves_plaintext_longer_than_the_pad_alone() {
        let secret = SharedSecretKey([0_u8; 32]);
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([0_u8; 32]));
        let kind = PrivateAccountKind::Regular(Identifier::ZERO);
        let account = account_with_data(1000);
        let base = plaintext_len(&account);

        let pad = base.saturating_sub(1);
        let ct = EncryptionScheme::encrypt(&account, &kind, &secret, &nullifier, Some(pad));

        assert_eq!(
            ct.as_bytes().len(),
            usize::try_from(base).expect("plaintext length fits in usize")
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn padded_note_round_trips() {
        const PAD: u32 = 512;

        let d = [3_u8; 32];
        let z = [4_u8; 32];
        let vpk = shared_key_derivation::ViewingPublicKey::from_seed(&d, &z);
        let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
        let receiver_ss = SharedSecretKey::decapsulate(&epk, &d, &z).unwrap();

        let account = account_with_data(37).with_shard(
            crate::native_token::NATIVE_TOKEN_PROGRAM_ID,
            crate::native_token::encode_balance(42),
        );
        let kind = PrivateAccountKind::Pda {
            account_id: AccountId::new([1_u8; 32]),
            seed: PdaSeed::new([2_u8; 32]),
            identifier: Identifier::new([9; 32]),
        };
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([7_u8; 32]));

        let ct = EncryptionScheme::encrypt(&account, &kind, &sender_ss, &nullifier, Some(PAD));
        assert_eq!(
            ct.as_bytes().len(),
            usize::try_from(PAD).expect("pad fits in usize")
        );

        let (decoded_kind, decoded_account) =
            EncryptionScheme::decrypt(&ct, &receiver_ss, &nullifier)
                .expect("a padded note must decrypt");

        assert_eq!(decoded_account, account);
        assert_eq!(decoded_kind, kind);

        // Padding before the keystream, not after it: zeros bolted onto the ciphertext would
        // republish the plaintext length, which is the leak the pad exists to close.
        let tail = usize::try_from(plaintext_len(&account)).expect("plaintext fits in usize");
        assert!(ct.as_bytes()[tail..].iter().any(|byte| *byte != 0));
    }

    #[test]
    #[should_panic(expected = "ciphertext padding exceeds the maximum")]
    fn encrypt_rejects_padding_above_the_maximum() {
        let _ct = EncryptionScheme::encrypt(
            &Account::default(),
            &PrivateAccountKind::Regular(Identifier::ZERO),
            &SharedSecretKey([0_u8; 32]),
            &Nullifier::for_account_initialization(&AccountId::new([0_u8; 32])),
            Some(MAX_CIPHERTEXT_PADDING.saturating_add(1)),
        );
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

        let account = Account::funded(999).with_shard(
            AccountId::new([12; 32]),
            b"shard record".to_vec().try_into().unwrap(),
        );
        let kind = PrivateAccountKind::Regular(Identifier::ZERO);
        let nullifier = Nullifier::for_account_initialization(&AccountId::new([7_u8; 32]));

        let ct = EncryptionScheme::encrypt(&account, &kind, &sender_ss, &nullifier, None);
        let (decoded_kind, decoded_account) =
            EncryptionScheme::decrypt(&ct, &receiver_ss, &nullifier)
                .expect("decryption must succeed with correct shared secret");

        assert_eq!(decoded_account, account);
        assert_eq!(decoded_kind, kind);

        // Wrong shared secret must not decrypt correctly.
        let wrong_ss = SharedSecretKey([0_u8; 32]);
        let bad_via_ss = EncryptionScheme::decrypt(&ct, &wrong_ss, &nullifier);
        assert!(
            bad_via_ss.is_none_or(|(_, a)| a.data.native_balance() != Ok(999)),
            "wrong shared secret must not produce the correct plaintext"
        );

        // Wrong nullifier must not decrypt correctly.
        let wrong_nullifier = Nullifier::for_account_initialization(&AccountId::new([9; 32]));
        let bad_via_nlf = EncryptionScheme::decrypt(&ct, &receiver_ss, &wrong_nullifier);
        assert!(
            bad_via_nlf.is_none_or(|(_, a)| a.data.native_balance() != Ok(999)),
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
