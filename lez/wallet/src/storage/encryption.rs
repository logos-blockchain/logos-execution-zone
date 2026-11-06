//! Password encryption of the storage file: AES-256-GCM under an Argon2id key.

use aes_gcm::{Aes256Gcm, KeyInit as _, aead::Aead as _};
use anyhow::{Result, anyhow, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::WrongPassword;

/// Layout version of the encrypted file; a file of any other version is refused.
const FORMAT_VERSION: u32 = 1;

// Argon2id cost of a new key (memory in KiB, passes, lanes): RFC 9106's second recommended
// option, as its first one takes 2 GiB of memory.
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 4;

// Largest Argon2id cost a storage file may ask for, well above a new key's, so a tampered file
// cannot make opening exhaust memory or time.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;

/// Salt length, the 128 bits RFC 9106 recommends.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length, the 96 bits the mode is specified for.
const NONCE_LEN: usize = 12;
/// AES-256 key length.
const KEY_LEN: usize = 32;

/// The storage file: how to derive its key from the password, and the sealed storage.
#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    version: u32,
    kdf: KdfParams,
    #[serde(with = "hex::serde")]
    nonce: [u8; NONCE_LEN],
    #[serde(with = "hex::serde")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct KdfParams {
    #[serde(with = "hex::serde")]
    salt: [u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// The key the storage file is sealed under.
pub struct StorageKey {
    kdf: KdfParams,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl StorageKey {
    /// Derives a key from `password` under a fresh salt; an empty password, which stands for an
    /// unencrypted storage, has none.
    pub fn new(password: &str) -> Result<Self> {
        ensure!(
            !password.is_empty(),
            "An empty password leaves the storage unencrypted"
        );
        let mut salt = [0; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self::derive(
            password,
            KdfParams {
                salt,
                memory_kib: MEMORY_KIB,
                iterations: ITERATIONS,
                parallelism: PARALLELISM,
            },
        )
    }

    fn derive(password: &str, kdf: KdfParams) -> Result<Self> {
        ensure!(
            kdf.memory_kib <= MAX_MEMORY_KIB && kdf.iterations <= MAX_ITERATIONS,
            "Storage key parameters exceed {MAX_MEMORY_KIB} KiB or {MAX_ITERATIONS} iterations"
        );
        let params = Params::new(
            kdf.memory_kib,
            kdf.iterations,
            kdf.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|err| anyhow!("Invalid storage key parameters: {err}"))?;
        let mut key = Zeroizing::new([0; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &kdf.salt, key.as_mut())
            .map_err(|err| anyhow!("Failed to derive the storage key: {err}"))?;
        Ok(Self { kdf, key })
    }

    pub(super) fn seal(&self, plaintext: &[u8]) -> Result<EncryptedFile> {
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce.into(), plaintext)
            .map_err(|_err| anyhow!("Failed to encrypt the storage"))?;
        Ok(EncryptedFile {
            version: FORMAT_VERSION,
            kdf: self.kdf,
            nonce,
            ciphertext,
        })
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&(*self.key).into())
    }
}

impl EncryptedFile {
    /// Derives the key from `password` and decrypts the storage.
    pub(super) fn open(&self, password: &str) -> Result<(Zeroizing<Vec<u8>>, StorageKey)> {
        ensure!(
            self.version == FORMAT_VERSION,
            "Unsupported storage file version {}",
            self.version
        );
        let key = StorageKey::derive(password, self.kdf)?;
        let plaintext = key
            .cipher()
            .decrypt(&self.nonce.into(), self.ciphertext.as_slice())
            .map_err(|_err| WrongPassword)?;
        Ok((Zeroizing::new(plaintext), key))
    }
}
