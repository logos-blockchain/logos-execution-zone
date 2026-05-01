use sha2::{Sha256, Digest};
use crate::crypto::signature::{PrivateKey, PublicKey, Signature};
use crate::types::{EncryptedSharePerPost, ModerationCertificate};

pub struct ModeratorClient {
    pub privkey: PrivateKey,
}

impl ModeratorClient {
    pub fn new(privkey: [u8; 32]) -> Self {
        Self { 
            privkey: PrivateKey::try_new(privkey).expect("Invalid Private Key") 
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        let pk = PublicKey::new_from_private_key(&self.privkey);
        *pk.value()
    }

    pub fn issue_strike(
        &self,
        tracing_tag: [u8; 32],
        encrypted_share: &EncryptedSharePerPost,
        moderator_index: u32,
    ) -> Result<ModerationCertificate, &'static str> {
        
        // Reconstruct the Shared Secret
        let mut ss_hasher = Sha256::new();
        ss_hasher.update(encrypted_share.ephemeral_pk);
        ss_hasher.update(self.public_key());
        let shared_secret: [u8; 32] = ss_hasher.finalize().into();

        let mut decrypted_buffer = encrypted_share.ciphertext.clone();
        Self::decrypt_raw_share(&mut decrypted_buffer, &shared_secret, moderator_index);

        if decrypted_buffer.len() != 33 {
            return Err("Decrypted share invalid length. Expected 33 bytes.");
        }

        let message_to_sign = Self::hash_for_signature(&tracing_tag, &decrypted_buffer);
        let signature = Signature::new(&self.privkey, &message_to_sign);

        Ok(ModerationCertificate {
            tracing_tag,
            decrypted_share: decrypted_buffer,
            moderator_signature: signature.value.to_vec(), 
            moderator_pubkey: self.public_key().to_vec(),
        })
    }

    fn hash_for_signature(tracing_tag: &[u8; 32], share: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"LOGOS/v1/ModerationStrike/");
        hasher.update(tracing_tag);
        hasher.update(share);
        hasher.finalize().into()
    }

    fn decrypt_raw_share(buffer: &mut [u8], shared_secret: &[u8; 32], index: u32) {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(index.to_le_bytes());
        let keystream: [u8; 32] = hasher.finalize().into();
        
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte ^= keystream[i % 32];
        }
    }
}