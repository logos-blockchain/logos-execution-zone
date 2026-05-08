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
        let shared_secret = Self::compute_ecdh_shared_secret(
            self.privkey.value(),
            &encrypted_share.ephemeral_pk,
        )?;

        let mut decrypted_buffer = encrypted_share.ciphertext.clone();
        Self::xor_with_keystream(&mut decrypted_buffer, &shared_secret, moderator_index);

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

    fn compute_ecdh_shared_secret(
        mod_sk: &[u8; 32],
        ephemeral_xonly_pk: &[u8; 32],
    ) -> Result<[u8; 32], &'static str> {
        let mut sec1_compressed = [0u8; 33];
        sec1_compressed[0] = 0x02; 
        sec1_compressed[1..33].copy_from_slice(ephemeral_xonly_pk);

        let ephemeral_pubkey = k256::PublicKey::from_sec1_bytes(&sec1_compressed)
            .map_err(|_| "Invalid ephemeral public key for ECDH")?;

        let mod_secret = k256::SecretKey::from_bytes(&(*mod_sk).into())
            .map_err(|_| "Invalid moderator secret key")?;

        let shared_point = k256::ecdh::diffie_hellman(
            mod_secret.to_nonzero_scalar(),
            ephemeral_pubkey.as_affine(),
        );

        let mut hasher = Sha256::new();
        hasher.update(b"LOGOS/v1/ECDH/");
        hasher.update(shared_point.raw_secret_bytes());
        Ok(hasher.finalize().into())
    }

    fn hash_for_signature(tracing_tag: &[u8; 32], share: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"LOGOS/v1/ModerationStrike/");
        hasher.update(tracing_tag);
        hasher.update(share);
        hasher.finalize().into()
    }

    fn xor_with_keystream(buffer: &mut [u8], shared_secret: &[u8; 32], index: u32) {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(index.to_le_bytes());
        let keystream: [u8; 32] = hasher.finalize().into();
        
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte ^= keystream[i % 32];
        }
    }
}