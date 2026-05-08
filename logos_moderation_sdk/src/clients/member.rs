use sha2::{Sha256, Digest};
use rand::RngCore;
use sharks::Sharks;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;

use crate::types::{EncryptedSharePerPost, PostPayload};
use crate::crypto::sss::split_secret; 

pub struct MemberClient {
    pub nsk: [u8; 32],
    pub k_strikes_threshold: u32,
    tier2_shares: Vec<Vec<u8>>, 
    post_counter: u8,
}

impl MemberClient {
    pub fn new(nsk: [u8; 32], k_strikes_threshold: u32) -> Self {
        let sharks = Sharks(k_strikes_threshold as u8);
        let dealer = sharks.dealer(&nsk);
        
        let tier2_shares: Vec<Vec<u8>> = dealer.take(255).map(|s| Vec::from(&s)).collect();
        
        Self {
            nsk,
            k_strikes_threshold,
            tier2_shares,
            post_counter: 1,
        }
    }

    pub fn prepare_post(
        &mut self, 
        message: &[u8],
        post_salt: &[u8; 32],
        moderator_pubkeys: &[[u8; 32]],
        n_moderator_threshold: u32,
    ) -> Result<PostPayload, &'static str> {
        
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash: [u8; 32] = hasher.finalize().into();

        let tracing_tag = Self::generate_tracing_tag(&self.nsk, &message_hash, post_salt);
        let x_index = self.post_counter;

        let s_post = self.evaluate_tier2_polynomial(x_index);
        let raw_shares = split_secret(&s_post, n_moderator_threshold, moderator_pubkeys.len() as u32)?;

        let ephemeral_scalar = Self::generate_ephemeral_scalar();
        let ephemeral_pk = Self::derive_xonly_pubkey(&ephemeral_scalar);

        let mut encrypted_shares = Vec::new();
        for (i, mod_pk) in moderator_pubkeys.iter().enumerate() {
            let shared_secret = Self::compute_ecdh_shared_secret(&ephemeral_scalar, mod_pk)?;
            
            let mut buffer = raw_shares[i].clone();
            Self::xor_with_keystream(&mut buffer, &shared_secret, i as u32);

            encrypted_shares.push(EncryptedSharePerPost {
                moderator_pubkey: *mod_pk,
                ephemeral_pk,
                ciphertext: buffer,
            });
        }

        self.post_counter += 1;

        Ok(PostPayload {
            message: message.to_vec(),
            tracing_tag,
            x_index,
            encrypted_shares,
        })
    }

    fn generate_tracing_tag(nsk: &[u8; 32], message_hash: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(nsk);
        hasher.update(message_hash);
        hasher.update(salt);
        hasher.finalize().into()
    }

    fn evaluate_tier2_polynomial(&self, x: u8) -> [u8; 32] {
        let share_bytes = &self.tier2_shares[(x - 1) as usize];
        let mut s_post = [0u8; 32];
        s_post.copy_from_slice(&share_bytes[1..33]);
        s_post
    }

    fn generate_ephemeral_scalar() -> [u8; 32] {
        loop {
            let mut sk = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut sk);
            if k256::SecretKey::from_bytes(&sk.into()).is_ok() {
                return sk;
            }
        }
    }

    fn derive_xonly_pubkey(scalar_bytes: &[u8; 32]) -> [u8; 32] {
        let sk = k256::SecretKey::from_bytes(&(*scalar_bytes).into())
            .expect("Scalar was already validated");
        let encoded = sk.public_key().to_encoded_point(false);
        let x_coord = encoded.x().expect("Valid EC point has x-coordinate");
        let mut pk = [0u8; 32];
        pk.copy_from_slice(x_coord);
        pk
    }

    fn compute_ecdh_shared_secret(
        ephemeral_sk: &[u8; 32], 
        mod_xonly_pk: &[u8; 32],
    ) -> Result<[u8; 32], &'static str> {
        let mut sec1_compressed = [0u8; 33];
        sec1_compressed[0] = 0x02; 
        sec1_compressed[1..33].copy_from_slice(mod_xonly_pk);

        let mod_pubkey = k256::PublicKey::from_sec1_bytes(&sec1_compressed)
            .map_err(|_| "Invalid moderator public key for ECDH")?;

        let ephemeral_secret = k256::SecretKey::from_bytes(&(*ephemeral_sk).into())
            .map_err(|_| "Invalid ephemeral secret key")?;
    
        let shared_point = k256::ecdh::diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            mod_pubkey.as_affine(),
        );

        let mut hasher = Sha256::new();
        hasher.update(b"LOGOS/v1/ECDH/");
        hasher.update(shared_point.raw_secret_bytes());
        Ok(hasher.finalize().into())
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