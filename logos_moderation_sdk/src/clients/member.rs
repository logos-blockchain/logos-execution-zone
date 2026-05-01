use sha2::{Sha256, Digest};
use rand::RngCore;
use sharks::Sharks;

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
        
        // Take and store all 255 possible shares (GF(256) limit)
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
        self.post_counter += 1;

        // Extract the S_post point from the stored polynomial
        let s_post = self.evaluate_tier2_polynomial(x_index);
        let raw_shares = split_secret(&s_post, n_moderator_threshold, moderator_pubkeys.len() as u32)?;

        let mut ephemeral_sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_sk);
        let ephemeral_pk = ephemeral_sk.clone(); 

        let mut encrypted_shares = Vec::new();
        for (i, mod_pk) in moderator_pubkeys.iter().enumerate() {
            let mut ss_hasher = Sha256::new();
            ss_hasher.update(&ephemeral_sk);
            ss_hasher.update(mod_pk);
            let shared_secret: [u8; 32] = ss_hasher.finalize().into();
            
            let mut buffer = raw_shares[i].clone();
            Self::encrypt_raw_share(&mut buffer, &shared_secret, i as u32);

            encrypted_shares.push(EncryptedSharePerPost {
                moderator_pubkey: *mod_pk,
                ephemeral_pk,
                ciphertext: buffer,
            });
        }

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
        // Since x ranges from 1-255, the array index is x - 1
        let share_bytes = &self.tier2_shares[(x - 1) as usize];
        let mut s_post = [0u8; 32];
        s_post.copy_from_slice(&share_bytes[1..33]);
        s_post
    }

    fn encrypt_raw_share(buffer: &mut [u8], shared_secret: &[u8; 32], index: u32) {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(index.to_le_bytes());
        let keystream: [u8; 32] = hasher.finalize().into();
        
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte ^= keystream[i % 32];
        }
    }
}