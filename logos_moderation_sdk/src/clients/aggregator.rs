use sha2::{Sha256, Digest};
use sharks::{Sharks, Share};
use std::collections::HashSet;
use crate::crypto::signature::{PublicKey, Signature};
use crate::types::{ModerationCertificate, NullifierSecretKey};

pub struct SlashAggregator {
    pub n_moderator_threshold: u32,
    pub k_strikes_threshold: u32,
    pub valid_moderator_pubkeys: HashSet<[u8; 32]>, 
}

impl SlashAggregator {
    pub fn new(
        n_moderator_threshold: u32, 
        k_strikes_threshold: u32, 
        moderator_pubkeys: &[[u8; 32]]
    ) -> Self {
        let valid_keys = moderator_pubkeys.iter().cloned().collect();
        Self {
            n_moderator_threshold,
            k_strikes_threshold,
            valid_moderator_pubkeys: valid_keys,
        }
    }

    pub fn reconstruct_strike(
        &self,
        tracing_tag: &[u8; 32],
        certificates: &[ModerationCertificate],
    ) -> Result<[u8; 32], &'static str> {
        if certificates.len() < self.n_moderator_threshold as usize {
            return Err("The number of certificates has not yet reached the N-of-M moderator threshold.");
        }

        let mut valid_shares = Vec::new();
        let mut seen_moderators = HashSet::new();

        for cert in certificates {
            let pubkey_bytes: [u8; 32] = cert.moderator_pubkey.as_slice().try_into().unwrap_or([0; 32]);
            
            if !self.valid_moderator_pubkeys.contains(&pubkey_bytes) { continue; }
            
            let message_hash = Self::hash_for_signature(tracing_tag, &cert.decrypted_share);
            let pubkey_obj = PublicKey::try_new(pubkey_bytes).map_err(|_| "Invalid Moderator Pubkey")?;
            
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&cert.moderator_signature);
            let signature_obj = Signature { value: sig_bytes };

            if !signature_obj.is_valid_for(&message_hash, &pubkey_obj) {
                return Err("Strike certificate rejected: Invalid Schnorr signature!");
            }

            if !seen_moderators.insert(pubkey_bytes) { continue; }

            if let Ok(share) = Share::try_from(cert.decrypted_share.as_slice()) {
                valid_shares.push(share);
            }
        }

        if valid_shares.len() < self.n_moderator_threshold as usize {
            return Err("Not enough valid certificates.");
        }

        let sharks = Sharks(self.n_moderator_threshold as u8);
        let s_post_vec = sharks.recover(&valid_shares)
            .map_err(|_| "Failed to reconstruct S_post.")?;

        let mut s_post = [0u8; 32];
        s_post.copy_from_slice(&s_post_vec);
        Ok(s_post)
    }

    pub fn reconstruct_nsk(
        &self,
        accumulated_strikes: &[(u8, [u8; 32])],
    ) -> Result<NullifierSecretKey, &'static str> {
        if accumulated_strikes.len() < self.k_strikes_threshold as usize {
            return Err("K-Strikes threshold has not yet been reached for slashing.");
        }

        let mut tier2_shares = Vec::new();

        for (x_index, s_post) in accumulated_strikes.iter().take(self.k_strikes_threshold as usize) {
            let mut share_bytes = Vec::with_capacity(33);
            share_bytes.push(*x_index);
            share_bytes.extend_from_slice(s_post);

            if let Ok(share) = Share::try_from(share_bytes.as_slice()) {
                tier2_shares.push(share);
            }
        }

        let sharks = Sharks(self.k_strikes_threshold as u8);
        let nsk_vec = sharks.recover(&tier2_shares)
            .map_err(|_| "Failed to reconstruct NSK.")?;

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&nsk_vec);
        Ok(nsk)
    }

    fn hash_for_signature(tracing_tag: &[u8; 32], share: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"LOGOS/v1/ModerationStrike/");
        hasher.update(tracing_tag);
        hasher.update(share);
        hasher.finalize().into()
    }
}