//! How a block guest checks public-account authorization: BIP340 in the guest, left for the
//! verifier, or a hash-preimage receipt per signer checked by composition.

use borsh::BorshDeserialize;
use lee::stf_partial::{self, DeferredSignature};
use risc0_zkvm::guest::env;

pub const SCHNORR: u8 = 0;
pub const DEFER: u8 = 1;
pub const PREIMAGE: u8 = 2;

/// Read from the host with the tip.
#[derive(BorshDeserialize)]
pub struct Settings {
    pub tip_id: u64,
    pub tip_hash: [u8; 32],
    pub auth: u8,
    /// The image whose receipts authorize signers under `PREIMAGE`.
    pub auth_image: [u32; 8],
}

/// Runs before the block is decoded, since hash keys change how public keys decode.
pub fn begin(settings: &Settings) {
    assert!(
        matches!(settings.auth, SCHNORR | DEFER | PREIMAGE),
        "unknown authorization mode"
    );
    if settings.auth == PREIMAGE {
        stf_partial::use_hash_keys();
    }
    if settings.auth != SCHNORR {
        stf_partial::defer_signatures();
    }
}

/// Runs after the block is applied; returns the checks left for the verifier.
pub fn finish(settings: &Settings) -> Vec<DeferredSignature> {
    let deferred = stf_partial::take_deferred();
    if settings.auth != PREIMAGE {
        return deferred;
    }
    for check in &deferred {
        env::verify(
            settings.auth_image,
            &lee_core::to_borsh_frame(&(check.public_key, check.message_hash)),
        )
        .expect("a receipt authorizes the signer");
    }
    Vec::new()
}
