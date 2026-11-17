//! How a block guest checks public-account authorization: BIP340 in the guest one at a time,
//! left for the verifier, a hash-preimage receipt per signer checked by composition, or BIP340
//! in the guest as one batch.

use borsh::BorshDeserialize;
use lee::stf_partial::{self, DeferredSignature};
use risc0_zkvm::guest::env;

pub const SCHNORR: u8 = 0;
pub const DEFER: u8 = 1;
pub const PREIMAGE: u8 = 2;
pub const BATCH: u8 = 3;

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
        matches!(settings.auth, SCHNORR | DEFER | PREIMAGE | BATCH),
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
    if settings.auth == BATCH {
        let checks: Vec<_> = deferred
            .iter()
            .map(|d| stf_bench_guest::Check {
                public_key: &d.public_key,
                message_hash: &d.message_hash,
                signature: &d.signature,
            })
            .collect();
        assert!(stf_bench_guest::verify(&checks), "a signature in the block is invalid");
        return Vec::new();
    }
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
