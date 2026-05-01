#![no_main]

use serde::{Deserialize, Serialize};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use nssa_core::{
    Commitment, NullifierPublicKey, NullifierSecretKey,
    commitment::compute_digest_for_path,
    account::Account,
};

pub type MembershipProof = (usize, Vec<[u8; 32]>);

// Macro entry point for RISC Zero
risc0_zkvm::guest::entry!(main);

/// 1. PRIVATE INPUT
#[derive(Deserialize)]
pub struct PrivateInputs {
    pub nsk: NullifierSecretKey,
    pub registry_proof: MembershipProof,
}

/// 2. PUBLIC INPUT
#[derive(Deserialize)]
pub struct PublicInputs {
    pub registry_root: [u8; 32],
    pub revoked_commitments: Vec<[u8; 32]>,
    pub message_hash: [u8; 32], 
    pub post_salt: [u8; 32],    
}

/// 3. PROOF OUTPUT
#[derive(Serialize)]
pub struct ProofOutput {
    pub registry_root: [u8; 32],
    pub message_hash: [u8; 32],
    pub tracing_tag: [u8; 32], 
}

pub fn main() {
    // [A] READ INPUT FROM THE HOST ENVIRONMENT (SDK)
    let private_inputs: PrivateInputs = env::read();
    let public_inputs: PublicInputs = env::read();

    // [B] DERIVE IDENTITY 
    // Derive the NPK (Public Key) deterministically from the NSK
    let npk = NullifierPublicKey::from(&private_inputs.nsk);
    let default_account = Account::default();
    let commitment = Commitment::new(&npk, &default_account);

    // [C] VERIFY MEMBERSHIP (REGISTRY SMT)
    let computed_registry_root = compute_digest_for_path(
        &commitment, 
        &private_inputs.registry_proof
    );
    
    assert_eq!(
        computed_registry_root, public_inputs.registry_root,
        "ZK Error: Commitment not found in the Registry Tree."
    );

    // [D] VERIFY ACTIVE STATUS (Blocked User Prevention)
    let comm_bytes = commitment.to_byte_array();
    for rev_bytes in public_inputs.revoked_commitments.iter() {
        assert_ne!(
            &comm_bytes, rev_bytes,
            "ZK Error: You have been slashed and blocked from the forum!"
        );
    }

    // [E] GENERATE TRACING TAG (Retroactive Linkability)
    // This tag must be identical to how `MemberClient::generate_tracing_tag` creates it
    // SHA256( NSK || Message Hash || Salt )
    let mut tag_data = Vec::new();
    tag_data.extend_from_slice(&private_inputs.nsk);
    tag_data.extend_from_slice(&public_inputs.message_hash);
    tag_data.extend_from_slice(&public_inputs.post_salt);
    
    let tracing_tag: [u8; 32] = Impl::hash_bytes(&tag_data).as_bytes().try_into().unwrap();

    // [F] COMMIT TO JOURNAL
    let output = ProofOutput {
        registry_root: public_inputs.registry_root,
        message_hash: public_inputs.message_hash,
        tracing_tag,
    };
    env::commit(&output);
}