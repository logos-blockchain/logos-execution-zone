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

risc0_zkvm::guest::entry!(main);

#[derive(Deserialize)]
pub struct PrivateInputs {
    pub nsk: NullifierSecretKey,
    pub registry_proof: MembershipProof,
}

#[derive(Deserialize)]
pub struct PublicInputs {
    pub registry_root: [u8; 32],
    pub revoked_commitments: Vec<[u8; 32]>,
    pub message_hash: [u8; 32],
    pub post_salt: [u8; 32],
}

#[derive(Serialize)]
pub struct ProofOutput {
    pub registry_root: [u8; 32],
    pub message_hash: [u8; 32],
    pub tracing_tag: [u8; 32],
}

pub fn main() {
    let private_inputs: PrivateInputs = env::read();
    let public_inputs: PublicInputs = env::read();

    let npk = NullifierPublicKey::from(&private_inputs.nsk);
    let commitment = Commitment::new(&npk, &Account::default());

    // Verify commitment exists in the registry Merkle tree
    let computed_registry_root = compute_digest_for_path(
        &commitment,
        &private_inputs.registry_proof
    );

    assert_eq!(
        computed_registry_root, public_inputs.registry_root,
        "Commitment not found in the registry tree"
    );

    // Verify commitment has not been revoked
    let comm_bytes = commitment.to_byte_array();
    for rev_bytes in public_inputs.revoked_commitments.iter() {
        assert_ne!(
            &comm_bytes, rev_bytes,
            "Member has been slashed and revoked"
        );
    }

    // Compute tracing tag: SHA256(NSK || message_hash || salt)
    let mut tag_data = Vec::new();
    tag_data.extend_from_slice(&private_inputs.nsk);
    tag_data.extend_from_slice(&public_inputs.message_hash);
    tag_data.extend_from_slice(&public_inputs.post_salt);

    let tracing_tag: [u8; 32] = Impl::hash_bytes(&tag_data).as_bytes().try_into().unwrap();

    env::commit(&ProofOutput {
        registry_root: public_inputs.registry_root,
        message_hash: public_inputs.message_hash,
        tracing_tag,
    });
}