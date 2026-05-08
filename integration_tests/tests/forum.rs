use logos_moderation_sdk::{
    clients::{member::MemberClient, moderator::ModeratorClient, aggregator::SlashAggregator},
};
use membership_registry::{
    initialize::process_initialize,
    register::process_register,
    slash::process_slash,
    verify_post::process_verify_post,
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use program_methods::FORUM_MEMBERSHIP_PROOF_ELF;
use nssa_core::{NullifierPublicKey, NullifierSecretKey, Commitment, account::Account};
use serde::Serialize;
use rand::RngCore;

#[derive(Serialize)]
pub struct PrivateInputs {
    pub nsk: [u8; 32],
    pub registry_proof: (usize, Vec<[u8; 32]>),
}

#[derive(Serialize)]
pub struct PublicInputs {
    pub registry_root: [u8; 32],
    pub revoked_commitments: Vec<[u8; 32]>,
    pub message_hash: [u8; 32],
    pub post_salt: [u8; 32],
}

#[test]
fn test_forum_e2e_full_lifecycle() {
    println!("=== LP-0016 FORUM E2E TEST ===");

    // 1. Setup forum, moderators, and register a member 
    let n_threshold = 3;
    let m_total = 5;
    let k_strikes = 3;

    let mut moderators = Vec::new();
    let mut mod_pubkeys = Vec::new();

    for _ in 0..m_total {
        let mut privkey = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut privkey);
        privkey[0] = privkey[0].max(1);

        let mod_client = ModeratorClient::new(privkey);
        mod_pubkeys.push(mod_client.public_key());
        moderators.push(mod_client);
    }

    let aggregator = SlashAggregator::new(n_threshold, k_strikes, &mod_pubkeys);
    let mut forum_state = process_initialize(k_strikes, n_threshold, m_total)
        .expect("Initialization failed");

    let mut member_nsk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut member_nsk_bytes);

    let mut member_client = MemberClient::new(member_nsk_bytes, k_strikes);
    let member_nsk = member_client.nsk;
    let nsk_obj = NullifierSecretKey::from(member_nsk);
    let member_npk = NullifierPublicKey::from(&nsk_obj);
    let member_commitment = Commitment::new(&member_npk, &Account::default());

    process_register(&mut forum_state, member_commitment.clone(), 1500)
        .expect("Registration failed");
    println!("[OK] Member registered. Staked: {}", forum_state.total_staked);

    // 2. Member creates a post with ZK proof 
    println!(">>> Generating ZK membership proof...");

    let message_hash = [0u8; 32];
    let post_salt = [0u8; 32];

    let path = forum_state.registry.get_authentication_path_for(0).unwrap();
    let private_inputs = PrivateInputs {
        nsk: member_nsk,
        registry_proof: (0, path),
    };

    let public_inputs = PublicInputs {
        registry_root: forum_state.registry.root(),
        revoked_commitments: forum_state.revoked_commitments.clone(),
        message_hash,
        post_salt,
    };

    let env = ExecutorEnv::builder()
        .write(&private_inputs).unwrap()
        .write(&public_inputs).unwrap()
        .build().unwrap();

    let prover = default_prover();
    let prove_info = prover.prove(env, FORUM_MEMBERSHIP_PROOF_ELF).unwrap();

    // Deserialize the proof output from the journal
    let proof_output: membership_registry::ProofOutput =
        prove_info.receipt.journal.decode().expect("Failed to decode proof journal");

    // Verify post on-chain: check registry root + record tracing tag
    process_verify_post(
        &mut forum_state,
        proof_output.registry_root,
        proof_output.tracing_tag,
    ).expect("Post verification failed");
    println!("[OK] Anonymous post accepted via ZK proof.");

    // 3. Moderation — 3 posts get struck, NSK reconstructed 
    let mut accumulated_strikes: Vec<(u8, [u8; 32])> = Vec::new();

    for strike_num in 1..=k_strikes {
        let payload = member_client
            .prepare_post(&message_hash, &post_salt, &mod_pubkeys, n_threshold)
            .unwrap();

        let mut certs = Vec::new();
        for i in 0..n_threshold {
            let cert = moderators[i as usize]
                .issue_strike(payload.tracing_tag, &payload.encrypted_shares[i as usize], i)
                .unwrap();
            certs.push(cert);
        }

        let s_post = aggregator
            .reconstruct_strike(&payload.tracing_tag, &certs)
            .unwrap();
        accumulated_strikes.push((payload.x_index, s_post));
        println!("[OK] Strike {} of {} collected.", strike_num, k_strikes);
    }

    let reconstructed_nsk = aggregator
        .reconstruct_nsk(&accumulated_strikes)
        .unwrap();
    assert_eq!(reconstructed_nsk, member_nsk, "NSK reconstruction mismatch!");
    println!("[OK] NSK successfully reconstructed via Lagrange interpolation.");

    // 4. Slash the member on-chain
    let nsk_obj = NullifierSecretKey::from(reconstructed_nsk);
    let confiscated = process_slash(&mut forum_state, &nsk_obj)
        .expect("Slash failed");

    let comm_bytes = member_commitment.to_byte_array();
    assert!(forum_state.revoked_commitments.contains(&comm_bytes));
    assert_eq!(confiscated, 1500, "Should confiscate exact staked amount");
    assert_eq!(forum_state.total_staked, 0, "All stake should be confiscated");

    println!("[OK] Member slashed. Confiscated: {} tokens.", confiscated);
    println!("=== LP-0016 E2E TEST PASSED ===");
}