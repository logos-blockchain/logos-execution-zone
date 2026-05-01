use logos_moderation_sdk::{
    clients::{member::MemberClient, moderator::ModeratorClient, aggregator::SlashAggregator},
};
use membership_registry::{
    initialize::process_initialize,
    register::process_register,
    MembershipInstruction, process_instruction,
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
    println!("=== STARTING FORUM E2E TEST LP-0016 ===");

    // ==========================================
    // PHASE 1: PARAMETER SETUP, MODERATOR & REGISTRATION
    // ==========================================
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
    let mut forum_state = process_initialize(k_strikes, n_threshold, m_total).expect("Initialization failed");

    let mut member_nsk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut member_nsk_bytes);
    
    let mut member_client = MemberClient::new(member_nsk_bytes, k_strikes);
    let member_nsk = member_client.nsk; 
    let nsk_obj = NullifierSecretKey::from(member_nsk);
    let member_npk = NullifierPublicKey::from(&nsk_obj);
    let member_commitment = Commitment::new(&member_npk, &Account::default());

    process_register(&mut forum_state, member_commitment.clone(), 1500).expect("Registration failed");
    println!("[OK] Registration successful. Total Staked: {}", forum_state.total_staked);

    // ==========================================
    // PHASE 2: MEMBER CREATES A POST (WITH ZK PROOF)
    // ==========================================
    println!(">>> MEMBER CREATES A POST: GENERATING ZK PROOF (Wait ~90 Seconds) <<<");
    
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
    
    process_instruction(&mut forum_state, MembershipInstruction::VerifyPost { 
        zk_receipt: prove_info.receipt 
    }).expect("Failed to verify anonymous post");
    println!("[OK] Post accepted by the Contract via ZK Proof.");

    // ==========================================
    // PHASE 3: MODERATION & NSK RECONSTRUCTION (OFF-CHAIN)
    // ==========================================
    // Using a manual accumulation list because the aggregator does not store state
    let mut accumulated_strikes: Vec<(u8, [u8; 32])> = Vec::new();

    // --- STRIKE FOR POST 1 ---
    let payload_1 = member_client.prepare_post(&message_hash, &post_salt, &mod_pubkeys, n_threshold).unwrap();
    let mut strikes_post_1 = Vec::new();
    for i in 0..n_threshold {
        let cert = moderators[i as usize].issue_strike(payload_1.tracing_tag, &payload_1.encrypted_shares[i as usize], i).unwrap();
        strikes_post_1.push(cert);
    }
    let s_post_1 = aggregator.reconstruct_strike(&payload_1.tracing_tag, &strikes_post_1).unwrap();
    accumulated_strikes.push((payload_1.x_index, s_post_1));
    println!("[OK] Post 1 successfully struck. (1/3 strikes collected)");

    // --- STRIKE FOR POST 2 ---
    // The member uploads the second post (x_index automatically increments)
    let payload_2 = member_client.prepare_post(&message_hash, &post_salt, &mod_pubkeys, n_threshold).unwrap();
    let mut strikes_post_2 = Vec::new();
    for i in 0..n_threshold {
        let cert = moderators[i as usize].issue_strike(payload_2.tracing_tag, &payload_2.encrypted_shares[i as usize], i).unwrap();
        strikes_post_2.push(cert);
    }
    let s_post_2 = aggregator.reconstruct_strike(&payload_2.tracing_tag, &strikes_post_2).unwrap();
    accumulated_strikes.push((payload_2.x_index, s_post_2));
    println!("[OK] Post 2 successfully struck. (2/3 strikes collected)");

    // --- STRIKE FOR POST 3 ---
    let payload_3 = member_client.prepare_post(&message_hash, &post_salt, &mod_pubkeys, n_threshold).unwrap();
    let mut strikes_post_3 = Vec::new();
    for i in 0..n_threshold {
        let cert = moderators[i as usize].issue_strike(payload_3.tracing_tag, &payload_3.encrypted_shares[i as usize], i).unwrap();
        strikes_post_3.push(cert);
    }
    let s_post_3 = aggregator.reconstruct_strike(&payload_3.tracing_tag, &strikes_post_3).unwrap();
    accumulated_strikes.push((payload_3.x_index, s_post_3));
    println!("[OK] Post 3 successfully struck. (3/3 strikes collected)");
    
    // NSK RECONSTRUCTION (K-STRIKES REACHED USING ORIGINAL CURVE POINTS)
    let reconstructed_nsk = aggregator.reconstruct_nsk(&accumulated_strikes).unwrap();
    assert_eq!(reconstructed_nsk, member_nsk, "NSK reconstruction failed!");
    println!("[OK] Identity (NSK) successfully cryptographically exposed!");

    // ==========================================
    // PHASE 4: SLASHING (ON-CHAIN)
    // ==========================================
    println!(">>> MODERATOR PERFORMING SLASHING <<<");
    process_instruction(&mut forum_state, MembershipInstruction::Slash { 
        slashed_nsk: reconstructed_nsk 
    }).expect("Failed to execute slashing");

    let comm_bytes = member_commitment.to_byte_array();
    assert!(forum_state.revoked_commitments.contains(&comm_bytes));
    assert_eq!(forum_state.total_staked, 500, "Stake forfeiture failed!");
    
    println!("[OK] Member successfully blocked and stake forfeited.");
    println!("=== FORUM E2E TEST LP-0016 COMPLETED WITH ZK VERIFICATION SUCCESS ===");
}