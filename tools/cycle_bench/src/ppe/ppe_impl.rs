//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_native_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_native_transfer_in_ppe`).

use std::{collections::HashMap, time::Instant};

use borsh::to_vec;
use lee::{
    execute_and_prove,
    privacy_preserving_transaction::circuit::{ProgramWithDependencies, Proof, ProvingInput},
};
use lee_core::{
    CommitmentSetDigest, DummyInput, PrivacyPreservingCircuitOutput, SharedSecretKey,
    account::{AccountId, ProgramShardSelector},
    encryption::{Ciphertext, EncryptedAccountData, MlKem768EncapsulationKey, ViewTag},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
};
use rand::{RngCore as _, rngs::OsRng};
use test_guest_core::ChainCall;

use super::PpeBenchResult;

const SENDER_ID: AccountId = AccountId::new([17; 32]);
const RECIPIENT_ID: AccountId = AccountId::new([42; 32]);
const AMOUNT_TO_TRANSFER: u128 = 5_000;
/// Mirrors `wallet::CIPHERTEXT_PAD_SIZE`, so the padding cost here matches what a wallet pays.
const CIPHERTEXT_PAD: u32 = 512;

fn timed(
    label: String,
    chain_depth: usize,
    proof: impl Fn() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)>,
) -> PpeBenchResult {
    let started = Instant::now();
    match proof() {
        Ok((_out, proof)) => PpeBenchResult {
            label,
            chain_depth,
            prove_wall_ms: Some(started.elapsed().as_secs_f64() * 1_000.0),
            proof_bytes: Some(proof.into_inner().len()),
            error: None,
        },
        Err(err) => PpeBenchResult {
            label,
            chain_depth,
            prove_wall_ms: None,
            proof_bytes: None,
            error: Some(err.to_string()),
        },
    }
}

pub fn prove_native_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    prove_native_transfer_with_dummies(0)
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Dummy inputs as the wallet builds them: random seeds, a real ML-KEM epk toward a throwaway
/// key, and a padded random ciphertext.
fn dummy_inputs(count: usize) -> Vec<DummyInput> {
    let ciphertext_len = usize::try_from(CIPHERTEXT_PAD).expect("pad size fits in usize");
    std::iter::repeat_with(|| {
        let throwaway_ek = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
        let (_, epk) = SharedSecretKey::encapsulate(&throwaway_ek);
        let mut ciphertext = vec![0_u8; ciphertext_len];
        OsRng.fill_bytes(&mut ciphertext);
        let mut tag = [0_u8; 1];
        OsRng.fill_bytes(&mut tag);
        DummyInput {
            nullifier_seed: random_bytes(),
            commitment_seed: random_bytes(),
            note: EncryptedAccountData {
                ciphertext: Ciphertext::from_inner(ciphertext),
                epk,
                view_tag: ViewTag::from(tag[0]),
            },
            commitment_root: CommitmentSetDigest::default(),
        }
    })
    .take(count)
    .collect()
}

pub fn run_native_transfer_with_dummies(count: usize) -> PpeBenchResult {
    timed(
        format!("native Transfer in PPE, {count} dummy inputs"),
        0,
        || prove_native_transfer_with_dummies(count),
    )
}

fn prove_native_transfer_with_dummies(
    count: usize,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let pwd = ProgramWithDependencies::native();
    let instruction = lee_core::native_token::Instruction::Transfer {
        amount: AMOUNT_TO_TRANSFER,
    };

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(SENDER_ID),
                ProgramShardSelector::native_balance(RECIPIENT_ID),
            ],
            signers: [SENDER_ID, RECIPIENT_ID].into(),
            instruction_data: to_vec(&instruction)?,
            dummy_inputs: dummy_inputs(count),
            ciphertext_padding: Some(CIPHERTEXT_PAD),
            ..Default::default()
        },
        &pwd,
    )?)
}

pub fn run_chain_caller(depth: u32) -> PpeBenchResult {
    timed(
        format!("chain_caller to native Transfer depth={depth}"),
        depth as usize,
        || prove_chain_caller(depth),
    )
}

fn prove_chain_caller(
    num_chain_calls: u32,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let chain_caller = test_programs::chain_caller();
    let chain_caller_id = AccountId::from_builtin_program(chain_caller.id());
    let pwd = ProgramWithDependencies::new(chain_caller, chain_caller_id, HashMap::new());

    // chain_caller reads its accounts as [recipient, sender] and permutes them for the callee.
    let shard_selectors = vec![
        ProgramShardSelector::native_balance(RECIPIENT_ID),
        ProgramShardSelector::native_balance(SENDER_ID),
    ];

    let transfer = to_vec(&lee_core::native_token::Instruction::Transfer {
        amount: AMOUNT_TO_TRANSFER,
    })?;
    let instruction = ChainCall::new(NATIVE_TOKEN_PROGRAM_ID, transfer).repeated(num_chain_calls);

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors,
            signers: [RECIPIENT_ID, SENDER_ID].into(),
            instruction_data: to_vec(&instruction)?,
            ..Default::default()
        },
        &pwd,
    )?)
}
