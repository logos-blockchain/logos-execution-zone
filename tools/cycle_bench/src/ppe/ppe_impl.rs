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
    PrivacyPreservingCircuitOutput,
    account::{AccountId, ProgramShardSelector},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
};
use test_guest_core::ChainCall;

use super::PpeBenchResult;

const SENDER_ID: AccountId = AccountId::new([17; 32]);
const RECIPIENT_ID: AccountId = AccountId::new([42; 32]);
const AMOUNT_TO_TRANSFER: u128 = 5_000;

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

pub fn run_native_transfer_in_ppe() -> PpeBenchResult {
    timed(
        "native Transfer in PPE".to_owned(),
        0,
        prove_native_transfer_in_ppe,
    )
}

pub fn prove_native_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let pwd = ProgramWithDependencies::native();

    let sender_id = AccountId::new([1; 32]);
    let recipient_id = AccountId::new([2; 32]);

    let instruction = lee_core::native_token::Instruction::Transfer { amount: 5_000 };
    let instruction_data = to_vec(&instruction)?;

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            signers: [sender_id, recipient_id].into(),
            instruction_data,
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
