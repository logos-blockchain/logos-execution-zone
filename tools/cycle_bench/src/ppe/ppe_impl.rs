//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_auth_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_auth_transfer_in_ppe`).

use std::{collections::HashMap, time::Instant};

use borsh::to_vec;
use lee::{
    AccountData, execute_and_prove,
    privacy_preserving_transaction::circuit::{ProgramWithDependencies, Proof, ProvingInput},
};
use lee_core::{
    PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, ProgramShardSelector},
};

use super::PpeBenchResult;

pub fn run_auth_transfer_in_ppe() -> PpeBenchResult {
    let label = "auth_transfer Transfer in PPE".to_owned();
    let started = Instant::now();
    match prove_auth_transfer_in_ppe() {
        Ok((_out, proof)) => {
            let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
            PpeBenchResult {
                label,
                chain_depth: 0,
                prove_wall_ms: Some(prove_ms),
                proof_bytes: Some(proof.into_inner().len()),
                error: None,
            }
        }
        Err(err) => PpeBenchResult {
            label,
            chain_depth: 0,
            prove_wall_ms: None,
            proof_bytes: None,
            error: Some(err.to_string()),
        },
    }
}

pub fn prove_auth_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let auth_transfer = programs::authenticated_transfer();
    let pwd = ProgramWithDependencies::from(auth_transfer);

    let sender_id = AccountId::new([1; 32]);
    let recipient_id = AccountId::new([2; 32]);
    let sender_account = Account {
        data: AccountData {
            balance: 1_000_000,
            ..AccountData::default()
        },
        ..Account::default()
    };

    let instruction = authenticated_transfer_core::Instruction::Transfer { amount: 5_000 };
    let instruction_data = to_vec(&instruction)?;

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            signers: [sender_id, recipient_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            instruction_data,
            ..Default::default()
        },
        &pwd,
    )?)
}

pub fn run_chain_caller(depth: u32) -> PpeBenchResult {
    let label = format!("chain_caller depth={depth}");
    let started = Instant::now();
    match prove_chain_caller(depth) {
        Ok((_out, proof)) => {
            let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
            PpeBenchResult {
                label,
                chain_depth: depth as usize,
                prove_wall_ms: Some(prove_ms),
                proof_bytes: Some(proof.into_inner().len()),
                error: None,
            }
        }
        Err(err) => PpeBenchResult {
            label,
            chain_depth: depth as usize,
            prove_wall_ms: None,
            proof_bytes: None,
            error: Some(err.to_string()),
        },
    }
}

fn prove_chain_caller(
    num_chain_calls: u32,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let chain_caller = test_programs::chain_caller();
    let chain_caller_id = chain_caller.id();
    let auth_transfer = programs::authenticated_transfer();
    let auth_transfer_id = auth_transfer.id();
    let mut deps = HashMap::new();
    deps.insert(auth_transfer.id().into(), auth_transfer);
    let pwd = ProgramWithDependencies::new(chain_caller, chain_caller_id.into(), deps);

    let recipient_id = AccountId::new([2; 32]);
    let sender_id = AccountId::new([1; 32]);
    let sender_account = Account {
        data: AccountData {
            balance: 1_000_000,
            ..AccountData::default()
        },
        ..Account::default()
    };
    // chain_caller expects shard selectors = [recipient, sender].
    let shard_selectors = vec![
        ProgramShardSelector::balance_only(recipient_id),
        ProgramShardSelector::balance_only(sender_id),
    ];

    let balance: u128 = 1;
    let pda_seed: Option<lee_core::program::PdaSeed> = None;
    let instruction = (balance, auth_transfer_id, num_chain_calls, pda_seed);
    let instruction_data = to_vec(&instruction)?;

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors,
            signers: [recipient_id, sender_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            instruction_data,
            ..Default::default()
        },
        &pwd,
    )?)
}
