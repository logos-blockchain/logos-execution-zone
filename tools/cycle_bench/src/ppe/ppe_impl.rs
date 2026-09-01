//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_auth_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_auth_transfer_in_ppe`).

use std::{collections::HashMap, time::Instant};

use borsh::to_vec;
use lee::{
    execute_and_prove,
    privacy_preserving_transaction::circuit::{ProgramWithDependencies, Proof},
};
use lee_core::{
    InputAccountIdentity, PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, AccountWithMetadata},
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
    let auth_transfer_id = auth_transfer.id();
    let pwd = ProgramWithDependencies::from(auth_transfer);

    // The sender's balance may only be decremented because it is authorized;
    // its owner is incidental. The recipient stays default: a credit writes no
    // data, so it acquires no owner.
    let sender = AccountWithMetadata {
        account: Account {
            program_owner: auth_transfer_id.into(),
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let recipient = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let pre_states = vec![sender, recipient];

    let instruction = authenticated_transfer_core::Instruction::Transfer { amount: 5_000 };
    let instruction_data = to_vec(&instruction)?;

    let account_identities = vec![InputAccountIdentity::Public; pre_states.len()];

    Ok(execute_and_prove(
        pre_states,
        instruction_data,
        account_identities,
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
    let auth_transfer = programs::authenticated_transfer();
    let auth_transfer_id = auth_transfer.id();
    let mut deps = HashMap::new();
    deps.insert(auth_transfer.id(), auth_transfer);
    let pwd = ProgramWithDependencies::new(chain_caller, deps);

    // Both accounts are seeded owned by auth_transfer. Nothing forces it: the
    // sender needs only its authorization to be debited, and a credit writes no
    // data, so chain_caller echoes each owner unchanged down the whole chain.
    let recipient_pre = AccountWithMetadata {
        account: Account {
            program_owner: auth_transfer_id.into(),
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let sender_pre = AccountWithMetadata {
        account: Account {
            program_owner: auth_transfer_id.into(),
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    // chain_caller expects pre_states = [recipient, sender].
    let pre_states = vec![recipient_pre, sender_pre];

    let balance: u128 = 1;
    let pda_seed: Option<lee_core::program::PdaSeed> = None;
    let instruction = (balance, auth_transfer_id, num_chain_calls, pda_seed);
    let instruction_data = to_vec(&instruction)?;

    let account_identities = vec![InputAccountIdentity::Public; pre_states.len()];

    Ok(execute_and_prove(
        pre_states,
        instruction_data,
        account_identities,
        &pwd,
    )?)
}
