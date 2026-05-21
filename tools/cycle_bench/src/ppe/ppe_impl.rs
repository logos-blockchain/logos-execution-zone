//! Feature-gated implementation of PPE composition and verify benches.

use std::{collections::HashMap, time::Instant};

use nssa::{
    execute_and_prove,
    privacy_preserving_transaction::circuit::{ProgramWithDependencies, Proof},
    program::Program,
    program_methods::PRIVACY_PRESERVING_CIRCUIT_ID,
};
use nssa_core::{
    InputAccountIdentity, PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, AccountWithMetadata},
    program::ProgramId,
};
use risc0_zkvm::{InnerReceipt, Receipt, serde::to_vec};

use super::{PpeBenchResult, VerifyBenchResult};
use crate::stats::Stats;

const AUTH_TRANSFER_ID: ProgramId = nssa::program_methods::AUTHENTICATED_TRANSFER_ID;
const AUTH_TRANSFER_ELF: &[u8] = nssa::program_methods::AUTHENTICATED_TRANSFER_ELF;

/// `chain_caller` bytecode shipped at `artifacts/test_program_methods/chain_caller.bin`.
/// Loaded at compile time so we don't need a dev-dependency on `test_program_methods`.
const CHAIN_CALLER_ELF: &[u8] =
    include_bytes!("../../../../artifacts/test_program_methods/chain_caller.bin");

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

fn prove_auth_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let program = Program::new(AUTH_TRANSFER_ELF.to_vec())?;
    let pwd = ProgramWithDependencies::from(program);

    // For PPE to allow the sender's balance to be decremented by this
    // program, the sender must already be claimed by auth_transfer.
    // Recipient stays default-owned so the first call can claim it.
    let sender = AccountWithMetadata {
        account: Account {
            program_owner: AUTH_TRANSFER_ID,
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

    let balance_to_move: u128 = 5_000;
    let instruction_data = to_vec(&balance_to_move)?;

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
    let chain_caller = Program::new(CHAIN_CALLER_ELF.to_vec())?;
    let auth_transfer = Program::new(AUTH_TRANSFER_ELF.to_vec())?;
    let mut deps = HashMap::new();
    deps.insert(AUTH_TRANSFER_ID, auth_transfer);
    let pwd = ProgramWithDependencies::new(chain_caller, deps);

    // Both accounts pre-claimed by auth_transfer. chain_caller doesn't
    // track recipient's post-claim program_owner, so a default recipient
    // would cause a state mismatch on subsequent chained calls.
    let recipient_pre = AccountWithMetadata {
        account: Account {
            program_owner: AUTH_TRANSFER_ID,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let sender_pre = AccountWithMetadata {
        account: Account {
            program_owner: AUTH_TRANSFER_ID,
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    // chain_caller expects pre_states = [recipient, sender].
    let pre_states = vec![recipient_pre, sender_pre];

    let balance: u128 = 1;
    let pda_seed: Option<nssa_core::program::PdaSeed> = None;
    let instruction = (balance, AUTH_TRANSFER_ID, num_chain_calls, pda_seed);
    let instruction_data = to_vec(&instruction)?;

    let account_identities = vec![InputAccountIdentity::Public; pre_states.len()];

    Ok(execute_and_prove(
        pre_states,
        instruction_data,
        account_identities,
        &pwd,
    )?)
}

pub fn run_verify(iters: usize) -> anyhow::Result<VerifyBenchResult> {
    eprintln!("verify: generating PPE receipt for auth_transfer Transfer (~1 prove)");
    let (output, proof) = prove_auth_transfer_in_ppe()?;
    let journal = output.to_bytes();
    let journal_bytes = journal.len();
    let proof_bytes_vec = proof.into_inner();
    let proof_bytes = proof_bytes_vec.len();

    let inner: InnerReceipt = borsh::from_slice(&proof_bytes_vec)
        .map_err(|e| anyhow::anyhow!("InnerReceipt deserialize: {e}"))?;
    let receipt = Receipt::new(inner, journal);

    // Sanity-check before the timing loop so we don't measure 1000 failures.
    receipt
        .verify(PRIVACY_PRESERVING_CIRCUIT_ID)
        .map_err(|e| anyhow::anyhow!("verify sanity check failed: {e}"))?;

    eprintln!("verify: timing {iters} iters of receipt.verify(...)");
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let started = Instant::now();
        receipt
            .verify(PRIVACY_PRESERVING_CIRCUIT_ID)
            .map_err(|e| anyhow::anyhow!("verify failed mid-loop: {e}"))?;
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    let stats = Stats::from_samples(&samples);

    Ok(VerifyBenchResult {
        label: "auth_transfer Transfer in PPE".to_owned(),
        stats,
        proof_bytes,
        journal_bytes,
    })
}
