//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_auth_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_auth_transfer_in_ppe`).

use std::{collections::HashMap, time::Instant};

use lee::{
    privacy_preserving_transaction::circuit::{
        ProgramWithDependencies, Proof, execute_and_prove_with_cycles,
    },
    program::Program,
};
use lee_core::{
    EphemeralPublicKey, InputAccountIdentity, NullifierPublicKey, PrivacyPreservingCircuitOutput,
    SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata},
    program::ProgramId,
};
use risc0_zkvm::serde::to_vec;

use super::PpeBenchResult;

const AUTH_TRANSFER_ID: ProgramId = lee::program_methods::AUTHENTICATED_TRANSFER_ID;
const AUTH_TRANSFER_ELF: &[u8] = lee::program_methods::AUTHENTICATED_TRANSFER_ELF;

/// `chain_caller` bytecode shipped at `artifacts/test_program_methods/chain_caller.bin`.
/// Loaded at compile time so we don't need a dev-dependency on `test_program_methods`.
const CHAIN_CALLER_ELF: &[u8] =
    include_bytes!("../../../../artifacts/test_program_methods/chain_caller.bin");

pub fn run_auth_transfer_in_ppe(private: bool) -> PpeBenchResult {
    let label = if private {
        "auth_transfer Transfer in PPE (private output)".to_owned()
    } else {
        "auth_transfer Transfer in PPE (all public)".to_owned()
    };
    let started = Instant::now();
    match prove_auth_transfer_in_ppe(private) {
        Ok((_out, proof, user_cycles)) => {
            let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
            PpeBenchResult {
                label,
                chain_depth: 0,
                prove_wall_ms: Some(prove_ms),
                proof_bytes: Some(proof.into_inner().len()),
                user_cycles: Some(user_cycles),
                error: None,
            }
        }
        Err(err) => PpeBenchResult {
            label,
            chain_depth: 0,
            prove_wall_ms: None,
            proof_bytes: None,
            user_cycles: None,
            error: Some(err.to_string()),
        },
    }
}

/// Proves an `auth_transfer` Transfer wrapped in the privacy circuit.
/// `private` flag signals whether the receiver is a private account.
pub fn prove_auth_transfer_in_ppe(
    private: bool,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof, u64)> {
    let pwd = ProgramWithDependencies::from(Program::new(AUTH_TRANSFER_ELF.to_vec())?);

    // Sender must already be claimed by auth_transfer for its balance to be debited.
    let sender = AccountWithMetadata {
        account: Account {
            program_owner: AUTH_TRANSFER_ID,
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let instruction_data =
        to_vec(&authenticated_transfer_core::Instruction::Transfer { amount: 5_000 })?;

    let (recipient, recipient_identity) = if private {
        let npk = NullifierPublicKey::from(&[2; 32]);
        let recipient = AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: AccountId::for_regular_private_account(&npk, 0),
        };
        let identity = InputAccountIdentity::PrivateUnauthorized {
            epk: EphemeralPublicKey(Vec::new()),
            view_tag: 0,
            npk,
            ssk: SharedSecretKey([3; 32]),
            identifier: 0,
        };
        (recipient, identity)
    } else {
        // Recipient stays default-owned so the first call can claim it.
        let recipient = AccountWithMetadata {
            account: Account::default(),
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        };
        (recipient, InputAccountIdentity::Public)
    };

    Ok(execute_and_prove_with_cycles(
        vec![sender, recipient],
        instruction_data,
        vec![InputAccountIdentity::Public, recipient_identity],
        &pwd,
    )?)
}

pub fn run_chain_caller(depth: u32) -> PpeBenchResult {
    let label = format!("chain_caller depth={depth}");
    let started = Instant::now();
    match prove_chain_caller(depth) {
        Ok((_out, proof, user_cycles)) => {
            let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
            PpeBenchResult {
                label,
                chain_depth: depth as usize,
                prove_wall_ms: Some(prove_ms),
                proof_bytes: Some(proof.into_inner().len()),
                user_cycles: Some(user_cycles),
                error: None,
            }
        }
        Err(err) => PpeBenchResult {
            label,
            chain_depth: depth as usize,
            prove_wall_ms: None,
            proof_bytes: None,
            user_cycles: None,
            error: Some(err.to_string()),
        },
    }
}

fn prove_chain_caller(
    num_chain_calls: u32,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof, u64)> {
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
    let pda_seed: Option<lee_core::program::PdaSeed> = None;
    let instruction = (balance, AUTH_TRANSFER_ID, num_chain_calls, pda_seed);
    let instruction_data = to_vec(&instruction)?;

    let account_identities = vec![InputAccountIdentity::Public; pre_states.len()];

    Ok(execute_and_prove_with_cycles(
        pre_states,
        instruction_data,
        account_identities,
        &pwd,
    )?)
}
