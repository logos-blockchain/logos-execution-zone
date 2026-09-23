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
    account::{Account, AccountId, ProgramShardSelector, data::ShardData},
};
use test_guest_core::ChainCall;
use token_core::TokenHolding;

use super::PpeBenchResult;

const TOKEN_DEFINITION_ID: AccountId = AccountId::new([15; 32]);
const SENDER_ID: AccountId = AccountId::new([17; 32]);
const RECIPIENT_ID: AccountId = AccountId::new([42; 32]);
const SENDER_BALANCE: u128 = 100_000;
const RECIPIENT_BALANCE: u128 = 50_000;
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
    let sender_account = Account::funded(1_000_000);

    let instruction = lee_core::native_token::Instruction::Transfer { amount: 5_000 };
    let instruction_data = to_vec(&instruction)?;

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance(sender_id),
                ProgramShardSelector::balance(recipient_id),
            ],
            signers: [sender_id, recipient_id].into(),
            public_accounts: [(sender_id, sender_account)].into(),
            instruction_data,
            ..Default::default()
        },
        &pwd,
    )?)
}

pub fn run_token_transfer_in_ppe() -> PpeBenchResult {
    timed(
        "token Transfer in PPE".to_owned(),
        0,
        prove_token_transfer_in_ppe,
    )
}

fn token_program_id() -> AccountId {
    AccountId::from_builtin_program(programs::token().id())
}

fn token_holding(balance: u128) -> Account {
    Account::default().with_shard(
        token_program_id(),
        ShardData::from(&TokenHolding::Fungible {
            definition_id: TOKEN_DEFINITION_ID,
            balance,
        }),
    )
}

fn token_transfer_instruction() -> anyhow::Result<Vec<u8>> {
    Ok(to_vec(&token_core::Instruction::Transfer {
        amount_to_transfer: AMOUNT_TO_TRANSFER,
    })?)
}

fn prove_token_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let token = programs::token();
    let token_id = token_program_id();
    let pwd = ProgramWithDependencies::new(token, token_id, HashMap::new());

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(SENDER_ID, token_id),
                ProgramShardSelector::new(RECIPIENT_ID, token_id),
            ],
            signers: [SENDER_ID, RECIPIENT_ID].into(),
            public_accounts: [
                (SENDER_ID, token_holding(SENDER_BALANCE)),
                (RECIPIENT_ID, token_holding(RECIPIENT_BALANCE)),
            ]
            .into(),
            instruction_data: token_transfer_instruction()?,
            ..Default::default()
        },
        &pwd,
    )?)
}

pub fn run_chain_caller(depth: u32) -> PpeBenchResult {
    timed(
        format!("chain_caller to token Transfer depth={depth}"),
        depth as usize,
        || prove_chain_caller(depth),
    )
}

fn prove_chain_caller(
    num_chain_calls: u32,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let chain_caller = test_programs::chain_caller();
    let chain_caller_id = chain_caller.id();
    let token_id = token_program_id();
    let pwd = ProgramWithDependencies::new(
        chain_caller,
        AccountId::from_builtin_program(chain_caller_id),
        [(token_id, programs::token())].into(),
    );

    // chain_caller expects shard selectors = [recipient, sender].
    let shard_selectors = vec![
        ProgramShardSelector::new(RECIPIENT_ID, token_id),
        ProgramShardSelector::new(SENDER_ID, token_id),
    ];

    let instruction =
        ChainCall::new(token_id, token_transfer_instruction()?).repeated(num_chain_calls);
    let instruction_data = to_vec(&instruction)?;

    Ok(execute_and_prove(
        ProvingInput {
            shard_selectors,
            signers: [RECIPIENT_ID, SENDER_ID].into(),
            public_accounts: [
                (SENDER_ID, token_holding(SENDER_BALANCE)),
                (RECIPIENT_ID, token_holding(RECIPIENT_BALANCE)),
            ]
            .into(),
            instruction_data,
            ..Default::default()
        },
        &pwd,
    )?)
}
