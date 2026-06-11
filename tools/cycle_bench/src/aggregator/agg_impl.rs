//! Feature-gated implementation of aggregator circuit benches.
//!
//! ELFs are loaded at runtime from `artifacts/program_methods/` so this module
//! compiles even before a full RISC0 build. If the ELFs are not present, each
//! bench run reports an error rather than panicking.

use std::{path::PathBuf, time::Instant};

use authenticated_transfer_core::Instruction;
use lee::{
    PrivacyPreservingTransaction, PrivateKey, PublicKey, V03State,
    aggregator_circuit::aggregate,
    execute_and_prove,
    privacy_preserving_transaction::{
        circuit::ProgramWithDependencies, message::Message, witness_set::WitnessSet,
    },
    program::Program,
    program_methods::{AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID},
};
use lee_core::{
    BlockId, InputAccountIdentity, NullifierPublicKey, SharedSecretKey, Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    encryption::ViewingPublicKey,
};
use risc0_zkvm::serde::to_vec;

use super::AggregatorBenchResult;

/// Loads an aggregator ELF from `artifacts/program_methods/{name}.bin` at runtime.
fn load_aggregator_elf(name: &str) -> anyhow::Result<Vec<u8>> {
    let artifacts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("artifacts/program_methods");
    let path = artifacts.join(format!("{name}.bin"));
    std::fs::read(&path).map_err(|e| {
        anyhow::anyhow!(
            "aggregator ELF not found at {}: {e}\n\
             Run a full RISC0 build (without RISC0_SKIP_BUILD=1) to generate it.",
            path.display()
        )
    })
}

/// Derives a deterministic, valid `PrivateKey` for sender `tag`.
///
/// Only `seed[0]` varies; the remaining bytes are fixed at `50`, which keeps the
/// resulting 256-bit big-endian value comfortably below the secp256k1 curve order for
/// any `tag`, so the key is always valid.
fn sender_signing_key(tag: u8) -> PrivateKey {
    let mut seed = [50_u8; 32];
    seed[0] = tag;
    PrivateKey::try_new(seed).expect("deterministic seed should be a valid private key")
}

/// Generates a public-to-private (shielded) auth-transfer pp-transaction.
///
/// The sender is a public account whose id is derived from a real signing key, so the
/// resulting transaction's signature matches its `message.public_account_ids`; the
/// recipient is a fresh private account derived from `tag`. Distinct tags yield distinct
/// `npk` values → distinct commitments and nullifiers, so any number of these
/// transactions can be safely aggregated in one batch.
fn prove_shielded_transfer(tag: u8) -> anyhow::Result<(AccountId, PrivacyPreservingTransaction)> {
    let nsk: [u8; 32] = [tag; 32];
    let d: [u8; 32] = [tag.wrapping_add(64); 32];
    let z: [u8; 32] = [tag.wrapping_add(128); 32];

    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&d, &z);
    let (ssk, epk) = SharedSecretKey::encapsulate(&vpk);

    let recipient_account_id = AccountId::for_regular_private_account(&npk, 0);

    let signing_key = sender_signing_key(tag);
    let sender_account_id = AccountId::from(&PublicKey::new_from_private_key(&signing_key));

    let program = Program::new(AUTHENTICATED_TRANSFER_ELF.to_vec())?;
    let pwd = ProgramWithDependencies::from(program);

    // Public sender with sufficient balance; unique account ID per tag so the
    // strict aggregator's public-account-uniqueness check passes.
    let sender = AccountWithMetadata {
        account: Account {
            program_owner: AUTHENTICATED_TRANSFER_ID,
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: sender_account_id,
    };

    // Fresh private recipient account (zero balance, not yet authorized).
    let recipient = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: recipient_account_id,
    };

    let instruction_data = to_vec(&Instruction::Transfer { amount: 1_000 })?;
    let identities = vec![
        InputAccountIdentity::Public,
        InputAccountIdentity::PrivateUnauthorized {
            npk,
            ssk,
            identifier: 0,
        },
    ];

    let (output, proof) = execute_and_prove(vec![sender, recipient], instruction_data, identities, &pwd)?;

    let message = Message::try_from_circuit_output(
        vec![sender_account_id],
        vec![Nonce(0)],
        vec![(npk, vpk, epk)],
        output,
    )?;
    let witness_set = WitnessSet::for_message(&message, proof, &[&signing_key]);

    Ok((
        sender_account_id,
        PrivacyPreservingTransaction::new(message, witness_set),
    ))
}

pub fn run(n_txs: usize, strict: bool) -> AggregatorBenchResult {
    let elf_name = if strict {
        "aggregator_circuit_strict"
    } else {
        "aggregator_circuit"
    };
    let label = format!(
        "aggregator_{} n={n_txs}",
        if strict { "strict" } else { "core" }
    );

    let elf = match load_aggregator_elf(elf_name) {
        Ok(bytes) => bytes,
        Err(e) => {
            return AggregatorBenchResult {
                label,
                n_txs,
                strict,
                pp_prove_ms: None,
                agg_prove_ms: None,
                agg_proof_bytes: None,
                pp_proof_bytes_per_tx: None,
                error: Some(e.to_string()),
            };
        }
    };

    // Generate N pp-transactions with distinct private recipients (tags 1..=N).
    let pp_started = Instant::now();
    let txs: Result<Vec<_>, anyhow::Error> = (0..n_txs)
        .map(|i| prove_shielded_transfer(u8::try_from(i + 1).unwrap_or(u8::MAX)))
        .collect();
    let pp_prove_ms = pp_started.elapsed().as_secs_f64() * 1_000.0;

    let txs = match txs {
        Ok(t) => t,
        Err(e) => {
            return AggregatorBenchResult {
                label,
                n_txs,
                strict,
                pp_prove_ms: Some(pp_prove_ms),
                agg_prove_ms: None,
                agg_proof_bytes: None,
                pp_proof_bytes_per_tx: None,
                error: Some(e.to_string()),
            };
        }
    };

    // Capture per-tx proof size before the vec is consumed by aggregate().
    let pp_proof_bytes_per_tx = txs
        .first()
        .map(|(_, tx)| tx.witness_set().proof().clone().into_inner().len());

    let block_id: BlockId = 1;
    let timestamp = Timestamp::from(1_700_000_000_u64);

    // Genesis state containing each sender's public account, matching the balance used
    // when proving its transaction.
    let genesis_accounts: Vec<(AccountId, u128)> = txs
        .iter()
        .map(|(account_id, _)| (*account_id, 1_000_000))
        .collect();
    let state = V03State::new_with_genesis_accounts(&genesis_accounts, vec![], timestamp);
    let transactions: Vec<PrivacyPreservingTransaction> =
        txs.into_iter().map(|(_, tx)| tx).collect();

    let agg_started = Instant::now();
    let result = aggregate(block_id, timestamp, transactions, &state, &elf, None);
    let agg_prove_ms = agg_started.elapsed().as_secs_f64() * 1_000.0;

    match result {
        Ok((_output, agg_proof)) => AggregatorBenchResult {
            label,
            n_txs,
            strict,
            pp_prove_ms: Some(pp_prove_ms),
            agg_prove_ms: Some(agg_prove_ms),
            agg_proof_bytes: Some(agg_proof.into_inner().len()),
            pp_proof_bytes_per_tx,
            error: None,
        },
        Err(e) => AggregatorBenchResult {
            label,
            n_txs,
            strict,
            pp_prove_ms: Some(pp_prove_ms),
            agg_prove_ms: Some(agg_prove_ms),
            agg_proof_bytes: None,
            pp_proof_bytes_per_tx,
            error: Some(e.to_string()),
        },
    }
}
