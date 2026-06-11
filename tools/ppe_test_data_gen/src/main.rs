//! Generates LEZ privacy-preserving execution (PPE) proof fixtures for aggregation testing.
//!
//! Each fixture bundles a `PrivacyPreservingCircuitOutput` (serialised with risc0 serde via
//! `to_bytes()`) and the raw `InnerReceipt` bytes (Borsh-encoded, from `Proof::into_inner()`).
//! The whole bundle is a Borsh-encoded `Vec<PpeFixture>`.
//!
//! Each proof is also wrapped into a `PrivacyPreservingTransaction` (signed by a real key)
//! together with the genesis `V03State` its sender accounts were proven against, and written
//! as a `PpeTxFixtureBundle` for the aggregator circuit's host-side pre-checks.
//!
//! Keys are derived deterministically from the proof index so the fixture file is
//! reproducible.
//! # Usage
//!
//! ```sh
//! # Fast mock proofs — good for iteration:
//! RISC0_DEV_MODE=1 cargo run --release -p ppe_test_data_gen -- --output ppe_fixtures.bin
//!
//! # Real STARK proofs (slow, production-quality):
//! cargo run --release -p ppe_test_data_gen -- --output ppe_fixtures.bin
//! ```
//!
//! # Loading fixtures in aggregation code
//!
//! ```rust,ignore
//! let bytes = std::fs::read("ppe_fixtures.bin").unwrap();
//! let fixtures: Vec<PpeFixture> = borsh::from_slice(&bytes).unwrap();
//!
//! for f in &fixtures {
//!     // Decode the circuit output:
//!     let words: &[u32] = bytemuck::cast_slice(&f.output_bytes);
//!     let output: PrivacyPreservingCircuitOutput =
//!         risc0_zkvm::serde::from_slice(words).unwrap();
//!
//!     // Reconstruct the Receipt for use as an aggregation assumption:
//!     let inner: risc0_zkvm::InnerReceipt = borsh::from_slice(&f.proof_bytes).unwrap();
//!     let receipt = risc0_zkvm::Receipt::new(inner, output.to_bytes());
//! }
//! ```

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    reason = "CLI tool — intentional index-to-byte casts, counter arithmetic, and diagnostic output"
)]

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use authenticated_transfer_core::Instruction;
use borsh::{BorshDeserialize, BorshSerialize};
use clap::Parser;
use lee::{
    PrivacyPreservingTransaction, PrivateKey, PublicKey, V03State, execute_and_prove,
    privacy_preserving_transaction::{
        circuit::ProgramWithDependencies,
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    InputAccountIdentity, NullifierPublicKey, SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    encryption::ViewingPublicKey,
};

/// Block id and timestamp the generated transactions' validity windows and nonces are
/// proven/checked against, matching the values used by `bench_aggregator`.
const BLOCK_ID: u64 = 1;
const TIMESTAMP: u64 = 1_700_000_000;

/// Mirror of `test_program_methods::PpeFixture`. Borsh field order must stay in sync.
#[derive(BorshSerialize, BorshDeserialize)]
struct PpeFixture {
    label: String,
    output_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
}

/// Mirror of `test_program_methods::PpeTxFixtureBundle`. Borsh field order must stay in sync.
#[derive(BorshSerialize, BorshDeserialize)]
struct PpeTxFixtureBundle {
    block_id: u64,
    timestamp: u64,
    labels: Vec<String>,
    state_bytes: Vec<u8>,
    tx_bytes: Vec<Vec<u8>>,
}

#[derive(Parser)]
#[command(
    name = "ppe_test_data_gen",
    about = "Generate PPE proof fixtures for aggregation testing"
)]
struct Cli {
    /// Output file path for the Borsh-serialised `Vec<PpeFixture>` bundle.
    #[arg(long, default_value = "ppe_fixtures.bin")]
    output: PathBuf,

    /// Output file path for the Borsh-serialised `PpeTxFixtureBundle`.
    #[arg(long, default_value = "ppe_tx_fixtures.bin")]
    tx_output: PathBuf,

    /// Number of independent PPE proofs to generate.
    #[arg(long, default_value_t = 16)]
    count: usize,
}

/// Derives a deterministic, valid `PrivateKey` for proof index `i`.
///
/// Only `seed[0]` and `seed[1]` vary; the remaining bytes are fixed at `50`, which keeps
/// the resulting 256-bit big-endian value comfortably below the secp256k1 curve order for
/// any `seed[0]`/`seed[1]`, so the key is always valid.
fn sender_signing_key(i: usize) -> PrivateKey {
    let mut seed = [50_u8; 32];
    seed[0] = (i & 0xFF) as u8;
    seed[1] = ((i >> 8) & 0xFF) as u8;
    PrivateKey::try_new(seed).expect("deterministic seed should be a valid private key")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let program = Program::authenticated_transfer_program();
    let mut fixtures: Vec<PpeFixture> = Vec::with_capacity(cli.count);
    let mut tx_labels: Vec<String> = Vec::with_capacity(cli.count);
    let mut transactions: Vec<PrivacyPreservingTransaction> = Vec::with_capacity(cli.count);
    let mut genesis_accounts: Vec<(AccountId, u128)> = Vec::with_capacity(cli.count);

    for i in 0..cli.count {
        let lo = (i & 0xFF) as u8;
        let hi = ((i >> 8) & 0xFF) as u8;

        // ViewingPublicKey requires two independent 32-byte seed halves (d, z).
        let mut d = [42_u8; 32];
        d[0] = lo;
        d[1] = hi;
        let mut z = [43_u8; 32];
        z[0] = lo;
        z[1] = hi;

        // The message hash used for deterministic encapsulation; vary it per proof index.
        let mut msg = [44_u8; 32];
        msg[0] = lo;
        msg[1] = hi;

        let amount: u128 = 100;
        let label = format!("public_to_private_{i}");

        let vpk = ViewingPublicKey::from_seed(&d, &z);

        // Recipient: fresh private account derived from this proof's index.
        let mut nsk = [41_u8; 32];
        nsk[0] = lo;
        nsk[1] = hi;
        let npk = NullifierPublicKey::from(&nsk);
        // `encapsulate_deterministic` requires `lee_core` with `test_utils` feature.
        // The recipient output is at index 0 (the only private output in this scenario).
        let (ssk, epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &msg, 0);

        // Sender: public account whose id is derived from a real signing key, so the
        // transaction's signature matches `message.public_account_ids`.
        let signing_key = sender_signing_key(i);
        let sender_account_id = AccountId::from(&PublicKey::new_from_private_key(&signing_key));

        let sender = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: amount + 10,
                ..Account::default()
            },
            true,
            sender_account_id,
        );
        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            AccountId::for_regular_private_account(&npk, 0),
        );

        let instruction = Program::serialize_instruction(Instruction::Transfer { amount })
            .context("serialise instruction")?;

        eprintln!(
            "[ppe_test_data_gen] ({}/{}) proving '{label}' ...",
            i + 1,
            cli.count,
        );

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            instruction,
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::PrivateUnauthorized {
                    npk,
                    ssk,
                    identifier: 0,
                },
            ],
            &ProgramWithDependencies::from(program.clone()),
        )
        .with_context(|| format!("execute_and_prove for '{label}'"))?;

        let proof_bytes = proof.clone().into_inner();
        let output_bytes = output.to_bytes();

        eprintln!(
            "[ppe_test_data_gen]   proof={} B  output={} B  commitments={}  ciphertexts={}",
            proof_bytes.len(),
            output_bytes.len(),
            output.new_commitments.len(),
            output.ciphertexts.len(),
        );

        fixtures.push(PpeFixture {
            label: label.clone(),
            output_bytes,
            proof_bytes,
        });

        let message = Message::try_from_circuit_output(
            vec![sender_account_id],
            vec![Nonce(0)],
            vec![(npk, vpk, epk)],
            output,
        )
        .with_context(|| format!("build message for '{label}'"))?;
        let witness_set = WitnessSet::for_message(&message, proof, &[&signing_key]);

        transactions.push(PrivacyPreservingTransaction::new(message, witness_set));
        genesis_accounts.push((sender_account_id, amount + 10));
        tx_labels.push(label);
    }

    let bundle = borsh::to_vec(&fixtures).context("serialise fixture bundle")?;
    std::fs::write(&cli.output, &bundle).context("write output file")?;

    eprintln!(
        "[ppe_test_data_gen] wrote {} fixtures ({} bytes total) -> {}",
        fixtures.len(),
        bundle.len(),
        cli.output.display(),
    );

    let state = V03State::new_with_genesis_accounts(&genesis_accounts, vec![], TIMESTAMP);
    let tx_bundle = PpeTxFixtureBundle {
        block_id: BLOCK_ID,
        timestamp: TIMESTAMP,
        labels: tx_labels,
        state_bytes: borsh::to_vec(&state).context("serialise genesis state")?,
        tx_bytes: transactions
            .iter()
            .map(borsh::to_vec)
            .collect::<Result<_, _>>()
            .context("serialise transactions")?,
    };
    let tx_bundle_bytes = borsh::to_vec(&tx_bundle).context("serialise tx fixture bundle")?;
    std::fs::write(&cli.tx_output, &tx_bundle_bytes).context("write tx output file")?;

    eprintln!(
        "[ppe_test_data_gen] wrote {} transactions ({} bytes total) -> {}",
        tx_bundle.tx_bytes.len(),
        tx_bundle_bytes.len(),
        cli.tx_output.display(),
    );

    Ok(())
}
