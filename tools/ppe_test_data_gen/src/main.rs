//! Generates LEZ privacy-preserving execution (PPE) proof fixtures for aggregation testing.
//!
//! Each fixture bundles a `PrivacyPreservingCircuitOutput` (serialised with risc0 serde via
//! `to_bytes()`) and the raw `InnerReceipt` bytes (Borsh-encoded, from `Proof::into_inner()`).
//! The whole bundle is a Borsh-encoded `Vec<PpeFixture>`.
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
    execute_and_prove, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use lee_core::{
    InputAccountIdentity, NullifierPublicKey, SharedSecretKey,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::ViewingPublicKey,
};

/// Mirror of `test_program_methods::PpeFixture`. Borsh field order must stay in sync.
#[derive(BorshSerialize, BorshDeserialize)]
struct PpeFixture {
    label: String,
    output_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
}

#[derive(Parser)]
#[command(
    name = "ppe_test_data_gen",
    about = "Generate PPE proof fixtures for aggregation testing"
)]
struct Cli {
    /// Output file path for the Borsh-serialised fixture bundle.
    #[arg(long, default_value = "ppe_fixtures.bin")]
    output: PathBuf,

    /// Number of independent PPE proofs to generate.
    #[arg(long, default_value_t = 16)]
    count: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let program = Program::authenticated_transfer_program();
    let mut fixtures: Vec<PpeFixture> = Vec::with_capacity(cli.count);

    for i in 0..cli.count {
        let lo = (i & 0xFF) as u8;
        let hi = ((i >> 8) & 0xFF) as u8;

        // Non-zero bases ensure no key is accidentally all-zero.
        let mut nsk = [41_u8; 32];
        nsk[0] = lo;
        nsk[1] = hi;

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
        let npk = NullifierPublicKey::from(&nsk);
        // `encapsulate_deterministic` requires `lee_core` with `test_utils` feature.
        // The recipient output is at index 0 (the only private output in this scenario).
        let (ssk, _epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &msg, 0);

        let mut sender_seed = [45_u8; 32];
        sender_seed[0] = lo;
        sender_seed[1] = hi;

        let sender = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: amount + 10,
                ..Account::default()
            },
            true,
            AccountId::new(sender_seed),
        );
        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            AccountId::for_regular_private_account(&npk, 0),
        );

        let instruction =
            Program::serialize_instruction(Instruction::Transfer { amount })
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

        let proof_bytes = proof.into_inner();
        let output_bytes = output.to_bytes();

        eprintln!(
            "[ppe_test_data_gen]   proof={} B  output={} B  commitments={}  ciphertexts={}",
            proof_bytes.len(),
            output_bytes.len(),
            output.new_commitments.len(),
            output.ciphertexts.len(),
        );

        fixtures.push(PpeFixture {
            label,
            output_bytes,
            proof_bytes,
        });
    }

    let bundle = borsh::to_vec(&fixtures).context("serialise fixture bundle")?;
    std::fs::write(&cli.output, &bundle).context("write output file")?;

    eprintln!(
        "[ppe_test_data_gen] wrote {} fixtures ({} bytes total) -> {}",
        fixtures.len(),
        bundle.len(),
        cli.output.display(),
    );

    Ok(())
}
