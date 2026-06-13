//! Host program for the aggregation circuit. Multiple privacy
//! preserving transaction proofs are compressed into a single
//! zk-STARK.

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, SequencerAggregatorOutput,
    Timestamp,
    account::{AccountId, AccountWithMetadata},
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PRIVACY_PRESERVING_CIRCUIT_ID, PrivacyPreservingTransaction, error::LeeError,
    privacy_preserving_transaction::message::Message,
};

/// Converts `message` into its `lee_core`-resident mirror for the guest circuit.
/// `epk` is not necessary for guest program, and its inclusion increases the number of
/// cycles by (approximately) a million.
fn to_aggregator_message(message: &Message) -> lee_core::message::Message {
    lee_core::message::Message {
        public_account_ids: message.public_account_ids.clone(),
        nonces: message.nonces.clone(),
        public_post_states: message.public_post_states.clone(),
        encrypted_private_post_states: message
            .encrypted_private_post_states
            .iter()
            .map(|data| lee_core::message::EncryptedAccountData {
                ciphertext: data.ciphertext.clone(),
                view_tag: data.view_tag,
            })
            .collect(),
        new_commitments: message.new_commitments.clone(),
        new_nullifiers: message.new_nullifiers.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
    }
}

/// Filters `input_txs` down to the subset that can be aggregated together in one batch.
///
/// `public_pre_states[i]` must be the resolved `AccountWithMetadata` for each of
/// `input_txs[i].message().public_account_ids`, in the same order (i.e. the
/// `public_pre_states` of the `PrivacyPreservingCircuitOutput` `input_txs[i]`'s proof was
/// generated for).
///
/// A transaction is dropped if it reuses a nullifier or commitment already claimed earlier in
/// the batch, or updates a public account already updated earlier in the batch. The guest
/// re-asserts these same checks as defense-in-depth.
///
/// Returns the surviving transactions, each paired with its `lee_core`-resident message and
/// the `PrivacyPreservingCircuitOutput` its proof commits to, in input order.
fn select_aggregatable_transactions(
    input_txs: Vec<PrivacyPreservingTransaction>,
    public_pre_states: Vec<Vec<AccountWithMetadata>>,
) -> Vec<(
    PrivacyPreservingTransaction,
    lee_core::message::Message,
    PrivacyPreservingCircuitOutput,
)> {
    let mut accepted = Vec::new();
    let mut seen_nullifiers: Vec<Nullifier> = Vec::new();
    let mut seen_commitments: Vec<Commitment> = Vec::new();
    let mut seen_updated_account_ids: Vec<AccountId> = Vec::new();

    for (tx, pre_states) in input_txs.into_iter().zip(public_pre_states) {
        let message = to_aggregator_message(tx.message());
        let circuit_output = message.clone().into_circuit_output(pre_states);

        let updated_account_ids: Vec<AccountId> = circuit_output
            .public_pre_states
            .iter()
            .zip(&circuit_output.public_post_states)
            .filter(|(pre_state, post_state)| pre_state.account != **post_state)
            .map(|(pre_state, _)| pre_state.account_id)
            .collect();

        let has_duplicate_nullifier = circuit_output
            .new_nullifiers
            .iter()
            .any(|(nullifier, _)| seen_nullifiers.contains(nullifier));
        let has_duplicate_commitment = circuit_output
            .new_commitments
            .iter()
            .any(|commitment| seen_commitments.contains(commitment));
        let has_duplicate_account_update = updated_account_ids
            .iter()
            .any(|account_id| seen_updated_account_ids.contains(account_id));

        if has_duplicate_nullifier || has_duplicate_commitment || has_duplicate_account_update {
            continue;
        }

        seen_nullifiers.extend(circuit_output.new_nullifiers.iter().map(|(n, _)| *n));
        seen_commitments.extend(circuit_output.new_commitments.iter().cloned());
        seen_updated_account_ids.extend(updated_account_ids);

        accepted.push((tx, message, circuit_output));
    }

    accepted
}

/// Runs the sequencer aggregator guest over `input_txs`.
///
/// `public_pre_states[i]` must be the resolved `AccountWithMetadata` for each of
/// `input_txs[i].message().public_account_ids`, in the same order (see
/// [`select_aggregatable_transactions`]).
///
/// `input_txs` is first filtered down via [`select_aggregatable_transactions`]; only the
/// surviving transactions are proven against. For each surviving transaction, the host adds
/// its proof as a recursive assumption against the `PrivacyPreservingCircuitOutput` it
/// commits to. The guest redoes the same reconstruction from the mirrored message and
/// `public_pre_states`, verifies each proof via `env::verify`, checks nullifier/commitment/
/// account-update uniqueness and `block_id`/`timestamp` validity windows across the batch,
/// and commits the verified messages alongside `block_id`/`timestamp` as the journal.
///
/// `segment_limit_po2`, if set, caps each segment to `2^segment_limit_po2` cycles (see
/// [`risc0_zkvm::ExecutorEnvBuilder::segment_limit_po2`]).
///
/// Returns the aggregated journal alongside the Borsh-encoded aggregation proof
/// (`prove_info.receipt.inner`).
pub fn aggregate(
    input_txs: Vec<PrivacyPreservingTransaction>,
    public_pre_states: Vec<Vec<AccountWithMetadata>>,
    block_id: BlockId,
    timestamp: Timestamp,
    segment_limit_po2: Option<u32>, // Included due to hardware limitations.
    elf: &[u8],
) -> Result<(SequencerAggregatorOutput, Vec<u8>), LeeError> {
    crate::ensure!(
        input_txs.len() == public_pre_states.len(),
        LeeError::InvalidInput("transactions and public pre-states length mismatch".into())
    );

    let accepted = select_aggregatable_transactions(input_txs, public_pre_states);

    let mut env_builder = ExecutorEnv::builder();
    if let Some(po2) = segment_limit_po2 {
        env_builder.segment_limit_po2(po2);
    }

    let mut messages = Vec::with_capacity(accepted.len());
    let mut verified_pre_states = Vec::with_capacity(accepted.len());
    for (tx, message, circuit_output) in accepted {
        let proof_bytes = tx.witness_set().proof().clone().into_inner();
        let inner: InnerReceipt = borsh::from_slice(&proof_bytes)?;

        env_builder.add_assumption(Receipt::new(inner, circuit_output.to_bytes()));
        messages.push(message);
        verified_pre_states.push(circuit_output.public_pre_states);
    }

    env_builder
        .write(&PRIVACY_PRESERVING_CIRCUIT_ID)
        .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
    env_builder
        .write(&block_id)
        .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
    env_builder
        .write(&timestamp)
        .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
    env_builder
        .write(&messages)
        .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
    env_builder
        .write(&verified_pre_states)
        .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
    let env = env_builder.build().unwrap();

    let prove_info = default_prover()
        .prove_with_opts(env, elf, &ProverOpts::succinct())
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let output = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;
    let proof = borsh::to_vec(&prove_info.receipt.inner)?;

    Ok((output, proof))
}

#[cfg(test)]
pub(crate) mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        reason = "test transaction generator — deterministic index arithmetic and balance math"
    )]
    #![expect(
        clippy::print_stderr,
        reason = "test transaction cache reports hits/misses for local iteration"
    )]

    use authenticated_transfer_core::Instruction;
    use lee_core::{
        InputAccountIdentity, NullifierPublicKey, PrivacyPreservingCircuitOutput,
        SharedSecretKey,
        account::{Account, AccountId, AccountWithMetadata, Nonce},
        encryption::ViewingPublicKey,
    };
    use risc0_zkvm::serde::from_slice;
    use test_program_methods::SEQUENCER_AGGREGATOR_ELF;

    use super::*;
    use crate::{
        PrivateKey, PublicKey, V03State, execute_and_prove,
        privacy_preserving_transaction::{
            circuit::ProgramWithDependencies, message::Message, witness_set::WitnessSet,
        },
        program::Program,
    };

    /// Block id and timestamp the generated transactions' validity windows and nonces are
    /// proven/checked against.
    const TIMESTAMP: u64 = 1_700_000_000;

    /// Derives a deterministic, valid `PrivateKey` for transaction index `i`.
    ///
    /// Only `seed[0]` and `seed[1]` vary; the remaining bytes are fixed at `50`, which keeps
    /// the resulting 256-bit big-endian value comfortably below the secp256k1 curve order
    /// for any `seed[0]`/`seed[1]`, so the key is always valid.
    fn sender_signing_key(i: usize) -> PrivateKey {
        let (lo, hi) = index_bytes(i);
        let mut seed = [50_u8; 32];
        seed[0] = lo;
        seed[1] = hi;
        PrivateKey::try_new(seed).expect("deterministic seed should be a valid private key")
    }

    /// Splits `i` into its low and high byte, for use as deterministic seed variation.
    fn index_bytes(i: usize) -> (u8, u8) {
        let lo = u8::try_from(i & 0xFF).expect("masked value fits in u8");
        let hi = u8::try_from((i >> 8) & 0xFF).expect("masked value fits in u8");
        (lo, hi)
    }

    /// Generates `count` independent "public sender -> private recipient" transfers, each
    /// proven through the privacy-preserving execution circuit, plus the genesis
    /// `V03State` their sender accounts were proven against.
    pub(crate) fn generate_test_transactions(
        count: usize,
    ) -> (
        V03State,
        Vec<PrivacyPreservingTransaction>,
        Vec<PrivacyPreservingCircuitOutput>,
    ) {
        let program = Program::authenticated_transfer_program();
        let mut transactions = Vec::with_capacity(count);
        let mut circuit_outputs = Vec::with_capacity(count);
        let mut genesis_accounts = Vec::with_capacity(count);

        for i in 0..count {
            let (lo, hi) = index_bytes(i);

            // ViewingPublicKey requires two independent 32-byte seed halves (d, z).
            let mut d = [42_u8; 32];
            d[0] = lo;
            d[1] = hi;
            let mut z = [43_u8; 32];
            z[0] = lo;
            z[1] = hi;

            // The message hash used for deterministic encapsulation; vary it per index.
            let mut msg = [44_u8; 32];
            msg[0] = lo;
            msg[1] = hi;

            let amount: u128 = 100;
            let vpk = ViewingPublicKey::from_seed(&d, &z);

            // Recipient: fresh private account derived from this transaction's index.
            let mut nsk = [41_u8; 32];
            nsk[0] = lo;
            nsk[1] = hi;
            let npk = NullifierPublicKey::from(&nsk);
            let (ssk, epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &msg, 0);

            // Sender: public account whose id is derived from a real signing key, so the
            // transaction's signature matches `message.public_account_ids`.
            let signing_key = sender_signing_key(i);
            let sender_account_id =
                AccountId::from(&PublicKey::new_from_private_key(&signing_key));

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
                .expect("serialize instruction");

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
            .expect("execute_and_prove");

            // `output` is consumed by `try_from_circuit_output` below; keep its bytes so
            // we can hand the same circuit output to `aggregate` alongside the tx.
            let output_bytes = output.to_bytes();

            let message = Message::try_from_circuit_output(
                vec![sender_account_id],
                vec![Nonce(0)],
                vec![(npk, vpk, epk)],
                output,
            )
            .expect("build message from circuit output");
            let witness_set = WitnessSet::for_message(&message, proof, &[&signing_key]);

            transactions.push(PrivacyPreservingTransaction::new(message, witness_set));
            let output_words: &[u32] = bytemuck::cast_slice(&output_bytes);
            circuit_outputs
                .push(from_slice(output_words).expect("decode circuit output bytes"));
            genesis_accounts.push((sender_account_id, amount + 10));
        }

        let state = V03State::new_with_genesis_accounts(&genesis_accounts, vec![], TIMESTAMP);
        (state, transactions, circuit_outputs)
    }

    /// Maximum number of transactions [`bench_sequencer_aggregator`] loads/generates.
    ///
    /// `AGGREGATOR_COUNT` truncates down from this, so bumping it regenerates
    /// [`BENCH_TRANSACTIONS_CACHE_PATH`] (a one-time cost — see
    /// [`load_or_generate_test_transactions`]).
    const BENCH_MAX_TRANSACTIONS: usize = 16;

    /// Path to a Borsh-encoded cache of [`generate_test_transactions`]'s output, used by
    /// [`bench_sequencer_aggregator`].
    ///
    /// TEMPORARY: avoids re-running `execute_and_prove` on every test invocation while
    /// this circuit is under active development. Remove this caching (and the cache
    /// file) once the host/guest design has stabilized.
    const BENCH_TRANSACTIONS_CACHE_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/sequencer_aggregator_bench_transactions.bin"
    );

    /// Like [`generate_test_transactions`], but reuses a Borsh-encoded cache from disk
    /// when one matching `count` exists, instead of re-proving every transaction.
    ///
    /// `PrivacyPreservingCircuitOutput` doesn't derive Borsh, so it's cached via its
    /// risc0-serde `to_bytes()` representation (one `Vec<u8>` per output) and decoded
    /// back with `from_slice` on load, same as [`generate_test_transactions`] does for
    /// the freshly-generated case.
    pub(crate) fn load_or_generate_test_transactions(
        count: usize,
        cache_path: &str,
    ) -> (
        V03State,
        Vec<PrivacyPreservingTransaction>,
        Vec<PrivacyPreservingCircuitOutput>,
    ) {
        if let Ok(bytes) = std::fs::read(cache_path) {
            if let Ok((state, transactions, output_bytes)) =
                borsh::from_slice::<(V03State, Vec<PrivacyPreservingTransaction>, Vec<Vec<u8>>)>(
                    &bytes,
                )
            {
                if transactions.len() == count {
                    eprintln!(
                        "[sequencer_aggregator] loaded {count} cached test transaction(s) from {cache_path}"
                    );
                    let circuit_outputs = output_bytes
                        .iter()
                        .map(|bytes| {
                            let words: &[u32] = bytemuck::cast_slice(bytes);
                            from_slice(words).expect("decode cached circuit output")
                        })
                        .collect();
                    return (state, transactions, circuit_outputs);
                }
            }
        }

        eprintln!(
            "[sequencer_aggregator] generating {count} test transaction(s) (cache miss at {cache_path})"
        );
        let (state, transactions, circuit_outputs) = generate_test_transactions(count);
        let output_bytes: Vec<Vec<u8>> = circuit_outputs
            .iter()
            .map(PrivacyPreservingCircuitOutput::to_bytes)
            .collect();
        let bytes = borsh::to_vec(&(&state, &transactions, &output_bytes))
            .expect("serialize test transactions");
        std::fs::write(cache_path, bytes).expect("write test transactions cache");
        (state, transactions, circuit_outputs)
    }

    /// Benchmark: aggregate `AGGREGATOR_COUNT` (default: [`BENCH_MAX_TRANSACTIONS`]) PPE
    /// transactions from the cached test transaction set.
    ///
    /// The cache is generated once for [`BENCH_MAX_TRANSACTIONS`] transactions; lower
    /// `AGGREGATOR_COUNT` values truncate that set rather than regenerating it, so repeated
    /// runs across different counts don't re-prove the underlying PPE transactions.
    ///
    /// Control via env vars:
    /// - `AGGREGATOR_COUNT`: number of transactions to aggregate (default:
    ///   [`BENCH_MAX_TRANSACTIONS`]).
    /// - `PPE_SEGMENT_LIMIT_PO2`: segment size limit (`log2` of cycles per segment) passed to
    ///   the executor.
    ///
    /// Output line (captured by `bench_sequencer_aggregator_cuda.sh`):
    /// `[lee::analytics] sequencer_aggregator n=… proving_ms=… proof_size_bytes=…`.
    #[test]
    fn bench_sequencer_aggregator() {
        let (_state, mut transactions, mut circuit_outputs) = load_or_generate_test_transactions(
            BENCH_MAX_TRANSACTIONS,
            BENCH_TRANSACTIONS_CACHE_PATH,
        );

        if let Ok(s) = std::env::var("AGGREGATOR_COUNT") {
            let count: usize = s.parse().expect("AGGREGATOR_COUNT must be a number");
            transactions.truncate(count);
            circuit_outputs.truncate(count);
        }

        let public_pre_states: Vec<Vec<AccountWithMetadata>> = circuit_outputs
            .into_iter()
            .map(|output| output.public_pre_states)
            .collect();

        let segment_limit_po2: Option<u32> = std::env::var("PPE_SEGMENT_LIMIT_PO2")
            .ok()
            .map(|s| s.parse().expect("PPE_SEGMENT_LIMIT_PO2 must be a number"));

        let n = transactions.len();
        let t0 = std::time::Instant::now();
        let (_output, proof) = aggregate(
            transactions,
            public_pre_states,
            lee_core::GENESIS_BLOCK_ID,
            TIMESTAMP,
            segment_limit_po2,
            SEQUENCER_AGGREGATOR_ELF,
        )
        .expect("aggregate should succeed");
        let proving_ms = t0.elapsed().as_millis();
        let proof_size = proof.len();

        eprintln!(
            "[lee::analytics] sequencer_aggregator n={n} proving_ms={proving_ms} proof_size_bytes={proof_size}"
        );
    }
}
