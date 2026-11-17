//! STF proving prototype: proves that applying a block to a state with fingerprint H yields a
//! state with fingerprint H'. Gas, reverts and L1 inputs are taken on trust.
//!
//! Every public program session the block runs is proven on its own as a succinct receipt; the
//! block guest re-runs `chain_state::apply_block`, checking each session's journal by
//! composition. Two fingerprints:
//! - `flat`: SHA-256 of the whole state's borsh encoding; the guest holds the whole state.
//! - `merkle`: a compact sparse Merkle root over the public accounts, plus SHA-256 of the rest; the
//!   guest holds only the accounts the block touches.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context as _, Result, bail};
use chain_state::apply::{Tip, apply_block, derive_block_summary};
use clap::{Parser, ValueEnum};
use common::{
    block::{Block, HashableBlockData},
    test_utils::{
        create_transaction_native_token_transfer, produce_dummy_block,
        producer_account_for_testing, producer_seed, test_fee_declaration,
    },
    transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
};
use lee::{
    Account, AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction,
    Signature, V03State,
    program::stf_oracle,
    public_transaction::{Message, WitnessSet},
    stf_partial::{self, DeferredSignature},
};
use lee_core::{from_frame, to_frame};
use ping_core::{CrossZoneEmission, SenderMessage};
use risc0_zkvm::{AssumptionReceipt, ExecutorEnv, ProverOpts, default_executor, default_prover};
use serde::Serialize;
use stf_bench_methods::{
    AUTH_ELF, AUTH_ID, STF_BLOCK_ELF, STF_BLOCK_ID, STF_BLOCK_MERKLE_ELF, STF_BLOCK_MERKLE_ID,
};
use stf_smt::{Hash, Key, value_hash};
use testnet_initial_state::initial_state;

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Flat,
    Merkle,
}

/// How public accounts authorize a transaction; the order matches the guest's codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Auth {
    /// BIP340 signatures, checked in the guest.
    Schnorr,
    /// BIP340 signatures, committed by the guest and checked by the verifier.
    Defer,
    /// Public key = SHA-256(secret); each signer proves it knows the secret, and the guest
    /// checks that receipt by composition.
    Preimage,
}

/// What each user transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum TxKind {
    /// A native token transfer, which runs inside the block guest.
    Transfer,
    /// A `ping_sender` call that emits through `cross_zone_outbox` into a new slot: two program
    /// sessions, each proven on its own.
    Ping,
}

#[derive(Parser)]
struct Args {
    /// User transactions per block, one block per value, applied in sequence.
    #[arg(long, value_delimiter = ',', default_value = "0,1,5,20")]
    txs: Vec<usize>,
    #[arg(long, value_enum, default_value = "transfer")]
    tx_kind: TxKind,
    #[arg(long, value_enum, default_value = "merkle")]
    mode: Mode,
    /// Funded accounts added to genesis, so the tree has a realistic depth.
    #[arg(long, default_value_t = 0)]
    extra_accounts: usize,
    #[arg(long, value_enum, default_value = "schnorr")]
    auth: Auth,
    /// Under `preimage`: bytes each authorization receipt adds to the block, read and hashed by
    /// the guest as a block hash covering them would be.
    #[arg(long, default_value_t = 0)]
    auth_proof_bytes: usize,
    /// Prove; without it only the executor runs.
    #[arg(long)]
    prove: bool,
    /// Where to write the results as JSON, rewritten after every block.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Serialize)]
struct SessionRow {
    image_id: String,
    user_cycles: u64,
    total_cycles: u64,
    prove_ms: u128,
}

#[derive(Serialize, Default)]
struct BlockRow {
    mode: Option<Mode>,
    auth: Option<Auth>,
    tx_kind: Option<TxKind>,
    extra_accounts: usize,
    public_accounts: usize,
    user_txs: usize,
    block_bytes: usize,
    /// Bytes the guest reads besides the block and the sessions: the whole state (flat), or the
    /// tree witness, the touched accounts and the rest of the state (merkle).
    witness_bytes: [usize; 3],
    touched_accounts: usize,
    host_apply_ms: u128,
    sessions: usize,
    session_user_cycles: u64,
    guest_user_cycles: u64,
    guest_total_cycles: u64,
    guest_segments: usize,
    /// flat: read, hash pre, decode, apply, encode + hash post, one signature check.
    /// merkle: read, decode, verify accounts, apply, new root + rest hash, accounts changed.
    /// Both then: reading and hashing the stand-in authorization proof bytes.
    guest_breakdown: Vec<u64>,
    guest_exec_ms: u128,
    sessions_prove_ms: u128,
    guest_prove_ms: u128,
    compress_ms: u128,
    verify_ms: u128,
    receipt_bytes: usize,
    /// Signature checks the guest left for the verifier, and the time to run them natively.
    deferred_signatures: usize,
    verify_signatures_us: u128,
    /// Hash-preimage authorizations: how many, cycles of one, and each one's proving time.
    authorizations: usize,
    auth_user_cycles: u64,
    auth_prove_ms: Vec<u128>,
    session_rows: Vec<SessionRow>,
}

/// A public account that sends one transfer.
enum Signer {
    Schnorr {
        account_id: AccountId,
        key: PrivateKey,
    },
    Preimage {
        account_id: AccountId,
        public_key: PublicKey,
    },
}

impl Signer {
    const fn account_id(&self) -> AccountId {
        match self {
            Self::Schnorr { account_id, .. } | Self::Preimage { account_id, .. } => *account_id,
        }
    }
}

struct GuestInput {
    frames: Vec<Vec<u8>>,
    witness_bytes: [usize; 3],
    expected_post: Hash,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let prover = default_prover();
    eprintln!("prover: {}", prover.get_name());
    let (elf, image_id) = match args.mode {
        Mode::Flat => (STF_BLOCK_ELF, STF_BLOCK_ID),
        Mode::Merkle => (STF_BLOCK_MERKLE_ELF, STF_BLOCK_MERKLE_ID),
    };

    let extra = (0..args.extra_accounts).map(|i| {
        let mut seed = b"stf-bench-extra-account".to_vec();
        seed.extend_from_slice(&(i as u64).to_le_bytes());
        (AccountId::new(value_hash(&seed)), Account::funded(1))
    });
    // Each transfer gets its own fresh sender and recipient.
    let preimage = args.auth == Auth::Preimage;
    if preimage {
        stf_partial::use_hash_keys();
    }
    let total_txs: usize = args.txs.iter().sum();
    let mut secrets: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    let keys: Vec<Signer> = (0..2 * total_txs)
        .map(|i| {
            let mut seed = b"stf-bench-keyed-account".to_vec();
            seed.extend_from_slice(&(i as u64).to_le_bytes());
            let secret = value_hash(&seed);
            if preimage {
                let public_key = PublicKey::try_new(value_hash(&secret)).expect("any 32 bytes");
                secrets.insert(*public_key.value(), secret);
                Signer::Preimage {
                    account_id: AccountId::from(&public_key),
                    public_key,
                }
            } else {
                let key = PrivateKey::try_new(secret).expect("valid key");
                Signer::Schnorr {
                    account_id: AccountId::from(&PublicKey::new_from_private_key(&key)),
                    key,
                }
            }
        })
        .collect();
    let mut state = initial_state(true)
        .with_public_accounts([producer_seed()])
        .with_public_accounts(
            keys.iter()
                .map(|key| (key.account_id(), Account::funded(1_000_000_000_000))),
        )
        .with_public_accounts(extra);
    if args.tx_kind == TxKind::Ping {
        init_ping_sender(&mut state)?;
    }
    let genesis = produce_dummy_block(1, None, vec![]);
    apply_block(None, &genesis, &mut state).context("genesis applies")?;
    let mut tip = Tip::from(&genesis);

    let mut used = 0;
    let mut rows = Vec::new();

    for &user_txs in &args.txs {
        // Under `preimage` the host has no signature to check either: the authorizations it
        // records are proven below.
        if preimage {
            stf_partial::defer_signatures();
        }
        let block = build_block(
            &state,
            &tip,
            &keys[2 * used..2 * (used + user_txs)],
            args.tx_kind,
            u32::try_from(used)?,
        )?;
        let _ = stf_partial::take_deferred();
        used += user_txs;

        stf_oracle::start_recording();
        stf_partial::start_tracking();
        let mut post = state.clone();
        if preimage {
            stf_partial::defer_signatures();
        }
        let host_start = Instant::now();
        apply_block(Some(&tip), &block, &mut post).context("block applies on the host")?;
        let host_apply_ms = host_start.elapsed().as_millis();
        let authorizations = stf_partial::take_deferred();
        let touched = stf_partial::take_tracked();
        let (calls, elfs) = stf_oracle::take_recording();

        let block_bytes = borsh::to_vec(&block)?;
        let input = match args.mode {
            Mode::Flat => flat_input(&state, &post)?,
            Mode::Merkle => merkle_input(&state, &post, &touched)?,
        };
        let mut row = BlockRow {
            mode: Some(args.mode),
            auth: Some(args.auth),
            tx_kind: Some(args.tx_kind),
            authorizations: authorizations.len(),
            extra_accounts: args.extra_accounts,
            public_accounts: state.stf_public_accounts().count(),
            user_txs,
            block_bytes: block_bytes.len(),
            witness_bytes: input.witness_bytes,
            touched_accounts: touched.len(),
            host_apply_ms,
            sessions: calls.len(),
            session_user_cycles: calls.iter().map(|call| call.cycles).sum(),
            ..BlockRow::default()
        };
        eprintln!(
            "\n== {:?} block, {:?} auth, {user_txs} user txs ({:?}), {} public accounts: {} \
             sessions, {} touched accounts, witness {:?} B, block {} B, host apply {host_apply_ms} ms",
            args.mode,
            args.auth,
            args.tx_kind,
            row.public_accounts,
            row.sessions,
            row.touched_accounts,
            row.witness_bytes,
            row.block_bytes
        );

        // One assumption per session: a proven receipt, or the executor's claim.
        let mut assumptions: Vec<AssumptionReceipt> = Vec::with_capacity(calls.len());
        for (index, call) in calls.iter().enumerate() {
            let session_elf = &elfs[&call.image_id];
            let env = ExecutorEnv::builder().write_slice(&call.input).build()?;
            if args.prove {
                let started = Instant::now();
                let info = prover.prove_with_opts(env, session_elf, &ProverOpts::succinct())?;
                let session = SessionRow {
                    image_id: hex(&call.image_id),
                    user_cycles: info.stats.user_cycles,
                    total_cycles: info.stats.total_cycles,
                    prove_ms: started.elapsed().as_millis(),
                };
                eprintln!(
                    "   session {}/{}: {} user / {} total cycles, proved in {} ms",
                    index + 1,
                    calls.len(),
                    session.user_cycles,
                    session.total_cycles,
                    session.prove_ms
                );
                row.session_rows.push(session);
                assumptions.push(info.receipt.into());
            } else {
                let session = default_executor().execute(env, session_elf)?;
                assumptions.push(
                    session
                        .receipt_claim
                        .context("the executor returned no claim")?
                        .into(),
                );
            }
        }
        row.sessions_prove_ms = row.session_rows.iter().map(|s| s.prove_ms).sum();

        // One authorization receipt per signer, which the signer's wallet would prove.
        for (index, check) in authorizations.iter().enumerate() {
            let secret = secrets
                .get(&check.public_key)
                .context("a signer the bench holds")?;
            let env = ExecutorEnv::builder()
                .write_slice(&to_frame(secret))
                .write_slice(&to_frame(&check.message_hash))
                .build()?;
            if args.prove {
                let started = Instant::now();
                let info = prover.prove_with_opts(env, AUTH_ELF, &ProverOpts::succinct())?;
                let prove_ms = started.elapsed().as_millis();
                row.auth_user_cycles = info.stats.user_cycles;
                eprintln!(
                    "   authorization {}/{}: {} user / {} total cycles, proved in {prove_ms} ms, \
                     receipt {} B",
                    index + 1,
                    authorizations.len(),
                    info.stats.user_cycles,
                    info.stats.total_cycles,
                    borsh::to_vec(&info.receipt.inner)?.len()
                );
                row.auth_prove_ms.push(prove_ms);
                assumptions.push(info.receipt.into());
            } else {
                let session = default_executor().execute(env, AUTH_ELF)?;
                row.auth_user_cycles = session.cycles();
                assumptions.push(
                    session
                        .receipt_claim
                        .context("the executor returned no claim")?
                        .into(),
                );
            }
        }
        let proof_bytes = vec![0x5a_u8; args.auth_proof_bytes * authorizations.len()];

        let calls_bytes = borsh::to_vec(&calls)?;
        let settings = borsh::to_vec(&(tip.block_id, tip.hash.0, args.auth as u8, AUTH_ID))?;
        let guest_env = |assumptions: &[AssumptionReceipt]| -> Result<ExecutorEnv<'static>> {
            let mut builder = ExecutorEnv::builder();
            for frame in &input.frames {
                builder.write_slice(&to_frame(frame));
            }
            builder
                .write_slice(&to_frame(&block_bytes))
                .write_slice(&to_frame(&calls_bytes))
                .write_slice(&to_frame(&settings))
                .write_slice(&to_frame(&proof_bytes));
            for assumption in assumptions {
                builder.add_assumption(assumption.clone());
            }
            Ok(builder.build()?)
        };

        let started = Instant::now();
        let session = default_executor().execute(guest_env(&assumptions)?, elf)?;
        row.guest_exec_ms = started.elapsed().as_millis();
        row.guest_user_cycles = session.cycles();
        row.guest_segments = session.segments.len();
        let (guest_post, breakdown, deferred, auth_image) = read_journal(&session.journal.bytes)?;
        if guest_post != input.expected_post {
            bail!("the guest's post-state fingerprint differs from the host's");
        }
        if auth_image != AUTH_ID {
            bail!("the guest committed another authorization image");
        }
        row.guest_breakdown = breakdown;
        row.deferred_signatures = deferred.len();
        let started = Instant::now();
        if !deferred.iter().all(DeferredSignature::verify) {
            bail!("a deferred signature does not verify");
        }
        row.verify_signatures_us = started.elapsed().as_micros();
        eprintln!(
            "   guest: {} user cycles, {} segments, executed in {} ms, breakdown {:?}; {} \
             deferred signatures verified natively in {} us; {} authorizations of {} cycles",
            row.guest_user_cycles,
            row.guest_segments,
            row.guest_exec_ms,
            row.guest_breakdown,
            row.deferred_signatures,
            row.verify_signatures_us,
            row.authorizations,
            row.auth_user_cycles
        );

        if args.prove {
            let started = Instant::now();
            let info =
                prover.prove_with_opts(guest_env(&assumptions)?, elf, &ProverOpts::composite())?;
            row.guest_prove_ms = started.elapsed().as_millis();
            row.guest_total_cycles = info.stats.total_cycles;
            eprintln!(
                "   guest proved: {} total cycles in {} ms",
                row.guest_total_cycles, row.guest_prove_ms
            );

            let started = Instant::now();
            let succinct = prover.compress(&ProverOpts::succinct(), &info.receipt)?;
            row.compress_ms = started.elapsed().as_millis();
            eprintln!("   compressed in {} ms", row.compress_ms);

            let started = Instant::now();
            succinct.verify(image_id)?;
            row.verify_ms = started.elapsed().as_millis();
            row.receipt_bytes = borsh::to_vec(&succinct.inner)?.len();
            let output = succinct
                .claim()?
                .value()?
                .output
                .value()?
                .context("output")?;
            if !output.assumptions.is_empty() {
                bail!("the succinct receipt still has assumptions");
            }
            eprintln!(
                "   verified in {} ms, receipt {} B; total {} ms",
                row.verify_ms,
                row.receipt_bytes,
                row.sessions_prove_ms + row.guest_prove_ms + row.compress_ms
            );
        }

        rows.push(row);
        if let Some(out) = &args.out {
            std::fs::write(out, serde_json::to_string_pretty(&rows)?)?;
        }
        state = post;
        tip = Tip::from(&block);
    }
    Ok(())
}

type Journal = (
    [u8; 32],
    [u8; 32],
    [u8; 32],
    Hash,
    Vec<u64>,
    Vec<DeferredSignature>,
    [u32; 8],
);

fn read_journal(bytes: &[u8]) -> Result<(Hash, Vec<u64>, Vec<DeferredSignature>, [u32; 8])> {
    let (_, _, _, post, breakdown, deferred, auth_image): Journal =
        borsh::from_slice(from_frame(bytes).context("journal frame")?)?;
    Ok((post, breakdown, deferred, auth_image))
}

fn flat_input(state: &V03State, post: &V03State) -> Result<GuestInput> {
    let bytes = borsh::to_vec(state)?;
    let expected_post = value_hash(&borsh::to_vec(post)?);
    Ok(GuestInput {
        witness_bytes: [bytes.len(), 0, 0],
        frames: vec![bytes],
        expected_post,
    })
}

fn merkle_input(
    state: &V03State,
    post: &V03State,
    touched: &BTreeSet<AccountId>,
) -> Result<GuestInput> {
    let entries = account_entries(state)?;
    let mut touched_keys: Vec<Key> = touched.iter().map(|id| *id.value()).collect();
    touched_keys.sort_unstable();
    let tree = stf_smt::multiproof(&entries, &touched_keys);
    let accounts: Vec<(AccountId, Account)> = touched
        .iter()
        .filter_map(|id| state.stf_peek(*id).map(|account| (*id, account.clone())))
        .collect();
    let accounts = borsh::to_vec(&accounts)?;
    let rest = borsh::to_vec(&state.stf_without_public())?;
    let expected_post = fingerprint(
        &stf_smt::root(&account_entries(post)?),
        &value_hash(&borsh::to_vec(&post.stf_without_public())?),
    );
    Ok(GuestInput {
        witness_bytes: [tree.len(), accounts.len(), rest.len()],
        frames: vec![tree, accounts, rest],
        expected_post,
    })
}

fn account_entries(state: &V03State) -> Result<Vec<(Key, Hash)>> {
    let mut entries = state
        .stf_public_accounts()
        .map(|(id, account)| Ok((*id.value(), value_hash(&borsh::to_vec(account)?))))
        .collect::<Result<Vec<_>>>()?;
    entries.sort_unstable_by_key(|(key, _)| *key);
    Ok(entries)
}

fn fingerprint(account_root: &Hash, rest: &Hash) -> Hash {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(account_root);
    bytes[32..].copy_from_slice(rest);
    value_hash(&bytes)
}

/// A block of one transaction per pair in `pairs`, each from a sender that has not sent before;
/// pings take ordinals from `first_ordinal` on.
fn build_block(
    state: &V03State,
    tip: &Tip,
    pairs: &[Signer],
    kind: TxKind,
    first_ordinal: u32,
) -> Result<Block> {
    let id = tip.block_id + 1;
    let timestamp = id * 100;
    let mut transactions: Vec<LeeTransaction> = pairs
        .chunks_exact(2)
        .zip(first_ordinal..)
        .map(|(pair, ordinal)| match kind {
            TxKind::Transfer => transfer(&pair[0], pair[1].account_id()),
            TxKind::Ping => ping(&pair[0], ordinal),
        })
        .collect::<Result<_>>()?;
    let (summary, payout, receipts) = derive_block_summary(state, &transactions, id, timestamp)
        .map_err(|err| anyhow::anyhow!("block settles: {err}"))?;
    transactions.push(LeeTransaction::Public(fee_invocation(
        summary,
        payout,
        FeePayee::Present(producer_account_for_testing()),
    )));
    transactions.push(LeeTransaction::Public(clock_invocation(id, timestamp)));
    Ok(HashableBlockData {
        block_id: id,
        prev_block_hash: tip.hash,
        timestamp,
        transactions,
        receipts,
    }
    .into_pending_block())
}

fn transfer(from: &Signer, to: AccountId) -> Result<LeeTransaction> {
    Ok(match from {
        Signer::Schnorr { account_id, key } => {
            create_transaction_native_token_transfer(*account_id, 0, to, 1, key)
        }
        Signer::Preimage {
            account_id,
            public_key,
        } => {
            let message = Message::try_new_with_fees(
                Actor::native_balance(*account_id),
                [
                    Actor::native_balance(*account_id),
                    Actor::native_balance(to),
                ],
                BTreeMap::from([(*account_id, lee_core::account::Nonce(0))]),
                lee_core::native_token::Message::Transfer { to, amount: 1 },
                test_fee_declaration(*account_id),
            )?;
            // No signature: a receipt over (public key, message hash) authorizes the message.
            let witness_set =
                WitnessSet::from_parts(vec![(Signature { value: [0; 64] }, public_key.clone())]);
            LeeTransaction::Public(PublicTransaction::new(message, witness_set))
        }
    })
}

/// Pins `ping_sender` to the outbox, as the sequencer genesis does.
fn init_ping_sender(state: &mut V03State) -> Result<()> {
    let program = ping_core::ping_sender_account_id();
    let seed = ping_core::sender_config_seed();
    let config = Actor::new(AccountId::for_public_pda(&program, &seed), program);
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda { program, seed }],
        ..Message::try_new(
            config,
            [config],
            BTreeMap::new(),
            SenderMessage::InitConfig {
                outbox_account_id: cross_zone_outbox_core::cross_zone_outbox_account_id(),
            },
        )?
    };
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
    state
        .transition_from_public_transaction(&tx, 1, 0)
        .map_err(|err| anyhow::anyhow!("ping sender config: {err}"))?;
    Ok(())
}

/// A ping through `ping_sender` into the outbox slot `ordinal`, paid for by `from`.
fn ping(from: &Signer, ordinal: u32) -> Result<LeeTransaction> {
    let sender = ping_core::ping_sender_account_id();
    let outbox_program = cross_zone_outbox_core::cross_zone_outbox_account_id();
    let config = Actor::new(ping_core::sender_config_account_id(sender), sender);
    let target_zone = [0x42; 32];
    let slot = PublicAccountEvidence::Pda {
        program: outbox_program,
        seed: cross_zone_outbox_core::outbox_pda_seed(sender, &target_zone, ordinal),
    };
    let outbox = Actor::new(slot.account_id(), outbox_program);
    let payer = from.account_id();
    let message = Message {
        admission_evidence: vec![slot],
        ..Message::try_new_with_fees(
            config,
            [config, outbox],
            BTreeMap::from([(payer, lee_core::account::Nonce(0))]),
            SenderMessage::Send {
                outbox,
                emission: CrossZoneEmission {
                    target_zone,
                    target_account_id: AccountId::new([0x43; 32]),
                    target_accounts: vec![],
                    payload: b"ping".to_vec(),
                    ordinal,
                },
            },
            test_fee_declaration(payer),
        )?
    };
    let witness_set = match from {
        Signer::Schnorr { key, .. } => WitnessSet::for_message(&message, &[key]),
        // No signature: a receipt over (public key, message hash) authorizes the message.
        Signer::Preimage { public_key, .. } => {
            WitnessSet::from_parts(vec![(Signature { value: [0; 64] }, public_key.clone())])
        }
    };
    Ok(LeeTransaction::Public(PublicTransaction::new(message, witness_set)))
}

fn hex(id: &lee::ProgramId) -> String {
    id.iter().map(|word| format!("{word:08x}")).collect()
}
