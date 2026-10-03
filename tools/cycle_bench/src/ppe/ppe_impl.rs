//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_native_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_native_transfer_in_ppe`).

use std::{collections::HashSet, time::Instant};

use borsh::to_vec;
use lee::{
    ProvingInput, PublicExecutionContext, Simulation, execute_and_prove,
    privacy_preserving_transaction::circuit::{ProgramCatalog, Proof},
};
use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, Identifier, NullifierPublicKey,
    NullifierSecretKey, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateWitness,
    WitnessKind,
    account::{Account, AccountId, Actor, ActorState},
    encryption::ViewingPublicKey,
    execution_state::TransactionEntry,
    native_token,
    program::{Call, SendMode, StoredMessage},
};
use test_guest_core::Script;
use token_core::{TokenDescriptor, TokenHolding, TokenKind};

use super::PpeBenchResult;

const TOKEN_DEFINITION_ID: AccountId = AccountId::new([15; 32]);
const RECIPIENT_ID: AccountId = AccountId::new([42; 32]);
const AMOUNT_TO_TRANSFER: u128 = 5_000;
const SENDER_BALANCE: u128 = 100_000;

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

// A private account keyed off `tag`, as `(its id, a witness for it)`. With `account`, the witness
// spends that pre-state under the account's credential; the membership proof is a placeholder,
// which proving never checks against a commitment tree.
fn private_account(tag: u8, account: Option<Account>) -> (AccountId, PrivateWitness) {
    let ask = AuthorizationSecretKey([tag; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&[tag; 32], &[tag.wrapping_add(1); 32]);
    let account_id = AccountId::for_regular_private_account(&npk, &vpk, Identifier::ZERO);
    let nullifier = account.map_or(
        NullifierWitness::Init {
            npk,
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        |account| NullifierWitness::Update {
            account,
            view_tag: 0,
            nsk,
            membership_proof: (0, Vec::new()),
        },
    );
    let witness = PrivateWitness {
        vpk,
        random_seed: [0; 32],
        identifier: Identifier::ZERO,
        kind: WitnessKind::Regular { ask: Some(ask) },
        nullifier,
    };
    (account_id, witness)
}

fn proving_input(
    root: TransactionEntry<StoredMessage>,
    public_actors: Vec<Actor>,
    signers: HashSet<AccountId>,
    private_witnesses: Vec<PrivateWitness>,
) -> ProvingInput {
    ProvingInput {
        root,
        context: PublicExecutionContext::new(public_actors, signers),
        private_witnesses,
        dummy_inputs: Vec::new(),
        ciphertext_padding: None,
    }
}

pub fn run_native_transfer_in_ppe() -> PpeBenchResult {
    timed(
        "native Transfer in PPE".to_owned(),
        0,
        prove_native_transfer_in_ppe,
    )
}

// From the sender's public native actor into a private recipient, so the circuit runs the credit.
pub fn prove_native_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let sender = Actor::native_balance(AccountId::new([1; 32]));
    let (recipient_id, recipient_witness) = private_account(2, None);

    Ok(execute_and_prove(
        proving_input(
            TransactionEntry::Call {
                to: sender,
                message: to_vec(&native_token::Message::Transfer {
                    to: recipient_id,
                    amount: AMOUNT_TO_TRANSFER,
                    mode: SendMode::Call,
                })?,
            },
            vec![sender],
            [sender.account_id].into(),
            vec![recipient_witness],
        ),
        &Simulation {
            public_shards: [(sender, native_token::encode_balance(AMOUNT_TO_TRANSFER))].into(),
        },
        &ProgramCatalog::default(),
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
    programs::token_account_id()
}

fn recipient() -> Actor {
    Actor::new(RECIPIENT_ID, token_program_id())
}

const fn token_transfer_message() -> token_core::Message {
    token_core::Message::Transfer {
        to: RECIPIENT_ID,
        descriptor: TokenDescriptor {
            definition_id: TOKEN_DEFINITION_ID,
            kind: TokenKind::Fungible,
        },
        amount: AMOUNT_TO_TRANSFER,
        notify: None,
        mode: SendMode::Call,
    }
}

// A private sender holding `SENDER_BALANCE` of the benched token.
fn private_sender() -> (AccountId, PrivateWitness) {
    private_account(
        3,
        Some(Account::default().with_shard(
            token_program_id(),
            ActorState::from(&TokenHolding::Fungible {
                definition_id: TOKEN_DEFINITION_ID,
                balance: SENDER_BALANCE,
            }),
        )),
    )
}

fn prove_token_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let token_id = token_program_id();
    let catalog = ProgramCatalog::from([(token_id, programs::token())]);
    let (sender_id, sender_witness) = private_sender();

    Ok(execute_and_prove(
        proving_input(
            TransactionEntry::Call {
                to: Actor::new(sender_id, token_id),
                message: to_vec(&token_transfer_message())?,
            },
            vec![recipient()],
            HashSet::new(),
            vec![sender_witness],
        ),
        &Simulation::default(),
        &catalog,
    )?)
}

pub fn run_scripted_transfers(depth: u32) -> PpeBenchResult {
    timed(
        format!("scripted to token Transfer depth={depth}"),
        depth as usize,
        || prove_scripted_transfers(depth),
    )
}

fn prove_scripted_transfers(
    num_transfers: u32,
) -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    let scripted = test_programs::scripted();
    let scripted_id = AccountId::from_builtin_program(scripted.id());
    let token_id = token_program_id();
    let catalog = ProgramCatalog::from([(scripted_id, scripted), (token_id, programs::token())]);
    let (sender_id, sender_witness) = private_sender();

    // The sender's scripted actor sends every transfer to the sender's own token holding.
    let transfer = Call::new(Actor::new(sender_id, token_id), &token_transfer_message());
    let script =
        (0..num_transfers).fold(Script::default(), |script, _| script.send(transfer.clone()));

    Ok(execute_and_prove(
        proving_input(
            TransactionEntry::Call {
                to: Actor::new(sender_id, scripted_id),
                message: to_vec(&script)?,
            },
            vec![recipient()],
            HashSet::new(),
            vec![sender_witness],
        ),
        &Simulation::default(),
        &catalog,
    )?)
}
