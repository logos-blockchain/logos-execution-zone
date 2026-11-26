//! Feature-gated implementation of PPE composition benches.
//!
//! `prove_native_transfer_in_ppe` is reused by the `verify` criterion bench under
//! `benches/verify.rs` (re-exported via `super::prove_native_transfer_in_ppe`).

use std::{
    collections::{BTreeSet, HashSet},
    time::Instant,
};

use borsh::to_vec;
use lee::{
    ProvingInput, PublicExecutionContext, SenderPresentation, Simulation,
    error::LeeError,
    execute_and_prove_with_stats,
    privacy_preserving_transaction::circuit::{ProgramCatalog, Proof},
};
use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, DummyInput, DummyOutput, EncryptedNote,
    EphemeralSecretKey, FeeTransfer, MessageWitness, NullifierPublicKey, NullifierSecretKey,
    NullifierWitness, PrivacyPreservingCircuitOutput, PrivateAccountKind, PrivateWitness,
    PublicationMode, Recipient, RecipientEncryption, RegularKey, RootCall, SharedSecretKey,
    WitnessKind,
    account::{Account, AccountId, Actor},
    encryption::{Ciphertext, MlKem768EncapsulationKey, ViewingPublicKey},
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, SyncMessage},
};
use rand::{RngCore as _, rngs::OsRng};
use risc0_zkvm::SessionStats;
use test_guest_core::Script;

use super::PpeBenchResult;

const RECIPIENT_ID: AccountId = AccountId::new([42; 32]);
const FEE_INBOX_ID: AccountId = AccountId::new([43; 32]);
const REFUND_TARGET_ID: AccountId = AccountId::new([44; 32]);
const FEE_AMOUNT: u128 = 1_000;
const ALIAS_OPENING: [u8; 32] = [7; 32];
const AMOUNT_TO_TRANSFER: u128 = 5_000;
const SENDER_BALANCE: u128 = 100_000;
/// Mirrors `wallet::CIPHERTEXT_PAD_SIZE`, so the padding cost here matches what a wallet pays.
const CIPHERTEXT_PAD: u32 = 512;

/// The circuit's output, its proof and the cycle statistics of its run.
type Proven = (PrivacyPreservingCircuitOutput, Proof, SessionStats);

fn timed(
    label: String,
    chain_depth: usize,
    proof: impl Fn() -> anyhow::Result<Proven>,
) -> PpeBenchResult {
    let started = Instant::now();
    match proof() {
        Ok((_out, proof, stats)) => PpeBenchResult {
            label,
            chain_depth,
            user_cycles: Some(stats.user_cycles),
            total_cycles: Some(stats.total_cycles),
            segments: Some(stats.segments),
            prove_wall_ms: Some(started.elapsed().as_secs_f64() * 1_000.0),
            proof_bytes: Some(proof.into_inner().len()),
            error: None,
        },
        Err(err) => PpeBenchResult {
            label,
            chain_depth,
            user_cycles: None,
            total_cycles: None,
            segments: None,
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
    let npk = NullifierPublicKey::from(&NullifierSecretKey::from(&ask));
    let vpk = ViewingPublicKey::from_seed(&[tag; 32], &[tag.wrapping_add(1); 32]);
    let account_id = AccountId::for_regular_private_account(&npk, &vpk);
    let nullifier = account.map_or(
        NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        |account| NullifierWitness::Update {
            account,
            membership_proof: (0, Vec::new()),
        },
    );
    let witness = PrivateWitness {
        vpk,
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
        nullifier,
        address_openings: BTreeSet::new(),
    };
    (account_id, witness)
}

fn proving_input(
    root: TransactionEntry<MessageWitness>,
    public_actors: Vec<Actor>,
    signers: HashSet<AccountId>,
    private_witnesses: Vec<PrivateWitness>,
) -> ProvingInput {
    ProvingInput {
        claims: Vec::new(),
        root,
        fee: None,
        public_context: PublicExecutionContext::new(public_actors, signers),
        private_witnesses,
        dummy_inputs: Vec::new(),
        ciphertext_padding: None,
        recoveries: Vec::new(),
        private_promotions: BTreeSet::new(),
    }
}

fn no_seal(bodies: &[MessageBody]) -> Result<Vec<PublicationMode>, LeeError> {
    bodies.first().map_or_else(
        || Ok(Vec::new()),
        |body| {
            Err(LeeError::InvalidInput(format!(
                "No seal for the durable async message to {:?}",
                body.to
            )))
        },
    )
}

pub fn prove_native_transfer_in_ppe() -> anyhow::Result<(PrivacyPreservingCircuitOutput, Proof)> {
    prove_native_transfer_with_dummies(0).map(|(output, proof, _)| (output, proof))
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Dummy inputs as the wallet builds them: random seeds, a real ML-KEM epk toward a throwaway
/// key, and a padded random ciphertext.
fn dummy_inputs(count: usize) -> Vec<DummyInput> {
    let ciphertext_len = usize::try_from(CIPHERTEXT_PAD).expect("pad size fits in usize");
    std::iter::repeat_with(|| {
        let throwaway_ek = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
        let (_, epk) = SharedSecretKey::encapsulate(&throwaway_ek);
        let mut ciphertext = vec![0_u8; ciphertext_len];
        OsRng.fill_bytes(&mut ciphertext);
        DummyInput {
            nullifier_seed: random_bytes(),
            commitment_root: DUMMY_COMMITMENT_HASH,
            output: DummyOutput {
                commitment_seed: random_bytes(),
                note: EncryptedNote {
                    ciphertext: Ciphertext::from_inner(ciphertext),
                    epk,
                },
            },
        }
    })
    .take(count)
    .collect()
}

pub fn run_native_transfer_with_dummies(count: usize) -> PpeBenchResult {
    timed(
        format!("native Transfer in PPE, {count} dummy inputs"),
        0,
        || prove_native_transfer_with_dummies(count),
    )
}

// From the sender's public native actor into a private recipient, so the circuit runs the credit.
fn prove_native_transfer_with_dummies(count: usize) -> anyhow::Result<Proven> {
    let sender = Actor::native_balance(AccountId::new([1; 32]));
    let (recipient_id, recipient_witness) = private_account(2, None);

    Ok(execute_and_prove_with_stats(
        ProvingInput {
            dummy_inputs: dummy_inputs(count),
            ciphertext_padding: Some(CIPHERTEXT_PAD),
            ..proving_input(
                TransactionEntry::Sync(RootCall {
                    to: sender,
                    message: to_vec(&native_token::Message::Transfer {
                        to: recipient_id,
                        amount: AMOUNT_TO_TRANSFER,
                    })?,
                }),
                vec![sender],
                [sender.account_id].into(),
                vec![recipient_witness],
            )
        },
        &Simulation {
            public_actor_states: [(sender, native_token::encode_balance(AMOUNT_TO_TRANSFER))]
                .into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, body| body.to.account_id == recipient_id,
        no_seal,
    )?)
}

/// How a deshielding transfer pays its fee.
#[derive(Clone, Copy)]
pub enum FeeCase {
    /// No fee: what the transfer alone costs.
    None,
    /// A refund to the payer's alias, bound under a key of its own.
    SeparateRecoveryKey,
    /// A refund to the payer's alias, bound under the payer's note key as the wallet does.
    NoteRecoveryKey,
    /// A refund to a public target, which needs no binding.
    PublicRefundTarget,
}

impl FeeCase {
    pub const ALL: [Self; 4] = [
        Self::None,
        Self::SeparateRecoveryKey,
        Self::NoteRecoveryKey,
        Self::PublicRefundTarget,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::None => "deshield, no fee",
            Self::SeparateRecoveryKey => "deshield, fee, recovery under its own key",
            Self::NoteRecoveryKey => "deshield, fee, recovery under the note key",
            Self::PublicRefundTarget => "deshield, fee, public refund target",
        }
    }
}

pub fn run_fee_transfer(case: FeeCase) -> PpeBenchResult {
    timed(case.label().to_owned(), 0, || prove_fee_transfer(case))
}

// From a private sender to a public recipient, the sender paying the fee inside the proof: the
// only private account is the payer, so every encapsulation is its note's or the fee's.
fn prove_fee_transfer(case: FeeCase) -> anyhow::Result<Proven> {
    const TAG: u8 = 3;
    let funded = Account::funded(SENDER_BALANCE);
    let (sender_id, sender_witness) = private_account(TAG, Some(funded.clone()));
    let nsk = NullifierSecretKey::from(&AuthorizationSecretKey([TAG; 32]));
    let note_esk = EphemeralSecretKey::new(
        &sender_id,
        &sender_witness.random_seed,
        &funded.nonce.private_account_nonce_increment(&nsk),
    );
    let recovery = |esk| RecipientEncryption {
        recipient: Recipient {
            npk: NullifierPublicKey::from(&nsk),
            vpk: sender_witness.vpk.clone(),
            kind: PrivateAccountKind::Regular,
            opening: Some(ALIAS_OPENING),
        },
        esk,
    };
    let fee = |refund_to| FeeTransfer {
        payer: sender_id,
        recipient: FEE_INBOX_ID,
        amount: FEE_AMOUNT,
        refund_to,
        tip: 0,
    };
    let (fee, recoveries) = match case {
        FeeCase::None => (None, Vec::new()),
        FeeCase::SeparateRecoveryKey => (
            Some(fee(None)),
            vec![recovery(EphemeralSecretKey(random_bytes()))],
        ),
        FeeCase::NoteRecoveryKey => (Some(fee(None)), vec![recovery(note_esk)]),
        FeeCase::PublicRefundTarget => (Some(fee(Some(REFUND_TARGET_ID))), Vec::new()),
    };
    let public_actors = vec![
        Actor::native_balance(RECIPIENT_ID),
        Actor::native_balance(FEE_INBOX_ID),
    ];

    Ok(execute_and_prove_with_stats(
        ProvingInput {
            fee,
            recoveries,
            ciphertext_padding: Some(CIPHERTEXT_PAD),
            ..proving_input(
                TransactionEntry::Sync(RootCall {
                    to: Actor::native_balance(sender_id),
                    message: to_vec(&native_token::Message::Transfer {
                        to: RECIPIENT_ID,
                        amount: AMOUNT_TO_TRANSFER,
                    })?,
                }),
                public_actors,
                HashSet::new(),
                vec![sender_witness],
            )
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
        |_| SenderPresentation::Blinded(ALIAS_OPENING),
        |_, _| false,
        no_seal,
    )?)
}

pub fn run_scripted_transfers(depth: u32) -> PpeBenchResult {
    timed(
        format!("scripted to native Transfer depth={depth}"),
        depth as usize,
        || prove_scripted_transfers(depth),
    )
}

fn prove_scripted_transfers(num_transfers: u32) -> anyhow::Result<Proven> {
    let scripted = test_programs::scripted();
    let scripted_id = AccountId::from_builtin_program(scripted.id());
    let catalog = ProgramCatalog::from([(scripted_id, scripted)]);
    let (sender_id, sender_witness) = private_account(
        3,
        Some(Account::default().with_actor_state(
            NATIVE_TOKEN_PROGRAM_ID,
            native_token::encode_balance(SENDER_BALANCE),
        )),
    );

    // The sender's scripted actor sends every transfer to the sender's own native balance.
    let transfer = SyncMessage::new(
        Actor::native_balance(sender_id),
        &native_token::Message::Transfer {
            to: RECIPIENT_ID,
            amount: AMOUNT_TO_TRANSFER,
        },
    );
    let script =
        (0..num_transfers).fold(Script::default(), |script, _| script.send(transfer.clone()));

    Ok(execute_and_prove_with_stats(
        proving_input(
            TransactionEntry::Sync(RootCall {
                to: Actor::new(sender_id, scripted_id),
                message: to_vec(&script)?,
            }),
            vec![Actor::native_balance(RECIPIENT_ID)],
            HashSet::new(),
            vec![sender_witness],
        ),
        &Simulation::default(),
        &catalog,
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )?)
}
