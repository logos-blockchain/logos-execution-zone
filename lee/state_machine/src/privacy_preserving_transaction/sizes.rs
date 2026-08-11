//! Byte-size measurement of a Borsh-serialized [`PrivacyPreservingTransaction`].
//!
//! The fee subsystem charges every private transaction a constant storage gas
//! (`fee_core::params::PRIVATE_GAS_STOR`), which must equal the canonical serialized
//! length of the transaction as it appears in a block body: the Borsh encoding of
//! `common::LeeTransaction::PrivacyPreserving(tx)`, i.e. one enum discriminant byte
//! ([`LEE_TRANSACTION_TAG`]) plus the bytes measured here.
//!
//! Structural sizes are identical in dev mode and in production, so the committed tests run
//! under `RISC0_DEV_MODE=1` and pin the envelope. The proof blob is the only mode-dependent
//! part, and only in its constant term: a receipt is `seal + journal`, where the seal is
//! constant (223,139 B for a real succinct STARK, 126 B for a dev-mode fake) and the journal
//! is the circuit output, which grows with the transaction's contents. That growth is
//! identical in both modes, which is what lets the dev-mode test assert the rule and the
//! `#[ignore]`d [`measure_real_proof_size`] supply the production constant.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    reason = "measurement code: sizes are small and the numbers are the deliverable"
)]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptionScheme, EphemeralSecretKey, InputAccountIdentity,
    Nullifier, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateAccountKind, PrivateAction,
    PrivateWitness, PublicAction, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    encryption::{Ciphertext, EphemeralPublicKey, ViewingPublicKey},
    program::{BlockValidityWindow, TimestampValidityWindow},
};

use crate::{
    PrivateKey, PublicKey,
    privacy_preserving_transaction::{
        Message, PrivacyPreservingTransaction, WitnessSet,
        circuit::{Proof, execute_and_prove},
        message::{EncryptedAccountData, PublicActionWithID},
    },
    program::Program,
    state::{
        CommitmentSet,
        tests::{test_private_account_keys_1, test_private_account_keys_2},
    },
};

/// Borsh length prefix of a `Vec`, a `u32`.
const VEC_LEN_PREFIX: usize = 4;
/// `common::LeeTransaction` enum discriminant. Not measurable from this crate (`common`
/// depends on `lee`, not the reverse); pinned there by
/// `private_tx_wire_size_is_tag_plus_transaction`.
const LEE_TRANSACTION_TAG: usize = 1;
/// `PublicActionWithID` minus its variable part: `AccountId` (32) + `Account`
/// { `program_owner` `[u32; 8]` (32), `balance` u128 (16), `data` length prefix (4),
/// `nonce` u128 (16) }. Add `data.len()`.
const PUBLIC_ACTION_FIXED: usize = 100;
/// `Nonce`, a u128.
const NONCE: usize = 16;
/// `PrivateAction` minus its variable part: `nullifier` (32) + `root` (32) +
/// `commitment` (32) + `ciphertext` length prefix (4) + `epk` length prefix (4) +
/// `view_tag` u8 (1). Add `ciphertext.len() + epk.len()`.
const PRIVATE_ACTION_FIXED: usize = 105;
/// One `(Signature, PublicKey)` witness: 64 + 32.
const SIGNATURE_PAIR: usize = 96;
/// `ValidityWindow<u64>` with both bounds absent: two `Option` discriminants.
const VALIDITY_WINDOW_UNBOUNDED: usize = 2;
/// `ValidityWindow<u64>` with both bounds present: two discriminants + two u64.
const VALIDITY_WINDOW_BOUNDED: usize = 18;
/// ML-KEM-768 ciphertext length, the size of every note's ephemeral public key.
const EPHEMERAL_PUBLIC_KEY: usize = lee_core::ML_KEM_768_CIPHERTEXT_LEN;
/// Note ciphertext for a default-`Data` account: `PrivateAccountKind` header (81) +
/// `Account` bytes (`program_owner` 32 + `balance` 16 + `data` prefix 4 + `nonce` 16).
/// `ChaCha20` is a stream cipher, so the ciphertext is exactly the plaintext length.
const NOTE_CIPHERTEXT_EMPTY_DATA: usize = 149;
/// The part of the wire format no private transaction can avoid: the enum tag, the four
/// `Vec` length prefixes (`public_actions`, `nonces`, `private_actions`, signatures), the
/// proof length prefix, and two unbounded validity windows. This is the "zero envelope
/// overhead" the fee spec provisionally assumed away.
const FIXED_ENVELOPE: usize =
    LEE_TRANSACTION_TAG + 5 * VEC_LEN_PREFIX + 2 * VALIDITY_WINDOW_UNBOUNDED;
/// Journal (circuit output) of a transaction with no actions. The receipt embeds the journal,
/// so every journal byte is also a `data_bytes` byte.
const JOURNAL_BASE: usize = 24;
/// Journal cost of one `PublicAction` (default `Data`); add `8 * data.len()`.
const JOURNAL_PUBLIC_ACTION: usize = 188;
/// Journal cost of one `PrivateAction` (default `Data`); add `4 * data.len()`.
const JOURNAL_PRIVATE_ACTION: usize = 5_344;

/// One measured field of the serialized transaction.
struct Component {
    name: &'static str,
    bytes: usize,
}

/// A circuit-produced transaction together with the length of the journal it committed.
/// The journal matters because the receipt embeds it: the proof blob is not independent of
/// the transaction's contents (see [`measure_private_tx_sizes`]).
struct ProvedTx {
    tx: PrivacyPreservingTransaction,
    journal_bytes: usize,
}

/// Serializes `value` on its own and returns the byte count. Every number in the report
/// comes from this, never from the constants above — those are only ever checked against it.
fn borsh_len<T: borsh::BorshSerialize>(value: &T) -> usize {
    borsh::to_vec(value).unwrap().len()
}

/// Length of a Borsh-serialized byte vector without its length prefix.
fn payload_len<T: borsh::BorshSerialize>(value: &T) -> usize {
    borsh_len(value) - VEC_LEN_PREFIX
}

/// Splits the transaction into the components whose sizes sum to its wire size.
fn breakdown(tx: &PrivacyPreservingTransaction) -> Vec<Component> {
    let message = &tx.message;
    let witness_set = &tx.witness_set;

    vec![
        Component {
            name: "LeeTransaction enum tag",
            bytes: LEE_TRANSACTION_TAG,
        },
        Component {
            name: "message.public_actions len prefix",
            bytes: VEC_LEN_PREFIX,
        },
        Component {
            name: "message.public_actions elements",
            bytes: payload_len(&message.public_actions),
        },
        Component {
            name: "message.nonces len prefix",
            bytes: VEC_LEN_PREFIX,
        },
        Component {
            name: "message.nonces elements",
            bytes: payload_len(&message.nonces),
        },
        Component {
            name: "message.private_actions len prefix",
            bytes: VEC_LEN_PREFIX,
        },
        Component {
            name: "message.private_actions elements",
            bytes: payload_len(&message.private_actions),
        },
        Component {
            name: "message.block_validity_window",
            bytes: borsh_len(&message.block_validity_window),
        },
        Component {
            name: "message.timestamp_validity_window",
            bytes: borsh_len(&message.timestamp_validity_window),
        },
        Component {
            name: "witness_set.signatures len prefix",
            bytes: VEC_LEN_PREFIX,
        },
        Component {
            name: "witness_set.signatures elements",
            bytes: payload_len(&witness_set.signatures_and_public_keys),
        },
        Component {
            name: "witness_set.proof len prefix",
            bytes: VEC_LEN_PREFIX,
        },
        Component {
            name: "witness_set.proof bytes",
            bytes: proof_len(tx),
        },
    ]
}

/// Wire size of the transaction: what `data_bytes` would be for this transaction.
fn wire_size(tx: &PrivacyPreservingTransaction) -> usize {
    LEE_TRANSACTION_TAG + borsh_len(tx)
}

fn proof_len(tx: &PrivacyPreservingTransaction) -> usize {
    tx.witness_set.proof.0.len()
}

/// Prints the breakdown table and asserts the additive identity: the components sum to
/// the wire size. A field added to `Message`/`WitnessSet` without a matching row here
/// breaks the sum, so envelope drift cannot land silently.
fn report(label: &str, tx: &PrivacyPreservingTransaction) -> usize {
    let components = breakdown(tx);
    let total = wire_size(tx);

    println!("\n=== {label} ===");
    println!(
        "  shape: public_actions={} nonces={} private_actions={} signatures={}",
        tx.message.public_actions.len(),
        tx.message.nonces.len(),
        tx.message.private_actions.len(),
        tx.witness_set.signatures_and_public_keys.len(),
    );
    let mut sum = 0;
    for component in &components {
        println!("  {:38} {:>8}", component.name, component.bytes);
        sum += component.bytes;
    }
    println!("  {:38} {total:>8}", "TOTAL (wire size = data_bytes)");
    println!(
        "  {:38} {:>8}",
        "envelope (total - proof bytes)",
        total - proof_len(tx)
    );

    assert_eq!(
        sum, total,
        "component breakdown must sum to the wire size; a field is unaccounted for"
    );
    total
}

/// A `Message` with the given element counts, so per-element sizes can be measured
/// without running the circuit.
fn synthetic_message(
    public_actions: usize,
    nonces: usize,
    private_actions: usize,
    ciphertext_len: usize,
    epk_len: usize,
) -> Message {
    let dummy_id = AccountId::new([9; 32]);
    Message {
        public_actions: std::iter::repeat_with(|| PublicActionWithID {
            account_id: dummy_id,
            post_state: Account::default(),
        })
        .take(public_actions)
        .collect(),
        nonces: (0..nonces)
            .map(|i| Nonce(u128::try_from(i).unwrap()))
            .collect(),
        private_actions: std::iter::repeat_with(|| PrivateAction {
            nullifier: Nullifier::for_account_initialization(&dummy_id),
            root: DUMMY_COMMITMENT_HASH,
            commitment: Commitment::new(&dummy_id, &Account::default()),
            encrypted_post_state: EncryptedAccountData {
                ciphertext: Ciphertext::from_inner(vec![0; ciphertext_len]),
                epk: EphemeralPublicKey(vec![0; epk_len]),
                view_tag: 0,
            },
        })
        .take(private_actions)
        .collect(),
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    }
}

fn synthetic_tx(
    message: Message,
    signers: usize,
    proof_len: usize,
) -> PrivacyPreservingTransaction {
    let keys: Vec<PrivateKey> = (0..signers)
        .map(|i| PrivateKey::try_new([u8::try_from(i).unwrap() + 1; 32]).unwrap())
        .collect();
    let key_refs: Vec<&PrivateKey> = keys.iter().collect();
    let witness_set =
        WitnessSet::for_message(&message, Proof::from_inner(vec![0; proof_len]), &key_refs);
    PrivacyPreservingTransaction::new(message, witness_set)
}

/// Builds the private transaction a real flow inscribes: circuit output plus signatures.
/// Runs the circuit, so its cost is one dev-mode (or, with `RISC0_DEV_MODE=0`, real) proof.
fn proved_tx(
    pre_states: Vec<AccountWithMetadata>,
    instruction: &impl serde::Serialize,
    identities: Vec<InputAccountIdentity>,
    program: &Program,
    nonces: Vec<Nonce>,
    signers: &[&PrivateKey],
) -> ProvedTx {
    let (output, proof) = execute_and_prove(
        pre_states,
        Program::serialize_instruction(instruction).unwrap(),
        identities,
        &program.clone().into(),
    )
    .unwrap();
    let journal_bytes = output.to_bytes().len();
    let message = Message::from_circuit_output(nonces, output);
    let witness_set = WitnessSet::for_message(&message, proof, signers);
    ProvedTx {
        tx: PrivacyPreservingTransaction::new(message, witness_set),
        journal_bytes,
    }
}

/// The smallest real construction: one private account initialized by `noop`. No public
/// accounts, hence no nonces and no signatures.
fn minimal_private_tx() -> ProvedTx {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);

    proved_tx(
        vec![AccountWithMetadata::new(
            Account::default(),
            true,
            account_id,
        )],
        &(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program,
        vec![],
        &[],
    )
}

/// A public sender paying a private recipient: one public action, one nonce, one
/// signature, one private action — the shape of a shielding transfer.
fn shielding_transfer_tx() -> ProvedTx {
    let program = crate::test_methods::simple_balance_transfer();
    let recipient_keys = test_private_account_keys_1();
    let sender_key = PrivateKey::try_new([37; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program.id(),
            balance: 100,
            ..Account::default()
        },
        true,
        sender_id,
    );
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    proved_tx(
        vec![
            sender,
            AccountWithMetadata::new(Account::default(), true, recipient_id),
        ],
        &37_u128,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program,
        vec![Nonce::default()],
        &[&sender_key],
    )
}

/// A fully private transfer: two private actions, no public actions, no signatures.
fn fully_private_transfer_tx() -> ProvedTx {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();

    let sender_account = Account {
        balance: 100,
        nonce: Nonce(0xdead_beef),
        program_owner: program.id(),
        ..Account::default()
    };
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let commitment = Commitment::new(&sender_id, &sender_account);
    let mut commitment_set = CommitmentSet::with_capacity(2);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    proved_tx(
        vec![
            AccountWithMetadata::new(sender_account, true, sender_id),
            AccountWithMetadata::new(Account::default(), true, recipient_id),
        ],
        &37_u128,
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program,
        vec![],
        &[],
    )
}

/// Per-element sizes and the additive identity, with no proving at all. This is the
/// regression guard: it fails the moment a field, a length prefix or an element size in
/// the private-transaction wire format changes.
#[test]
fn private_tx_envelope_sizes_are_pinned() {
    let empty = synthetic_tx(synthetic_message(0, 0, 0, 0, 0), 0, 0);
    let empty_size = report("empty envelope (no actions, no proof)", &empty);
    assert_eq!(empty_size, FIXED_ENVELOPE, "unavoidable envelope changed");
    assert_eq!(FIXED_ENVELOPE, 25);

    // Each per-element constant is the measured delta of adding exactly one element.
    let delta = |tx: &PrivacyPreservingTransaction| wire_size(tx) - empty_size;

    assert_eq!(
        delta(&synthetic_tx(synthetic_message(1, 0, 0, 0, 0), 0, 0)),
        PUBLIC_ACTION_FIXED
    );
    assert_eq!(
        delta(&synthetic_tx(synthetic_message(0, 1, 0, 0, 0), 0, 0)),
        NONCE
    );
    assert_eq!(
        delta(&synthetic_tx(synthetic_message(0, 0, 1, 0, 0), 0, 0)),
        PRIVATE_ACTION_FIXED
    );
    assert_eq!(
        delta(&synthetic_tx(synthetic_message(0, 0, 0, 0, 0), 1, 0)),
        SIGNATURE_PAIR
    );

    // Note bytes and proof bytes are passed through one-for-one: nothing in the wire
    // format compresses them.
    assert_eq!(
        delta(&synthetic_tx(
            synthetic_message(0, 0, 1, NOTE_CIPHERTEXT_EMPTY_DATA, EPHEMERAL_PUBLIC_KEY),
            0,
            0
        )),
        PRIVATE_ACTION_FIXED + NOTE_CIPHERTEXT_EMPTY_DATA + EPHEMERAL_PUBLIC_KEY
    );
    assert_eq!(
        delta(&synthetic_tx(synthetic_message(0, 0, 0, 0, 0), 0, 1_000)),
        1_000
    );

    // Public-action `Data` is passed through one-for-one as well.
    let mut with_data = synthetic_message(1, 0, 0, 0, 0);
    with_data.public_actions[0].post_state.data = vec![0; 64].try_into().unwrap();
    assert_eq!(
        delta(&synthetic_tx(with_data, 0, 0)),
        PUBLIC_ACTION_FIXED + 64
    );

    // A bounded validity window costs two u64 more than an unbounded one.
    let bounded = BlockValidityWindow::try_from((Some(1_u64), Some(2_u64))).unwrap();
    assert_eq!(borsh_len(&bounded), VALIDITY_WINDOW_BOUNDED);
    assert_eq!(
        VALIDITY_WINDOW_BOUNDED - VALIDITY_WINDOW_UNBOUNDED,
        2 * size_of::<u64>()
    );
}

/// The journal — the circuit output the receipt embeds — is what makes the proof blob
/// content-dependent, so its growth rates matter as much as the wire format's. Measured by
/// serializing hand-built outputs; no circuit run needed.
#[test]
fn journal_growth_is_pinned() {
    let account_with_data = |len: usize| Account {
        data: vec![0_u8; len].try_into().unwrap(),
        ..Account::default()
    };
    let journal = |public: Vec<PublicAction>, private: Vec<PrivateAction>| {
        PrivacyPreservingCircuitOutput {
            public_actions: public,
            private_actions: private,
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        }
        .to_bytes()
        .len()
    };
    let public_action = |data_len: usize| PublicAction {
        pre: AccountWithMetadata::new(account_with_data(data_len), true, AccountId::new([9; 32])),
        post: account_with_data(data_len),
    };
    // The note ciphertext comes from the real encryption path, so the account-`Data` slope is
    // measured end to end (`Data` -> ciphertext -> journal) rather than assumed.
    let nullifier = Nullifier::for_account_initialization(&AccountId::new([9; 32]));
    let vpk = ViewingPublicKey::from_seed(&[7; 32], &[8; 32]);
    let shared_secret =
        SharedSecretKey::encapsulate_deterministic(&vpk, &EphemeralSecretKey([0_u8; 32])).0;
    let encrypt = |data_len: usize| {
        EncryptionScheme::encrypt(
            &account_with_data(data_len),
            &PrivateAccountKind::Regular(0),
            &shared_secret,
            &nullifier,
        )
    };
    let private_action = |data_len: usize| PrivateAction {
        nullifier,
        root: DUMMY_COMMITMENT_HASH,
        commitment: Commitment::new(&AccountId::new([9; 32]), &Account::default()),
        encrypted_post_state: EncryptedAccountData {
            ciphertext: encrypt(data_len),
            epk: EphemeralPublicKey(vec![0; EPHEMERAL_PUBLIC_KEY]),
            view_tag: 0,
        },
    };

    // `ChaCha20` is a stream cipher, so one byte of account `Data` is one ciphertext byte.
    // Pinning this is what makes the private-action `Data` slope below a real measurement.
    let ciphertext_len = |data_len: usize| payload_len(&encrypt(data_len));
    println!(
        "note ciphertext: data=0 -> {} bytes, data=1 -> {} bytes",
        ciphertext_len(0),
        ciphertext_len(1)
    );
    assert_eq!(ciphertext_len(0), NOTE_CIPHERTEXT_EMPTY_DATA);
    assert_eq!(
        ciphertext_len(1) - ciphertext_len(0),
        1,
        "account `Data` must map 1:1 onto note ciphertext bytes"
    );

    let base = journal(vec![], vec![]);
    let public_cost = journal(vec![public_action(0)], vec![]) - base;
    let private_cost = journal(vec![], vec![private_action(0)]) - base;
    // Slope per byte of account `Data`, measured over a single extra byte.
    let public_slope = journal(vec![public_action(1)], vec![]) - base - public_cost;
    let private_slope = journal(vec![], vec![private_action(1)]) - base - private_cost;

    println!(
        "journal: base={base} public={public_cost}+{public_slope}/data-byte \
         private={private_cost}+{private_slope}/data-byte"
    );

    assert_eq!(base, JOURNAL_BASE);
    assert_eq!(public_cost, JOURNAL_PUBLIC_ACTION);
    assert_eq!(private_cost, JOURNAL_PRIVATE_ACTION);
    // A public action carries the account twice (`pre` and `post`), a private action once, and
    // the journal encoding spends one 32-bit word per byte.
    assert_eq!(public_slope, 8);
    assert_eq!(private_slope, 4);
}

/// Full breakdowns for real, circuit-produced transactions. Under `RISC0_DEV_MODE=1` the
/// proof blob is the dev-mode fake receipt; every other byte is what production puts on
/// the wire.
#[test]
fn measure_private_tx_sizes() {
    let minimal = minimal_private_tx();
    let minimal_size = report("minimal: 1 private account init (noop)", &minimal.tx);

    let shielding = shielding_transfer_tx();
    let shielding_size = report(
        "shielding transfer: 1 public + 1 private action, 1 signer",
        &shielding.tx,
    );

    let fully_private = fully_private_transfer_tx();
    let fully_private_size = report(
        "fully private transfer: 2 private actions, no signers",
        &fully_private.tx,
    );

    // The proof blob is NOT independent of the transaction's contents: the receipt embeds
    // the (unpruned) journal, so it grows byte-for-byte with the circuit output. This holds
    // in dev mode and in production alike — `measure_real_proof_size` shows the same 188-byte
    // step for the same journal step. T5 cannot treat `PROOF_BYTES` as a constant without
    // capping the journal too.
    println!(
        "\nInnerReceipt (borsh):  minimal={} shielding={} fully_private={}",
        proof_len(&minimal.tx),
        proof_len(&shielding.tx),
        proof_len(&fully_private.tx),
    );
    println!(
        "journal (circuit out): minimal={} shielding={} fully_private={}",
        minimal.journal_bytes, shielding.journal_bytes, fully_private.journal_bytes,
    );
    assert_eq!(
        proof_len(&shielding.tx) - proof_len(&minimal.tx),
        shielding.journal_bytes - minimal.journal_bytes,
        "the receipt grows exactly by the journal growth"
    );
    assert_eq!(
        proof_len(&fully_private.tx) - proof_len(&minimal.tx),
        fully_private.journal_bytes - minimal.journal_bytes,
        "the receipt grows exactly by the journal growth"
    );

    let minimal_envelope = minimal_size - proof_len(&minimal.tx);
    let shielding_envelope = shielding_size - proof_len(&shielding.tx);
    let fully_private_envelope = fully_private_size - proof_len(&fully_private.tx);
    println!(
        "envelopes (total - proof): minimal={minimal_envelope} shielding={shielding_envelope} \
         fully_private={fully_private_envelope}"
    );

    // A real private action carries an ML-KEM-768 ephemeral key and a ChaCha20 note
    // ciphertext; together they dominate the envelope.
    let note = &minimal.tx.message.private_actions[0].encrypted_post_state;
    let ciphertext_len = payload_len(&note.ciphertext);
    let epk_len = note.epk.0.len();
    println!(
        "private action: fixed={PRIVATE_ACTION_FIXED} ciphertext={ciphertext_len} epk={epk_len} \
         total={}",
        PRIVATE_ACTION_FIXED + ciphertext_len + epk_len
    );
    assert_eq!(epk_len, EPHEMERAL_PUBLIC_KEY);
    assert_eq!(ciphertext_len, NOTE_CIPHERTEXT_EMPTY_DATA);

    // The minimal real envelope: the unavoidable framing plus exactly one note.
    let private_action = PRIVATE_ACTION_FIXED + NOTE_CIPHERTEXT_EMPTY_DATA + EPHEMERAL_PUBLIC_KEY;
    assert_eq!(private_action, 1_342);
    assert_eq!(minimal_envelope, FIXED_ENVELOPE + private_action);

    // The envelope grows exactly by the elements added, with no hidden framing.
    assert_eq!(
        shielding_envelope - minimal_envelope,
        PUBLIC_ACTION_FIXED + NONCE + SIGNATURE_PAIR
    );
    assert_eq!(
        fully_private_envelope - minimal_envelope,
        private_action,
        "one extra private action costs exactly one note"
    );
}

/// Production STARK proof size. Not run by default: needs `RISC0_DEV_MODE=0` and real
/// proving (~2.5 min per proof). Run with
/// `RISC0_DEV_MODE=0 cargo test -p lee measure_real_proof_size -- --ignored --nocapture`.
#[test]
#[ignore = "requires RISC0_DEV_MODE=0 and real proving (minutes)"]
fn measure_real_proof_size() {
    assert_ne!(
        std::env::var("RISC0_DEV_MODE").as_deref(),
        Ok("1"),
        "this measurement is meaningless in dev mode; set RISC0_DEV_MODE=0"
    );

    let minimal = minimal_private_tx();
    let minimal_proof = proof_len(&minimal.tx);
    let minimal_size = report("REAL minimal: 1 private account init (noop)", &minimal.tx);

    let shielding = shielding_transfer_tx();
    let shielding_proof = proof_len(&shielding.tx);
    let shielding_size = report(
        "REAL shielding transfer: simple_balance_transfer",
        &shielding.tx,
    );

    println!("\nreal InnerReceipt (borsh), noop:                    {minimal_proof}");
    println!("real InnerReceipt (borsh), simple_balance_transfer: {shielding_proof}");
    println!("wire sizes: minimal={minimal_size} shielding={shielding_size}");
    println!(
        "journals: minimal={} shielding={}",
        minimal.journal_bytes, shielding.journal_bytes
    );

    // The succinct seal is constant across programs; the receipt is not, because it embeds
    // the journal. The seal is the figure a padded, journal-capped envelope budgets for.
    let minimal_seal = minimal_proof - minimal.journal_bytes;
    let shielding_seal = shielding_proof - shielding.journal_bytes;
    println!("seal (receipt - journal): minimal={minimal_seal} shielding={shielding_seal}");
    assert_eq!(
        minimal_seal, shielding_seal,
        "the succinct seal must not depend on the proven program"
    );
}
