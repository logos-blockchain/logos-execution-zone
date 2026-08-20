#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Single-zone state-machine tests for cross-zone delivery (ping demo) and the
//! wrapped-token bridge (Demo 2). They drive the guests in isolation, no watcher
//! or Bedrock: a hand-built `cross_zone_inbox::Dispatch` (as the watcher would
//! inject) and the source `bridge_lock::Lock` (which escrows and chains
//! `outbox::Emit`). Fast, so they pin guest logic before the e2e exercises the
//! plumbing. Run with `RISC0_DEV_MODE=1`.

use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction as InboxInstruction, SeenShard,
    inbox_config_account_id, inbox_seen_shard_account_id,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use cross_zone_outbox_core::{OutboxRecord, outbox_pda};
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction, V03State, ValidatedStateDiff,
    public_transaction::{Message, WitnessSet},
};
use lee_core::account::Account;
use ping_core::{
    ReceiverInstruction, outbox_bytes, ping_record_pda, read_outbox, receiver_config_account_id,
    sender_config_account_id,
};

/// Serializes an instruction to the risc0 word form the guests read. A macro
/// because the serde trait a generic fn would have to name is not a dependency
/// of this crate.
macro_rules! words_of {
    ($instruction:expr) => {
        risc0_zkvm::serde::to_vec($instruction).expect("serialize instruction")
    };
}

const INITIAL_BALANCE: u128 = 100;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];
/// These tests drive the guest directly, so any fixed source-block hash does.
const SRC_BLOCK_HASH: [u8; 32] = [7; 32];

/// State registering the cross-zone builtins these tests exercise.
fn base_state() -> V03State {
    V03State::new().with_programs([
        programs::cross_zone_inbox(),
        programs::cross_zone_outbox(),
        programs::ping_sender(),
        programs::ping_receiver(),
        programs::bridge_lock(),
        programs::wrapped_token(),
    ])
}

/// Seeds the inbox config (inbox-owned), which is now just this zone's id.
fn seed_inbox_config(state: &mut V03State, self_zone: [u8; 32]) {
    let inbox_id = programs::cross_zone_inbox().id();
    let config = InboxConfig { self_zone };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        inbox_config_account_id(inbox_id),
        Account {
            program_owner: inbox_id.into(),
            balance: 0,
            data: config
                .to_bytes()
                .try_into()
                .expect("config fits in account data"),
            nonce: 0_u128.into(),
        },
    )]);
}

/// Seeds the wrapped-token config pinning the inbox as minter and `sources` as the
/// peer pairs it will mint for, matching what genesis seeds for a real zone.
fn seed_wrapped_config(
    state: &mut V03State,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], lee_core::program::ProgramId)>,
) {
    seed_wrapped_config_with_governance(state, None, authority, sources);
}

/// The same, naming a program allowed to act for the authority through a chain.
fn seed_wrapped_config_with_governance(
    state: &mut V03State,
    governance: Option<lee_core::program::ProgramId>,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], lee_core::program::ProgramId)>,
) {
    let wrapped_token_id = programs::wrapped_token().id();
    let config = wrapped_token_core::WrappedTokenConfig {
        minter: programs::cross_zone_inbox().id(),
        governance,
        authority,
        sources,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        wrapped_token_core::config_account_id(wrapped_token_id),
        Account {
            program_owner: wrapped_token_id.into(),
            data: config
                .to_bytes()
                .try_into()
                .expect("wrapped-token config fits in account data"),
            ..Default::default()
        },
    )]);
}

/// Seeds the ping-receiver config pinning the inbox as deliverer and `sources` as
/// the peer pairs it accepts a delivery from.
fn seed_receiver_config(
    state: &mut V03State,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], lee_core::program::ProgramId)>,
) {
    seed_receiver_config_with_governance(state, None, authority, sources);
}

/// The same, naming a program allowed to act for the authority through a chain.
fn seed_receiver_config_with_governance(
    state: &mut V03State,
    governance: Option<lee_core::program::ProgramId>,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], lee_core::program::ProgramId)>,
) {
    let receiver_id = programs::ping_receiver().id();
    let config = ping_core::ReceiverConfig {
        deliverer: programs::cross_zone_inbox().id(),
        governance,
        authority,
        sources,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        receiver_config_account_id(receiver_id),
        Account {
            program_owner: receiver_id.into(),
            data: config
                .to_bytes()
                .try_into()
                .expect("receiver config fits in account data"),
            ..Default::default()
        },
    )]);
}

/// Seeds the ping-sender config account pinning the real outbox, matching what
/// genesis seeds for a real zone.
fn seed_ping_sender_config(state: &mut V03State) {
    let sender_id = programs::ping_sender().id();
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        sender_config_account_id(sender_id),
        Account {
            program_owner: sender_id.into(),
            data: outbox_bytes(programs::cross_zone_outbox().id())
                .to_vec()
                .try_into()
                .expect("outbox id fits in account data"),
            ..Default::default()
        },
    )]);
}

/// Seeds the bridge-lock config account pinning the real outbox and the wrapped
/// token, matching what genesis seeds for a real zone.
fn seed_bridge_lock_config(state: &mut V03State) {
    let bridge_lock_id = programs::bridge_lock().id();
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        bridge_lock_core::config_account_id(bridge_lock_id),
        Account {
            program_owner: bridge_lock_id.into(),
            data: bridge_lock_core::config_bytes(
                programs::cross_zone_outbox().id(),
                programs::wrapped_token().id(),
            )
            .to_vec()
            .try_into()
            .expect("pinned ids fit in account data"),
            ..Default::default()
        },
    )]);
}

/// The account list a dispatch declares, mirroring `cross_zone::build_inbox_dispatch_tx`:
/// config, seen shard, source marker, then the target's own accounts.
fn dispatch_accounts(
    inbox_id: lee_core::program::ProgramId,
    msg: &CrossZoneMessage,
    targets: Vec<AccountId>,
) -> Vec<AccountId> {
    let mut ids = vec![
        inbox_config_account_id(inbox_id),
        inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id),
        inbox_source_marker_account_id(inbox_id, &msg.src_zone, msg.src_program_id),
    ];
    ids.extend(targets);
    ids
}

/// Asserts the transaction fails at `block` with an error mentioning `expected`,
/// so a refusal for an unrelated reason cannot keep a guard test green.
fn rejects_at(state: &V03State, tx: &PublicTransaction, block: u64, expected: &str) {
    let Err(err) = ValidatedStateDiff::from_public_transaction(tx, state, block, 0) else {
        panic!("expected a rejection mentioning {expected}");
    };
    assert!(
        format!("{err:?}").contains(expected),
        "rejected for the wrong reason: {err:?}"
    );
}

/// A top-level authority transaction: the instruction words over `accounts`,
/// signed by `key` at `nonce`.
fn signed_tx(
    program: lee_core::program::ProgramId,
    accounts: Vec<AccountId>,
    nonce: u128,
    words: Vec<u32>,
    key: &PrivateKey,
) -> PublicTransaction {
    let message = Message::new_preserialized(program, accounts, vec![nonce.into()], words);
    let witness = WitnessSet::for_message(&message, &[key]);
    PublicTransaction::new(message, witness)
}

/// An unsigned call through the governance proxy, delegating `delegated` (or
/// nothing) on the chained call into `target`.
fn via_proxy(
    proxy_id: lee_core::program::ProgramId,
    target: lee_core::program::ProgramId,
    config: AccountId,
    authority: AccountId,
    delegated: Option<lee_core::program::PdaSeed>,
    words: Vec<u32>,
) -> PublicTransaction {
    let message = Message::try_new(
        proxy_id,
        vec![config, authority],
        vec![],
        (target, words, delegated),
    )
    .expect("build proxy message");
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

/// An authority instruction delivered through the inbox, as a peer would have to
/// send it: the dispatch shape over the target's config and authority accounts.
fn chained_via_inbox(
    target: lee_core::program::ProgramId,
    config_id: AccountId,
    authority: AccountId,
    words: Vec<u32>,
) -> PublicTransaction {
    let inbox_id = programs::cross_zone_inbox().id();
    let msg = CrossZoneMessage {
        src_zone: [2; 32],
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: programs::bridge_lock().id(),
        target_program_id: target,
        payload: words.into_iter().flat_map(u32::to_le_bytes).collect(),
        l1_inclusion_witness: None,
    };
    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(inbox_id, &msg, vec![config_id, authority]),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

/// A `ping_sender::Send` carrying `payload` to `target_zone`, over the accounts
/// given rather than the correct ones, so tests can vary them.
fn send_tx(accounts: Vec<AccountId>, target_zone: [u8; 32], ordinal: u32) -> PublicTransaction {
    let receiver_id = programs::ping_receiver().id();
    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: b"ping".to_vec(),
    })
    .expect("serialize ping instruction");
    let send = ping_core::SenderInstruction::Send {
        target_zone,
        target_program_id: receiver_id,
        target_accounts: vec![
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        payload: words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        ordinal,
    };
    let message = Message::try_new(programs::ping_sender().id(), accounts, vec![], send)
        .expect("build ping_sender message");
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

/// The wrapped-token `Mint` the bridge forwards, serialized as the cross-zone
/// payload (risc0 words, little-endian bytes).
fn mint_payload() -> Vec<u8> {
    mint_payload_of(LOCK_AMOUNT)
}

fn mint_payload_of(amount: u128) -> Vec<u8> {
    let mint = wrapped_token_core::Instruction::Mint {
        recipient: RECIPIENT,
        amount,
    };
    let words = risc0_zkvm::serde::to_vec(&mint).expect("serialize mint");
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Runs a bridge mint of `amount` through the inbox, as the watcher would.
fn dispatch_mint(amount: u128) -> Result<ValidatedStateDiff, lee::error::LeeError> {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, None, vec![(src_zone, [9_u32; 8])]);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: [9_u32; 8],
        target_program_id: wrapped_token_id,
        payload: mint_payload_of(amount),
        l1_inclusion_witness: None,
    };

    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &msg,
            vec![
                wrapped_token_core::config_account_id(wrapped_token_id),
                wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
            ],
        ),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
}

/// One message must not be able to pin a holding near `u128::MAX`, which would
/// make every later honest mint to that recipient overflow and fail for good.
#[test]
fn a_mint_above_the_cap_is_rejected() {
    assert!(
        dispatch_mint(wrapped_token_core::MAX_MINT_AMOUNT + 1).is_err(),
        "an amount over the per-mint cap must not execute"
    );
}

#[test]
fn a_mint_at_the_cap_is_accepted() {
    let diff = dispatch_mint(wrapped_token_core::MAX_MINT_AMOUNT)
        .expect("the cap itself is a legitimate amount");
    let holding_id =
        wrapped_token_core::holding_account_id(programs::wrapped_token().id(), &RECIPIENT);
    let minted = wrapped_token_core::read_balance(
        &diff.public_diff()[&holding_id].data.clone().into_inner(),
    );
    assert_eq!(minted, wrapped_token_core::MAX_MINT_AMOUNT);
}

/// Drives `cross_zone_inbox::Dispatch` directly through the state machine
/// (no watcher) and asserts the message is delivered to `ping_receiver`, which
/// records the payload into its own PDA.
#[test]
fn inbox_dispatch_delivers_payload_to_ping_receiver() {
    let inbox_id = programs::cross_zone_inbox().id();
    let receiver_id = programs::ping_receiver().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(&mut state, None, vec![(src_zone, [9_u32; 8])]);

    // The payload is the ping_receiver instruction, serialized as risc0 words in
    // little-endian bytes (the contract the inbox reverses when forwarding).
    let inner = b"hello-cross-zone".to_vec();
    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: inner.clone(),
    })
    .expect("serialize ping instruction");
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: [9_u32; 8],
        target_program_id: receiver_id,
        payload,
        l1_inclusion_witness: None,
    };

    let record_id = ping_record_pda(receiver_id);

    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &msg,
            vec![receiver_config_account_id(receiver_id), record_id],
        ),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("dispatch must validate and execute");
    let record = diff
        .public_diff()
        .get(&record_id)
        .expect("ping record account must change")
        .clone();
    assert_eq!(
        record.data.into_inner(),
        inner,
        "ping_receiver must record the delivered payload"
    );
}

/// Drives `bridge_lock::Lock` and asserts it debits the holder, credits the
/// escrow, and records the forwarded mint in the outbox PDA.
#[test]
fn lock_escrows_balance_and_emits_to_outbox() {
    let bridge_lock_id = programs::bridge_lock().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let mut state = base_state();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    state = state.with_public_accounts([(
        holder_id,
        Account {
            program_owner: bridge_lock_id.into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);
    seed_bridge_lock_config(&mut state);

    let payload = mint_payload();
    let escrow_id = bridge_lock_core::escrow_account_id(bridge_lock_id);
    let outbox_record_id = outbox_pda(outbox_id, bridge_lock_id, &zone_b, ordinal);
    let tx = lock_tx(&holder_key, holder_id, zone_b, ordinal, 0);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("lock must validate and execute");
    let public_diff = diff.public_diff();

    let holder_after = public_diff[&holder_id].balance;
    assert_eq!(
        holder_after,
        INITIAL_BALANCE - LOCK_AMOUNT,
        "holder debited"
    );

    let escrow_after = public_diff[&escrow_id].balance;
    assert_eq!(escrow_after, LOCK_AMOUNT, "escrow credited");

    let record =
        OutboxRecord::from_bytes(&public_diff[&outbox_record_id].data.clone().into_inner())
            .expect("outbox PDA holds an OutboxRecord");
    assert_eq!(
        record.emitter, bridge_lock_id,
        "the record names the program that emitted it"
    );
    assert_eq!(record.target_zone, zone_b);
    assert_eq!(record.ordinal, ordinal);
    assert_eq!(record.target_program_id, wrapped_token_id);
    assert_eq!(
        record.payload, payload,
        "emitted payload is the wrapped mint"
    );
}

/// A `bridge_lock::Lock` emitting to `(zone_b, ordinal)`, ready to run twice.
fn lock_tx(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    zone_b: [u8; 32],
    ordinal: u32,
    nonce: u128,
) -> PublicTransaction {
    let wrapped_token_id = programs::wrapped_token().id();
    lock_tx_to(
        holder_key,
        holder_id,
        zone_b,
        ordinal,
        nonce,
        wrapped_token_id,
        mint_target_accounts(wrapped_token_id),
    )
}

/// The mint's own account list: the wrapped-token config, then the recipient's
/// holding. What `wrapped_token::Mint` requires on the destination zone.
fn mint_target_accounts(wrapped_token_id: lee_core::program::ProgramId) -> Vec<[u8; 32]> {
    vec![
        wrapped_token_core::config_account_id(wrapped_token_id).into_value(),
        wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT).into_value(),
    ]
}

/// The same lock aimed at `target_program_id` over `target_accounts`, so a test
/// can vary what the destination would be asked to do.
fn lock_tx_to(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    zone_b: [u8; 32],
    ordinal: u32,
    nonce: u128,
    target_program_id: lee_core::program::ProgramId,
    target_accounts: Vec<[u8; 32]>,
) -> PublicTransaction {
    let bridge_lock_id = programs::bridge_lock().id();
    let outbox_id = programs::cross_zone_outbox().id();

    let lock = bridge_lock_core::Instruction::Lock {
        amount: LOCK_AMOUNT,
        target_zone: zone_b,
        target_program_id,
        target_accounts,
        payload: mint_payload(),
        ordinal,
    };
    let message = Message::try_new(
        bridge_lock_id,
        vec![
            bridge_lock_core::config_account_id(bridge_lock_id),
            holder_id,
            bridge_lock_core::escrow_account_id(bridge_lock_id),
            outbox_pda(outbox_id, bridge_lock_id, &zone_b, ordinal),
        ],
        vec![nonce.into()],
        lock,
    )
    .expect("build lock message");
    let witness = WitnessSet::for_message(&message, &[holder_key]);
    PublicTransaction::new(message, witness)
}

/// A slot holds one message for ever, so a second emission into it fails rather
/// than replacing the record. Without this a later emitter silently destroys an
/// earlier one, and for a bridge that means an escrow with no record of what it
/// was for.
#[test]
fn a_second_emit_at_the_same_slot_is_rejected() {
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state().with_public_accounts([(
        holder_id,
        Account {
            program_owner: programs::bridge_lock().id().into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);
    seed_bridge_lock_config(&mut state);

    let first = lock_tx(&holder_key, holder_id, zone_b, ordinal, 0);
    let diff = ValidatedStateDiff::from_public_transaction(&first, &state, 1, 0)
        .expect("the first lock executes");
    state.apply_state_diff(diff);

    // Same slot, fresh nonce, so the only thing that can reject it is the slot
    // already holding a record. Matched on the guest's own message rather than
    // any error, or a future change that rejected it earlier for an unrelated
    // reason would keep this passing.
    let second = lock_tx(&holder_key, holder_id, zone_b, ordinal, 1);
    let Err(err) = ValidatedStateDiff::from_public_transaction(&second, &state, 2, 0) else {
        panic!("a second emission into a written slot must not execute");
    };
    assert!(
        format!("{err:?}").contains("Outbox slot already written"),
        "rejected for the wrong reason: {err:?}"
    );

    // Control: the same second lock into a fresh ordinal executes, so the
    // refusal above is the slot and not the transaction's shape.
    let elsewhere = lock_tx(&holder_key, holder_id, zone_b, ordinal + 1, 1);
    ValidatedStateDiff::from_public_transaction(&elsewhere, &state, 2, 0)
        .expect("a lock into an unwritten slot executes");
}

/// Two programs emitting to one zone and ordinal address two different slots,
/// so neither can overwrite or block the other.
#[test]
fn two_emitters_share_an_ordinal_without_colliding() {
    let outbox_id = programs::cross_zone_outbox().id();
    let sender_id = programs::ping_sender().id();
    let bridge_lock_id = programs::bridge_lock().id();
    let receiver_id = programs::ping_receiver().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state().with_public_accounts([(
        holder_id,
        Account {
            program_owner: bridge_lock_id.into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);
    seed_ping_sender_config(&mut state);
    seed_bridge_lock_config(&mut state);

    let lock_slot = outbox_pda(outbox_id, bridge_lock_id, &zone_b, ordinal);
    let send_slot = outbox_pda(outbox_id, sender_id, &zone_b, ordinal);
    assert_ne!(
        lock_slot, send_slot,
        "the same zone and ordinal under two emitters are two slots"
    );

    let lock = lock_tx(&holder_key, holder_id, zone_b, ordinal, 0);
    let diff = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0)
        .expect("the lock executes");
    state.apply_state_diff(diff);

    let send = send_tx(
        vec![sender_config_account_id(sender_id), send_slot],
        zone_b,
        ordinal,
    );
    let send_diff = ValidatedStateDiff::from_public_transaction(&send, &state, 2, 0)
        .expect("the send executes into its own slot, not the lock's");

    let record = OutboxRecord::from_bytes(
        &send_diff.public_diff()[&send_slot]
            .data
            .clone()
            .into_inner(),
    )
    .expect("outbox PDA holds an OutboxRecord");
    assert_eq!(record.emitter, sender_id);
    assert_eq!(record.target_program_id, receiver_id);

    // And the lock's own slot is untouched by it.
    let lock_record =
        OutboxRecord::from_bytes(&state.get_account_by_id(lock_slot).data.into_inner())
            .expect("the lock's record survives");
    assert_eq!(lock_record.emitter, bridge_lock_id);
}

/// A caller can no longer aim an emission at a program of their own and still
/// succeed, leaving no record of it. With the program no longer an instruction
/// field, the account is the only way left to try.
#[test]
fn a_send_into_a_foreign_outbox_slot_is_rejected() {
    let sender_id = programs::ping_sender().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let mut state = base_state();
    seed_ping_sender_config(&mut state);

    // A slot under some other program, which is what the caller would have to
    // pass to reach it.
    let foreign_slot = outbox_pda([3; 8], sender_id, &zone_b, ordinal);
    let send = send_tx(
        vec![sender_config_account_id(sender_id), foreign_slot],
        zone_b,
        ordinal,
    );

    // Refused inside the pinned outbox, not by the sender: the chained call goes
    // there whatever account the caller passes, which is the point.
    let Err(err) = ValidatedStateDiff::from_public_transaction(&send, &state, 1, 0) else {
        panic!("a send into a slot outside the pinned outbox must not execute");
    };
    assert!(
        format!("{err:?}").contains("Account must be the outbox PDA"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// Nothing releases an escrow, so a message the destination will refuse is a
/// burn: debited here, never minted there. The refusal has to come before the
/// debit.
#[test]
fn a_lock_naming_another_target_program_is_rejected() {
    let bridge_lock_id = programs::bridge_lock().id();
    let zone_b = [2_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state().with_public_accounts([(
        holder_id,
        Account {
            program_owner: bridge_lock_id.into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);
    seed_bridge_lock_config(&mut state);

    let elsewhere = programs::ping_receiver().id();
    let lock = lock_tx_to(
        &holder_key,
        holder_id,
        zone_b,
        0,
        0,
        elsewhere,
        mint_target_accounts(elsewhere),
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0) else {
        panic!("a lock aimed at another program must not execute");
    };
    assert!(
        format!("{err:?}").contains("only mints through the wrapped token it is pinned to"),
        "rejected for the wrong reason: {err:?}"
    );
    assert_eq!(
        state.get_account_by_id(holder_id).balance,
        INITIAL_BALANCE,
        "a refused lock leaves the holder's balance alone"
    );
}

/// The same burn by a different route: the right target program, the wrong
/// accounts for it. `wrapped_token::Mint` fails its own address asserts on the
/// destination, so the escrow has to be refused here instead.
#[test]
fn a_lock_naming_other_mint_accounts_is_rejected() {
    let bridge_lock_id = programs::bridge_lock().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let zone_b = [2_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state().with_public_accounts([(
        holder_id,
        Account {
            program_owner: bridge_lock_id.into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);
    seed_bridge_lock_config(&mut state);

    // A holding under someone other than the payload's recipient: a mint the
    // destination would credit to the wrong account if it credited it at all.
    let other_holding =
        wrapped_token_core::holding_account_id(wrapped_token_id, &[4; 32]).into_value();
    let lock = lock_tx_to(
        &holder_key,
        holder_id,
        zone_b,
        0,
        0,
        wrapped_token_id,
        vec![
            wrapped_token_core::config_account_id(wrapped_token_id).into_value(),
            other_holding,
        ],
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0) else {
        panic!("a lock over the wrong mint accounts must not execute");
    };
    assert!(
        format!("{err:?}").contains("target accounts must be the mint's config"),
        "rejected for the wrong reason: {err:?}"
    );
    assert_eq!(
        state.get_account_by_id(holder_id).balance,
        INITIAL_BALANCE,
        "a refused lock leaves the holder's balance alone"
    );
}

/// The config is read by address, so substituting another account for it fails
/// rather than reading the pins out of whatever that account holds. Without the
/// address check, 64 bytes a caller controls would re-pin both for one lock.
#[test]
fn a_lock_with_a_substituted_config_account_is_rejected() {
    let bridge_lock_id = programs::bridge_lock().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    // A bridge-lock-owned account holding pins of the caller's choosing, so only
    // the address check stands between it and being read as the config.
    let decoy_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let decoy_id = AccountId::from(&PublicKey::new_from_private_key(&decoy_key));
    let mut state = base_state().with_public_accounts([
        (
            holder_id,
            Account {
                program_owner: bridge_lock_id.into(),
                balance: INITIAL_BALANCE,
                ..Default::default()
            },
        ),
        (
            decoy_id,
            Account {
                program_owner: bridge_lock_id.into(),
                data: bridge_lock_core::config_bytes([3; 8], [4; 8])
                    .to_vec()
                    .try_into()
                    .expect("pinned ids fit in account data"),
                ..Default::default()
            },
        ),
    ]);
    seed_bridge_lock_config(&mut state);

    let lock = bridge_lock_core::Instruction::Lock {
        amount: LOCK_AMOUNT,
        target_zone: zone_b,
        target_program_id: wrapped_token_id,
        target_accounts: mint_target_accounts(wrapped_token_id),
        payload: mint_payload(),
        ordinal,
    };
    let message = Message::try_new(
        bridge_lock_id,
        vec![
            decoy_id,
            holder_id,
            bridge_lock_core::escrow_account_id(bridge_lock_id),
            outbox_pda(outbox_id, bridge_lock_id, &zone_b, ordinal),
        ],
        vec![0_u128.into()],
        lock,
    )
    .expect("build lock message");
    let tx = PublicTransaction::new(
        message.clone(),
        WitnessSet::for_message(&message, &[&holder_key]),
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a lock over a substituted config account must not execute");
    };
    assert!(
        format!("{err:?}").contains("must be the bridge-lock config PDA"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// A bridge with no pin cannot fall back to caller-named programs: it stops
/// locking. The state a zone reaches by skipping the genesis init.
#[test]
fn a_lock_before_the_pins_are_set_is_rejected() {
    let bridge_lock_id = programs::bridge_lock().id();
    let zone_b = [2_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let state = base_state().with_public_accounts([(
        holder_id,
        Account {
            program_owner: bridge_lock_id.into(),
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);

    let lock = lock_tx(&holder_key, holder_id, zone_b, 0, 0);
    let Err(err) = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0) else {
        panic!("a lock with nothing pinned must not execute");
    };
    assert!(
        format!("{err:?}").contains("config account holds an outbox and a mint target"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// Written once, on the same terms as the sender's: an identical re-init is the
/// genesis replay, a different one would redirect every lock on the zone.
#[test]
fn the_bridge_pins_are_written_once_and_replayable() {
    let bridge_lock_id = programs::bridge_lock().id();
    let config_id = bridge_lock_core::config_account_id(bridge_lock_id);
    let outbox_id = programs::cross_zone_outbox().id();
    let wrapped_token_id = programs::wrapped_token().id();

    let init = |outbox: lee_core::program::ProgramId, target: lee_core::program::ProgramId| {
        let message = Message::try_new(
            bridge_lock_id,
            vec![config_id],
            vec![],
            bridge_lock_core::Instruction::InitConfig {
                outbox_program_id: outbox,
                target_program_id: target,
            },
        )
        .expect("build InitConfig message");
        PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
    };

    let mut state = base_state();

    let diff = ValidatedStateDiff::from_public_transaction(
        &init(outbox_id, wrapped_token_id),
        &state,
        1,
        0,
    )
    .expect("the first init claims the config PDA");
    state.apply_state_diff(diff);
    assert_eq!(
        bridge_lock_core::read_config(&state.get_account_by_id(config_id).data.into_inner()),
        Some((outbox_id, wrapped_token_id)),
        "the config pins both programs after genesis"
    );

    ValidatedStateDiff::from_public_transaction(&init(outbox_id, wrapped_token_id), &state, 2, 0)
        .expect("replaying the identical init is a no-op, not a failure");

    // Either half moving is a redirect: the outbox decides whether the emission is
    // recorded, the target where the value lands.
    for (outbox, target, what) in [
        ([3; 8], wrapped_token_id, "outbox"),
        (outbox_id, [3; 8], "mint target"),
    ] {
        let Err(err) =
            ValidatedStateDiff::from_public_transaction(&init(outbox, target), &state, 3, 0)
        else {
            panic!("a re-init naming a different {what} must not execute");
        };
        assert!(
            format!("{err:?}").contains("already pins a different outbox or mint target"),
            "rejected for the wrong reason: {err:?}"
        );
    }
}

/// An emitter with no pin cannot fall back to a caller-named outbox: it stops
/// emitting. The state a zone reaches by skipping the genesis init.
#[test]
fn a_send_before_the_pin_is_set_is_rejected() {
    let sender_id = programs::ping_sender().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let state = base_state();
    let slot = outbox_pda(outbox_id, sender_id, &zone_b, ordinal);
    let send = send_tx(
        vec![sender_config_account_id(sender_id), slot],
        zone_b,
        ordinal,
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&send, &state, 1, 0) else {
        panic!("a send with no outbox pinned must not execute");
    };
    assert!(
        format!("{err:?}").contains("config account holds an outbox program id"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The config is read by address, so substituting another account for it fails
/// rather than pinning the outbox to whatever that account happens to hold.
#[test]
fn a_send_with_a_substituted_config_account_is_rejected() {
    let sender_id = programs::ping_sender().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let zone_b = [2_u8; 32];
    let ordinal = 0;

    let mut state = base_state();
    seed_ping_sender_config(&mut state);

    let slot = outbox_pda(outbox_id, sender_id, &zone_b, ordinal);
    let send = send_tx(vec![ping_record_pda(sender_id), slot], zone_b, ordinal);

    let Err(err) = ValidatedStateDiff::from_public_transaction(&send, &state, 1, 0) else {
        panic!("a send over a substituted config account must not execute");
    };
    assert!(
        format!("{err:?}").contains("must be the ping-sender config PDA"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// Written once: an identical re-init has to succeed, since genesis is replayed
/// during multi-sequencer reconstruction, while one naming a different outbox has
/// to fail, or anyone could redirect every emission on the zone after genesis.
#[test]
fn the_outbox_pin_is_written_once_and_replayable() {
    let sender_id = programs::ping_sender().id();
    let config_id = sender_config_account_id(sender_id);

    // Unsigned and nonce-free, as genesis builds it: the config PDA has no signer.
    let init = |outbox: lee_core::program::ProgramId| {
        let message = Message::try_new(
            sender_id,
            vec![config_id],
            vec![],
            ping_core::SenderInstruction::InitConfig {
                outbox_program_id: outbox,
            },
        )
        .expect("build InitConfig message");
        PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
    };

    let mut state = base_state();
    let outbox_id = programs::cross_zone_outbox().id();

    let first = init(outbox_id);
    let diff = ValidatedStateDiff::from_public_transaction(&first, &state, 1, 0)
        .expect("the first init claims the config PDA");
    state.apply_state_diff(diff);
    assert_eq!(
        read_outbox(&state.get_account_by_id(config_id).data.into_inner()),
        Some(outbox_id),
        "the config pins the outbox after genesis"
    );

    ValidatedStateDiff::from_public_transaction(&init(outbox_id), &state, 2, 0)
        .expect("replaying the identical init is a no-op, not a failure");

    let Err(err) = ValidatedStateDiff::from_public_transaction(&init([3; 8]), &state, 3, 0) else {
        panic!("a re-init naming a different outbox must not execute");
    };
    assert!(
        format!("{err:?}").contains("already pins a different outbox"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The token's authority path, end to end: each guard refuses for its own
/// reason, the signed path works more than once through the claimed account, and
/// renouncing is one-way. The receiver battery mirrors this one.
#[test]
fn the_token_authority_path_holds() {
    let wrapped_token_id = programs::wrapped_token().id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let other_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let other = AccountId::from(&PublicKey::new_from_private_key(&other_key));

    let update = |account: AccountId,
                  signer: &PrivateKey,
                  nonce: u128,
                  sources: Vec<([u8; 32], lee_core::program::ProgramId)>| {
        signed_tx(
            wrapped_token_id,
            vec![config_id, account],
            nonce,
            words_of!(&wrapped_token_core::Instruction::UpdateSources { sources }),
            signer,
        )
    };
    let renounce = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            wrapped_token_id,
            vec![config_id, account],
            nonce,
            words_of!(&wrapped_token_core::Instruction::RenounceAuthority),
            signer,
        )
    };
    let bridge_source = vec![(src_zone, programs::bridge_lock().id())];

    // With no authority configured, nothing moves in either direction.
    let mut unset = base_state();
    seed_wrapped_config(&mut unset, None, vec![]);
    rejects_at(
        &unset,
        &update(authority, &key, 0, bridge_source.clone()),
        1,
        "fixed at genesis",
    );
    rejects_at(
        &unset,
        &renounce(authority, &key, 0),
        1,
        "already renounced",
    );

    // With one configured: the wrong account, and the right account without its
    // own signature, are refused for their own reasons.
    let mut state = base_state();
    seed_wrapped_config(&mut state, Some(authority), vec![]);
    rejects_at(
        &state,
        &update(other, &other_key, 0, bridge_source.clone()),
        1,
        "second account must be the configured authority",
    );
    rejects_at(
        &state,
        &renounce(other, &other_key, 0),
        1,
        "second account must be the configured authority",
    );
    rejects_at(
        &state,
        &update(authority, &other_key, 0, bridge_source.clone()),
        1,
        "must authorize a source change",
    );
    rejects_at(
        &state,
        &renounce(authority, &other_key, 0),
        1,
        "must authorize renouncing it",
    );

    // Substituting another account for the config is refused rather than read,
    // on both instructions.
    let substituted = |words: Vec<u32>| {
        signed_tx(
            wrapped_token_id,
            vec![ping_record_pda(wrapped_token_id), authority],
            0,
            words,
            &key,
        )
    };
    rejects_at(
        &state,
        &substituted(words_of!(&wrapped_token_core::Instruction::UpdateSources {
            sources: bridge_source.clone(),
        })),
        1,
        "must be the wrapped-token config PDA",
    );
    rejects_at(
        &state,
        &substituted(words_of!(
            &wrapped_token_core::Instruction::RenounceAuthority
        )),
        1,
        "must be the wrapped-token config PDA",
    );

    // The authority itself works, and more than once: the first use claims the
    // account for the target, and the second runs on the claimed path.
    let diff = ValidatedStateDiff::from_public_transaction(
        &update(authority, &key, 0, bridge_source.clone()),
        &state,
        1,
        0,
    )
    .expect("the configured authority changes sources");
    state.apply_state_diff(diff);
    let cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(cfg.sources, bridge_source, "the new source is authorized");
    assert_eq!(
        state.get_account_by_id(authority).program_owner,
        wrapped_token_id.into(),
        "the first use claims the authority account for the target"
    );

    let sender_source = vec![(src_zone, programs::ping_sender().id())];
    let second = ValidatedStateDiff::from_public_transaction(
        &update(authority, &key, 1, sender_source.clone()),
        &state,
        2,
        0,
    )
    .expect("the authority acts again");
    state.apply_state_diff(second);
    let updated_cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(
        updated_cfg.sources, sender_source,
        "the second change took effect"
    );
    assert_eq!(
        updated_cfg.authority,
        Some(authority),
        "the authority is unchanged"
    );

    // Renouncing is one-way: the sources freeze at their last value and nothing
    // moves afterwards, in either direction.
    let renounced =
        ValidatedStateDiff::from_public_transaction(&renounce(authority, &key, 2), &state, 3, 0)
            .expect("the authority renounces itself");
    state.apply_state_diff(renounced);
    let renounced_cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(renounced_cfg.authority, None, "the authority is gone");
    assert_eq!(
        renounced_cfg.sources, sender_source,
        "renouncing leaves the sources it froze"
    );
    assert_eq!(
        renounced_cfg.minter,
        programs::cross_zone_inbox().id(),
        "the minter is unchanged"
    );
    rejects_at(
        &state,
        &update(authority, &key, 3, bridge_source),
        4,
        "fixed at genesis",
    );
    rejects_at(
        &state,
        &renounce(authority, &key, 3),
        4,
        "already renounced",
    );
}

/// `ping_receiver` authorizes its own sources too. It holds nothing worth
/// stealing, but without this any program on any configured peer could overwrite
/// the record, and a delivery would prove only that some peer sent it.
#[test]
fn a_delivery_from_an_unauthorized_source_does_not_reach_ping_receiver() {
    let inbox_id = programs::cross_zone_inbox().id();
    let receiver_id = programs::ping_receiver().id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    // Authorizes one source; the delivery comes from another.
    seed_receiver_config(
        &mut state,
        None,
        vec![(src_zone, programs::bridge_lock().id())],
    );

    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: b"ping".to_vec(),
    })
    .expect("serialize ping instruction");
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: programs::ping_sender().id(),
        target_program_id: receiver_id,
        payload: words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        l1_inclusion_witness: None,
    };
    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &msg,
            vec![
                receiver_config_account_id(receiver_id),
                ping_record_pda(receiver_id),
            ],
        ),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("an unauthorized source must not reach the receiver");
    };
    assert!(
        format!("{err:?}").contains("peer source this receiver authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The inbox binds the marker to the message it is delivering. Without that the
/// marker would be a field the dispatch could set freely, and a target checking it
/// would be checking nothing.
#[test]
fn the_inbox_refuses_a_marker_that_does_not_match_the_message() {
    let inbox_id = programs::cross_zone_inbox().id();
    let receiver_id = programs::ping_receiver().id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let sender_id = programs::ping_sender().id();

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(&mut state, None, vec![(src_zone, sender_id)]);

    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: b"ping".to_vec(),
    })
    .expect("serialize ping instruction");
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: sender_id,
        target_program_id: receiver_id,
        payload: words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        l1_inclusion_witness: None,
    };

    // The message says ping_sender; the marker names bridge_lock, which the
    // receiver also would not accept. The inbox must refuse it first.
    let message = Message::try_new(
        inbox_id,
        vec![
            inbox_config_account_id(inbox_id),
            inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id),
            inbox_source_marker_account_id(inbox_id, &src_zone, programs::bridge_lock().id()),
            receiver_config_account_id(receiver_id),
            ping_record_pda(receiver_id),
        ],
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a marker that does not match the message must not be delivered");
    };
    assert!(
        format!("{err:?}").contains("must be the source marker PDA for this message"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The receiver's authority path is a mirror of the token's, and a mirror is
/// exactly where a copy-paste slip hides. Same battery, run against it.
#[test]
fn the_receiver_authority_path_holds() {
    let receiver_id = programs::ping_receiver().id();
    let config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];
    let sender_id = programs::ping_sender().id();

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let other_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let other = AccountId::from(&PublicKey::new_from_private_key(&other_key));

    let update = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            receiver_id,
            vec![config_id, account],
            nonce,
            words_of!(&ping_core::ReceiverInstruction::UpdateSources {
                sources: vec![(src_zone, sender_id)],
            }),
            signer,
        )
    };
    let renounce = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            receiver_id,
            vec![config_id, account],
            nonce,
            words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
            signer,
        )
    };

    // The wrong account, and the right account without its own signature, are
    // both refused for their own reasons.
    let mut state = base_state();
    seed_receiver_config(&mut state, Some(authority), vec![]);
    rejects_at(
        &state,
        &update(other, &other_key, 0),
        1,
        "must be the configured authority",
    );
    rejects_at(
        &state,
        &renounce(other, &other_key, 0),
        1,
        "must be the configured authority",
    );
    rejects_at(
        &state,
        &update(authority, &other_key, 0),
        1,
        "must authorize a source change",
    );
    rejects_at(
        &state,
        &renounce(authority, &other_key, 0),
        1,
        "must authorize renouncing it",
    );

    // The authority itself works, and renouncing is one-way.
    let diff =
        ValidatedStateDiff::from_public_transaction(&update(authority, &key, 0), &state, 1, 0)
            .expect("the configured authority changes sources");
    state.apply_state_diff(diff);
    let cfg = ping_core::ReceiverConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(cfg.sources, vec![(src_zone, sender_id)]);
    assert_eq!(cfg.deliverer, programs::cross_zone_inbox().id());

    let renounce_diff =
        ValidatedStateDiff::from_public_transaction(&renounce(authority, &key, 1), &state, 2, 0)
            .expect("the authority renounces itself");
    state.apply_state_diff(renounce_diff);
    let renounced_cfg = ping_core::ReceiverConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(renounced_cfg.authority, None, "the authority is gone");
    assert_eq!(
        renounced_cfg.sources,
        vec![(src_zone, sender_id)],
        "renouncing freezes the list it had"
    );
    rejects_at(&state, &update(authority, &key, 2), 3, "fixed at genesis");
    rejects_at(
        &state,
        &renounce(authority, &key, 2),
        3,
        "already renounced",
    );
}

/// The inbox cannot reach the authority instructions, named as governance or not:
/// it prepends the source marker to every chained call, so the config never lands
/// where these instructions read it. Worth pinning, because the inbox is the only
/// program that chain-calls a target today, so this is what actually keeps a peer
/// away from the source list.
#[test]
fn the_inbox_cannot_reach_the_authority_instructions() {
    let wrapped_token_id = programs::wrapped_token().id();
    let inbox_id = programs::cross_zone_inbox().id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));

    let update = || {
        chained_via_inbox(
            wrapped_token_id,
            config_id,
            authority,
            words_of!(&wrapped_token_core::Instruction::UpdateSources {
                sources: vec![(src_zone, programs::bridge_lock().id())],
            }),
        )
    };

    // No governance named: the chained call is refused.
    let mut closed = base_state();
    seed_inbox_config(&mut closed, self_zone);
    seed_wrapped_config(&mut closed, Some(authority), vec![]);
    rejects_at(
        &closed,
        &update(),
        1,
        "must be the wrapped-token config PDA",
    );

    // Naming the inbox as governance changes nothing: the obstacle is structural,
    // not the caller check. The prepended marker sits at index 0, so with or
    // without the inbox named as governance the call dies on the config-address
    // check, before the caller check is even reached.
    let mut open = base_state();
    seed_inbox_config(&mut open, self_zone);
    seed_wrapped_config_with_governance(&mut open, Some(inbox_id), Some(authority), vec![]);
    rejects_at(&open, &update(), 1, "must be the wrapped-token config PDA");
}

/// A program-held authority acts through the governance program delegating its
/// PDA on the chained call: the first use has the target claim the account, the
/// second runs on the claimed path, and renouncing through it is as total as
/// renouncing top-level.
#[test]
fn the_governance_path_holds() {
    let wrapped_token_id = programs::wrapped_token().id();
    let proxy_id = test_programs::authority_proxy().id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs([test_programs::authority_proxy()]);
    seed_wrapped_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);

    let update = |sources: Vec<([u8; 32], lee_core::program::ProgramId)>| {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            authority,
            Some(seed),
            words_of!(&wrapped_token_core::Instruction::UpdateSources { sources }),
        )
    };
    let renounce = || {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            authority,
            Some(seed),
            words_of!(&wrapped_token_core::Instruction::RenounceAuthority),
        )
    };

    let first = ValidatedStateDiff::from_public_transaction(
        &update(vec![(src_zone, programs::bridge_lock().id())]),
        &state,
        1,
        0,
    )
    .expect("the governance path changes sources");
    state.apply_state_diff(first);

    let cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(cfg.sources, vec![(src_zone, programs::bridge_lock().id())]);
    assert_eq!(
        state.get_account_by_id(authority).program_owner,
        wrapped_token_id.into(),
        "the first use claims the delegated PDA for the target"
    );

    let second = ValidatedStateDiff::from_public_transaction(&update(vec![]), &state, 2, 0)
        .expect("the governance path acts again");
    state.apply_state_diff(second);
    let cleared_cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert!(
        cleared_cfg.sources.is_empty(),
        "the second change took effect"
    );
    assert_eq!(cleared_cfg.authority, Some(authority));

    let renounced = ValidatedStateDiff::from_public_transaction(&renounce(), &state, 3, 0)
        .expect("the governance path renounces");
    state.apply_state_diff(renounced);
    let renounced_cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(renounced_cfg.authority, None, "the authority is gone");

    rejects_at(
        &state,
        &update(vec![(src_zone, programs::bridge_lock().id())]),
        4,
        "fixed at genesis",
    );
    rejects_at(&state, &renounce(), 4, "already renounced");
}

/// Each governance-path guard fails on its own: a caller other than the
/// configured governance program is refused with the delegation in order, no
/// configured governance refuses every chained caller (on the token's update
/// and on its three sibling handlers), and the governance program without
/// delegating finds the authority unauthorized.
#[test]
fn the_governance_path_guards_hold() {
    let wrapped_token_id = programs::wrapped_token().id();
    let receiver_id = programs::ping_receiver().id();
    let proxy_id = test_programs::authority_proxy().id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let call = |delegated: Option<lee_core::program::PdaSeed>| {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            authority,
            delegated,
            words_of!(&wrapped_token_core::Instruction::UpdateSources {
                sources: vec![(src_zone, programs::bridge_lock().id())],
            }),
        )
    };

    // A perfect call shape from a program that is not the configured governance.
    let mut other = base_state().with_programs([test_programs::authority_proxy()]);
    seed_wrapped_config_with_governance(
        &mut other,
        Some(programs::ping_sender().id()),
        Some(authority),
        vec![],
    );
    rejects_at(
        &other,
        &call(Some(seed)),
        1,
        "through the configured governance program",
    );

    // No governance configured: every chained caller is refused.
    let mut closed = base_state().with_programs([test_programs::authority_proxy()]);
    seed_wrapped_config(&mut closed, Some(authority), vec![]);
    seed_receiver_config(&mut closed, Some(authority), vec![]);
    rejects_at(
        &closed,
        &call(Some(seed)),
        1,
        "through the configured governance program",
    );

    // The same pin guards the three sibling handlers, both renounces and the
    // receiver's update, each of which would otherwise accept the delegated
    // authority and succeed.
    for (target, config, words) in [
        (
            wrapped_token_id,
            config_id,
            words_of!(&wrapped_token_core::Instruction::RenounceAuthority),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::UpdateSources {
                sources: vec![(src_zone, programs::ping_sender().id())],
            }),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
        ),
    ] {
        rejects_at(
            &closed,
            &via_proxy(proxy_id, target, config, authority, Some(seed), words),
            1,
            "through the configured governance program",
        );
    }

    // The configured governance itself, but not delegating the authority.
    let mut undelegated = base_state().with_programs([test_programs::authority_proxy()]);
    seed_wrapped_config_with_governance(&mut undelegated, Some(proxy_id), Some(authority), vec![]);
    rejects_at(
        &undelegated,
        &call(None),
        1,
        "must authorize a source change",
    );
}

/// The receiver's governance path works the same way; without this its config
/// never carries a governance in any test.
#[test]
fn the_receiver_governance_path_holds() {
    let receiver_id = programs::ping_receiver().id();
    let proxy_id = test_programs::authority_proxy().id();
    let config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs([test_programs::authority_proxy()]);
    seed_receiver_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);

    let tx = via_proxy(
        proxy_id,
        receiver_id,
        config_id,
        authority,
        Some(seed),
        words_of!(&ping_core::ReceiverInstruction::UpdateSources {
            sources: vec![(src_zone, programs::ping_sender().id())],
        }),
    );

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("the receiver governance path changes sources");
    state.apply_state_diff(diff);
    let cfg = ping_core::ReceiverConfig::from_bytes(
        &state.get_account_by_id(config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(cfg.sources, vec![(src_zone, programs::ping_sender().id())]);
    assert_eq!(
        state.get_account_by_id(authority).program_owner,
        receiver_id.into(),
        "the first use claims the delegated PDA for the receiver"
    );
}

/// One authority seeds both targets at genesis, and the config doc promises that
/// whichever target is used first owns the account while the other keeps
/// working. Claim through the token, then act and renounce on the receiver.
#[test]
fn a_shared_authority_survives_the_first_claim() {
    let wrapped_token_id = programs::wrapped_token().id();
    let receiver_id = programs::ping_receiver().id();
    let proxy_id = test_programs::authority_proxy().id();
    let token_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let receiver_config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs([test_programs::authority_proxy()]);
    seed_wrapped_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);
    seed_receiver_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);

    let token_update = via_proxy(
        proxy_id,
        wrapped_token_id,
        token_config_id,
        authority,
        Some(seed),
        words_of!(&wrapped_token_core::Instruction::UpdateSources {
            sources: vec![(src_zone, programs::bridge_lock().id())],
        }),
    );
    let first = ValidatedStateDiff::from_public_transaction(&token_update, &state, 1, 0)
        .expect("the token claims the shared authority");
    state.apply_state_diff(first);
    assert_eq!(
        state.get_account_by_id(authority).program_owner,
        wrapped_token_id.into(),
        "the first target to be used owns the account"
    );

    let receiver_update = via_proxy(
        proxy_id,
        receiver_id,
        receiver_config_id,
        authority,
        Some(seed),
        words_of!(&ping_core::ReceiverInstruction::UpdateSources {
            sources: vec![(src_zone, programs::ping_sender().id())],
        }),
    );
    let second = ValidatedStateDiff::from_public_transaction(&receiver_update, &state, 2, 0)
        .expect("the other target still acts on the token-owned authority");
    state.apply_state_diff(second);
    let receiver_cfg = ping_core::ReceiverConfig::from_bytes(
        &state
            .get_account_by_id(receiver_config_id)
            .data
            .into_inner(),
    )
    .expect("config decodes");
    assert_eq!(
        receiver_cfg.sources,
        vec![(src_zone, programs::ping_sender().id())]
    );
    assert_eq!(
        state.get_account_by_id(authority).program_owner,
        wrapped_token_id.into(),
        "the receiver never takes the account over"
    );

    let receiver_renounce = via_proxy(
        proxy_id,
        receiver_id,
        receiver_config_id,
        authority,
        Some(seed),
        words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
    );
    let third = ValidatedStateDiff::from_public_transaction(&receiver_renounce, &state, 3, 0)
        .expect("the other target renounces on the token-owned authority");
    state.apply_state_diff(third);
    let renounced_cfg = ping_core::ReceiverConfig::from_bytes(
        &state
            .get_account_by_id(receiver_config_id)
            .data
            .into_inner(),
    )
    .expect("config decodes");
    assert_eq!(renounced_cfg.authority, None, "the receiver side is gone");
    let token_cfg = wrapped_token_core::WrappedTokenConfig::from_bytes(
        &state.get_account_by_id(token_config_id).data.into_inner(),
    )
    .expect("config decodes");
    assert_eq!(
        token_cfg.authority,
        Some(authority),
        "renouncing one target leaves the other's grant alone"
    );
}

/// An authority account with any history can never be claimed, so all four
/// authority handlers refuse it, and say why rather than surfacing a rule number.
#[test]
fn an_authority_account_with_history_is_refused() {
    let wrapped_token_id = programs::wrapped_token().id();
    let receiver_id = programs::ping_receiver().id();
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));

    let mut state = base_state();
    seed_wrapped_config(&mut state, Some(authority), vec![]);
    seed_receiver_config(&mut state, Some(authority), vec![]);
    // Unowned but already used: exactly what one prior signature leaves behind.
    state = state.with_public_accounts([(
        authority,
        Account {
            nonce: 1_u128.into(),
            ..Default::default()
        },
    )]);

    for (program, config_id, words) in [
        (
            wrapped_token_id,
            wrapped_token_core::config_account_id(wrapped_token_id),
            words_of!(&wrapped_token_core::Instruction::UpdateSources {
                sources: vec![(src_zone, programs::bridge_lock().id())],
            }),
        ),
        (
            wrapped_token_id,
            wrapped_token_core::config_account_id(wrapped_token_id),
            words_of!(&wrapped_token_core::Instruction::RenounceAuthority),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::UpdateSources {
                sources: vec![(src_zone, programs::ping_sender().id())],
            }),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
        ),
    ] {
        rejects_at(
            &state,
            &signed_tx(program, vec![config_id, authority], 1, words, &key),
            1,
            "must be untouched before its first use",
        );
    }
}

/// The guards that survive a deletion otherwise: the receiver's config-address
/// checks its substitution cases miss, and the three caller pins that are only
/// reachable through the inbox.
#[test]
fn the_remaining_authority_guards_hold() {
    let wrapped_token_id = programs::wrapped_token().id();
    let receiver_id = programs::ping_receiver().id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, Some(authority), vec![]);
    seed_receiver_config(&mut state, Some(authority), vec![]);

    // Config address, on both receiver instructions.
    for words in [
        words_of!(&ping_core::ReceiverInstruction::UpdateSources {
            sources: vec![(src_zone, programs::ping_sender().id())],
        }),
        words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
    ] {
        rejects_at(
            &state,
            &signed_tx(
                receiver_id,
                vec![ping_record_pda(receiver_id), authority],
                0,
                words,
                &key,
            ),
            1,
            "must be the receiver config PDA",
        );
    }

    // Reached through the inbox rather than top-level: the prepended marker sits
    // at index 0, so each call dies on the target's config-address check. The
    // caller pins themselves are exercised through the proxy in
    // the_governance_path_guards_hold, where the account list is well formed.
    for (target, config_id, words, expected) in [
        (
            wrapped_token_id,
            wrapped_token_core::config_account_id(wrapped_token_id),
            words_of!(&wrapped_token_core::Instruction::RenounceAuthority),
            "must be the wrapped-token config PDA",
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::RenounceAuthority),
            "must be the receiver config PDA",
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            words_of!(&ping_core::ReceiverInstruction::UpdateSources {
                sources: vec![(src_zone, programs::ping_sender().id())],
            }),
            "must be the receiver config PDA",
        ),
    ] {
        rejects_at(
            &state,
            &chained_via_inbox(target, config_id, authority, words),
            1,
            expected,
        );
    }
}

/// A token that authorizes nothing mints for nobody. The state a zone reaches with
/// no peers configured, where the config is still seeded so its PDA cannot be
/// claimed by a first initializer.
#[test]
fn a_mint_is_refused_when_the_token_authorizes_no_source() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, None, vec![]);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: programs::bridge_lock().id(),
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };
    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &msg,
            vec![
                wrapped_token_core::config_account_id(wrapped_token_id),
                wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
            ],
        ),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a token authorizing nothing must not mint");
    };
    assert!(
        format!("{err:?}").contains("peer source this token authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The marker only means something because the caller is pinned to the inbox.
/// Invoked directly, with the caller handing in the marker themselves, the mint
/// must refuse before it ever looks at it.
#[test]
fn a_top_level_mint_is_refused() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let src_zone = [2_u8; 32];
    let src_program_id = programs::bridge_lock().id();

    let mut state = base_state();
    seed_wrapped_config(&mut state, None, vec![(src_zone, src_program_id)]);

    let marker_id = inbox_source_marker_account_id(inbox_id, &src_zone, src_program_id);
    let message = Message::try_new(
        wrapped_token_id,
        vec![
            marker_id,
            wrapped_token_core::config_account_id(wrapped_token_id),
            wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
        ],
        vec![],
        wrapped_token_core::Instruction::Mint {
            recipient: RECIPIENT,
            amount: LOCK_AMOUNT,
        },
    )
    .expect("build mint message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a directly invoked mint must not execute");
    };
    assert!(
        format!("{err:?}").contains("only callable by the authorized minter"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// Drives a hand-built `cross_zone_inbox::Dispatch` (as the watcher would inject)
/// and asserts it chains into `wrapped_token::Mint`, crediting the recipient.
#[test]
fn inbox_dispatch_mints_wrapped_token() {
    let diff = dispatch_mint(LOCK_AMOUNT).expect("dispatch must validate and execute");
    let holding_id =
        wrapped_token_core::holding_account_id(programs::wrapped_token().id(), &RECIPIENT);
    let minted = wrapped_token_core::read_balance(
        &diff.public_diff()[&holding_id].data.clone().into_inner(),
    );
    assert_eq!(
        minted, LOCK_AMOUNT,
        "recipient holding minted the locked amount"
    );
}

/// `ping_sender` lets its caller choose the target and payload freely, so any user
/// on a peer can aim a `Mint` payload at `wrapped_token`. The inbox no longer
/// refuses it; the token does, because the marker names `ping_sender` and the
/// token authorized only the bridge. This is the check that replaced the central
/// route table, so it must be the thing that rejects here.
#[test]
fn a_mint_from_an_unrouted_emitter_is_rejected() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    // The config a bridging zone writes: the lock program may mint, nothing else.
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(
        &mut state,
        None,
        vec![(src_zone, programs::bridge_lock().id())],
    );

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        // The emitter a user can drive directly, aimed at the bridge's target.
        src_program_id: programs::ping_sender().id(),
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(inbox_id, &msg, vec![wrapped_config_id, holding_id]),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a delivery from a source the token did not authorize must not mint");
    };
    assert!(
        format!("{err:?}").contains("peer source this token authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

/// The same target reached by the emitter the route names still works. Without
/// this, the test above would pass equally against an inbox that rejected every
/// delivery.
#[test]
fn a_mint_from_the_routed_emitter_is_accepted() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let bridge_lock_id = programs::bridge_lock().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(
        &mut state,
        None,
        vec![(src_zone, programs::bridge_lock().id())],
    );

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 0,
        src_program_id: bridge_lock_id,
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(inbox_id, &msg, vec![wrapped_config_id, holding_id]),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("the routed emitter must still deliver");
    let minted = wrapped_token_core::read_balance(
        &diff.public_diff()[&holding_id].data.clone().into_inner(),
    );
    assert_eq!(minted, LOCK_AMOUNT);
}

/// A dispatch whose message key is already in the seen-shard is an idempotent
/// no-op: the inbox makes no chained call, so the wrapped token is not minted a
/// second time. This is the bridge's replay defense.
#[test]
fn mint_replay_rejected() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;
    let src_tx_index = 0;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, None, vec![(src_zone, [9_u32; 8])]);

    // Seed the seen-shard as already holding this delivery, so the inbox takes
    // the replay no-op branch. The shard is inbox-owned (claimed on a prior
    // delivery) and bound to the same source block, so the guest leaves it
    // untouched.
    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let mut shard = SeenShard::default();
    shard.insert(SRC_BLOCK_HASH, src_tx_index);
    state = state.with_public_accounts([(
        seen_id,
        Account {
            program_owner: inbox_id.into(),
            balance: 0,
            data: shard
                .to_bytes()
                .try_into()
                .expect("shard fits in account data"),
            nonce: 0_u128.into(),
        },
    )]);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index,
        src_program_id: [9_u32; 8],
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(inbox_id, &msg, vec![wrapped_config_id, holding_id]),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("a replayed dispatch is a valid no-op, not an error");
    let public_diff = diff.public_diff();

    // No mint: the holding is never credited on replay.
    let minted = public_diff.get(&holding_id).map_or(0, |account| {
        wrapped_token_core::read_balance(&account.data.clone().into_inner())
    });
    assert_eq!(minted, 0, "a replayed message must not mint again");

    // The seen-shard is untouched by the no-op.
    if let Some(seen) = public_diff.get(&seen_id) {
        let shard_after =
            SeenShard::from_bytes(&seen.data.clone().into_inner()).expect("seen shard decodes");
        assert_eq!(shard_after, shard, "replay must not modify the seen-shard");
    }
}

/// A peer publishing two blocks at one block id gets at most one delivered from.
///
/// Both resolve to the same shard account; the first binds it. Failing rather
/// than no-opping is the point: a replay no-op would let a peer choose which of
/// two messages at one coordinate the target program ever sees.
#[test]
fn a_delivery_from_a_second_block_at_the_same_id_is_refused() {
    let inbox_id = programs::cross_zone_inbox().id();
    let receiver_id = programs::ping_receiver().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;
    let other_block_hash = [8_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(&mut state, None, vec![(src_zone, [9_u32; 8])]);

    // The shard as the first delivery left it: bound, holding transaction 0.
    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let mut shard = SeenShard::default();
    shard.insert(SRC_BLOCK_HASH, 0);
    state = state.with_public_accounts([(
        seen_id,
        Account {
            program_owner: inbox_id.into(),
            balance: 0,
            data: shard
                .to_bytes()
                .try_into()
                .expect("shard fits in account data"),
            nonce: 0_u128.into(),
        },
    )]);

    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: b"from-the-other-block".to_vec(),
    })
    .expect("serialize ping instruction");
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    // A different transaction index, so this is not a replay: only the source
    // block differs from what the shard is bound to.
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: other_block_hash,
        src_tx_index: 1,
        src_program_id: [9_u32; 8],
        target_program_id: receiver_id,
        payload,
        l1_inclusion_witness: None,
    };

    let record_id = ping_record_pda(receiver_id);
    let message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &msg,
            vec![receiver_config_account_id(receiver_id), record_id],
        ),
        vec![],
        InboxInstruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    assert!(
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).is_err(),
        "a delivery from a block the shard is not bound to must not execute"
    );

    // Control: the same delivery naming the bound block executes, so the refusal
    // above is the binding and not the transaction's shape.
    let control_words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: b"from-the-bound-block".to_vec(),
    })
    .expect("serialize ping instruction");
    let control_msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_tx_index: 1,
        src_program_id: [9_u32; 8],
        target_program_id: receiver_id,
        payload: control_words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect(),
        l1_inclusion_witness: None,
    };
    let control_message = Message::try_new(
        inbox_id,
        dispatch_accounts(
            inbox_id,
            &control_msg,
            vec![receiver_config_account_id(receiver_id), record_id],
        ),
        vec![],
        InboxInstruction::Dispatch(control_msg),
    )
    .expect("build dispatch message");
    let control_tx = PublicTransaction::new(control_message, WitnessSet::from_raw_parts(vec![]));

    let diff = ValidatedStateDiff::from_public_transaction(&control_tx, &state, 1, 0)
        .expect("a second delivery from the bound block executes");
    let public_diff = diff.public_diff();
    let seen_after = public_diff
        .get(&seen_id)
        .expect("the shard records the new delivery");
    let shard_after =
        SeenShard::from_bytes(&seen_after.data.clone().into_inner()).expect("seen shard decodes");
    assert!(shard_after.contains(0), "the first delivery is still there");
    assert!(shard_after.contains(1), "and the second is recorded");
    assert_eq!(
        shard_after.src_block_hash, SRC_BLOCK_HASH,
        "a shard stays bound to the block that claimed it"
    );
}
