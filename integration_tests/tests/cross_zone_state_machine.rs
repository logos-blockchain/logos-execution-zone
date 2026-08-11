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

use std::collections::BTreeMap;

use cross_zone_inbox_core::{
    CrossZoneMessage, CrossZoneRoute, InboxConfig, Instruction as InboxInstruction, SeenShard,
    inbox_config_account_id, inbox_seen_shard_account_id, message_key,
};
use cross_zone_outbox_core::{OutboxRecord, outbox_pda};
use fee_core::params::MAX_GAS_EXEC;
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction, V03State, ValidatedStateDiff,
    public_transaction::{Message, WitnessSet},
};
use lee_core::account::Account;
use ping_core::{ReceiverInstruction, ping_record_pda};

const INITIAL_BALANCE: u128 = 100;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];

/// State registering the cross-zone builtins these tests exercise.
fn base_state() -> V03State {
    V03State::new().with_programs([
        programs::cross_zone_inbox(),
        programs::cross_zone_outbox(),
        programs::ping_receiver(),
        programs::bridge_lock(),
        programs::wrapped_token(),
    ])
}

/// Seeds an inbox config (inbox-owned) allowing `src_zone -> target`.
fn seed_inbox_config(
    state: &mut V03State,
    self_zone: [u8; 32],
    src_zone: [u8; 32],
    src_program_id: lee_core::program::ProgramId,
    target: lee_core::program::ProgramId,
) {
    let inbox_id = programs::cross_zone_inbox().id();
    let mut allowed_routes = BTreeMap::new();
    allowed_routes.insert(
        src_zone,
        vec![CrossZoneRoute {
            src_program_id,
            target_program_id: target,
        }],
    );
    let config = InboxConfig {
        self_zone,
        allowed_routes,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        inbox_config_account_id(inbox_id),
        Account {
            program_owner: inbox_id,
            balance: 0,
            data: config
                .to_bytes()
                .try_into()
                .expect("config fits in account data"),
            nonce: 0_u128.into(),
        },
    )]);
}

/// Seeds the wrapped-token config account pinning the inbox as authorized minter,
/// matching what genesis seeds for a real zone.
fn seed_wrapped_config(state: &mut V03State) {
    let wrapped_token_id = programs::wrapped_token().id();
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        wrapped_token_core::config_account_id(wrapped_token_id),
        Account {
            program_owner: wrapped_token_id,
            data: wrapped_token_core::minter_bytes(programs::cross_zone_inbox().id())
                .to_vec()
                .try_into()
                .expect("minter id fits in account data"),
            ..Default::default()
        },
    )]);
}

/// The wrapped-token `Mint` the bridge forwards, serialized as the cross-zone
/// payload (risc0 words, little-endian bytes).
fn mint_payload() -> Vec<u8> {
    let mint = wrapped_token_core::Instruction::Mint {
        recipient: RECIPIENT,
        amount: LOCK_AMOUNT,
    };
    let words = risc0_zkvm::serde::to_vec(&mint).expect("serialize mint");
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
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
    seed_inbox_config(&mut state, self_zone, src_zone, [9_u32; 8], receiver_id);

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
        src_tx_index: 0,
        src_program_id: [9_u32; 8],
        target_program_id: receiver_id,
        payload,
        l1_inclusion_witness: None,
    };

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let record_id = ping_record_pda(receiver_id);

    let message = Message::try_new(
        inbox_id,
        vec![inbox_config_account_id(inbox_id), seen_id, record_id],
        vec![],
        InboxInstruction::Dispatch(msg),
        lee::FeeFields::ZERO,
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
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
            program_owner: bridge_lock_id,
            balance: INITIAL_BALANCE,
            ..Default::default()
        },
    )]);

    let payload = mint_payload();
    let target_accounts = vec![
        wrapped_token_core::config_account_id(wrapped_token_id).into_value(),
        wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT).into_value(),
    ];
    let lock = bridge_lock_core::Instruction::Lock {
        amount: LOCK_AMOUNT,
        target_zone: zone_b,
        target_program_id: wrapped_token_id,
        target_accounts,
        payload: payload.clone(),
        outbox_program_id: outbox_id,
        ordinal,
    };

    let escrow_id = bridge_lock_core::escrow_account_id(bridge_lock_id);
    let outbox_record_id = outbox_pda(outbox_id, &zone_b, ordinal);
    let message = Message::try_new(
        bridge_lock_id,
        vec![holder_id, escrow_id, outbox_record_id],
        vec![0_u128.into()],
        lock,
        lee::FeeFields::ZERO,
    )
    .expect("build lock message");
    let witness = WitnessSet::for_message(&message, &[&holder_key]);
    let tx = PublicTransaction::new(message, witness);

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
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
    assert_eq!(record.target_zone, zone_b);
    assert_eq!(record.target_program_id, wrapped_token_id);
    assert_eq!(
        record.payload, payload,
        "emitted payload is the wrapped mint"
    );
}

/// Drives a hand-built `cross_zone_inbox::Dispatch` (as the watcher would inject)
/// and asserts it chains into `wrapped_token::Mint`, crediting the recipient.
#[test]
fn inbox_dispatch_mints_wrapped_token() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(
        &mut state,
        self_zone,
        src_zone,
        [9_u32; 8],
        wrapped_token_id,
    );
    seed_wrapped_config(&mut state);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_tx_index: 0,
        src_program_id: [9_u32; 8],
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        vec![
            inbox_config_account_id(inbox_id),
            seen_id,
            wrapped_config_id,
            holding_id,
        ],
        vec![],
        InboxInstruction::Dispatch(msg),
        lee::FeeFields::ZERO,
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
            .expect("dispatch must validate and execute");
    let minted = wrapped_token_core::read_balance(
        &diff.public_diff()[&holding_id].data.clone().into_inner(),
    );
    assert_eq!(
        minted, LOCK_AMOUNT,
        "recipient holding minted the locked amount"
    );
}

/// A zone that bridges must allow `wrapped_token` as a target. When that
/// allowance was per peer rather than per source program, it was enough for any
/// emitter on the peer to reach it, and `ping_sender` lets its caller choose the
/// target and payload freely. Any user on the peer could therefore mint wrapped
/// tokens with no lock and no escrow behind them, by routing a `Mint` payload
/// through the ping emitter. The route is the pair, so this must not execute.
#[test]
fn a_mint_from_an_unrouted_emitter_is_rejected() {
    let inbox_id = programs::cross_zone_inbox().id();
    let wrapped_token_id = programs::wrapped_token().id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    // The config a bridging zone writes: the lock program may mint, nothing else.
    seed_inbox_config(
        &mut state,
        self_zone,
        src_zone,
        programs::bridge_lock().id(),
        wrapped_token_id,
    );
    seed_wrapped_config(&mut state);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_tx_index: 0,
        // The emitter a user can drive directly, aimed at the bridge's target.
        src_program_id: programs::ping_sender().id(),
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        vec![
            inbox_config_account_id(inbox_id),
            seen_id,
            wrapped_config_id,
            holding_id,
        ],
        vec![],
        InboxInstruction::Dispatch(msg),
        lee::FeeFields::ZERO,
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    assert!(
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC).is_err(),
        "a delivery from an emitter with no route to wrapped_token must not mint"
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
    seed_inbox_config(
        &mut state,
        self_zone,
        src_zone,
        bridge_lock_id,
        wrapped_token_id,
    );
    seed_wrapped_config(&mut state);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_tx_index: 0,
        src_program_id: bridge_lock_id,
        target_program_id: wrapped_token_id,
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let message = Message::try_new(
        inbox_id,
        vec![
            inbox_config_account_id(inbox_id),
            seen_id,
            wrapped_config_id,
            holding_id,
        ],
        vec![],
        InboxInstruction::Dispatch(msg),
        lee::FeeFields::ZERO,
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
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
    seed_inbox_config(
        &mut state,
        self_zone,
        src_zone,
        [9_u32; 8],
        wrapped_token_id,
    );
    seed_wrapped_config(&mut state);

    // Seed the seen-shard as already containing this message's key, so the inbox
    // takes the replay no-op branch. The shard is inbox-owned (claimed on a prior
    // delivery), so the guest leaves it untouched.
    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let mut shard = SeenShard::default();
    shard.insert(message_key(&src_zone, src_block_id, src_tx_index));
    state = state.with_public_accounts([(
        seen_id,
        Account {
            program_owner: inbox_id,
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
        vec![
            inbox_config_account_id(inbox_id),
            seen_id,
            wrapped_config_id,
            holding_id,
        ],
        vec![],
        InboxInstruction::Dispatch(msg),
        lee::FeeFields::ZERO,
    )
    .expect("build dispatch message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
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
