#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Single-zone state-machine tests for cross-zone delivery (ping demo) and the wrapped-token bridge
//! (Demo 2).

use std::collections::BTreeMap;

use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Message as InboxMessage, SeenShard, inbox_config_account_id,
    inbox_seen_shard_account_id, inbox_seen_shard_seed,
};
use lee::{
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction, V03State,
    ValidatedStateDiff,
    error::{InvalidProgramBehaviorError, LeeError},
    public_transaction::{Message, WitnessSet},
};
use lee_core::{account::Account, native_token::TransferError, program::SyncMessage};
use ping_core::{
    ReceiverMessage, ping_record_pda, receiver_config_account_id, receiver_config_seed,
};
use test_guest_core::{
    Script,
    chat::{ChatLog, ChatMessage, chat_log_account_id, chat_log_seed},
};

macro_rules! bytes_of {
    ($message:expr) => {
        borsh::to_vec($message).expect("serialize message")
    };
}

const INITIAL_BALANCE: u128 = 100;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];
const MINT_SRC_ZONE: [u8; 32] = [2; 32];
const MINT_SRC_PROGRAM_ID: lee_core::program::ProgramId = [9_u32; 8];
const SRC_BLOCK_HASH: [u8; 32] = [7; 32];
const LOCK_TARGET_ZONES: [[u8; 32]; 2] = [[2; 32], [9; 32]];

fn wrapped_token_config(
    state: &V03State,
    config_id: AccountId,
) -> wrapped_token_core::WrappedTokenConfig {
    let wrapped_token_id = programs::wrapped_token_account_id();
    wrapped_token_core::WrappedTokenConfig::from_bytes(
        state
            .get_account_by_id(config_id)
            .data
            .actor_state(wrapped_token_id)
            .as_ref(),
    )
    .expect("config decodes")
}

fn receiver_config(state: &V03State, config_id: AccountId) -> ping_core::ReceiverConfig {
    let receiver_id = programs::ping_receiver_account_id();
    ping_core::ReceiverConfig::from_bytes(
        state
            .get_account_by_id(config_id)
            .data
            .actor_state(receiver_id)
            .as_ref(),
    )
    .expect("config decodes")
}

fn base_state() -> V03State {
    V03State::new().with_programs_at([
        (
            programs::cross_zone_inbox_account_id(),
            programs::cross_zone_inbox(),
            true,
        ),
        (
            programs::ping_sender_account_id(),
            programs::ping_sender(),
            true,
        ),
        (
            programs::ping_receiver_account_id(),
            programs::ping_receiver(),
            true,
        ),
        (
            programs::bridge_lock_account_id(),
            programs::bridge_lock(),
            true,
        ),
        (
            programs::wrapped_token_account_id(),
            programs::wrapped_token(),
            true,
        ),
    ])
}

fn seed_inbox_config(state: &mut V03State, self_zone: [u8; 32]) {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let config = InboxConfig { self_zone };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        inbox_config_account_id(inbox_id),
        Account::default().with_actor_state(inbox_id, config.to_bytes().into()),
    )]);
}

fn uncapped_policies(pairs: &[([u8; 32], AccountId)]) -> Vec<wrapped_token_core::SourcePolicy> {
    pairs
        .iter()
        .map(
            |&(src_zone, src_account_id)| wrapped_token_core::SourcePolicy {
                src_zone,
                src_account_id,
                mint_cap: None,
            },
        )
        .collect()
}

fn uncapped_entries(pairs: &[([u8; 32], AccountId)]) -> Vec<wrapped_token_core::SourceEntry> {
    uncapped_policies(pairs)
        .into_iter()
        .map(|policy| wrapped_token_core::SourceEntry { policy, minted: 0 })
        .collect()
}

fn seed_wrapped_config(
    state: &mut V03State,
    authority: Option<AccountId>,
    sources: &[([u8; 32], AccountId)],
) {
    seed_wrapped_config_with_governance(state, None, authority, sources);
}

fn seed_wrapped_config_with_governance(
    state: &mut V03State,
    governance: Option<AccountId>,
    authority: Option<AccountId>,
    sources: &[([u8; 32], AccountId)],
) {
    seed_wrapped_config_entries(state, governance, authority, uncapped_entries(sources));
}

fn seed_wrapped_config_entries(
    state: &mut V03State,
    governance: Option<AccountId>,
    authority: Option<AccountId>,
    entries: Vec<wrapped_token_core::SourceEntry>,
) {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let config = wrapped_token_core::WrappedTokenConfig {
        minter: programs::cross_zone_inbox_account_id(),
        governance,
        authority,
        sources: entries,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        wrapped_token_core::config_account_id(wrapped_token_id),
        Account::default().with_actor_state(wrapped_token_id, config.to_bytes().into()),
    )]);
}

fn seed_receiver_config(
    state: &mut V03State,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], AccountId)>,
) {
    seed_receiver_config_with_governance(state, None, authority, sources);
}

fn seed_receiver_config_with_governance(
    state: &mut V03State,
    governance: Option<AccountId>,
    authority: Option<AccountId>,
    sources: Vec<([u8; 32], AccountId)>,
) {
    let receiver_id = programs::ping_receiver_account_id();
    let config = ping_core::ReceiverConfig {
        deliverer: programs::cross_zone_inbox_account_id(),
        governance,
        authority,
        sources,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        receiver_config_account_id(receiver_id),
        Account::default().with_actor_state(receiver_id, config.to_bytes().into()),
    )]);
}

fn holding_id_of(holder_id: AccountId) -> AccountId {
    bridge_lock_core::holding_account_id(
        programs::bridge_lock_account_id(),
        &holder_id.into_value(),
    )
}

fn seed_holding(state: &mut V03State, holder_id: AccountId, balance: u128) {
    *state = std::mem::replace(state, V03State::new())
        .with_public_accounts([(holding_id_of(holder_id), Account::funded(balance))]);
}

fn seed_bridge_lock_config(state: &mut V03State) {
    let bridge_lock_id = programs::bridge_lock_account_id();
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        bridge_lock_core::config_account_id(bridge_lock_id),
        Account::default().with_actor_state(
            bridge_lock_id,
            bridge_lock_core::config_bytes(
                programs::wrapped_token_account_id(),
                &LOCK_TARGET_ZONES,
            )
            .into(),
        ),
    )]);
}

fn inbox_config_actor(inbox_id: AccountId) -> Actor {
    Actor::new(inbox_config_account_id(inbox_id), inbox_id)
}

fn dispatch_tx(
    inbox_id: AccountId,
    msg: CrossZoneMessage,
    targets: Vec<Actor>,
) -> PublicTransaction {
    let mut public_actors = vec![
        inbox_config_actor(inbox_id),
        Actor::new(
            inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id),
            inbox_id,
        ),
        msg.target,
    ];
    public_actors.extend(targets);
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: inbox_id,
            seed: inbox_seen_shard_seed(&msg.src_zone, msg.src_block_id),
        }],
        ..Message::try_new(
            inbox_config_actor(inbox_id),
            public_actors,
            BTreeMap::new(),
            InboxMessage::Dispatch(msg),
        )
        .expect("build dispatch message")
    };
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

fn rejects_at(state: &V03State, tx: &PublicTransaction, block: u64, expected: &str) {
    let Err(err) = ValidatedStateDiff::from_public_transaction(tx, state, block, 0) else {
        panic!("expected a rejection mentioning {expected}");
    };
    assert!(
        format!("{err:?}").contains(expected),
        "rejected for the wrong reason: {err:?}"
    );
}

fn signed_tx(
    target: AccountId,
    account: AccountId,
    config_id: AccountId,
    nonce: u128,
    message: Vec<u8>,
    key: &PrivateKey,
) -> PublicTransaction {
    let root = Actor::new(account, target);
    let message = Message::new_preserialized(
        root,
        message,
        vec![root, Actor::new(config_id, target)],
        BTreeMap::from([(
            AccountId::from(&PublicKey::new_from_private_key(key)),
            nonce.into(),
        )]),
        None,
    );
    let witness = WitnessSet::for_message(&message, &[key]);
    PublicTransaction::new(message, witness)
}

fn via_proxy(
    proxy_id: AccountId,
    target: AccountId,
    config: AccountId,
    authority_seed: lee_core::program::PdaSeed,
    delegated: Option<lee_core::program::PdaSeed>,
    forwarded: Vec<u8>,
) -> PublicTransaction {
    let authority = AccountId::for_public_pda(&proxy_id, &authority_seed);
    let caller = Actor::new(authority, proxy_id);
    let entry = Actor::new(authority, target);
    let config = Actor::new(config, target);
    let script = Script::default().send(SyncMessage {
        to: entry.into(),
        message: forwarded,
        pda_seeds: delegated.into_iter().collect(),
    });
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: proxy_id,
            seed: authority_seed,
        }],
        ..Message::try_new(caller, vec![caller, entry, config], BTreeMap::new(), script)
            .expect("build proxy message")
    };
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

fn chained_via_inbox(
    target: AccountId,
    config_id: AccountId,
    authority: AccountId,
    payload: Vec<u8>,
) -> PublicTransaction {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let msg = CrossZoneMessage {
        src_zone: [2; 32],
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: programs::bridge_lock_account_id(),
        target: Actor::new(target, target),
        payload,
        l1_inclusion_witness: None,
    };
    dispatch_tx(
        inbox_id,
        msg,
        vec![Actor::new(config_id, target), Actor::new(authority, target)],
    )
}

fn send_tx(target_zone: [u8; 32]) -> PublicTransaction {
    let receiver_id = programs::ping_receiver_account_id();
    let sender_id = programs::ping_sender_account_id();
    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: b"ping".to_vec(),
    })
    .expect("serialize ping message");
    let sender = Actor::new(sender_id, sender_id);
    let send = ping_core::SenderMessage::Send {
        target_zone,
        target: Actor::new(receiver_id, receiver_id),
        accounts: vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(ping_record_pda(receiver_id), receiver_id),
        ],
        payload,
    };
    let message = Message::try_new(sender, vec![sender], BTreeMap::new(), send)
        .expect("build ping_sender message");
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

#[test]
fn a_top_level_send_surfaces_an_outbound_message() {
    let receiver_id = programs::ping_receiver_account_id();
    let sender_id = programs::ping_sender_account_id();
    let state = base_state();

    let diff = ValidatedStateDiff::from_public_transaction(&send_tx([2; 32]), &state, 1, 0)
        .expect("the send executes");

    assert_eq!(
        diff.outbound(),
        [lee::OutboundMessage {
            from: Actor::new(sender_id, sender_id),
            zone: [2; 32],
            to: Actor::new(receiver_id, receiver_id),
            message: borsh::to_vec(&ReceiverMessage::Record {
                payload: b"ping".to_vec(),
            })
            .expect("serialize ping message"),
            accounts: vec![
                Actor::new(receiver_config_account_id(receiver_id), receiver_id),
                Actor::new(ping_record_pda(receiver_id), receiver_id),
            ],
        }]
    );
}

fn mint_payload() -> Vec<u8> {
    mint_payload_of(LOCK_AMOUNT)
}

fn mint_payload_of(amount: u128) -> Vec<u8> {
    let mint = wrapped_token_core::Message::Mint {
        recipient: RECIPIENT,
        amount,
    };
    borsh::to_vec(&mint).expect("serialize mint")
}

fn capped_mint_state(
    mint_cap: Option<u128>,
    minted: u128,
    authority: Option<AccountId>,
) -> V03State {
    let mut state = base_state();
    seed_inbox_config(&mut state, [1_u8; 32]);
    seed_wrapped_config_entries(
        &mut state,
        None,
        authority,
        vec![wrapped_token_core::SourceEntry {
            policy: wrapped_token_core::SourcePolicy {
                src_zone: MINT_SRC_ZONE,
                src_account_id: AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID),
                mint_cap,
            },
            minted,
        }],
    );
    state
}

fn mint_dispatch_tx(amount: u128, src_outbound_index: u32) -> PublicTransaction {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();
    let msg = CrossZoneMessage {
        src_zone: MINT_SRC_ZONE,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index,
        src_account_id: AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID),
        target: Actor::new(wrapped_token_id, wrapped_token_id),
        payload: mint_payload_of(amount),
        l1_inclusion_witness: None,
    };

    dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(
                wrapped_token_core::config_account_id(wrapped_token_id),
                wrapped_token_id,
            ),
            Actor::new(
                wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
                wrapped_token_id,
            ),
        ],
    )
}

fn dispatch_mint_on(
    state: &V03State,
    amount: u128,
    src_outbound_index: u32,
    block: u64,
) -> Result<ValidatedStateDiff, lee::error::LeeError> {
    ValidatedStateDiff::from_public_transaction(
        &mint_dispatch_tx(amount, src_outbound_index),
        state,
        block,
        0,
    )
}

fn dispatch_mint(amount: u128) -> Result<ValidatedStateDiff, lee::error::LeeError> {
    dispatch_mint_on(&capped_mint_state(None, 0, None), amount, 0, 1)
}

fn source_minted(state: &V03State) -> u128 {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let cfg = wrapped_token_config(state, config_id);
    cfg.sources
        .iter()
        .find(|entry| {
            entry.policy.src_zone == MINT_SRC_ZONE
                && entry.policy.src_account_id
                    == AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID)
        })
        .expect("the canonical source is configured")
        .minted
}

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
    let wrapped_token_id = programs::wrapped_token_account_id();
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);
    let minted = wrapped_token_core::read_balance(
        diff.public_diff()[&holding_id]
            .data
            .actor_state(wrapped_token_id)
            .as_ref(),
    );
    assert_eq!(minted, wrapped_token_core::MAX_MINT_AMOUNT);
}

fn mint_src_policy(mint_cap: Option<u128>) -> wrapped_token_core::SourcePolicy {
    wrapped_token_core::SourcePolicy {
        src_zone: MINT_SRC_ZONE,
        src_account_id: AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID),
        mint_cap,
    }
}

fn update_sources_tx(
    key: &PrivateKey,
    authority: AccountId,
    nonce: u128,
    sources: Vec<wrapped_token_core::SourcePolicy>,
) -> PublicTransaction {
    let wrapped_token_id = programs::wrapped_token_account_id();
    signed_tx(
        wrapped_token_id,
        authority,
        wrapped_token_core::config_account_id(wrapped_token_id),
        nonce,
        bytes_of!(&wrapped_token_core::Message::UpdateSources {
            authority,
            via: None,
            sources,
        }),
        key,
    )
}

fn rejects_on_cap(state: &V03State, amount: u128, src_outbound_index: u32, block: u64) {
    let Err(err) = dispatch_mint_on(state, amount, src_outbound_index, block) else {
        panic!("expected the lifetime cap to refuse the mint");
    };
    assert!(
        format!("{err:?}").contains("lifetime cap"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn a_mint_that_reaches_the_lifetime_cap_is_accepted() {
    let mut state = capped_mint_state(Some(LOCK_AMOUNT), 0, None);
    let diff = dispatch_mint_on(&state, LOCK_AMOUNT, 0, 1).expect("the cap itself is spendable");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), LOCK_AMOUNT);
}

#[test]
fn a_mint_over_the_lifetime_cap_is_rejected() {
    let state = capped_mint_state(Some(LOCK_AMOUNT), 0, None);
    rejects_on_cap(&state, LOCK_AMOUNT + 1, 0, 1);
}

#[test]
fn mints_accumulate_into_the_lifetime_cap() {
    let mut state = capped_mint_state(Some(100), 0, None);
    let first = dispatch_mint_on(&state, 60, 0, 1).expect("under the cap");
    state
        .apply_state_diff(first)
        .expect("the validated diff applies");
    rejects_on_cap(&state, 60, 1, 2);
    let exact = dispatch_mint_on(&state, 40, 1, 2).expect("the remainder is spendable");
    state
        .apply_state_diff(exact)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 100);
}

#[test]
fn an_uncapped_source_counts_but_never_refuses() {
    let mut state = capped_mint_state(None, 0, None);
    for index in 0..2 {
        let diff = dispatch_mint_on(
            &state,
            wrapped_token_core::MAX_MINT_AMOUNT,
            index,
            u64::from(index) + 1,
        )
        .expect("an uncapped source refuses nothing");
        state
            .apply_state_diff(diff)
            .expect("the validated diff applies");
    }
    assert_eq!(
        source_minted(&state),
        2 * wrapped_token_core::MAX_MINT_AMOUNT
    );
}

#[test]
fn the_counter_survives_a_source_update() {
    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = capped_mint_state(Some(100), 0, Some(authority));
    let diff = dispatch_mint_on(&state, 60, 0, 1).expect("under the cap");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");

    let update = update_sources_tx(&key, authority, 0, vec![mint_src_policy(Some(70))]);
    let applied = ValidatedStateDiff::from_public_transaction(&update, &state, 2, 0)
        .expect("the authority updates the cap");
    state
        .apply_state_diff(applied)
        .expect("the validated diff applies");
    assert_eq!(
        source_minted(&state),
        60,
        "an update cannot reset spent allowance"
    );

    rejects_on_cap(&state, 11, 1, 3);
    let exact = dispatch_mint_on(&state, 10, 1, 3).expect("the remaining headroom is spendable");
    state
        .apply_state_diff(exact)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 70);
}

#[test]
fn a_source_removed_and_re_added_restarts_its_counter() {
    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = capped_mint_state(Some(100), 0, Some(authority));
    let diff = dispatch_mint_on(&state, 60, 0, 1).expect("under the cap");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");

    let removed = update_sources_tx(&key, authority, 0, vec![]);
    let applied = ValidatedStateDiff::from_public_transaction(&removed, &state, 2, 0)
        .expect("the authority removes the source");
    state
        .apply_state_diff(applied)
        .expect("the validated diff applies");

    let re_added = update_sources_tx(&key, authority, 1, vec![mint_src_policy(Some(100))]);
    let restored = ValidatedStateDiff::from_public_transaction(&re_added, &state, 3, 0)
        .expect("the authority re-adds the source");
    state
        .apply_state_diff(restored)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 0, "a re-added source starts at zero");

    let full = dispatch_mint_on(&state, 100, 1, 4).expect("the fresh allowance is spendable");
    state
        .apply_state_diff(full)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 100);
}

#[test]
fn an_update_listing_a_source_twice_is_refused() {
    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let state = capped_mint_state(Some(100), 0, Some(authority));

    let duplicated = update_sources_tx(
        &key,
        authority,
        0,
        vec![mint_src_policy(Some(100)), mint_src_policy(Some(1_000))],
    );
    rejects_at(&state, &duplicated, 1, "same source twice");
}

#[test]
fn a_refused_mint_leaves_the_message_deliverable() {
    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = capped_mint_state(Some(50), 0, Some(authority));
    rejects_on_cap(&state, 60, 0, 1);

    let raised = update_sources_tx(&key, authority, 0, vec![mint_src_policy(Some(60))]);
    let applied = ValidatedStateDiff::from_public_transaction(&raised, &state, 2, 0)
        .expect("the authority raises the cap");
    state
        .apply_state_diff(applied)
        .expect("the validated diff applies");

    let delivered =
        dispatch_mint_on(&state, 60, 0, 3).expect("the refused delivery was never marked seen");
    state
        .apply_state_diff(delivered)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 60);
}

#[test]
fn a_many_source_config_still_fits_and_mints() {
    let mut entries: Vec<_> = (0..16_u8)
        .map(|index| wrapped_token_core::SourceEntry {
            policy: wrapped_token_core::SourcePolicy {
                src_zone: if index == 0 {
                    MINT_SRC_ZONE
                } else {
                    [index.wrapping_add(10); 32]
                },
                src_account_id: AccountId::from_builtin_program([u32::from(index) + 100; 8]),
                mint_cap: Some(u128::MAX),
            },
            minted: u128::from(u64::MAX),
        })
        .collect();
    entries.push(wrapped_token_core::SourceEntry {
        policy: wrapped_token_core::SourcePolicy {
            src_zone: MINT_SRC_ZONE,
            src_account_id: AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID),
            mint_cap: Some(100),
        },
        minted: 0,
    });

    let mut state = base_state();
    seed_inbox_config(&mut state, [1_u8; 32]);
    seed_wrapped_config_entries(&mut state, None, None, entries);

    let diff = dispatch_mint_on(&state, 100, 0, 1)
        .expect("a mint against the last of many sources executes");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    assert_eq!(source_minted(&state), 100);

    let wrapped_token_id = programs::wrapped_token_account_id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let cfg = wrapped_token_config(&state, config_id);
    for entry in cfg.sources.iter().filter(|entry| {
        entry.policy.src_account_id != AccountId::from_builtin_program(MINT_SRC_PROGRAM_ID)
    }) {
        assert_eq!(
            entry.minted,
            u128::from(u64::MAX),
            "a mint must not spend another source's allowance"
        );
    }
}

#[test]
fn inbox_dispatch_delivers_payload_to_ping_receiver() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let receiver_id = programs::ping_receiver_account_id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(
        &mut state,
        None,
        vec![(src_zone, AccountId::from_builtin_program([9_u32; 8]))],
    );

    let inner = b"hello-cross-zone".to_vec();
    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: inner.clone(),
    })
    .expect("serialize ping message");

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: AccountId::from_builtin_program([9_u32; 8]),
        target: Actor::new(receiver_id, receiver_id),
        payload,
        l1_inclusion_witness: None,
    };

    let record_id = ping_record_pda(receiver_id);

    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(record_id, receiver_id),
        ],
    );

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("dispatch must validate and execute");
    let record = diff
        .public_diff()
        .get(&record_id)
        .expect("ping record account must change")
        .clone();
    assert_eq!(
        record.data.actor_state(receiver_id).to_vec(),
        inner,
        "ping_receiver must record the delivered payload"
    );
}

#[test]
fn lock_escrows_balance_and_sends_the_mint() {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();
    let zone_b = [2_u8; 32];

    let mut state = base_state();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let escrow_id = bridge_lock_core::escrow_account_id(bridge_lock_id);
    let tx = lock_tx(&holder_key, holder_id, zone_b, 0);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("lock must validate and execute");
    let public_diff = diff.public_diff();

    let holding_after = public_diff[&holding_id_of(holder_id)]
        .data
        .native_balance()
        .unwrap();
    assert_eq!(
        holding_after,
        INITIAL_BALANCE - LOCK_AMOUNT,
        "holding debited"
    );

    let escrow_after = public_diff[&escrow_id].data.native_balance().unwrap();
    assert_eq!(escrow_after, LOCK_AMOUNT, "escrow credited");

    assert_eq!(
        diff.outbound(),
        [lee::OutboundMessage {
            from: Actor::new(holder_id, bridge_lock_id),
            zone: zone_b,
            to: Actor::new(wrapped_token_id, wrapped_token_id),
            message: mint_payload(),
            accounts: mint_target_accounts(wrapped_token_id),
        }],
        "the mint leaves the zone as the lock's outbound message"
    );
}

#[test]
fn a_second_identical_lock_escrows_and_sends_again() {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let zone_b = [2_u8; 32];

    let mut state = base_state();
    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);
    let escrow_id = bridge_lock_core::escrow_account_id(bridge_lock_id);

    let first = ValidatedStateDiff::from_public_transaction(
        &lock_tx(&holder_key, holder_id, zone_b, 0),
        &state,
        1,
        0,
    )
    .expect("the first lock executes");
    assert_eq!(first.outbound().len(), 1);
    state
        .apply_state_diff(first)
        .expect("the first lock applies");

    let second = ValidatedStateDiff::from_public_transaction(
        &lock_tx(&holder_key, holder_id, zone_b, 1),
        &state,
        1,
        1,
    )
    .expect("an identical second lock executes");
    assert_eq!(
        second.outbound().len(),
        1,
        "the second lock sends its own mint"
    );
    let public_diff = second.public_diff();
    assert_eq!(
        public_diff[&holding_id_of(holder_id)]
            .data
            .native_balance()
            .unwrap(),
        INITIAL_BALANCE - 2 * LOCK_AMOUNT,
        "holding debited twice"
    );
    assert_eq!(
        public_diff[&escrow_id].data.native_balance().unwrap(),
        2 * LOCK_AMOUNT,
        "escrow credited twice"
    );
}

fn lock_tx(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    zone_b: [u8; 32],
    nonce: u128,
) -> PublicTransaction {
    lock_tx_to(
        holder_key,
        holder_id,
        zone_b,
        nonce,
        programs::wrapped_token_account_id(),
    )
}

fn mint_target_accounts(wrapped_token_id: AccountId) -> Vec<Actor> {
    vec![
        Actor::new(
            wrapped_token_core::config_account_id(wrapped_token_id),
            wrapped_token_id,
        ),
        Actor::new(
            wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
            wrapped_token_id,
        ),
    ]
}

fn lock_tx_to(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    zone_b: [u8; 32],
    nonce: u128,
    target_account_id: AccountId,
) -> PublicTransaction {
    signed_lock(
        holder_key,
        holder_id,
        nonce,
        bridge_lock_core::Message::Lock {
            amount: LOCK_AMOUNT,
            target_zone: zone_b,
            target_account_id,
            payload: mint_payload(),
        },
    )
}

fn signed_lock(
    key: &PrivateKey,
    holder_id: AccountId,
    nonce: u128,
    lock: bridge_lock_core::Message,
) -> PublicTransaction {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let holder = Actor::new(holder_id, bridge_lock_id);
    let message = Message {
        admission_evidence: vec![
            PublicAccountEvidence::Pda {
                program: bridge_lock_id,
                seed: bridge_lock_core::config_seed(),
            },
            PublicAccountEvidence::Pda {
                program: bridge_lock_id,
                seed: bridge_lock_core::escrow_seed(),
            },
        ],
        ..Message::try_new(
            holder,
            vec![
                holder,
                Actor::new(
                    bridge_lock_core::config_account_id(bridge_lock_id),
                    bridge_lock_id,
                ),
                Actor::native_balance(holding_id_of(holder_id)),
                Actor::native_balance(bridge_lock_core::escrow_account_id(bridge_lock_id)),
            ],
            BTreeMap::from([(
                AccountId::from(&PublicKey::new_from_private_key(key)),
                nonce.into(),
            )]),
            lock,
        )
        .expect("build lock message")
    };
    let witness = WitnessSet::for_message(&message, &[key]);
    PublicTransaction::new(message, witness)
}

#[test]
fn a_lock_naming_another_target_program_is_rejected() {
    let zone_b = [2_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state();
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let elsewhere = programs::ping_receiver_account_id();
    let lock = lock_tx_to(&holder_key, holder_id, zone_b, 0, elsewhere);

    let Err(err) = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0) else {
        panic!("a lock aimed at another program must not execute");
    };
    assert!(
        format!("{err:?}").contains("only mints through the wrapped token it is pinned to"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn a_lock_to_an_unpinned_zone_is_rejected() {
    let unpinned = [0xAA_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state();
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let lock = lock_tx(&holder_key, holder_id, unpinned, 0);
    rejects_at(
        &state,
        &lock,
        1,
        "bridge_lock only locks to a zone it is pinned to",
    );
}

#[test]
fn a_direct_transfer_from_the_holding_is_refused() {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state();
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);

    let holding = Actor::native_balance(holding_id_of(holder_id));
    let escrow = Actor::native_balance(bridge_lock_core::escrow_account_id(bridge_lock_id));
    let message = Message::try_new(
        holding,
        vec![holding, escrow],
        BTreeMap::new(),
        lee_core::native_token::Message::Transfer {
            to: escrow.account_id,
            amount: INITIAL_BALANCE,
        },
    )
    .expect("build transfer message");
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("an unauthorized holding debit must not execute");
    };
    assert!(
        matches!(
            &err,
            LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::UnauthorizedSender { account_id },
            )) if *account_id == holding_id_of(holder_id)
        ),
        "rejected for the wrong reason: {err:?}"
    );
    assert_eq!(
        state
            .get_account_by_id(holding_id_of(holder_id))
            .data
            .native_balance()
            .unwrap(),
        INITIAL_BALANCE
    );
}

#[test]
fn lock_debits_the_holding_not_the_holder() {
    let zone_b = [9_u8; 32];
    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state().with_public_accounts([(holder_id, Account::funded(55))]);
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let tx = lock_tx(&holder_key, holder_id, zone_b, 0);
    let diff =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).expect("the lock executes");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");

    assert_eq!(
        state
            .get_account_by_id(holding_id_of(holder_id))
            .data
            .native_balance()
            .unwrap(),
        INITIAL_BALANCE - LOCK_AMOUNT,
        "the holding is what a lock debits"
    );
    assert_eq!(
        state
            .get_account_by_id(holder_id)
            .data
            .native_balance()
            .unwrap(),
        55,
        "the holder's own balance is untouched"
    );
}

#[test]
fn a_zero_amount_lock_is_refused() {
    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state();
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let wrapped_token_id = programs::wrapped_token_account_id();
    let zone_b = [9_u8; 32];
    let tx = signed_lock(
        &holder_key,
        holder_id,
        0,
        bridge_lock_core::Message::Lock {
            amount: 0,
            target_zone: zone_b,
            target_account_id: wrapped_token_id,
            payload: mint_payload_of(0),
        },
    );
    rejects_at(&state, &tx, 1, "locked amount must be positive");
}

#[test]
fn a_lock_naming_someone_elses_holding_is_refused() {
    let attacker_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let victim_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let victim_id = AccountId::from(&PublicKey::new_from_private_key(&victim_key));
    let mut state = base_state().with_public_accounts([(victim_id, Account::default())]);
    seed_holding(&mut state, victim_id, INITIAL_BALANCE);
    seed_bridge_lock_config(&mut state);

    let wrapped_token_id = programs::wrapped_token_account_id();
    let zone_b = [9_u8; 32];
    let tx = signed_lock(
        &attacker_key,
        victim_id,
        0,
        bridge_lock_core::Message::Lock {
            amount: LOCK_AMOUNT,
            target_zone: zone_b,
            target_account_id: wrapped_token_id,
            payload: mint_payload(),
        },
    );
    rejects_at(&state, &tx, 1, "holder must authorize the lock");
    assert_eq!(
        state
            .get_account_by_id(holding_id_of(victim_id))
            .data
            .native_balance()
            .unwrap(),
        INITIAL_BALANCE,
        "the victim's holding is untouched"
    );
}

#[test]
fn a_lock_before_the_pins_are_set_is_rejected() {
    let zone_b = [2_u8; 32];

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));
    let mut state = base_state();
    seed_holding(&mut state, holder_id, INITIAL_BALANCE);

    let lock = lock_tx(&holder_key, holder_id, zone_b, 0);
    let Err(err) = ValidatedStateDiff::from_public_transaction(&lock, &state, 1, 0) else {
        panic!("a lock with nothing pinned must not execute");
    };
    assert!(
        format!("{err:?}").contains("config account holds a mint target and the zones"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn the_bridge_pins_are_written_once_and_replayable() {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let config_id = bridge_lock_core::config_account_id(bridge_lock_id);
    let wrapped_token_id = programs::wrapped_token_account_id();

    let init = |target: AccountId, zones: Vec<[u8; 32]>| {
        let config = Actor::new(config_id, bridge_lock_id);
        let message = Message {
            admission_evidence: vec![PublicAccountEvidence::Pda {
                program: bridge_lock_id,
                seed: bridge_lock_core::config_seed(),
            }],
            ..Message::try_new(
                config,
                vec![config],
                BTreeMap::new(),
                bridge_lock_core::Message::InitConfig {
                    target_account_id: target,
                    lock_target_zones: zones,
                },
            )
            .expect("build InitConfig message")
        };
        PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
    };
    let zones = || LOCK_TARGET_ZONES.to_vec();

    let mut state = base_state();

    let diff =
        ValidatedStateDiff::from_public_transaction(&init(wrapped_token_id, zones()), &state, 1, 0)
            .expect("the first init claims the config PDA");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    assert_eq!(
        bridge_lock_core::read_config(
            state
                .get_account_by_id(config_id)
                .data
                .actor_state(bridge_lock_id)
                .as_ref()
        ),
        Some((wrapped_token_id, zones())),
        "the config pins the mint target and the zones it locks to after genesis"
    );

    ValidatedStateDiff::from_public_transaction(&init(wrapped_token_id, zones()), &state, 2, 0)
        .expect("replaying the identical init is a no-op, not a failure");

    for (target, pinned, what) in [
        (
            AccountId::from_builtin_program([3; 8]),
            zones(),
            "mint target",
        ),
        (wrapped_token_id, vec![[0xAA; 32]], "lock target zone"),
    ] {
        let Err(err) =
            ValidatedStateDiff::from_public_transaction(&init(target, pinned), &state, 3, 0)
        else {
            panic!("a re-init naming a different {what} must not execute");
        };
        assert!(
            format!("{err:?}").contains("actor state already holds different data"),
            "rejected for the wrong reason: {err:?}"
        );
    }
}

#[test]
fn the_token_authority_path_holds() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let other_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let other = AccountId::from(&PublicKey::new_from_private_key(&other_key));

    let update = |account: AccountId,
                  signer: &PrivateKey,
                  nonce: u128,
                  sources: Vec<([u8; 32], AccountId)>| {
        signed_tx(
            wrapped_token_id,
            account,
            config_id,
            nonce,
            bytes_of!(&wrapped_token_core::Message::UpdateSources {
                authority: account,
                via: None,
                sources: uncapped_policies(&sources),
            }),
            signer,
        )
    };
    let renounce = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            wrapped_token_id,
            account,
            config_id,
            nonce,
            bytes_of!(&wrapped_token_core::Message::RenounceAuthority {
                authority: account,
                via: None,
            }),
            signer,
        )
    };
    let bridge_source = vec![(src_zone, programs::bridge_lock_account_id())];

    let mut unset = base_state();
    seed_wrapped_config(&mut unset, None, &[]);
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

    let mut state = base_state().with_public_accounts([(authority, Account::default())]);
    seed_wrapped_config(&mut state, Some(authority), &[]);
    rejects_at(
        &state,
        &update(other, &other_key, 0, bridge_source.clone()),
        1,
        "the signing account must be the configured authority",
    );
    rejects_at(
        &state,
        &renounce(other, &other_key, 0),
        1,
        "the signing account must be the configured authority",
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

    let diff = ValidatedStateDiff::from_public_transaction(
        &update(authority, &key, 0, bridge_source.clone()),
        &state,
        1,
        0,
    )
    .expect("the configured authority changes sources");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    let cfg = wrapped_token_config(&state, config_id);
    assert_eq!(
        cfg.sources,
        uncapped_entries(&bridge_source),
        "the new source is authorized"
    );
    assert!(
        state
            .get_account_by_id(authority)
            .data
            .actor_states
            .is_empty(),
        "acting as the authority must not hand the account to wrapped_token"
    );

    let sender_source = vec![(src_zone, programs::ping_sender_account_id())];
    let second = ValidatedStateDiff::from_public_transaction(
        &update(authority, &key, 1, sender_source.clone()),
        &state,
        2,
        0,
    )
    .expect("the authority acts again");
    state
        .apply_state_diff(second)
        .expect("the validated diff applies");
    let updated_cfg = wrapped_token_config(&state, config_id);
    assert_eq!(
        updated_cfg.sources,
        uncapped_entries(&sender_source),
        "the second change took effect"
    );
    assert_eq!(
        updated_cfg.authority,
        Some(authority),
        "the authority is unchanged"
    );

    let renounced =
        ValidatedStateDiff::from_public_transaction(&renounce(authority, &key, 2), &state, 3, 0)
            .expect("the authority renounces itself");
    state
        .apply_state_diff(renounced)
        .expect("the validated diff applies");
    let renounced_cfg = wrapped_token_config(&state, config_id);
    assert_eq!(renounced_cfg.authority, None, "the authority is gone");
    assert_eq!(
        renounced_cfg.sources,
        uncapped_entries(&sender_source),
        "renouncing leaves the sources it froze"
    );
    assert_eq!(
        renounced_cfg.minter,
        programs::cross_zone_inbox_account_id(),
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

#[test]
fn a_delivery_from_an_unauthorized_source_does_not_reach_ping_receiver() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let receiver_id = programs::ping_receiver_account_id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(
        &mut state,
        None,
        vec![(src_zone, programs::bridge_lock_account_id())],
    );

    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: b"ping".to_vec(),
    })
    .expect("serialize ping message");
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: programs::ping_sender_account_id(),
        target: Actor::new(receiver_id, receiver_id),
        payload,
        l1_inclusion_witness: None,
    };
    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(ping_record_pda(receiver_id), receiver_id),
        ],
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("an unauthorized source must not reach the receiver");
    };
    assert!(
        format!("{err:?}").contains("peer source this receiver authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn the_receiver_authority_path_holds() {
    let receiver_id = programs::ping_receiver_account_id();
    let config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];
    let sender_id = programs::ping_sender_account_id();

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));
    let other_key = PrivateKey::try_new([8; 32]).expect("valid key");
    let other = AccountId::from(&PublicKey::new_from_private_key(&other_key));

    let update = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            receiver_id,
            account,
            config_id,
            nonce,
            bytes_of!(&ping_core::ReceiverMessage::UpdateSources {
                authority: account,
                via: None,
                sources: vec![(src_zone, sender_id)],
            }),
            signer,
        )
    };
    let renounce = |account: AccountId, signer: &PrivateKey, nonce: u128| {
        signed_tx(
            receiver_id,
            account,
            config_id,
            nonce,
            bytes_of!(&ping_core::ReceiverMessage::RenounceAuthority {
                authority: account,
                via: None,
            }),
            signer,
        )
    };

    let mut state = base_state().with_public_accounts([(authority, Account::default())]);
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
        "must authorize a change",
    );
    rejects_at(
        &state,
        &renounce(authority, &other_key, 0),
        1,
        "must authorize a change",
    );

    let diff =
        ValidatedStateDiff::from_public_transaction(&update(authority, &key, 0), &state, 1, 0)
            .expect("the configured authority changes sources");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    let cfg = receiver_config(&state, config_id);
    assert_eq!(cfg.sources, vec![(src_zone, sender_id)]);
    assert_eq!(cfg.deliverer, programs::cross_zone_inbox_account_id());

    let renounce_diff =
        ValidatedStateDiff::from_public_transaction(&renounce(authority, &key, 1), &state, 2, 0)
            .expect("the authority renounces itself");
    state
        .apply_state_diff(renounce_diff)
        .expect("the validated diff applies");
    let renounced_cfg = receiver_config(&state, config_id);
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

#[test]
fn the_inbox_cannot_reach_the_authority_instructions() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let inbox_id = programs::cross_zone_inbox_account_id();
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
            bytes_of!(&wrapped_token_core::Message::UpdateSources {
                authority,
                via: None,
                sources: uncapped_policies(&[(src_zone, programs::bridge_lock_account_id())]),
            }),
        )
    };

    let mut closed = base_state();
    seed_inbox_config(&mut closed, self_zone);
    seed_wrapped_config(&mut closed, Some(authority), &[]);
    rejects_at(
        &closed,
        &update(),
        1,
        "a delivery to wrapped_token must carry a Mint",
    );

    let mut open = base_state();
    seed_inbox_config(&mut open, self_zone);
    seed_wrapped_config_with_governance(&mut open, Some(inbox_id), Some(authority), &[]);
    rejects_at(
        &open,
        &update(),
        1,
        "a delivery to wrapped_token must carry a Mint",
    );
}

#[test]
fn the_governance_path_holds() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let proxy_id = AccountId::from_builtin_program(test_programs::scripted().id());
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_wrapped_config_with_governance(&mut state, Some(proxy_id), Some(authority), &[]);

    let update = |sources: Vec<([u8; 32], AccountId)>| {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            seed,
            Some(seed),
            bytes_of!(&wrapped_token_core::Message::UpdateSources {
                authority,
                via: None,
                sources: uncapped_policies(&sources),
            }),
        )
    };
    let renounce = || {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            seed,
            Some(seed),
            bytes_of!(&wrapped_token_core::Message::RenounceAuthority {
                authority,
                via: None,
            }),
        )
    };

    let first = ValidatedStateDiff::from_public_transaction(
        &update(vec![(src_zone, programs::bridge_lock_account_id())]),
        &state,
        1,
        0,
    )
    .expect("the governance path changes sources");
    state
        .apply_state_diff(first)
        .expect("the validated diff applies");

    let cfg = wrapped_token_config(&state, config_id);
    assert_eq!(
        cfg.sources,
        uncapped_entries(&[(src_zone, programs::bridge_lock_account_id())])
    );
    assert!(
        state
            .get_account_by_id(authority)
            .data
            .actor_states
            .is_empty(),
        "acting as the authority must not hand the account to wrapped_token"
    );

    let second = ValidatedStateDiff::from_public_transaction(&update(vec![]), &state, 2, 0)
        .expect("the governance path acts again");
    state
        .apply_state_diff(second)
        .expect("the validated diff applies");
    let cleared_cfg = wrapped_token_config(&state, config_id);
    assert!(
        cleared_cfg.sources.is_empty(),
        "the second change took effect"
    );
    assert_eq!(cleared_cfg.authority, Some(authority));

    let renounced = ValidatedStateDiff::from_public_transaction(&renounce(), &state, 3, 0)
        .expect("the governance path renounces");
    state
        .apply_state_diff(renounced)
        .expect("the validated diff applies");
    let renounced_cfg = wrapped_token_config(&state, config_id);
    assert_eq!(renounced_cfg.authority, None, "the authority is gone");

    rejects_at(
        &state,
        &update(vec![(src_zone, programs::bridge_lock_account_id())]),
        4,
        "fixed at genesis",
    );
    rejects_at(&state, &renounce(), 4, "already renounced");
}

#[test]
fn the_governance_path_guards_hold() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let receiver_id = programs::ping_receiver_account_id();
    let proxy_id = AccountId::from_builtin_program(test_programs::scripted().id());
    let config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let call = |delegated: Option<lee_core::program::PdaSeed>| {
        via_proxy(
            proxy_id,
            wrapped_token_id,
            config_id,
            seed,
            delegated,
            bytes_of!(&wrapped_token_core::Message::UpdateSources {
                authority,
                via: None,
                sources: uncapped_policies(&[(src_zone, programs::bridge_lock_account_id())]),
            }),
        )
    };

    let mut other = base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_wrapped_config_with_governance(
        &mut other,
        Some(programs::ping_sender_account_id()),
        Some(authority),
        &[],
    );
    rejects_at(
        &other,
        &call(Some(seed)),
        1,
        "through the configured governance program",
    );

    let mut closed = base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_wrapped_config(&mut closed, Some(authority), &[]);
    seed_receiver_config(&mut closed, Some(authority), vec![]);
    rejects_at(
        &closed,
        &call(Some(seed)),
        1,
        "through the configured governance program",
    );

    for (target, config, message) in [
        (
            wrapped_token_id,
            config_id,
            bytes_of!(&wrapped_token_core::Message::RenounceAuthority {
                authority,
                via: None,
            }),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            bytes_of!(&ping_core::ReceiverMessage::UpdateSources {
                authority,
                via: None,
                sources: vec![(src_zone, programs::ping_sender_account_id())],
            }),
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            bytes_of!(&ping_core::ReceiverMessage::RenounceAuthority {
                authority,
                via: None,
            }),
        ),
    ] {
        rejects_at(
            &closed,
            &via_proxy(proxy_id, target, config, seed, Some(seed), message),
            1,
            "through the configured governance program",
        );
    }

    let mut undelegated =
        base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_wrapped_config_with_governance(&mut undelegated, Some(proxy_id), Some(authority), &[]);
    rejects_at(
        &undelegated,
        &call(None),
        1,
        "must authorize a source change",
    );
}

#[test]
fn the_receiver_governance_path_holds() {
    let receiver_id = programs::ping_receiver_account_id();
    let proxy_id = AccountId::from_builtin_program(test_programs::scripted().id());
    let config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_receiver_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);

    let tx = via_proxy(
        proxy_id,
        receiver_id,
        config_id,
        seed,
        Some(seed),
        bytes_of!(&ping_core::ReceiverMessage::UpdateSources {
            authority,
            via: None,
            sources: vec![(src_zone, programs::ping_sender_account_id())],
        }),
    );

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("the receiver governance path changes sources");
    state
        .apply_state_diff(diff)
        .expect("the validated diff applies");
    let cfg = receiver_config(&state, config_id);
    assert_eq!(
        cfg.sources,
        vec![(src_zone, programs::ping_sender_account_id())]
    );
    assert!(
        state
            .get_account_by_id(authority)
            .data
            .actor_states
            .is_empty(),
        "acting as the authority must not hand the account to ping_receiver"
    );
}

#[test]
fn a_shared_authority_serves_both_targets() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let receiver_id = programs::ping_receiver_account_id();
    let proxy_id = AccountId::from_builtin_program(test_programs::scripted().id());
    let token_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let receiver_config_id = receiver_config_account_id(receiver_id);
    let src_zone = [2_u8; 32];

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let authority = AccountId::for_public_pda(&proxy_id, &seed);

    let mut state = base_state().with_programs_at([(proxy_id, test_programs::scripted(), true)]);
    seed_wrapped_config_with_governance(&mut state, Some(proxy_id), Some(authority), &[]);
    seed_receiver_config_with_governance(&mut state, Some(proxy_id), Some(authority), vec![]);

    let token_update = via_proxy(
        proxy_id,
        wrapped_token_id,
        token_config_id,
        seed,
        Some(seed),
        bytes_of!(&wrapped_token_core::Message::UpdateSources {
            authority,
            via: None,
            sources: uncapped_policies(&[(src_zone, programs::bridge_lock_account_id())]),
        }),
    );
    let first = ValidatedStateDiff::from_public_transaction(&token_update, &state, 1, 0)
        .expect("the token acts for the shared authority");
    state
        .apply_state_diff(first)
        .expect("the validated diff applies");
    assert!(
        state
            .get_account_by_id(authority)
            .data
            .actor_states
            .is_empty(),
        "a data-free authority is owned by nobody, whichever target uses it first"
    );

    let receiver_update = via_proxy(
        proxy_id,
        receiver_id,
        receiver_config_id,
        seed,
        Some(seed),
        bytes_of!(&ping_core::ReceiverMessage::UpdateSources {
            authority,
            via: None,
            sources: vec![(src_zone, programs::ping_sender_account_id())],
        }),
    );
    let second = ValidatedStateDiff::from_public_transaction(&receiver_update, &state, 2, 0)
        .expect("the other target still acts on the token-owned authority");
    state
        .apply_state_diff(second)
        .expect("the validated diff applies");
    let receiver_cfg = receiver_config(&state, receiver_config_id);
    assert_eq!(
        receiver_cfg.sources,
        vec![(src_zone, programs::ping_sender_account_id())]
    );
    assert!(
        state
            .get_account_by_id(authority)
            .data
            .actor_states
            .is_empty(),
        "the authority holds no record from either target"
    );

    let receiver_renounce = via_proxy(
        proxy_id,
        receiver_id,
        receiver_config_id,
        seed,
        Some(seed),
        bytes_of!(&ping_core::ReceiverMessage::RenounceAuthority {
            authority,
            via: None,
        }),
    );
    let third = ValidatedStateDiff::from_public_transaction(&receiver_renounce, &state, 3, 0)
        .expect("the other target renounces on the token-owned authority");
    state
        .apply_state_diff(third)
        .expect("the validated diff applies");
    let renounced_cfg = receiver_config(&state, receiver_config_id);
    assert_eq!(renounced_cfg.authority, None, "the receiver side is gone");
    let token_cfg = wrapped_token_config(&state, token_config_id);
    assert_eq!(
        token_cfg.authority,
        Some(authority),
        "renouncing one target leaves the other's grant alone"
    );
}

#[test]
fn the_remaining_authority_guards_hold() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let receiver_id = programs::ping_receiver_account_id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let key = PrivateKey::try_new([7; 32]).expect("valid key");
    let authority = AccountId::from(&PublicKey::new_from_private_key(&key));

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, Some(authority), &[]);
    seed_receiver_config(&mut state, Some(authority), vec![]);

    for (target, config_id, message, refusal) in [
        (
            wrapped_token_id,
            wrapped_token_core::config_account_id(wrapped_token_id),
            bytes_of!(&wrapped_token_core::Message::RenounceAuthority {
                authority,
                via: None,
            }),
            "a delivery to wrapped_token must carry a Mint",
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            bytes_of!(&ping_core::ReceiverMessage::RenounceAuthority {
                authority,
                via: None,
            }),
            "a delivery to ping_receiver must carry a Record",
        ),
        (
            receiver_id,
            receiver_config_account_id(receiver_id),
            bytes_of!(&ping_core::ReceiverMessage::UpdateSources {
                authority,
                via: None,
                sources: vec![(src_zone, programs::ping_sender_account_id())],
            }),
            "a delivery to ping_receiver must carry a Record",
        ),
    ] {
        rejects_at(
            &state,
            &chained_via_inbox(target, config_id, authority, message),
            1,
            refusal,
        );
    }
}

#[test]
fn a_mint_is_refused_when_the_token_authorizes_no_source() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();
    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(&mut state, None, &[]);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: programs::bridge_lock_account_id(),
        target: Actor::new(wrapped_token_id, wrapped_token_id),
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };
    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(
                wrapped_token_core::config_account_id(wrapped_token_id),
                wrapped_token_id,
            ),
            Actor::new(
                wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
                wrapped_token_id,
            ),
        ],
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a token authorizing nothing must not mint");
    };
    assert!(
        format!("{err:?}").contains("peer source this token authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn a_top_level_mint_is_refused() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();
    let src_zone = [2_u8; 32];
    let src_program_id = programs::bridge_lock_account_id();

    let mut state = base_state();
    seed_wrapped_config(&mut state, None, &[(src_zone, src_program_id)]);

    let config = Actor::new(
        wrapped_token_core::config_account_id(wrapped_token_id),
        wrapped_token_id,
    );
    let message = Message::try_new(
        config,
        vec![
            config,
            Actor::new(
                wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT),
                wrapped_token_id,
            ),
        ],
        BTreeMap::new(),
        wrapped_token_core::Message::MintFrom {
            deliverer: inbox_id,
            src_zone,
            src_account_id: src_program_id,
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

#[test]
fn inbox_dispatch_mints_wrapped_token() {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let diff = dispatch_mint(LOCK_AMOUNT).expect("dispatch must validate and execute");
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);
    let minted = wrapped_token_core::read_balance(
        diff.public_diff()[&holding_id]
            .data
            .actor_state(wrapped_token_id)
            .as_ref(),
    );
    assert_eq!(
        minted, LOCK_AMOUNT,
        "recipient holding minted the locked amount"
    );
}

#[test]
fn a_mint_from_an_unrouted_emitter_is_rejected() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(
        &mut state,
        None,
        &[(src_zone, programs::bridge_lock_account_id())],
    );

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: programs::ping_sender_account_id(),
        target: Actor::new(wrapped_token_id, wrapped_token_id),
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(wrapped_config_id, wrapped_token_id),
            Actor::new(holding_id, wrapped_token_id),
        ],
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a delivery from a source the token did not authorize must not mint");
    };
    assert!(
        format!("{err:?}").contains("peer source this token authorizes"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn a_mint_from_the_routed_emitter_is_accepted() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();
    let bridge_lock_id = programs::bridge_lock_account_id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(
        &mut state,
        None,
        &[(src_zone, programs::bridge_lock_account_id())],
    );

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id: bridge_lock_id,
        target: Actor::new(wrapped_token_id, wrapped_token_id),
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(wrapped_config_id, wrapped_token_id),
            Actor::new(holding_id, wrapped_token_id),
        ],
    );

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("the routed emitter must still deliver");
    let minted = wrapped_token_core::read_balance(
        diff.public_diff()[&holding_id]
            .data
            .actor_state(wrapped_token_id)
            .as_ref(),
    );
    assert_eq!(minted, LOCK_AMOUNT);
}

#[test]
fn mint_replay_rejected() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;
    let src_outbound_index = 0;

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_wrapped_config(
        &mut state,
        None,
        &[(src_zone, AccountId::from_builtin_program([9_u32; 8]))],
    );

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let mut shard = SeenShard::default();
    shard.insert(SRC_BLOCK_HASH, src_outbound_index);
    state = state.with_public_accounts([(
        seen_id,
        Account::default().with_actor_state(inbox_id, shard.to_bytes().into()),
    )]);

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index,
        src_account_id: AccountId::from_builtin_program([9_u32; 8]),
        target: Actor::new(wrapped_token_id, wrapped_token_id),
        payload: mint_payload(),
        l1_inclusion_witness: None,
    };

    let wrapped_config_id = wrapped_token_core::config_account_id(wrapped_token_id);
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(wrapped_config_id, wrapped_token_id),
            Actor::new(holding_id, wrapped_token_id),
        ],
    );

    let Err(err) = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0) else {
        panic!("a replayed message must not mint again");
    };
    assert!(
        format!("{err:?}").contains("This delivery is already recorded"),
        "rejected for the wrong reason: {err:?}"
    );
}

#[test]
fn a_delivery_from_a_second_block_at_the_same_id_is_refused() {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let receiver_id = programs::ping_receiver_account_id();

    let self_zone = [1_u8; 32];
    let src_zone = [2_u8; 32];
    let src_block_id = 5;
    let other_block_hash = [8_u8; 32];

    let mut state = base_state();
    seed_inbox_config(&mut state, self_zone);
    seed_receiver_config(
        &mut state,
        None,
        vec![(src_zone, AccountId::from_builtin_program([9_u32; 8]))],
    );

    let seen_id = inbox_seen_shard_account_id(inbox_id, &src_zone, src_block_id);
    let mut shard = SeenShard::default();
    shard.insert(SRC_BLOCK_HASH, 0);
    state = state.with_public_accounts([(
        seen_id,
        Account::default().with_actor_state(inbox_id, shard.to_bytes().into()),
    )]);

    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: b"from-the-other-block".to_vec(),
    })
    .expect("serialize ping message");

    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: other_block_hash,
        src_outbound_index: 1,
        src_account_id: AccountId::from_builtin_program([9_u32; 8]),
        target: Actor::new(receiver_id, receiver_id),
        payload,
        l1_inclusion_witness: None,
    };

    let record_id = ping_record_pda(receiver_id);
    let tx = dispatch_tx(
        inbox_id,
        msg,
        vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(record_id, receiver_id),
        ],
    );

    assert!(
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0).is_err(),
        "a delivery from a block the shard is not bound to must not execute"
    );

    let control_payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: b"from-the-bound-block".to_vec(),
    })
    .expect("serialize ping message");
    let control_msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 1,
        src_account_id: AccountId::from_builtin_program([9_u32; 8]),
        target: Actor::new(receiver_id, receiver_id),
        payload: control_payload,
        l1_inclusion_witness: None,
    };
    let control_tx = dispatch_tx(
        inbox_id,
        control_msg,
        vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(record_id, receiver_id),
        ],
    );

    let diff = ValidatedStateDiff::from_public_transaction(&control_tx, &state, 1, 0)
        .expect("a second delivery from the bound block executes");
    let public_diff = diff.public_diff();
    let seen_after = public_diff
        .get(&seen_id)
        .expect("the shard records the new delivery");
    let shard_after = SeenShard::from_bytes(seen_after.data.actor_state(inbox_id).as_ref())
        .expect("seen shard decodes");
    assert!(shard_after.contains(0), "the first delivery is still there");
    assert!(shard_after.contains(1), "and the second is recorded");
    assert_eq!(
        shard_after.src_block_hash, SRC_BLOCK_HASH,
        "a shard stays bound to the block that claimed it"
    );
}

fn chat_state(self_zone: [u8; 32]) -> (V03State, AccountId) {
    let chat_id = AccountId::from_builtin_program(test_programs::zone_chat().id());
    let mut state = base_state().with_programs_at([(chat_id, test_programs::zone_chat(), true)]);
    seed_inbox_config(&mut state, self_zone);
    (state, chat_id)
}

fn seed_chat_config(state: &mut V03State, chat_id: AccountId, sources: Vec<([u8; 32], AccountId)>) {
    let config = ping_core::ReceiverConfig {
        deliverer: programs::cross_zone_inbox_account_id(),
        governance: None,
        authority: None,
        sources,
    };
    *state = std::mem::replace(state, V03State::new()).with_public_accounts([(
        receiver_config_account_id(chat_id),
        Account::default().with_actor_state(chat_id, config.to_bytes().into()),
    )]);
}

fn chat_init_config_tx(chat_id: AccountId, to: Actor) -> PublicTransaction {
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: chat_id,
            seed: receiver_config_seed(),
        }],
        ..Message::try_new(
            to,
            vec![to],
            BTreeMap::new(),
            ChatMessage::InitConfig(ping_core::ReceiverConfig {
                deliverer: programs::cross_zone_inbox_account_id(),
                governance: None,
                authority: None,
                sources: vec![],
            }),
        )
        .expect("build InitConfig message")
    };
    PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]))
}

fn chat_dispatch_tx(
    chat_id: AccountId,
    src_zone: [u8; 32],
    src_account_id: AccountId,
    text: &[u8],
) -> PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id: 5,
        src_block_hash: SRC_BLOCK_HASH,
        src_outbound_index: 0,
        src_account_id,
        target: Actor::new(chat_id, chat_id),
        payload: text.to_vec(),
        l1_inclusion_witness: None,
    };
    dispatch_tx(
        programs::cross_zone_inbox_account_id(),
        msg,
        vec![
            Actor::new(receiver_config_account_id(chat_id), chat_id),
            Actor::new(chat_log_account_id(chat_id), chat_id),
        ],
    )
}

#[test]
fn inbox_dispatch_delivers_to_the_chat_receiver() {
    let src_zone = [2_u8; 32];
    let source = AccountId::from_builtin_program([9_u32; 8]);
    let (mut state, chat_id) = chat_state([1_u8; 32]);

    seed_chat_config(&mut state, chat_id, vec![(src_zone, source)]);

    let tx = chat_dispatch_tx(chat_id, src_zone, source, b"hello-chat");
    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 2, 0)
        .expect("dispatch must validate and execute");
    let log = ChatLog::from_bytes(
        diff.public_diff()[&chat_log_account_id(chat_id)]
            .data
            .actor_state(chat_id)
            .as_ref(),
    )
    .expect("chat log decodes");
    assert_eq!(log.entries, vec![(src_zone, b"hello-chat".to_vec())]);
}

#[test]
fn a_delivery_from_an_unauthorized_source_does_not_reach_the_chat_log() {
    let src_zone = [2_u8; 32];
    let (mut state, chat_id) = chat_state([1_u8; 32]);

    seed_chat_config(
        &mut state,
        chat_id,
        vec![(src_zone, AccountId::from_builtin_program([9_u32; 8]))],
    );

    let tx = chat_dispatch_tx(
        chat_id,
        src_zone,
        AccountId::from_builtin_program([8_u32; 8]),
        b"hello-chat",
    );
    rejects_at(&state, &tx, 2, "peer source this receiver authorizes");
}

#[test]
fn a_direct_write_to_the_chat_log_is_refused() {
    let (state, chat_id) = chat_state([1_u8; 32]);
    let log = Actor::new(chat_log_account_id(chat_id), chat_id);
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: chat_id,
            seed: chat_log_seed(),
        }],
        ..Message::try_new(
            log,
            vec![log],
            BTreeMap::new(),
            ChatMessage::WriteLog {
                src_zone: [2; 32],
                text: b"forged".to_vec(),
            },
        )
        .expect("build WriteLog message")
    };
    let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
    rejects_at(&state, &tx, 1, "only written by this program's config");
}

#[test]
fn a_deployer_signed_claim_at_the_program_account_writes_the_config() {
    let key = PrivateKey::try_new([77; 32]).expect("valid key");
    let chat_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = base_state().with_programs_at([(chat_id, test_programs::zone_chat(), true)]);
    seed_inbox_config(&mut state, [1_u8; 32]);

    let src_zone = [2_u8; 32];
    let source = AccountId::from_builtin_program([9_u32; 8]);
    let claimed = ping_core::ReceiverConfig {
        deliverer: programs::cross_zone_inbox_account_id(),
        governance: None,
        authority: None,
        sources: vec![(src_zone, source)],
    };

    let program = Actor::new(chat_id, chat_id);
    let config = Actor::new(receiver_config_account_id(chat_id), chat_id);
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: chat_id,
            seed: receiver_config_seed(),
        }],
        ..Message::try_new(
            program,
            vec![program, config],
            BTreeMap::from([(chat_id, 0_u128.into())]),
            ChatMessage::InitConfig(claimed.clone()),
        )
        .expect("build InitConfig message")
    };
    let witness = WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("the deployer's signed claim writes the config");
    assert_eq!(
        ping_core::ReceiverConfig::from_bytes(
            diff.public_diff()[&config.account_id]
                .data
                .actor_state(chat_id)
                .as_ref()
        ),
        Some(claimed),
        "the config PDA holds exactly what the deployer claimed"
    );
}

#[test]
fn a_claim_sent_straight_to_the_config_pda_is_refused() {
    let (state, chat_id) = chat_state([1_u8; 32]);
    let config = Actor::new(receiver_config_account_id(chat_id), chat_id);
    let tx = chat_init_config_tx(chat_id, config);
    rejects_at(&state, &tx, 1, "only claimed through the program account");
}

#[test]
fn an_unauthorized_claim_at_the_program_account_is_refused() {
    let (state, chat_id) = chat_state([1_u8; 32]);
    let tx = chat_init_config_tx(chat_id, Actor::new(chat_id, chat_id));
    rejects_at(&state, &tx, 1, "must authorize the receiver config claim");
}

#[test]
fn a_chained_post_is_refused_and_a_top_level_post_sends() {
    let chat_id = AccountId::from_builtin_program(test_programs::zone_chat().id());
    let proxy_id = AccountId::from_builtin_program(test_programs::scripted().id());
    let mut state = base_state().with_programs_at([
        (chat_id, test_programs::zone_chat(), true),
        (proxy_id, test_programs::scripted(), true),
    ]);
    seed_inbox_config(&mut state, [1_u8; 32]);

    let post_message = || ChatMessage::Post {
        target_zone: [2; 32],
        target: Actor::new(AccountId::new([9; 32]), AccountId::new([9; 32])),
        accounts: vec![],
        payload: b"hi".to_vec(),
    };
    let entry = Actor::new(chat_id, chat_id);

    let seed = lee_core::program::PdaSeed::new([3; 32]);
    let caller = Actor::new(AccountId::for_public_pda(&proxy_id, &seed), proxy_id);
    let script = Script::default().send(SyncMessage {
        to: entry.into(),
        message: bytes_of!(&post_message()),
        pda_seeds: std::collections::BTreeSet::new(),
    });
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: proxy_id,
            seed,
        }],
        ..Message::try_new(caller, vec![caller, entry], BTreeMap::new(), script)
            .expect("build proxy message")
    };
    let chained = PublicTransaction::new(message, WitnessSet::from_raw_parts(vec![]));
    rejects_at(&state, &chained, 1, "a delivery decodes");

    let post = Message::try_new(entry, vec![entry], BTreeMap::new(), post_message())
        .expect("build Post message");
    let top_level = PublicTransaction::new(post, WitnessSet::from_raw_parts(vec![]));
    let diff = ValidatedStateDiff::from_public_transaction(&top_level, &state, 1, 0)
        .expect("a top-level Post sends and writes nothing");
    assert_eq!(
        diff.outbound(),
        [lee::OutboundMessage {
            from: entry,
            zone: [2; 32],
            to: Actor::new(AccountId::new([9; 32]), AccountId::new([9; 32])),
            message: b"hi".to_vec(),
            accounts: vec![],
        }],
        "the post is the transaction's outbound message"
    );
}
