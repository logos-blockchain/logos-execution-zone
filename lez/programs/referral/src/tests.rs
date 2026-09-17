#![cfg(test)]
#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    account::{AccountId, ShardData},
    program::AccountInput,
};
use referral_core::ed25519_dalek::{Signer as _, SigningKey};

use super::*;

const PROGRAM: AccountId = AccountId::new([9; 32]);

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

const fn participant(seed: u8) -> AccountId {
    AccountId::new([seed; 32])
}

fn signature(
    key: &SigningKey,
    node: NodeId,
    participant: AccountId,
    referrer: Option<NodeId>,
) -> [u8; 64] {
    let authorization = ParticipantAuthorizationV1::new(PROGRAM, node, participant, referrer);
    key.sign(&authorization.message()).to_bytes()
}

fn account(id: AccountId, state: Option<State>, authorized: bool) -> AccountInput {
    let data = state.map_or_else(ShardData::empty, |state| state.to_data());
    AccountInput::with_shard(id, authorized, PROGRAM, data)
}

fn oracle() -> AccountInput {
    AccountInput::balance(ORACLE_ACCOUNT_ID, true, 0)
}

fn registry(nodes: &[NodeId]) -> Registry {
    let mut registry = Registry::default();
    for node in nodes {
        assert!(registry.register(*node));
    }
    registry
}

fn registered(nodes: &[NodeId]) -> AccountInput {
    account(
        registry_account_id(PROGRAM),
        Some(State::Registry(registry(nodes))),
        false,
    )
}

const fn register(node: NodeId, referrer: Option<NodeId>, node_signature: [u8; 64]) -> Instruction {
    Instruction::Register {
        node,
        referrer,
        node_signature,
    }
}

const fn collect() -> Instruction {
    Instruction::Collect
}

const fn credit(recipient_node: NodeId, amount: u128) -> State {
    State::Credit {
        recipient_node,
        amount,
    }
}

fn tickets(node: NodeId, amount: u128) -> AccountInput {
    account(
        ticket_account_id(PROGRAM, node),
        Some(credit(node, amount)),
        false,
    )
}

fn note(id: u8, recipient_node: NodeId, amount: u128) -> AccountInput {
    account(
        AccountId::new([id; 32]),
        Some(credit(recipient_node, amount)),
        false,
    )
}

fn fresh(id: u8) -> AccountInput {
    account(AccountId::new([id; 32]), None, false)
}

fn initialized(
    participant: AccountId,
    node: NodeId,
    referrer: Option<NodeId>,
    reward_balance: u128,
) -> AccountInput {
    account(
        participant,
        Some(State::Participant {
            node,
            referrer,
            reward_balance,
        }),
        true,
    )
}

fn unauthorized(participant: AccountId, node: NodeId) -> AccountInput {
    account(
        participant,
        Some(State::Participant {
            node,
            referrer: None,
            reward_balance: 0,
        }),
        false,
    )
}

fn written(diffs: &[ShardStateDiff], id: AccountId) -> State {
    let diff = diffs
        .iter()
        .find(|diff| diff.pre_state.account_id == id)
        .expect("account is among the diffs");
    State::decode(diff.post_data.as_ref().expect("account was written"))
        .expect("written state decodes")
}

fn unchanged(diffs: &[ShardStateDiff], id: AccountId) -> bool {
    diffs
        .iter()
        .find(|diff| diff.pre_state.account_id == id)
        .expect("account is among the diffs")
        .post_data
        .is_none()
}

fn balance_of(state: &State) -> u128 {
    let State::Participant { reward_balance, .. } = state else {
        panic!("not a participant");
    };
    *reward_balance
}

#[test]
fn a_registered_chain_pays_one_for_one() {
    let (bob_key, bob_node) = node(1);
    let (alice_key, alice_node) = node(2);
    let (carol_key, carol_node) = node(3);
    let bob = participant(11);
    let alice = participant(12);
    let carol = participant(13);

    let diffs = execute(
        PROGRAM,
        vec![
            account(carol, None, true),
            account(registry_account_id(PROGRAM), None, false),
        ],
        &register(
            carol_node,
            None,
            signature(&carol_key, carol_node, carol, None),
        ),
    );

    assert_eq!(
        written(&diffs, carol),
        State::Participant {
            node: carol_node,
            referrer: None,
            reward_balance: 0,
        }
    );
    assert_eq!(
        written(&diffs, registry_account_id(PROGRAM)),
        State::Registry(registry(&[carol_node]))
    );

    let diffs = execute(
        PROGRAM,
        vec![account(alice, None, true), registered(&[carol_node])],
        &register(
            alice_node,
            Some(carol_node),
            signature(&alice_key, alice_node, alice, Some(carol_node)),
        ),
    );

    assert_eq!(
        written(&diffs, registry_account_id(PROGRAM)),
        State::Registry(registry(&[carol_node, alice_node]))
    );

    let diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registered(&[carol_node, alice_node]),
        ],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );

    assert_eq!(
        written(&diffs, bob),
        State::Participant {
            node: bob_node,
            referrer: Some(alice_node),
            reward_balance: 0,
        }
    );

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(bob, bob_node, Some(alice_node), 7),
            tickets(bob_node, 5),
            fresh(0x41),
        ],
        &collect(),
    );

    assert_eq!(balance_of(&written(&diffs, bob)), 12);
    assert_eq!(
        written(&diffs, ticket_account_id(PROGRAM, bob_node)),
        credit(bob_node, 0)
    );
    assert_eq!(
        written(&diffs, AccountId::new([0x41; 32])),
        credit(alice_node, 5)
    );
    assert_eq!(diffs.len(), 3);

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 5),
            fresh(0x42),
        ],
        &collect(),
    );

    assert_eq!(balance_of(&written(&diffs, alice)), 5);
    assert_eq!(
        written(&diffs, AccountId::new([0x41; 32])),
        credit(alice_node, 0)
    );
    assert_eq!(
        written(&diffs, AccountId::new([0x42; 32])),
        credit(carol_node, 5)
    );
}

#[test]
fn grant_initializes_an_empty_ticket_account_and_refills_a_consumed_one() {
    let (_key, node_id) = node(1);

    let diffs = grant(
        PROGRAM,
        vec![
            oracle(),
            account(ticket_account_id(PROGRAM, node_id), None, false),
        ],
        node_id,
        5,
    );
    assert_eq!(
        written(&diffs, ticket_account_id(PROGRAM, node_id)),
        credit(node_id, 5)
    );

    let diffs = grant(PROGRAM, vec![oracle(), tickets(node_id, 0)], node_id, 3);
    assert_eq!(
        written(&diffs, ticket_account_id(PROGRAM, node_id)),
        credit(node_id, 3)
    );
    assert!(unchanged(&diffs, ORACLE_ACCOUNT_ID));
}

#[test]
#[should_panic(expected = "granted amount must be positive")]
fn grant_rejects_a_zero_amount() {
    let (_key, node_id) = node(1);
    let _diffs = grant(PROGRAM, vec![oracle(), tickets(node_id, 1)], node_id, 0);
}

#[test]
#[should_panic(expected = "granted credit fits in u128")]
fn grant_rejects_an_overflowing_amount() {
    let (_key, node_id) = node(1);
    let _diffs = grant(
        PROGRAM,
        vec![oracle(), tickets(node_id, u128::MAX)],
        node_id,
        1,
    );
}

#[test]
#[should_panic(expected = "second account must be the node's ticket account")]
fn grant_rejects_another_nodes_ticket_account() {
    let (_key, node_id) = node(1);
    let (_key, other_node) = node(2);

    let _diffs = grant(PROGRAM, vec![oracle(), tickets(other_node, 0)], node_id, 1);
}

#[test]
#[should_panic(expected = "node authorization signature is invalid")]
fn register_rejects_a_signature_addressed_to_another_participant() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);
    let other = participant(14);

    let _diffs = execute(
        PROGRAM,
        vec![account(bob, None, true), registered(&[])],
        &register(bob_node, None, signature(&bob_key, bob_node, other, None)),
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_collect() {
    let (_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![unauthorized(bob, bob_node), tickets(bob_node, 1)],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "credit is addressed to another node")]
fn collect_rejects_a_credit_for_another_node() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, 0),
            note(0x41, bob_node, 10),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "credit is already collected")]
fn collect_rejects_a_second_collection() {
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, 0),
            note(0x41, alice_node, 0),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "reward balance fits in u128")]
fn collect_rejects_an_overflowing_reward_balance() {
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, u128::MAX),
            note(0x41, alice_node, 1),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "exactly when its participant has a referrer")]
fn a_root_collect_rejects_an_outgoing_credit_account() {
    let (_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, 0),
            note(0x41, alice_node, 10),
            fresh(0x42),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "exactly when its participant has a referrer")]
fn a_referred_collect_requires_an_outgoing_credit_account() {
    let (_alice_key, alice_node) = node(2);
    let (_carol_key, carol_node) = node(3);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 10),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "outgoing credit account is not fresh")]
fn collect_rejects_a_consumed_account_as_its_outgoing_credit() {
    let (_alice_key, alice_node) = node(2);
    let (_carol_key, carol_node) = node(3);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 10),
            note(0x42, carol_node, 0),
        ],
        &collect(),
    );
}

#[test]
#[should_panic(expected = "node is already registered")]
fn register_rejects_an_already_registered_node() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![account(bob, None, true), registered(&[bob_node])],
        &register(bob_node, None, signature(&bob_key, bob_node, bob, None)),
    );
}

#[test]
#[should_panic(expected = "referrer node is not registered")]
fn register_requires_a_registered_referrer() {
    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![account(bob, None, true), registered(&[])],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );
}

#[test]
#[should_panic(expected = "participant is already initialized")]
fn register_rejects_an_initialized_participant() {
    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(bob, bob_node, None, 0),
            registered(&[alice_node]),
        ],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );
}

#[test]
#[should_panic(expected = "account holds initialized referral state")]
fn collect_rejects_an_unregistered_participant() {
    let (_bob_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![account(bob, None, true), tickets(bob_node, 1)],
        &collect(),
    );
}
