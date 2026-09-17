#![cfg(test)]
#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
    program::AccountInput,
};
use referral_core::{
    MAX_REGISTERED_NODES,
    ed25519_dalek::{Signer as _, SigningKey},
};

use super::*;

const PROGRAM: AccountId = AccountId::new([9; 32]);

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

fn participant(seed: u8) -> ParticipantDescriptor {
    ParticipantDescriptor {
        npk: NullifierPublicKey([seed; 32]),
        vpk: ViewingPublicKey::from_seed(&[seed; 32], &[seed.wrapping_add(1); 32]),
        identifier: u128::from(seed),
    }
}

fn signature(
    key: &SigningKey,
    node: NodeId,
    descriptor: &ParticipantDescriptor,
    referrer: Option<NodeId>,
) -> [u8; 64] {
    let authorization =
        ParticipantAuthorizationV1::new(PROGRAM, node, descriptor.account_id(), referrer);
    key.sign(&authorization.message()).to_bytes()
}

fn account(id: AccountId, state: Option<State>, authorized: bool) -> AccountInput {
    let data = state.map_or_else(ShardData::empty, |state| StoredState::new(state).to_data());
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

fn register(
    participant: &ParticipantDescriptor,
    node: NodeId,
    referrer: Option<NodeId>,
    node_signature: [u8; 64],
) -> Instruction {
    Instruction::Register {
        participant: participant.clone(),
        node,
        referrer,
        node_signature,
    }
}

fn collect(participant: &ParticipantDescriptor) -> Instruction {
    Instruction::Collect {
        participant: participant.clone(),
    }
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
    descriptor: &ParticipantDescriptor,
    node: NodeId,
    referrer: Option<NodeId>,
    reward_balance: u128,
) -> AccountInput {
    account(
        descriptor.account_id(),
        Some(State::Participant {
            node,
            referrer,
            reward_balance,
        }),
        true,
    )
}

fn unauthorized(descriptor: &ParticipantDescriptor, node: NodeId) -> AccountInput {
    account(
        descriptor.account_id(),
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
    StoredState::decode(diff.post_data.as_ref().expect("account was written"))
        .expect("written state decodes")
        .state
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
            account(carol.account_id(), None, true),
            account(registry_account_id(PROGRAM), None, false),
        ],
        register(
            &carol,
            carol_node,
            None,
            signature(&carol_key, carol_node, &carol, None),
        ),
    );

    assert_eq!(
        written(&diffs, carol.account_id()),
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
        vec![
            account(alice.account_id(), None, true),
            registered(&[carol_node]),
        ],
        register(
            &alice,
            alice_node,
            Some(carol_node),
            signature(&alice_key, alice_node, &alice, Some(carol_node)),
        ),
    );

    assert_eq!(
        written(&diffs, registry_account_id(PROGRAM)),
        State::Registry(registry(&[carol_node, alice_node]))
    );

    let diffs = execute(
        PROGRAM,
        vec![
            account(bob.account_id(), None, true),
            registered(&[carol_node, alice_node]),
        ],
        register(
            &bob,
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, &bob, Some(alice_node)),
        ),
    );

    assert_eq!(
        written(&diffs, bob.account_id()),
        State::Participant {
            node: bob_node,
            referrer: Some(alice_node),
            reward_balance: 0,
        }
    );

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(&bob, bob_node, Some(alice_node), 0),
            tickets(bob_node, 5),
            fresh(0x41),
        ],
        collect(&bob),
    );

    assert_eq!(balance_of(&written(&diffs, bob.account_id())), 5);
    assert_eq!(
        written(&diffs, ticket_account_id(PROGRAM, bob_node)),
        credit(bob_node, 0)
    );
    assert_eq!(
        written(&diffs, AccountId::new([0x41; 32])),
        credit(alice_node, 5)
    );

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(&alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 5),
            fresh(0x42),
        ],
        collect(&alice),
    );

    assert_eq!(balance_of(&written(&diffs, alice.account_id())), 5);
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
fn a_later_collect_uses_neither_the_registry_nor_a_signature() {
    let (_key, bob_node) = node(1);
    let bob = participant(11);

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(&bob, bob_node, None, 7),
            note(0x41, bob_node, 3),
        ],
        collect(&bob),
    );

    assert_eq!(balance_of(&written(&diffs, bob.account_id())), 10);
    assert_eq!(
        written(&diffs, AccountId::new([0x41; 32])),
        credit(bob_node, 0)
    );
    assert_eq!(diffs.len(), 2);
}

#[test]
fn a_same_node_participant_with_other_keys_collects_its_nodes_credit() {
    let (_key, alice_node) = node(2);
    let other = participant(15);

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(&other, alice_node, None, 0),
            note(0x41, alice_node, 4),
        ],
        collect(&other),
    );

    assert_eq!(balance_of(&written(&diffs, other.account_id())), 4);
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
#[should_panic(expected = "ticket account holds another node's credit")]
fn grant_rejects_a_credit_addressed_to_another_node() {
    let (_key, node_id) = node(1);
    let (_key, other_node) = node(2);

    let _diffs = grant(
        PROGRAM,
        vec![
            oracle(),
            account(
                ticket_account_id(PROGRAM, node_id),
                Some(credit(other_node, 5)),
                false,
            ),
        ],
        node_id,
        1,
    );
}

#[test]
#[should_panic(expected = "ticket account does not hold a credit")]
fn grant_rejects_a_ticket_account_holding_another_state() {
    let (_key, node_id) = node(1);

    let _diffs = grant(
        PROGRAM,
        vec![
            oracle(),
            account(
                ticket_account_id(PROGRAM, node_id),
                Some(State::Participant {
                    node: node_id,
                    referrer: None,
                    reward_balance: 0,
                }),
                false,
            ),
        ],
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
        vec![account(bob.account_id(), None, true), registered(&[])],
        register(
            &bob,
            bob_node,
            None,
            signature(&bob_key, bob_node, &other, None),
        ),
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_collect() {
    let (_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![unauthorized(&bob, bob_node), tickets(bob_node, 1)],
        collect(&bob),
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
            initialized(&alice, alice_node, None, 0),
            note(0x41, bob_node, 10),
        ],
        collect(&alice),
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
            initialized(&alice, alice_node, None, 0),
            note(0x41, alice_node, 0),
        ],
        collect(&alice),
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
            initialized(&alice, alice_node, None, u128::MAX),
            note(0x41, alice_node, 1),
        ],
        collect(&alice),
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
            initialized(&alice, alice_node, None, 0),
            note(0x41, alice_node, 10),
            fresh(0x42),
        ],
        collect(&alice),
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
            initialized(&alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 10),
        ],
        collect(&alice),
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
            initialized(&alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 10),
            note(0x42, carol_node, 0),
        ],
        collect(&alice),
    );
}

#[test]
#[should_panic(expected = "must be distinct accounts")]
fn collect_rejects_an_outgoing_credit_that_aliases_its_source() {
    let (_alice_key, alice_node) = node(2);
    let (_carol_key, carol_node) = node(3);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(&alice, alice_node, Some(carol_node), 0),
            note(0x41, alice_node, 10),
            note(0x41, alice_node, 10),
        ],
        collect(&alice),
    );
}

#[test]
#[should_panic(expected = "node is already registered")]
fn register_rejects_an_already_registered_node() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(bob.account_id(), None, true),
            registered(&[bob_node]),
        ],
        register(
            &bob,
            bob_node,
            None,
            signature(&bob_key, bob_node, &bob, None),
        ),
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
        vec![account(bob.account_id(), None, true), registered(&[])],
        register(
            &bob,
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, &bob, Some(alice_node)),
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
            initialized(&bob, bob_node, None, 0),
            registered(&[alice_node]),
        ],
        register(
            &bob,
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, &bob, Some(alice_node)),
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
        vec![account(bob.account_id(), None, true), tickets(bob_node, 1)],
        collect(&bob),
    );
}

#[test]
#[should_panic(expected = "referrer node is not registered")]
fn register_rejects_a_self_referrer() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![account(bob.account_id(), None, true), registered(&[])],
        register(
            &bob,
            bob_node,
            Some(bob_node),
            signature(&bob_key, bob_node, &bob, Some(bob_node)),
        ),
    );
}

#[test]
#[should_panic(expected = "the registry is full")]
fn register_rejects_a_full_registry() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);
    let capacity = u64::try_from(MAX_REGISTERED_NODES).expect("the capacity fits in u64");
    let filler: Vec<NodeId> = (0..capacity)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_le_bytes());
            NodeId::new(bytes)
        })
        .collect();

    let _diffs = execute(
        PROGRAM,
        vec![account(bob.account_id(), None, true), registered(&filler)],
        register(
            &bob,
            bob_node,
            None,
            signature(&bob_key, bob_node, &bob, None),
        ),
    );
}
