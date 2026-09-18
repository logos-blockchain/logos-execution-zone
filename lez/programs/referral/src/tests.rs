#![cfg(test)]

use std::collections::BTreeMap;

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

fn registry(nodes: &[NodeId], epoch: u32, active: &[NodeId]) -> Registry {
    Registry {
        nodes: nodes.iter().copied().collect(),
        epoch,
        active: active.iter().copied().collect(),
    }
}

fn registry_account(registry: Registry, authorized: bool) -> AccountInput {
    account(
        ORACLE_ACCOUNT_ID,
        Some(State::Registry(registry)),
        authorized,
    )
}

const fn register(node: NodeId, referrer: Option<NodeId>, node_signature: [u8; 64]) -> Instruction {
    Instruction::Register {
        node,
        referrer,
        node_signature,
    }
}

fn publish(epoch: u32, active: &[NodeId]) -> Instruction {
    Instruction::Publish {
        epoch,
        active: active.iter().copied().collect(),
    }
}

const fn claim() -> Instruction {
    Instruction::Claim
}

const fn credit(recipient_node: NodeId, amount: u128) -> State {
    State::Credit {
        recipient_node,
        amount,
    }
}

const fn child(node: NodeId, referrer: NodeId) -> State {
    State::Child { node, referrer }
}

fn note(id: u8, state: State) -> AccountInput {
    account(AccountId::new([id; 32]), Some(state), false)
}

fn fresh(id: u8) -> AccountInput {
    account(AccountId::new([id; 32]), None, false)
}

fn initialized(
    participant: AccountId,
    node: NodeId,
    referrer: Option<NodeId>,
    children: &[(NodeId, u32)],
    reward_balance: u128,
) -> AccountInput {
    account(
        participant,
        Some(State::Participant(Participant {
            node,
            referrer,
            children: children.iter().copied().collect(),
            reward_balance,
        })),
        true,
    )
}

fn unauthorized(participant: AccountId, node: NodeId) -> AccountInput {
    account(
        participant,
        Some(State::Participant(Participant::new(node, None))),
        false,
    )
}

fn diff_of(diffs: &[ShardStateDiff], id: AccountId) -> &ShardStateDiff {
    diffs
        .iter()
        .find(|diff| diff.pre_state.account_id == id)
        .expect("account is among the diffs")
}

fn ids(diffs: &[ShardStateDiff]) -> Vec<AccountId> {
    diffs.iter().map(|diff| diff.pre_state.account_id).collect()
}

fn written(diffs: &[ShardStateDiff], id: AccountId) -> State {
    State::decode(
        diff_of(diffs, id)
            .post_data
            .as_ref()
            .expect("account was written"),
    )
    .expect("written state decodes")
}

fn unchanged(diffs: &[ShardStateDiff], id: AccountId) -> bool {
    diff_of(diffs, id).post_data.is_none()
}

fn cleared(diffs: &[ShardStateDiff], id: AccountId) -> bool {
    diff_of(diffs, id).post_data == Some(ShardData::empty())
}

#[test]
#[should_panic(expected = "node authorization signature is invalid")]
fn register_rejects_a_signature_addressed_to_another_participant() {
    let (bob_key, bob_node) = node(1);
    let bob = participant(11);
    let other = participant(14);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registry_account(registry(&[], 0, &[]), false),
        ],
        &register(bob_node, None, signature(&bob_key, bob_node, other, None)),
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_claim() {
    let (_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            unauthorized(bob, bob_node),
            registry_account(registry(&[bob_node], 0, &[]), false),
            note(0x41, credit(bob_node, 1)),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "credit is addressed to another node")]
fn claim_rejects_a_credit_for_another_node() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], 0),
            registry_account(registry(&[alice_node, bob_node], 0, &[]), false),
            note(0x41, credit(bob_node, 10)),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "reward balance fits in u128")]
fn claim_rejects_an_overflowing_reward_balance() {
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], u128::MAX),
            registry_account(registry(&[alice_node], 0, &[]), false),
            note(0x41, credit(alice_node, 1)),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "exactly when its participant has a referrer")]
fn a_root_claim_rejects_an_outgoing_credit_account() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], 0),
            registry_account(registry(&[alice_node, bob_node], 1, &[bob_node]), false),
            note(0x41, child(bob_node, alice_node)),
            fresh(0x42),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "exactly when its participant has a referrer")]
fn a_referred_claim_requires_an_outgoing_credit_account() {
    let (_alice_key, alice_node) = node(2);
    let (_carol_key, carol_node) = node(3);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, Some(carol_node), &[], 0),
            registry_account(registry(&[alice_node, carol_node], 0, &[]), false),
            note(0x41, credit(alice_node, 10)),
        ],
        &claim(),
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
            account(bob, None, true),
            registry_account(registry(&[bob_node], 0, &[]), false),
        ],
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
        vec![
            account(bob, None, true),
            registry_account(registry(&[], 0, &[]), false),
            fresh(0x41),
        ],
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
            initialized(bob, bob_node, None, &[], 0),
            registry_account(registry(&[alice_node], 0, &[]), false),
            fresh(0x41),
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
fn claim_rejects_an_unregistered_participant() {
    let (_bob_key, bob_node) = node(1);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registry_account(registry(&[], 0, &[]), false),
            note(0x41, credit(bob_node, 1)),
        ],
        &claim(),
    );
}

#[test]
fn publish_replaces_the_epoch_and_the_active_set() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);

    let diffs = execute(
        PROGRAM,
        vec![registry_account(
            registry(&[bob_node, alice_node], 1, &[bob_node]),
            true,
        )],
        &publish(2, &[alice_node]),
    );

    assert_eq!(ids(&diffs), [ORACLE_ACCOUNT_ID]);
    assert_eq!(
        written(&diffs, ORACLE_ACCOUNT_ID),
        State::Registry(registry(&[bob_node, alice_node], 2, &[alice_node]))
    );
}

#[test]
#[should_panic(expected = "oracle authorization is missing")]
fn publish_rejects_an_unsigned_registry() {
    let _diffs = execute(
        PROGRAM,
        vec![registry_account(registry(&[], 0, &[]), false)],
        &publish(1, &[]),
    );
}

#[test]
#[should_panic(expected = "account must be the registry")]
fn publish_rejects_a_signed_account_that_is_not_the_registry() {
    let _diffs = execute(
        PROGRAM,
        vec![account(participant(11), None, true)],
        &publish(1, &[]),
    );
}

#[test]
fn a_referred_register_announces_the_child_to_its_referrer() {
    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = participant(11);
    let announcement = AccountId::new([0x41; 32]);

    let diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registry_account(registry(&[alice_node], 0, &[]), false),
            fresh(0x41),
        ],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );

    assert_eq!(ids(&diffs), [bob, ORACLE_ACCOUNT_ID, announcement]);
    assert_eq!(
        written(&diffs, bob),
        State::Participant(Participant::new(bob_node, Some(alice_node)))
    );
    assert_eq!(
        written(&diffs, ORACLE_ACCOUNT_ID),
        State::Registry(registry(&[alice_node, bob_node], 0, &[]))
    );
    assert_eq!(written(&diffs, announcement), child(bob_node, alice_node));
}

#[test]
#[should_panic(expected = "exactly when it has one")]
fn a_root_register_rejects_a_child_note_account() {
    let (carol_key, carol_node) = node(3);
    let carol = participant(13);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(carol, None, true),
            registry_account(registry(&[], 0, &[]), false),
            fresh(0x41),
        ],
        &register(
            carol_node,
            None,
            signature(&carol_key, carol_node, carol, None),
        ),
    );
}

#[test]
#[should_panic(expected = "exactly when it has one")]
fn a_referred_register_requires_a_child_note_account() {
    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registry_account(registry(&[alice_node], 0, &[]), false),
        ],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );
}

#[test]
#[should_panic(expected = "child note account is not fresh")]
fn register_rejects_a_live_child_note_account() {
    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = participant(11);

    let _diffs = execute(
        PROGRAM,
        vec![
            account(bob, None, true),
            registry_account(registry(&[alice_node], 0, &[]), false),
            note(0x41, credit(alice_node, 1)),
        ],
        &register(
            bob_node,
            Some(alice_node),
            signature(&bob_key, bob_node, bob, Some(alice_node)),
        ),
    );
}

#[test]
fn a_claim_adopts_announced_children_and_forwards_what_it_earns() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let (_carol_key, carol_node) = node(3);
    let (_dave_key, dave_node) = node(4);
    let alice = participant(12);
    let bob_note = AccountId::new([0x41; 32]);
    let dave_note = AccountId::new([0x42; 32]);
    let outgoing = AccountId::new([0x43; 32]);
    let credit_note = AccountId::new([0x44; 32]);

    let diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, Some(carol_node), &[], 0),
            registry_account(
                registry(&[alice_node, bob_node, dave_node], 1, &[bob_node]),
                false,
            ),
            note(0x41, child(bob_node, alice_node)),
            note(0x42, child(dave_node, alice_node)),
            note(0x44, credit(alice_node, 4)),
            fresh(0x43),
        ],
        &claim(),
    );

    assert_eq!(
        ids(&diffs),
        [
            alice,
            ORACLE_ACCOUNT_ID,
            bob_note,
            dave_note,
            credit_note,
            outgoing
        ]
    );
    assert_eq!(
        written(&diffs, alice),
        State::Participant(Participant {
            node: alice_node,
            referrer: Some(carol_node),
            children: BTreeMap::from([(bob_node, 1), (dave_node, 0)]),
            reward_balance: 5,
        })
    );
    assert!(
        unchanged(&diffs, ORACLE_ACCOUNT_ID),
        "a claim leaves the registry untouched"
    );
    assert!(
        cleared(&diffs, bob_note) && cleared(&diffs, dave_note) && cleared(&diffs, credit_note),
        "consumed notes are cleared"
    );
    assert_eq!(written(&diffs, outgoing), credit(carol_node, 5));
}

#[test]
#[should_panic(expected = "note does not hold a child or a credit")]
fn claim_rejects_a_note_holding_a_registry() {
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], 0),
            registry_account(registry(&[alice_node], 1, &[alice_node]), false),
            note(
                0x41,
                State::Registry(registry(&[alice_node], 1, &[alice_node])),
            ),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "child is announced to another node")]
fn claim_rejects_a_child_announced_to_another_node() {
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], 0),
            registry_account(registry(&[alice_node, bob_node], 1, &[alice_node]), false),
            note(0x41, child(alice_node, bob_node)),
        ],
        &claim(),
    );
}

#[test]
#[should_panic(expected = "Claim takes at most one outgoing credit account, in last place")]
fn claim_rejects_a_note_after_the_outgoing_credit_account() {
    let (_alice_key, alice_node) = node(2);
    let alice = participant(12);

    let _diffs = execute(
        PROGRAM,
        vec![
            initialized(alice, alice_node, None, &[], 0),
            registry_account(registry(&[alice_node], 0, &[]), false),
            fresh(0x41),
            note(0x42, credit(alice_node, 1)),
        ],
        &claim(),
    );
}
