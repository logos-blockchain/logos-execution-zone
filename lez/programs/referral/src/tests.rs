#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan, PlanInput, ShardEffect},
};
use referral_core::{
    Claim, Effect, Instruction, NodeId, ORACLE_ACCOUNT_ID, Participant, ParticipantAuthorizationV1,
    Registry, State, active_digest, cash_out_receipt,
    ed25519_dalek::{Signer as _, SigningKey},
};

const PROGRAM: AccountId = AccountId::new([9; 32]);

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

fn account(seed: u8) -> AccountId {
    AccountId::new([seed; 32])
}

fn meta(account_id: AccountId, is_authorized: bool) -> AccountMeta {
    AccountMeta::new(account_id, is_authorized, PROGRAM)
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

fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    crate::plan(
        &PlanInput {
            self_account_id: PROGRAM,
            caller_account_id: None,
            accounts,
            instruction_data: Vec::new(),
        },
        instruction,
    )
}

fn registry_data(registry: Registry) -> ShardData {
    State::Registry(registry).to_data()
}

fn claim(total: u128, referrer: Option<NodeId>) -> Claim {
    Claim {
        epoch: 0,
        active: BTreeSet::new(),
        notes: vec![],
        total,
        referrer,
    }
}

#[test]
fn publish_replaces_the_epoch_and_the_active_set() {
    let (_, a) = node(1);
    let effect = Effect::Publish {
        epoch: 2,
        active: BTreeSet::new(),
    };

    let plan = plan_for(
        vec![meta(ORACLE_ACCOUNT_ID, true)],
        Instruction::Publish {
            epoch: 2,
            active: BTreeSet::new(),
        },
    );

    assert_eq!(
        plan.output().effects,
        vec![ShardEffect::new(&meta(ORACLE_ACCOUNT_ID, true), &effect)]
    );

    let post = crate::apply(
        effect,
        &registry_data(Registry {
            nodes: BTreeSet::from([a]),
            epoch: 1,
            active: BTreeSet::from([a]),
        }),
    )
    .expect("Publish writes the registry");

    assert_eq!(
        State::decode(&post),
        Some(State::Registry(Registry {
            nodes: BTreeSet::from([a]),
            epoch: 2,
            ..Registry::default()
        }))
    );
}

#[test]
#[should_panic(expected = "oracle authorization is missing")]
fn publish_rejects_an_unsigned_registry() {
    let _plan = plan_for(
        vec![meta(ORACLE_ACCOUNT_ID, false)],
        Instruction::Publish {
            epoch: 1,
            active: BTreeSet::new(),
        },
    );
}

#[test]
fn a_referred_register_announces_the_child_to_its_referrer() {
    let (node_key, node_id) = node(1);
    let (_, parent) = node(2);
    let (_, other) = node(3);
    let participant_account = account(11);
    let child_account = account(41);
    let pool = BTreeSet::from([parent, other]);

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            meta(child_account, false),
        ],
        Instruction::Register {
            node: node_id,
            referrer: Some(parent),
            node_signature: signature(&node_key, node_id, participant_account, Some(parent)),
            pool: pool.clone(),
        },
    );

    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Create(State::Participant(Participant::new(node_id, Some(parent)))),
            ),
            ShardEffect::new(
                &meta(ORACLE_ACCOUNT_ID, false),
                &Effect::Register {
                    node: node_id,
                    pool,
                },
            ),
            ShardEffect::new(
                &meta(child_account, false),
                &Effect::Create(State::Child {
                    node: node_id,
                    referrer: parent,
                }),
            ),
        ]
    );
}

#[test]
#[should_panic(
    expected = "a Register announces the participant to its referrer exactly when it has one"
)]
fn a_referred_register_requires_a_child_note_account() {
    let (_, parent) = node(2);
    let participant_account = account(11);

    let _plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
        ],
        Instruction::Register {
            node: node(1).1,
            referrer: Some(parent),
            node_signature: [0; 64],
            pool: BTreeSet::new(),
        },
    );
}

#[test]
#[should_panic(expected = "node authorization signature is invalid")]
fn register_rejects_a_signature_addressed_to_another_participant() {
    let (node_key, node_id) = node(1);
    let signed_for = account(11);
    let submitted_as = account(12);

    let _plan = plan_for(
        vec![meta(submitted_as, true), meta(ORACLE_ACCOUNT_ID, false)],
        Instruction::Register {
            node: node_id,
            referrer: None,
            node_signature: signature(&node_key, node_id, signed_for, None),
            pool: BTreeSet::new(),
        },
    );
}

#[test]
#[should_panic(expected = "the pool must contain the referrer")]
fn register_requires_the_referrer_in_its_pool() {
    let (node_key, node_id) = node(1);
    let (_, parent) = node(2);
    let (_, other) = node(3);
    let participant_account = account(11);
    let child_account = account(41);

    let _plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            meta(child_account, false),
        ],
        Instruction::Register {
            node: node_id,
            referrer: Some(parent),
            node_signature: signature(&node_key, node_id, participant_account, Some(parent)),
            pool: BTreeSet::from([other]),
        },
    );
}

#[test]
#[should_panic(expected = "the pool names an unregistered node")]
fn register_checks_the_pool_before_inserting_its_node() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Register {
            node: node_id,
            pool: BTreeSet::from([node_id]),
        },
        &registry_data(Registry::default()),
    );
}

#[test]
#[should_panic(expected = "node is already registered")]
fn register_rejects_an_already_registered_node() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Register {
            node: node_id,
            pool: BTreeSet::new(),
        },
        &registry_data(Registry {
            nodes: BTreeSet::from([node_id]),
            ..Registry::default()
        }),
    );
}

#[test]
#[should_panic(expected = "account already holds referral state")]
fn create_rejects_an_account_that_holds_referral_state() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Create(State::Participant(Participant::new(node_id, None))),
        &State::Child {
            node: node_id,
            referrer: node_id,
        }
        .to_data(),
    );
}

#[test]
fn a_claim_adopts_announced_children_and_forwards_what_it_earns() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let child_note = account(41);
    let credit_note = account(42);
    let outgoing = account(43);
    let active = BTreeSet::from([c]);
    let child = State::Child {
        node: c,
        referrer: me,
    };
    let credit = State::Credit {
        recipient_node: me,
        amount: 4,
    };
    let check_epoch = Effect::CheckEpoch {
        epoch: 2,
        active_digest: active_digest(&active),
    };

    let claim = Claim {
        epoch: 2,
        active: active.clone(),
        notes: vec![child.clone(), credit.clone()],
        total: 5,
        referrer: Some(parent),
    };

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            meta(child_note, false),
            meta(credit_note, false),
            meta(outgoing, false),
        ],
        Instruction::Claim(claim.clone()),
    );

    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(&meta(ORACLE_ACCOUNT_ID, false), &check_epoch),
            ShardEffect::new(&meta(child_note, false), &Effect::Consume(child.clone()),),
            ShardEffect::new(&meta(credit_note, false), &Effect::Consume(credit.clone()),),
            ShardEffect::new(
                &meta(outgoing, false),
                &Effect::Create(State::Credit {
                    recipient_node: parent,
                    amount: 5,
                }),
            ),
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Claim(claim.clone()),
            ),
        ]
    );

    assert_eq!(
        crate::apply(
            check_epoch,
            &registry_data(Registry {
                epoch: 2,
                active,
                ..Registry::default()
            }),
        ),
        None
    );
    assert_eq!(
        crate::apply(Effect::Consume(child.clone()), &child.to_data()),
        Some(ShardData::empty())
    );
    assert_eq!(
        crate::apply(Effect::Consume(credit.clone()), &credit.to_data()),
        Some(ShardData::empty())
    );

    let written = crate::apply(
        Effect::Claim(claim),
        &State::Participant(Participant::new(me, Some(parent))).to_data(),
    )
    .expect("Claim writes the participant");
    assert_eq!(
        State::decode(&written),
        Some(State::Participant(Participant {
            node: me,
            referrer: Some(parent),
            children: BTreeMap::from([(c, 2)]),
            reward_balance: 5,
        }))
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_claim() {
    let participant_account = account(20);

    let _plan = plan_for(
        vec![
            meta(participant_account, false),
            meta(ORACLE_ACCOUNT_ID, false),
        ],
        Instruction::Claim(claim(1, None)),
    );
}

#[test]
#[should_panic(expected = "account must be the registry")]
fn claim_rejects_an_account_that_is_not_the_registry() {
    let participant_account = account(20);
    let not_registry = account(21);

    let _plan = plan_for(
        vec![meta(participant_account, true), meta(not_registry, false)],
        Instruction::Claim(claim(1, None)),
    );
}

#[test]
#[should_panic(expected = "a referred Claim ends with its outgoing credit account")]
fn a_referred_claim_requires_an_outgoing_credit_account() {
    let (_, parent) = node(2);
    let participant_account = account(20);

    let _plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
        ],
        Instruction::Claim(claim(1, Some(parent))),
    );
}

#[test]
#[should_panic(expected = "the claim total does not match")]
fn claim_rejects_a_total_that_does_not_match() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::Claim(claim(1, None)),
        &State::Participant(Participant::new(me, None)).to_data(),
    );
}

#[test]
#[should_panic(expected = "the claim names another referrer")]
fn claim_rejects_another_referrer() {
    let (_, me) = node(1);
    let (_, other) = node(2);

    let _written = crate::apply(
        Effect::Claim(claim(0, Some(other))),
        &State::Participant(Participant::new(me, None)).to_data(),
    );
}

#[test]
#[should_panic(expected = "note does not hold the claimed state")]
fn consume_rejects_a_note_that_differs_from_the_claim() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::Consume(State::Credit {
            recipient_node: me,
            amount: 1,
        }),
        &State::Credit {
            recipient_node: me,
            amount: 2,
        }
        .to_data(),
    );
}

#[test]
#[should_panic(expected = "the registry has moved to another epoch")]
fn check_epoch_rejects_a_moved_epoch() {
    let _written = crate::apply(
        Effect::CheckEpoch {
            epoch: 1,
            active_digest: active_digest(&BTreeSet::new()),
        },
        &registry_data(Registry {
            epoch: 2,
            ..Registry::default()
        }),
    );
}

#[test]
#[should_panic(expected = "the claim names another active set")]
fn check_epoch_rejects_another_active_set() {
    let (_, a) = node(1);

    let _written = crate::apply(
        Effect::CheckEpoch {
            epoch: 2,
            active_digest: active_digest(&BTreeSet::from([a])),
        },
        &registry_data(Registry {
            epoch: 2,
            ..Registry::default()
        }),
    );
}

fn cash_out(node: NodeId, points: u128) -> Instruction {
    Instruction::CashOut {
        node,
        points,
        blinding_factor: [5; 32],
    }
}

fn holding(node: NodeId, reward_balance: u128) -> ShardData {
    State::Participant(Participant {
        reward_balance,
        ..Participant::new(node, None)
    })
    .to_data()
}

#[test]
fn a_cash_out_burns_the_full_balance_into_its_receipt() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let receipt = cash_out_receipt(PROGRAM, me, [5; 32]);

    let plan = plan_for(
        vec![meta(participant_account, true), meta(receipt, false)],
        cash_out(me, 7),
    );

    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::CashOutBurn {
                    node: me,
                    points: 7
                },
            ),
            ShardEffect::new(
                &meta(receipt, false),
                &Effect::Create(State::CashOut { points: 7 }),
            ),
        ]
    );

    let earned = Participant {
        node: me,
        referrer: Some(parent),
        children: BTreeMap::from([(c, 2)]),
        reward_balance: 7,
    };
    let burned = crate::apply(
        Effect::CashOutBurn {
            node: me,
            points: 7,
        },
        &State::Participant(earned.clone()).to_data(),
    )
    .expect("the burn writes the participant");
    assert_eq!(
        State::decode(&burned),
        Some(State::Participant(Participant {
            reward_balance: 0,
            ..earned
        }))
    );
    assert_eq!(
        crate::apply(
            Effect::Create(State::CashOut { points: 7 }),
            &ShardData::empty()
        ),
        Some(State::CashOut { points: 7 }.to_data())
    );
}

#[test]
#[should_panic(expected = "the receipt account does not match the node and blinding factor")]
fn a_cash_out_rejects_a_receipt_for_another_factor() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            meta(cash_out_receipt(PROGRAM, me, [6; 32]), false),
        ],
        cash_out(me, 7),
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_cash_out() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), false),
            meta(cash_out_receipt(PROGRAM, me, [5; 32]), false),
        ],
        cash_out(me, 7),
    );
}

#[test]
#[should_panic(expected = "nothing to cash out")]
fn a_cash_out_requires_points() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            meta(cash_out_receipt(PROGRAM, me, [5; 32]), false),
        ],
        cash_out(me, 0),
    );
}

#[test]
#[should_panic(expected = "the cash out names another node")]
fn the_burn_rejects_another_node() {
    let (_, me) = node(1);
    let (_, other) = node(2);

    let _written = crate::apply(
        Effect::CashOutBurn {
            node: other,
            points: 7,
        },
        &holding(me, 7),
    );
}

#[test]
#[should_panic(expected = "a cash out takes the full reward balance")]
fn the_burn_takes_the_full_balance() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::CashOutBurn {
            node: me,
            points: 6,
        },
        &holding(me, 7),
    );
}

#[test]
#[should_panic(expected = "account already holds referral state")]
fn a_receipt_is_never_written_twice() {
    let _written = crate::apply(
        Effect::Create(State::CashOut { points: 7 }),
        &State::CashOut { points: 7 }.to_data(),
    );
}
