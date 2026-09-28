use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan, PlanInput},
};
pub use referral_core as core;
use referral_core::{
    Effect, Instruction, ORACLE_ACCOUNT_ID, Participant, ParticipantAuthorizationV1, Registry,
    State, active_digest,
};

pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "referral instructions are only invoked as top-level user transactions"
    );

    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Publish { epoch, active } => {
            let [registry] = input.accounts.as_slice() else {
                panic!("Publish requires the registry")
            };
            assert!(registry.is_authorized, "oracle authorization is missing");
            assert_registry(registry);
            plan.effect(registry, &Effect::Publish { epoch, active });
        }
        Instruction::Register {
            node,
            referrer,
            node_signature,
            pool,
        } => {
            let (participant, registry, child) = match input.accounts.as_slice() {
                [participant, registry] => (participant, registry, None),
                [participant, registry, child] => (participant, registry, Some(child)),
                _ => panic!(
                    "Register requires the participant, the registry and at most one child note account"
                ),
            };
            assert_eq!(
                referrer.is_some(),
                child.is_some(),
                "a Register announces the participant to its referrer exactly when it has one"
            );
            assert_authorized(participant);
            assert_registry(registry);
            if let Some(parent) = referrer {
                assert!(pool.contains(&parent), "the pool must contain the referrer");
            }
            assert!(
                ParticipantAuthorizationV1::new(
                    input.self_account_id,
                    node,
                    participant.account_id,
                    referrer,
                )
                .verify(&node_signature),
                "node authorization signature is invalid"
            );

            plan.effect(
                participant,
                &Effect::Create(State::Participant(Participant::new(node, referrer))),
            );
            plan.effect(registry, &Effect::Register { node, pool });
            if let Some((parent, child)) = referrer.zip(child) {
                plan.effect(
                    child,
                    &Effect::Create(State::Child {
                        node,
                        referrer: parent,
                    }),
                );
            }
        }
        Instruction::Claim(claim) => {
            let [participant, registry, rest @ ..] = input.accounts.as_slice() else {
                panic!("Claim requires the participant and the registry")
            };
            assert_authorized(participant);
            assert_registry(registry);
            assert!(claim.total > 0, "nothing to claim");

            let (notes, outgoing) = match claim.referrer {
                Some(_) => {
                    let (outgoing, notes) = rest
                        .split_last()
                        .expect("a referred Claim ends with its outgoing credit account");
                    (notes, Some(outgoing))
                }
                None => (rest, None),
            };
            assert_eq!(
                notes.len(),
                claim.notes.len(),
                "a Claim names one account per note, then the outgoing credit account exactly when its participant has a referrer"
            );

            plan.effect(
                registry,
                &Effect::CheckEpoch {
                    epoch: claim.epoch,
                    active_digest: active_digest(&claim.active),
                },
            );
            for (note, account) in claim.notes.iter().zip(notes) {
                plan.effect(account, &Effect::Consume(note.clone()));
            }
            if let Some((parent, credit)) = claim.referrer.zip(outgoing) {
                plan.effect(
                    credit,
                    &Effect::Create(State::Credit {
                        recipient_node: parent,
                        amount: claim.total,
                    }),
                );
            }
            plan.effect(participant, &Effect::Claim(claim));
        }
    }
    plan
}

#[must_use]
pub fn apply(effect: Effect, pre_data: &ShardData) -> Option<ShardData> {
    match effect {
        Effect::Publish { epoch, active } => {
            let mut registry = decode_registry(pre_data);
            registry.epoch = epoch;
            registry.active = active;
            Some(State::Registry(registry).to_data())
        }
        Effect::Register { node, pool } => {
            let mut registry = decode_registry(pre_data);
            assert!(
                pool.is_subset(&registry.nodes),
                "the pool names an unregistered node"
            );
            assert!(registry.nodes.insert(node), "node is already registered");
            Some(State::Registry(registry).to_data())
        }
        Effect::CheckEpoch {
            epoch,
            active_digest: digest,
        } => {
            let registry = decode_registry(pre_data);
            assert_eq!(
                registry.epoch, epoch,
                "the registry has moved to another epoch"
            );
            assert_eq!(
                active_digest(&registry.active),
                digest,
                "the claim names another active set"
            );
            None
        }
        Effect::Create(state) => {
            assert!(pre_data.is_empty(), "account already holds referral state");
            Some(state.to_data())
        }
        Effect::Claim(claim) => {
            let State::Participant(mut participant) = decode(pre_data) else {
                panic!("participant state must be a participant")
            };
            assert_eq!(
                participant.referrer, claim.referrer,
                "the claim names another referrer"
            );
            assert_eq!(
                participant.claim(claim.epoch, &claim.active, &claim.notes),
                claim.total,
                "the claim total does not match"
            );
            Some(State::Participant(participant).to_data())
        }
        Effect::Consume(note) => {
            assert_eq!(
                decode(pre_data),
                note,
                "note does not hold the claimed state"
            );
            Some(ShardData::empty())
        }
    }
}

fn decode(pre_data: &ShardData) -> State {
    State::decode(pre_data).expect("account holds a decodable referral state")
}

fn decode_registry(pre_data: &ShardData) -> Registry {
    if pre_data.is_empty() {
        return Registry::default();
    }
    let State::Registry(registry) = decode(pre_data) else {
        panic!("registry account does not hold the registry")
    };
    registry
}

fn assert_authorized(participant: &AccountMeta) {
    assert!(
        participant.is_authorized,
        "participant authorization is missing"
    );
}

fn assert_registry(registry: &AccountMeta) {
    assert_eq!(
        registry.account_id, ORACLE_ACCOUNT_ID,
        "account must be the registry"
    );
}

mod tests;
