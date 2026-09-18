use std::collections::BTreeSet;

use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountInput, ShardStateDiff},
};
pub use referral_core as core;
use referral_core::{
    Instruction, NodeId, ORACLE_ACCOUNT_ID, Participant, ParticipantAuthorizationV1, Registry,
    State,
};

#[must_use]
pub fn execute(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    instruction: &Instruction,
) -> Vec<ShardStateDiff> {
    match instruction {
        Instruction::Register {
            node,
            referrer,
            node_signature,
        } => register(program, pre_states, *node, *referrer, *node_signature),
        Instruction::Publish { epoch, active } => publish(program, pre_states, *epoch, active),
        Instruction::Claim => claim(program, pre_states),
    }
}

fn register(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    node: NodeId,
    referrer: Option<NodeId>,
    node_signature: [u8; 64],
) -> Vec<ShardStateDiff> {
    let mut accounts = pre_states.into_iter();
    let participant = accounts
        .next()
        .expect("Register requires the participant and the registry");
    let registry_account = accounts
        .next()
        .expect("Register requires the participant and the registry");
    let child = accounts.next();
    assert!(
        accounts.next().is_none(),
        "Register takes at most one child note account"
    );
    assert_eq!(
        referrer.is_some(),
        child.is_some(),
        "a Register announces the participant to its referrer exactly when it has one"
    );

    assert_authorized(&participant);
    assert!(
        participant.shard_of(program).is_empty(),
        "participant is already initialized"
    );

    let mut registry = decode_registry(&registry_account, program);
    if let Some(parent) = referrer {
        assert!(
            registry.nodes.contains(&parent),
            "referrer node is not registered"
        );
    }
    assert!(registry.nodes.insert(node), "node is already registered");
    assert!(
        ParticipantAuthorizationV1::new(program, node, participant.account_id, referrer)
            .verify(&node_signature),
        "node authorization signature is invalid"
    );

    let mut diffs = vec![
        write_state(
            participant,
            &State::Participant(Participant::new(node, referrer)),
        ),
        write_state(registry_account, &State::Registry(registry)),
    ];
    if let Some((parent, child)) = referrer.zip(child) {
        assert!(
            child.shard_of(program).is_empty(),
            "child note account is not fresh"
        );
        diffs.push(write_state(
            child,
            &State::Child {
                node,
                referrer: parent,
            },
        ));
    }

    diffs
}

fn publish(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    epoch: u32,
    active: &BTreeSet<NodeId>,
) -> Vec<ShardStateDiff> {
    let [registry_account] =
        <[AccountInput; 1]>::try_from(pre_states).expect("Publish requires the registry");

    assert!(
        registry_account.is_authorized,
        "oracle authorization is missing"
    );

    let mut registry = decode_registry(&registry_account, program);
    registry.epoch = epoch;
    registry.active.clone_from(active);

    vec![write_state(registry_account, &State::Registry(registry))]
}

fn claim(program: AccountId, pre_states: Vec<AccountInput>) -> Vec<ShardStateDiff> {
    let mut accounts = pre_states.into_iter();
    let participant_account = accounts
        .next()
        .expect("Claim requires the participant and the registry");
    let registry_account = accounts
        .next()
        .expect("Claim requires the participant and the registry");

    assert_authorized(&participant_account);
    let State::Participant(mut participant) = decode_state(&participant_account, program) else {
        panic!("participant state must be a participant");
    };
    let registry = decode_registry(&registry_account, program);

    let mut notes: Vec<AccountInput> = Vec::new();
    let mut outgoing = None;
    for account in accounts {
        assert!(
            outgoing.is_none(),
            "Claim takes at most one outgoing credit account, in last place"
        );
        if account.shard_of(program).is_empty() {
            outgoing = Some(account);
        } else {
            notes.push(account);
        }
    }

    let states: Vec<State> = notes
        .iter()
        .map(|note| decode_state(note, program))
        .collect();
    let total = participant.claim(&registry, &states);
    assert!(total > 0, "nothing to claim");
    assert_eq!(
        participant.referrer.is_some(),
        outgoing.is_some(),
        "a Claim delivers an outgoing credit exactly when its participant has a referrer"
    );

    let referrer = participant.referrer;
    let mut diffs = vec![
        write_state(participant_account, &State::Participant(participant)),
        ShardStateDiff::unchanged(registry_account),
    ];
    diffs.extend(notes.into_iter().map(clear));
    if let Some((parent, credit)) = referrer.zip(outgoing) {
        diffs.push(write_state(
            credit,
            &State::Credit {
                recipient_node: parent,
                amount: total,
            },
        ));
    }

    diffs
}

fn assert_authorized(participant: &AccountInput) {
    assert!(
        participant.is_authorized,
        "participant authorization is missing"
    );
}

fn decode_state(account: &AccountInput, program: AccountId) -> State {
    let shard = account.shard_of(program);
    assert!(
        !shard.is_empty(),
        "account holds initialized referral state"
    );
    State::decode(shard).expect("account holds a decodable referral state")
}

fn decode_registry(account: &AccountInput, program: AccountId) -> Registry {
    assert_eq!(
        account.account_id, ORACLE_ACCOUNT_ID,
        "account must be the registry"
    );
    if account.shard_of(program).is_empty() {
        return Registry::default();
    }
    let State::Registry(registry) = decode_state(account, program) else {
        panic!("registry account does not hold the registry")
    };
    registry
}

fn write_state(account: AccountInput, state: &State) -> ShardStateDiff {
    ShardStateDiff::new(account, state.to_data())
}

const fn clear(account: AccountInput) -> ShardStateDiff {
    ShardStateDiff::new(account, ShardData::empty())
}

mod tests;
