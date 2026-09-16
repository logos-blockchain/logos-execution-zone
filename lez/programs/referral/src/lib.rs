use std::collections::BTreeSet;

use lee_core::{
    account::AccountId,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{AccountInput, ShardStateDiff},
};
pub use referral_core as core;
use referral_core::{
    FirstUse, Instruction, L1Epoch, NodeId, ORACLE_ACCOUNT_ID, ParticipantAuthorizationV1,
    ParticipantDescriptor, Registry, State, StoredState, registry_account_id, ticket_account_id,
};

#[must_use]
pub fn execute(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    instruction: Instruction,
) -> Vec<ShardStateDiff> {
    match instruction {
        Instruction::AddEpochData {
            epoch,
            new_node_ids,
        } => add_epoch_data(program, pre_states, epoch, &new_node_ids),
        Instruction::Grant { node, amount } => grant(program, pre_states, node, amount),
        Instruction::Collect {
            participant,
            first_use,
        } => collect(program, pre_states, &participant, first_use),
    }
}

fn add_epoch_data(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    epoch: L1Epoch,
    new_node_ids: &[NodeId],
) -> Vec<ShardStateDiff> {
    let [oracle, registry_account] = <[AccountInput; 2]>::try_from(pre_states)
        .expect("AddEpochData requires the oracle and the registry");

    assert_oracle(&oracle);
    assert_eq!(
        registry_account.account_id,
        registry_account_id(program),
        "second account must be the referral registry"
    );

    let mut registry = match decode_optional_state(&registry_account, program) {
        None => Registry::default(),
        Some(State::Registry(registry)) => registry,
        Some(State::Participant { .. } | State::Credit { .. }) => {
            panic!("registry account does not hold the registry")
        }
    };
    assert!(
        registry.insert_batch(epoch, new_node_ids),
        "batch is empty, repeats a node, contains an already registered node, or exceeds capacity"
    );

    vec![
        ShardStateDiff::unchanged(oracle),
        write_state(registry_account, State::Registry(registry)),
    ]
}

fn grant(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    node: NodeId,
    amount: u128,
) -> Vec<ShardStateDiff> {
    let [oracle, ticket_account] = <[AccountInput; 2]>::try_from(pre_states)
        .expect("Grant requires the oracle and the node's ticket account");

    assert_oracle(&oracle);
    assert_eq!(
        ticket_account.account_id,
        ticket_account_id(program, node),
        "second account must be the node's ticket account"
    );
    assert!(amount > 0, "granted amount must be positive");

    let granted = match decode_optional_state(&ticket_account, program) {
        None => amount,
        Some(State::Credit {
            recipient_node,
            amount: available,
        }) => {
            assert_eq!(
                recipient_node, node,
                "ticket account holds another node's credit"
            );
            available
                .checked_add(amount)
                .expect("granted credit fits in u128")
        }
        Some(State::Registry(_) | State::Participant { .. }) => {
            panic!("ticket account does not hold a credit")
        }
    };

    vec![
        ShardStateDiff::unchanged(oracle),
        write_state(
            ticket_account,
            State::Credit {
                recipient_node: node,
                amount: granted,
            },
        ),
    ]
}

fn collect(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    descriptor: &ParticipantDescriptor,
    first_use: Option<FirstUse>,
) -> Vec<ShardStateDiff> {
    let (accounts, registry_account) = split_registry(pre_states, first_use.is_some());
    let mut accounts = accounts.into_iter();
    let participant = accounts
        .next()
        .expect("Collect requires the participant and its source");
    let source = accounts
        .next()
        .expect("Collect requires the participant and its source");
    let outgoing = accounts.next();
    assert!(
        accounts.next().is_none(),
        "Collect takes at most one outgoing credit account"
    );

    let State::Participant {
        node,
        referrer,
        reward_balance,
    } = resolve_participant(
        program,
        &participant,
        descriptor,
        first_use,
        registry_account.as_ref(),
    )
    else {
        panic!("participant state must be a participant");
    };

    assert_eq!(
        referrer.is_some(),
        outgoing.is_some(),
        "a Collect delivers an outgoing credit exactly when its participant has a referrer"
    );
    let outgoing = referrer.zip(outgoing);

    let touched: Vec<AccountId> = [
        Some(participant.account_id),
        Some(source.account_id),
        outgoing.as_ref().map(|(_parent, credit)| credit.account_id),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(
        touched.iter().collect::<BTreeSet<_>>().len(),
        touched.len(),
        "the participant, its source and its outgoing credit must be distinct accounts"
    );

    let State::Credit {
        recipient_node,
        amount,
    } = decode_state(&source, program)
    else {
        panic!("source account does not hold a credit");
    };
    assert_eq!(recipient_node, node, "credit is addressed to another node");
    assert!(amount > 0, "credit is already collected");

    let mut diffs = vec![
        write_state(
            participant,
            State::Participant {
                node,
                referrer,
                reward_balance: reward_balance
                    .checked_add(amount)
                    .expect("reward balance fits in u128"),
            },
        ),
        write_state(
            source,
            State::Credit {
                recipient_node,
                amount: 0,
            },
        ),
    ];

    if let Some((parent, credit)) = outgoing {
        assert!(
            credit.shard_of(program).is_empty(),
            "outgoing credit account is not fresh"
        );
        diffs.push(write_state(
            credit,
            State::Credit {
                recipient_node: parent,
                amount,
            },
        ));
    }

    if let Some(registry_account) = registry_account {
        diffs.push(ShardStateDiff::unchanged(registry_account));
    }
    diffs
}

fn split_registry(
    mut pre_states: Vec<AccountInput>,
    first_use: bool,
) -> (Vec<AccountInput>, Option<AccountInput>) {
    let registry_account = first_use.then(|| pre_states.pop()).flatten();
    assert!(
        !first_use || registry_account.is_some(),
        "first use requires the registry as its last account"
    );
    (pre_states, registry_account)
}

fn resolve_participant(
    program: AccountId,
    participant: &AccountInput,
    descriptor: &ParticipantDescriptor,
    first_use: Option<FirstUse>,
    registry_account: Option<&AccountInput>,
) -> State {
    assert!(
        participant.is_authorized,
        "participant authorization is missing"
    );
    let participant_id = descriptor.account_id();
    assert_eq!(
        participant.account_id, participant_id,
        "participant is not the regular private account its descriptor derives"
    );

    match (
        decode_optional_state(participant, program),
        first_use,
        registry_account,
    ) {
        (Some(state @ State::Participant { .. }), None, None) => state,
        (Some(_), _, _) => {
            panic!("an initialized participant takes no first-use arguments or registry")
        }
        (None, Some(first_use), Some(registry_account)) => {
            initialize(program, participant_id, &first_use, registry_account)
        }
        (None, _, _) => {
            panic!("an empty participant requires first-use arguments and the registry")
        }
    }
}

fn initialize(
    program: AccountId,
    participant_id: AccountId,
    first_use: &FirstUse,
    registry_account: &AccountInput,
) -> State {
    let &FirstUse {
        node,
        referrer,
        node_signature,
    } = first_use;

    assert_eq!(
        registry_account.account_id,
        registry_account_id(program),
        "the last account must be the referral registry"
    );
    let State::Registry(registry) = decode_state(registry_account, program) else {
        panic!("registry account does not hold the registry");
    };

    let own_epoch = registry
        .first_used(node)
        .expect("node is absent from the registry");
    if let Some(parent) = referrer {
        let parent_epoch = registry
            .first_used(parent)
            .expect("referrer node is absent from the registry");
        assert!(
            parent_epoch < own_epoch,
            "referrer node must have been first used in a strictly earlier epoch"
        );
    }

    assert!(
        ParticipantAuthorizationV1::new(program, node, participant_id, referrer)
            .verify(&node_signature),
        "node authorization signature is invalid"
    );

    State::Participant {
        node,
        referrer,
        reward_balance: 0,
    }
}

fn assert_oracle(oracle: &AccountInput) {
    assert_eq!(
        oracle.account_id, ORACLE_ACCOUNT_ID,
        "first account must be the configured oracle"
    );
    assert!(oracle.is_authorized, "oracle authorization is missing");
    assert_eq!(
        oracle.program_account_id(),
        NATIVE_TOKEN_PROGRAM_ID,
        "the oracle account is selected by balance only"
    );
}

fn decode_optional_state(account: &AccountInput, program: AccountId) -> Option<State> {
    let shard = account.shard_of(program);
    if shard.is_empty() {
        None
    } else {
        Some(
            StoredState::decode(shard)
                .expect("account holds a decodable referral state")
                .state,
        )
    }
}

fn decode_state(account: &AccountInput, program: AccountId) -> State {
    decode_optional_state(account, program).expect("account holds initialized referral state")
}

fn write_state(account: AccountInput, state: State) -> ShardStateDiff {
    ShardStateDiff::new(account, StoredState::new(state).to_data())
}
