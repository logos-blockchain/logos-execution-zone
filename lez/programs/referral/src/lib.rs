use lee_core::{
    account::AccountId,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{AccountInput, ShardStateDiff},
};
pub use referral_core as core;
use referral_core::{
    Instruction, NodeId, ORACLE_ACCOUNT_ID, ParticipantAuthorizationV1, Registry, State,
    registry_account_id, ticket_account_id,
};

#[must_use]
pub fn execute(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    instruction: &Instruction,
) -> Vec<ShardStateDiff> {
    match *instruction {
        Instruction::Register {
            node,
            referrer,
            node_signature,
        } => register(program, pre_states, node, referrer, node_signature),
        Instruction::Grant { node, amount } => grant(program, pre_states, node, amount),
        Instruction::Collect => collect(program, pre_states),
    }
}

fn register(
    program: AccountId,
    pre_states: Vec<AccountInput>,
    node: NodeId,
    referrer: Option<NodeId>,
    node_signature: [u8; 64],
) -> Vec<ShardStateDiff> {
    let [participant, registry_account] = <[AccountInput; 2]>::try_from(pre_states)
        .expect("Register requires the participant and the registry");

    assert_participant(&participant);
    assert!(
        participant.shard_of(program).is_empty(),
        "participant is already initialized"
    );
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
    assert!(!registry.contains(node), "node is already registered");
    if let Some(parent) = referrer {
        assert!(registry.contains(parent), "referrer node is not registered");
    }
    assert!(
        ParticipantAuthorizationV1::new(program, node, participant.account_id, referrer)
            .verify(&node_signature),
        "node authorization signature is invalid"
    );
    assert!(registry.register(node), "the registry is full");

    vec![
        write_state(
            participant,
            &State::Participant {
                node,
                referrer,
                reward_balance: 0,
            },
        ),
        write_state(registry_account, &State::Registry(registry)),
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
            amount: available, ..
        }) => available
            .checked_add(amount)
            .expect("granted credit fits in u128"),
        Some(State::Registry(_) | State::Participant { .. }) => {
            panic!("ticket account does not hold a credit")
        }
    };

    vec![
        ShardStateDiff::unchanged(oracle),
        write_state(
            ticket_account,
            &State::Credit {
                recipient_node: node,
                amount: granted,
            },
        ),
    ]
}

fn collect(program: AccountId, pre_states: Vec<AccountInput>) -> Vec<ShardStateDiff> {
    let mut accounts = pre_states.into_iter();
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

    assert_participant(&participant);
    let State::Participant {
        node,
        referrer,
        reward_balance,
    } = decode_state(&participant, program)
    else {
        panic!("participant state must be a participant");
    };

    assert_eq!(
        referrer.is_some(),
        outgoing.is_some(),
        "a Collect delivers an outgoing credit exactly when its participant has a referrer"
    );
    let outgoing = referrer.zip(outgoing);

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
            &State::Participant {
                node,
                referrer,
                reward_balance: reward_balance
                    .checked_add(amount)
                    .expect("reward balance fits in u128"),
            },
        ),
        write_state(
            source,
            &State::Credit {
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
            &State::Credit {
                recipient_node: parent,
                amount,
            },
        ));
    }

    diffs
}

fn assert_participant(participant: &AccountInput) {
    assert!(
        participant.is_authorized,
        "participant authorization is missing"
    );
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
        Some(State::decode(shard).expect("account holds a decodable referral state"))
    }
}

fn decode_state(account: &AccountInput, program: AccountId) -> State {
    decode_optional_state(account, program).expect("account holds initialized referral state")
}

fn write_state(account: AccountInput, state: &State) -> ShardStateDiff {
    ShardStateDiff::new(account, state.to_data())
}

mod tests;
