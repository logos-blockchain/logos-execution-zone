#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use super::*;
use crate::{
    AuthorizationSecretKey,
    account::{Account, Nonce},
    encryption::ViewingPublicKey,
};

const PROGRAM: AccountId = AccountId::new([0; 32]);
const OTHER_PROGRAM: AccountId = AccountId::new([1; 32]);
const SEED: PdaSeed = PdaSeed::new([2; 32]);
const OTHER_SEED: PdaSeed = PdaSeed::new([3; 32]);
const ALICE: AccountId = AccountId::new([10; 32]);
const BOB: AccountId = AccountId::new([11; 32]);
const CAROL: AccountId = AccountId::new([12; 32]);

struct Keys {
    ask: AuthorizationSecretKey,
    vpk: ViewingPublicKey,
}

impl Keys {
    fn new(tag: u8) -> Self {
        Self {
            ask: AuthorizationSecretKey([tag; 32]),
            vpk: ViewingPublicKey::from_seed(&[tag; 32], &[tag; 32]),
        }
    }

    fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask)
    }

    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    fn regular_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk, 0)
    }

    fn pda_id(&self, program: AccountId, seed: PdaSeed) -> AccountId {
        AccountId::for_private_pda(&program, &seed, &self.npk(), &self.vpk, 0)
    }

    fn witness(&self, kind: WitnessKind, account: Account) -> PrivateWitness {
        PrivateWitness {
            account,
            vpk: self.vpk.clone(),
            random_seed: [0; 32],
            identifier: 0,
            kind,
            nullifier: NullifierWitness::Init {
                npk: self.npk(),
                commitment_root: [8; 32],
            },
        }
    }

    fn regular(&self, ask: bool, account: Account) -> PrivateWitness {
        self.witness(
            WitnessKind::Regular {
                ask: ask.then_some(self.ask),
            },
            account,
        )
    }

    fn pda(&self, program: AccountId, seed: PdaSeed) -> PrivateWitness {
        self.witness(
            WitnessKind::Pda {
                binding: (program, seed),
            },
            Account::default(),
        )
    }
}

struct Recording {
    facts: PublicFacts,
    asked: Vec<ProgramShardSelector>,
}

impl PublicSource for Recording {
    type Error = ExecutionError;

    fn account(&mut self, account_id: AccountId) -> Result<(bool, Balance), ExecutionError> {
        self.facts.account(account_id)
    }

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<Data, ExecutionError> {
        self.asked
            .push(ProgramShardSelector::new(account_id, program_account_id));
        self.facts.shard(account_id, program_account_id)
    }
}

fn data(bytes: &[u8]) -> Data {
    bytes.to_vec().try_into().unwrap()
}

fn funded(balance: Balance) -> AccountData {
    AccountData {
        balance,
        ..AccountData::default()
    }
}

fn facts(entries: impl IntoIterator<Item = (AccountId, bool, AccountData)>) -> PublicFacts {
    entries
        .into_iter()
        .map(|(account_id, is_authorized, data)| (account_id, (is_authorized, data)))
        .collect()
}

fn root(shard_selectors: Vec<ProgramShardSelector>) -> RootCall {
    RootCall {
        program_account_id: PROGRAM,
        shard_selectors,
        instruction_data: vec![1, 2, 3],
    }
}

fn chained(
    program_account_id: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
) -> ChainedCall {
    ChainedCall::new(program_account_id, shard_selectors, &())
}

fn unchanged(count: usize) -> Vec<AccountChange> {
    vec![
        AccountChange {
            balance_diff: BalanceDiff::Add(0),
            data: None,
        };
        count
    ]
}

fn effects(account_changes: Vec<AccountChange>, chained_calls: Vec<ChainedCall>) -> CallEffects {
    CallEffects {
        account_changes,
        chained_calls,
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        events: Vec::new(),
    }
}

fn echo(call: &ProgramInput<InstructionData>, chained_calls: Vec<ChainedCall>) -> CallEffects {
    effects(unchanged(call.pre_states.len()), chained_calls)
}

fn output_of(call: &ProgramInput<InstructionData>, effects: &CallEffects) -> ProgramOutput {
    ProgramOutput {
        self_account_id: call.self_account_id,
        caller_account_id: call.caller_account_id,
        call_kind: CallKind::Execute,
        instruction_data: call.instruction.clone(),
        state_diffs: call
            .pre_states
            .iter()
            .cloned()
            .zip(&effects.account_changes)
            .map(|(pre_state, change)| AccountStateDiff {
                pre_state,
                post_balance_diff: change.balance_diff,
                post_data: change.data.clone(),
            })
            .collect(),
        chained_calls: effects.chained_calls.clone(),
        block_validity_window: effects.block_validity_window,
        timestamp_validity_window: effects.timestamp_validity_window,
        events: effects.events.clone(),
    }
}

fn start<'witnesses, S: PublicSource>(
    root: RootCall,
    witnesses: &'witnesses [PrivateWitness],
    source: &mut S,
) -> ExecutionState<'witnesses> {
    ExecutionState::initialize(root, CallKind::Execute, witnesses, source)
        .unwrap_or_else(|_| panic!("initialization must succeed"))
}

fn step<S: PublicSource>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
    respond: impl FnOnce(&ProgramInput<InstructionData>) -> CallEffects,
) -> Vec<ProgramEvent> {
    let call = state
        .prepare_next_call(source)
        .unwrap_or_else(|_| panic!("preparation must succeed"))
        .expect("a call must be pending");
    let effects = respond(call);
    state.complete_call(effects, |_| {}).unwrap()
}

fn run_to_end<S: PublicSource>(state: &mut ExecutionState<'_>, source: &mut S) -> Vec<AccountId> {
    let mut visited = Vec::new();
    loop {
        let Some(call) = state
            .prepare_next_call(source)
            .unwrap_or_else(|_| panic!("preparation must succeed"))
        else {
            return visited;
        };
        visited.push(call.self_account_id);
        let effects = echo(call, Vec::new());
        state.complete_call(effects, |_| {}).unwrap();
    }
}

#[test]
fn a_delegated_seed_grants_the_binding_that_names_its_caller() {
    let keys = Keys::new(4);
    assert_eq!(
        private_seed_grant(Some(PROGRAM), &[OTHER_SEED, SEED], &keys.pda(PROGRAM, SEED)),
        Some((PROGRAM, SEED))
    );
}

#[test]
fn a_caller_other_than_the_bound_program_grants_nothing() {
    let keys = Keys::new(4);
    assert_eq!(
        private_seed_grant(Some(OTHER_PROGRAM), &[SEED], &keys.pda(PROGRAM, SEED)),
        None
    );
}

#[test]
fn an_undelegated_seed_grants_nothing() {
    let keys = Keys::new(4);
    assert_eq!(
        private_seed_grant(Some(PROGRAM), &[OTHER_SEED], &keys.pda(PROGRAM, SEED)),
        None
    );
}

#[test]
fn a_regular_witness_has_no_binding_to_grant() {
    let keys = Keys::new(4);
    assert_eq!(
        private_seed_grant(
            Some(PROGRAM),
            &[SEED],
            &keys.regular(false, Account::default())
        ),
        None
    );
}

#[test]
fn root_inputs_come_from_the_facts_in_selector_order() {
    let mut facts = facts([
        (ALICE, true, funded(5)),
        (BOB, false, funded(7).with_shard(PROGRAM, data(b"bob"))),
    ]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::new(BOB, PROGRAM),
            ProgramShardSelector::balance_only(ALICE),
        ]),
        &[],
        &mut facts,
    );

    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();

    assert_eq!(call.self_account_id, PROGRAM);
    assert_eq!(call.caller_account_id, None);
    assert_eq!(call.instruction, vec![1, 2, 3]);
    assert_eq!(
        call.pre_states,
        vec![
            AccountInput::with_shard(BOB, false, 7, PROGRAM, data(b"bob")),
            AccountInput::balance_only(ALICE, true, 5),
        ]
    );
}

#[test]
fn a_missing_fact_for_a_root_account_is_rejected() {
    let mut facts = facts([]);

    let result = ExecutionState::initialize(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        CallKind::Execute,
        &[],
        &mut facts,
    );

    assert!(matches!(
        result.err(),
        Some(ExecutionError::MissingPublicFact { shard_selector })
            if shard_selector == ProgramShardSelector::balance_only(ALICE)
    ));
}

#[test]
fn a_selected_shard_without_an_explicit_fact_is_rejected_while_an_empty_one_is_read() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let mut state = start(
        root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]),
        &[],
        &mut facts,
    );
    assert!(matches!(
        state.prepare_next_call(&mut facts).err(),
        Some(ExecutionError::MissingPublicFact { shard_selector })
            if shard_selector == ProgramShardSelector::new(ALICE, PROGRAM)
    ));

    let mut explicit = facts.clone();
    explicit
        .get_mut(&ALICE)
        .unwrap()
        .1
        .shards
        .insert(PROGRAM, Data::empty());
    let mut state = start(
        root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]),
        &[],
        &mut explicit,
    );
    let call = state.prepare_next_call(&mut explicit).unwrap().unwrap();
    assert_eq!(
        call.pre_states,
        vec![AccountInput::with_shard(
            ALICE,
            false,
            1,
            PROGRAM,
            Data::empty()
        )]
    );
}

#[test]
fn fewer_effect_rows_than_inputs_are_rejected() {
    let mut facts = facts([(ALICE, false, funded(1)), (BOB, false, funded(1))]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance_only(ALICE),
            ProgramShardSelector::balance_only(BOB),
        ]),
        &[],
        &mut facts,
    );
    state.prepare_next_call(&mut facts).unwrap().unwrap();

    let result = state.complete_call(effects(unchanged(1), Vec::new()), |_| {});

    assert!(matches!(
        result,
        Err(ExecutionError::RowCountMismatch {
            program_account_id: PROGRAM,
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn a_journal_must_repeat_the_prepared_inputs_exactly() {
    let mut facts = facts([
        (ALICE, false, funded(1).with_shard(PROGRAM, data(b"a"))),
        (BOB, false, funded(2)),
    ]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance_only(BOB),
        ]),
        &[],
        &mut facts,
    );
    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();
    let effects = echo(call, Vec::new());
    let reference = output_of(call, &effects);

    let mut dropped = reference.clone();
    dropped.state_diffs.pop();
    assert!(matches!(
        state.bind_output(dropped, InstructionEcho::Checked),
        Err(ExecutionError::RowCountMismatch {
            expected: 2,
            actual: 1,
            ..
        })
    ));

    let mut reordered = reference.clone();
    reordered.state_diffs.reverse();
    assert!(matches!(
        state.bind_output(reordered, InstructionEcho::Checked),
        Err(ExecutionError::PreStateMismatch { expected, .. }) if expected.account_id == ALICE
    ));

    let mut other_shard = reference.clone();
    other_shard.state_diffs[0].pre_state.shard = Some((OTHER_PROGRAM, data(b"a")));
    assert!(matches!(
        state.bind_output(other_shard, InstructionEcho::Checked),
        Err(ExecutionError::PreStateMismatch { .. })
    ));

    let mut balance_only = reference.clone();
    balance_only.state_diffs[0].pre_state.shard = None;
    assert!(matches!(
        state.bind_output(balance_only, InstructionEcho::Checked),
        Err(ExecutionError::PreStateMismatch { .. })
    ));

    let mut stale = reference.clone();
    stale.state_diffs[1].pre_state.balance = 3;
    assert!(matches!(
        state.bind_output(stale, InstructionEcho::Checked),
        Err(ExecutionError::PreStateMismatch { .. })
    ));

    let mut claimed = reference.clone();
    claimed.state_diffs[1].pre_state.is_authorized = true;
    assert!(matches!(
        state.bind_output(claimed, InstructionEcho::Checked),
        Err(ExecutionError::PreStateMismatch { .. })
    ));

    let mut wrong_self = reference.clone();
    wrong_self.self_account_id = OTHER_PROGRAM;
    assert!(matches!(
        state.bind_output(wrong_self, InstructionEcho::Checked),
        Err(ExecutionError::MismatchedProgramId { .. })
    ));

    let mut wrong_caller = reference.clone();
    wrong_caller.caller_account_id = Some(OTHER_PROGRAM);
    assert!(matches!(
        state.bind_output(wrong_caller, InstructionEcho::Checked),
        Err(ExecutionError::MismatchedCallerProgramId { .. })
    ));

    let mut wrong_instruction = reference;
    wrong_instruction.instruction_data = vec![9];
    assert!(matches!(
        state.bind_output(wrong_instruction.clone(), InstructionEcho::Checked),
        Err(ExecutionError::MismatchedInstruction { .. })
    ));
    assert_eq!(
        state
            .bind_output(wrong_instruction, InstructionEcho::Unchecked)
            .unwrap(),
        effects
    );
}

#[test]
fn a_chained_call_must_execute_while_the_root_may_not() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let mut state = start(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        &[],
        &mut facts,
    );
    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();
    let effects = echo(
        call,
        vec![chained(
            OTHER_PROGRAM,
            vec![ProgramShardSelector::balance_only(ALICE)],
        )],
    );
    let mut unknown = output_of(call, &effects);
    unknown.call_kind = CallKind::Unknown(7);
    let bound = state
        .bind_output(unknown, InstructionEcho::Checked)
        .unwrap();
    assert_eq!(state.root_call_kind(), CallKind::Unknown(7));
    state.complete_call(bound, |_| {}).unwrap();

    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();
    let mut unknown = output_of(call, &echo(call, Vec::new()));
    unknown.call_kind = CallKind::Unknown(7);
    assert!(matches!(
        state.bind_output(unknown, InstructionEcho::Checked),
        Err(ExecutionError::ChainedCallDidNotExecute {
            program_account_id: OTHER_PROGRAM
        })
    ));
}

#[test]
fn the_reconstructed_journal_preserves_every_distinct_encoding() {
    let mut facts = facts([(ALICE, true, funded(1).with_shard(PROGRAM, data(b"a")))]);
    let mut state = ExecutionState::initialize(
        root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]),
        CallKind::Unknown(7),
        &[],
        &mut facts,
    )
    .unwrap();
    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();
    let inputs = call.pre_states.clone();
    let events = vec![
        ProgramEvent {
            selector: [1; 8],
            data: vec![1],
        },
        ProgramEvent {
            selector: [0; 8],
            data: vec![],
        },
    ];
    let calls = vec![
        chained(
            OTHER_PROGRAM,
            vec![ProgramShardSelector::balance_only(ALICE)],
        ),
        chained(PROGRAM, vec![ProgramShardSelector::balance_only(ALICE)]),
    ];
    let effects = CallEffects {
        account_changes: vec![AccountChange {
            balance_diff: BalanceDiff::Sub(0),
            data: Some(Data::empty()),
        }],
        chained_calls: calls.clone(),
        block_validity_window: (1..).into(),
        timestamp_validity_window: (..9).into(),
        events: events.clone(),
    };

    let mut seen = None;
    let returned = state
        .complete_call(effects, |output| seen = Some(output.clone()))
        .unwrap();

    let output = seen.unwrap();
    assert_eq!(output.self_account_id, PROGRAM);
    assert_eq!(output.caller_account_id, None);
    assert_eq!(output.call_kind, CallKind::Unknown(7));
    assert_eq!(output.instruction_data, vec![1, 2, 3]);
    assert_eq!(output.state_diffs.len(), 1);
    assert_eq!(output.state_diffs[0].pre_state, inputs[0]);
    assert_eq!(output.state_diffs[0].post_balance_diff, BalanceDiff::Sub(0));
    assert_eq!(output.state_diffs[0].post_data, Some(Data::empty()));
    assert_eq!(output.chained_calls, calls);
    assert_eq!(output.block_validity_window, (1..).into());
    assert_eq!(output.timestamp_validity_window, (..9).into());
    assert_eq!(output.events, events);
    assert_eq!(returned, events);

    let call = state.prepare_next_call(&mut facts).unwrap().unwrap();
    let mut child_kind = None;
    let effects = echo(call, Vec::new());
    state
        .complete_call(effects, |output| child_kind = Some(output.call_kind))
        .unwrap();
    assert_eq!(child_kind, Some(CallKind::Execute));
}

#[test]
fn a_chained_call_may_select_another_shard_of_a_root_account() {
    let mut source = Recording {
        facts: facts([
            (
                ALICE,
                true,
                funded(10)
                    .with_shard(PROGRAM, data(b"p"))
                    .with_shard(OTHER_PROGRAM, data(b"s")),
            ),
            (BOB, false, funded(0)),
        ]),
        asked: Vec::new(),
    };
    let mut state = start(
        root(vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance_only(BOB),
        ]),
        &[],
        &mut source,
    );

    step(&mut state, &mut source, |call| {
        assert_eq!(
            call.pre_states,
            vec![
                AccountInput::with_shard(ALICE, true, 10, PROGRAM, data(b"p")),
                AccountInput::balance_only(BOB, false, 0),
            ]
        );
        effects(
            vec![
                AccountChange {
                    balance_diff: BalanceDiff::Sub(4),
                    data: None,
                },
                AccountChange {
                    balance_diff: BalanceDiff::Add(4),
                    data: None,
                },
            ],
            vec![
                chained(
                    OTHER_PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
                ),
                chained(
                    OTHER_PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
                ),
            ],
        )
    });
    for written in [b"s2", b"s3"] {
        step(&mut state, &mut source, |call| {
            assert_eq!(call.pre_states.len(), 1);
            assert_eq!(call.pre_states[0].balance, 6);
            assert_eq!(call.pre_states[0].program_account_id(), Some(OTHER_PROGRAM));
            effects(
                vec![AccountChange {
                    balance_diff: BalanceDiff::Add(0),
                    data: Some(data(written)),
                }],
                Vec::new(),
            )
        });
    }

    assert_eq!(
        source.asked,
        vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::new(ALICE, OTHER_PROGRAM)
        ]
    );
    let FinalState { public_actions, .. } = state.finish().unwrap();
    assert_eq!(
        public_actions[0],
        PublicAction {
            account_id: ALICE,
            is_authorized: true,
            pre: funded(10)
                .with_shard(PROGRAM, data(b"p"))
                .with_shard(OTHER_PROGRAM, data(b"s")),
            post: funded(6)
                .with_shard(PROGRAM, data(b"p"))
                .with_shard(OTHER_PROGRAM, data(b"s3")),
        }
    );
    assert_eq!(public_actions[1].post, funded(4));
}

#[test]
fn a_balance_only_root_then_a_shard_read_after_a_balance_change_keeps_the_write() {
    let mut facts = facts([
        (
            ALICE,
            true,
            funded(10).with_shard(OTHER_PROGRAM, data(b"s")),
        ),
        (BOB, false, funded(0)),
    ]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance_only(ALICE),
            ProgramShardSelector::balance_only(BOB),
        ]),
        &[],
        &mut facts,
    );

    step(&mut state, &mut facts, |call| {
        assert_eq!(
            call.pre_states,
            vec![
                AccountInput::balance_only(ALICE, true, 10),
                AccountInput::balance_only(BOB, false, 0),
            ]
        );
        effects(
            vec![
                AccountChange {
                    balance_diff: BalanceDiff::Sub(3),
                    data: None,
                },
                AccountChange {
                    balance_diff: BalanceDiff::Add(3),
                    data: None,
                },
            ],
            vec![chained(
                OTHER_PROGRAM,
                vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
            )],
        )
    });
    step(&mut state, &mut facts, |call| {
        assert_eq!(
            call.pre_states,
            vec![AccountInput::with_shard(
                ALICE,
                true,
                7,
                OTHER_PROGRAM,
                data(b"s")
            )]
        );
        echo(call, Vec::new())
    });

    let FinalState { public_actions, .. } = state.finish().unwrap();
    assert_eq!(
        public_actions[0].pre,
        funded(10).with_shard(OTHER_PROGRAM, data(b"s"))
    );
    assert_eq!(
        public_actions[0].post,
        funded(7).with_shard(OTHER_PROGRAM, data(b"s"))
    );
}

#[test]
fn a_cleared_shard_reads_back_empty_and_stays_in_both_projections() {
    let mut facts = facts([(ALICE, false, funded(1).with_shard(PROGRAM, data(b"a")))]);
    let mut state = start(
        root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]),
        &[],
        &mut facts,
    );

    step(&mut state, &mut facts, |_| {
        effects(
            vec![AccountChange {
                balance_diff: BalanceDiff::Add(0),
                data: Some(Data::empty()),
            }],
            vec![chained(
                PROGRAM,
                vec![ProgramShardSelector::new(ALICE, PROGRAM)],
            )],
        )
    });
    step(&mut state, &mut facts, |call| {
        assert_eq!(
            call.pre_states,
            vec![AccountInput::with_shard(
                ALICE,
                false,
                1,
                PROGRAM,
                Data::empty()
            )]
        );
        echo(call, Vec::new())
    });

    let FinalState { public_actions, .. } = state.finish().unwrap();
    assert_eq!(public_actions[0].pre.shards[&PROGRAM], data(b"a"));
    assert_eq!(public_actions[0].post.shards[&PROGRAM], Data::empty());
}

#[test]
fn a_chained_call_cannot_name_an_account_the_root_did_not() {
    let mut facts = facts([(ALICE, false, funded(1)), (BOB, false, funded(1))]);
    let mut state = start(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        &[],
        &mut facts,
    );
    step(&mut state, &mut facts, |call| {
        echo(
            call,
            vec![chained(
                PROGRAM,
                vec![ProgramShardSelector::balance_only(BOB)],
            )],
        )
    });

    assert!(matches!(
        state.prepare_next_call(&mut facts),
        Err(ExecutionError::UnknownAccount { account_id: BOB })
    ));
}

#[test]
fn a_witness_outside_the_root_inputs_is_rejected() {
    let keys = Keys::new(4);
    let witnesses = [keys.regular(true, Account::default())];
    let mut facts = facts([(ALICE, false, funded(1))]);

    let result = ExecutionState::initialize(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        CallKind::Execute,
        &witnesses,
        &mut facts,
    );

    assert!(matches!(
        result.err(),
        Some(ExecutionError::WitnessNotInRoot { account_id }) if account_id == keys.regular_id()
    ));
}

#[test]
fn duplicate_witnesses_and_unlinked_authorization_keys_are_rejected() {
    let keys = Keys::new(4);
    let other = Keys::new(5);
    let mut facts = facts([]);
    let selectors = vec![ProgramShardSelector::balance_only(keys.regular_id())];

    let duplicate = [
        keys.regular(true, Account::default()),
        keys.regular(true, Account::default()),
    ];
    assert!(matches!(
        ExecutionState::initialize(root(selectors.clone()), CallKind::Execute, &duplicate, &mut facts).err(),
        Some(ExecutionError::DuplicateWitness { account_id }) if account_id == keys.regular_id()
    ));

    let mut unlinked = keys.regular(true, Account::default());
    unlinked.kind = WitnessKind::Regular {
        ask: Some(other.ask),
    };
    let unlinked = [unlinked];
    assert!(matches!(
        ExecutionState::initialize(root(selectors), CallKind::Execute, &unlinked, &mut facts).err(),
        Some(ExecutionError::InvalidAuthorizationKey { account_id }) if account_id == keys.regular_id()
    ));
}

#[test]
fn two_private_pdas_under_one_seed_conflict() {
    let keys = Keys::new(4);
    let other = Keys::new(5);
    let witnesses = [keys.pda(PROGRAM, SEED), other.pda(PROGRAM, SEED)];
    let mut facts = facts([]);

    let result = ExecutionState::initialize(
        root(vec![
            ProgramShardSelector::balance_only(keys.pda_id(PROGRAM, SEED)),
            ProgramShardSelector::balance_only(other.pda_id(PROGRAM, SEED)),
        ]),
        CallKind::Execute,
        &witnesses,
        &mut facts,
    );

    assert!(matches!(
        result.err(),
        Some(ExecutionError::FamilyBindingConflict { existing, account_id })
            if existing == keys.pda_id(PROGRAM, SEED) && account_id == other.pda_id(PROGRAM, SEED)
    ));
}

#[test]
fn credentials_are_fixed_and_seed_grants_stay_in_their_subtree() {
    let signer = Keys::new(4);
    let holder = Keys::new(5);
    let public_pda = AccountId::for_public_pda(&PROGRAM, &SEED);
    let witnesses = [
        signer.regular(true, Account::default()),
        holder.regular(false, Account::default()),
    ];
    let mut facts = facts([(public_pda, false, funded(1))]);
    let selectors = vec![
        ProgramShardSelector::balance_only(signer.regular_id()),
        ProgramShardSelector::balance_only(holder.regular_id()),
        ProgramShardSelector::balance_only(public_pda),
    ];
    let authorization = |call: &ProgramInput<InstructionData>| -> Vec<bool> {
        call.pre_states
            .iter()
            .map(|input| input.is_authorized)
            .collect()
    };
    let mut state = start(root(selectors.clone()), &witnesses, &mut facts);

    step(&mut state, &mut facts, |call| {
        assert_eq!(authorization(call), vec![true, false, false]);
        echo(
            call,
            vec![
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
                chained(OTHER_PROGRAM, selectors.clone()),
            ],
        )
    });
    step(&mut state, &mut facts, |call| {
        assert_eq!(authorization(call), vec![true, false, true]);
        echo(call, vec![chained(PROGRAM, selectors.clone())])
    });
    step(&mut state, &mut facts, |call| {
        assert_eq!(authorization(call), vec![true, false, true]);
        echo(call, Vec::new())
    });
    step(&mut state, &mut facts, |call| {
        assert_eq!(authorization(call), vec![true, false, false]);
        echo(call, Vec::new())
    });

    let FinalState { public_actions, .. } = state.finish().unwrap();
    assert!(!public_actions[0].is_authorized);
}

#[test]
fn a_private_pda_is_granted_only_by_its_own_seed_from_its_own_program() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let pda = keys.pda_id(PROGRAM, SEED);
    let mut facts = facts([]);
    let selectors = vec![ProgramShardSelector::balance_only(pda)];
    let mut state = start(root(selectors.clone()), &witnesses, &mut facts);

    step(&mut state, &mut facts, |call| {
        assert!(!call.pre_states[0].is_authorized);
        echo(
            call,
            vec![
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![OTHER_SEED]),
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
                chained(OTHER_PROGRAM, selectors.clone()),
            ],
        )
    });
    step(&mut state, &mut facts, |call| {
        assert!(!call.pre_states[0].is_authorized);
        echo(
            call,
            vec![chained(PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED])],
        )
    });
    step(&mut state, &mut facts, |call| {
        assert!(!call.pre_states[0].is_authorized);
        echo(call, Vec::new())
    });
    step(&mut state, &mut facts, |call| {
        assert!(call.pre_states[0].is_authorized);
        echo(call, Vec::new())
    });
    step(&mut state, &mut facts, |call| {
        assert!(!call.pre_states[0].is_authorized);
        echo(call, Vec::new())
    });

    let FinalState {
        public_actions,
        private_accounts,
        ..
    } = state.finish().unwrap();
    assert!(public_actions.is_empty());
    assert_eq!(private_accounts.len(), 1);
}

#[test]
fn a_public_pda_grant_under_a_privately_bound_seed_conflicts() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let public_pda = AccountId::for_public_pda(&PROGRAM, &SEED);
    let mut facts = facts([(public_pda, false, funded(1))]);
    let selectors = vec![
        ProgramShardSelector::balance_only(keys.pda_id(PROGRAM, SEED)),
        ProgramShardSelector::balance_only(public_pda),
    ];
    let mut state = start(root(selectors.clone()), &witnesses, &mut facts);
    step(&mut state, &mut facts, |call| {
        echo(
            call,
            vec![chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED])],
        )
    });

    assert!(matches!(
        state.prepare_next_call(&mut facts),
        Err(ExecutionError::FamilyBindingConflict { account_id, .. }) if account_id == public_pda
    ));
}

#[test]
fn calls_run_depth_first_in_sibling_order_up_to_the_limit() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance_only(ALICE)];
    let mut state = start(root(selectors.clone()), &[], &mut facts);
    step(&mut state, &mut facts, |call| {
        echo(
            call,
            vec![
                chained(AccountId::new([1; 32]), selectors.clone()),
                chained(AccountId::new([3; 32]), selectors.clone()),
            ],
        )
    });
    step(&mut state, &mut facts, |call| {
        echo(
            call,
            vec![chained(AccountId::new([2; 32]), selectors.clone())],
        )
    });
    assert_eq!(
        run_to_end(&mut state, &mut facts),
        vec![AccountId::new([2; 32]), AccountId::new([3; 32])]
    );
    assert!(state.prepare_next_call(&mut facts).unwrap().is_none());
    state.finish().unwrap();

    let chain = |count: usize| {
        let mut facts = facts.clone();
        let mut state = start(root(selectors.clone()), &[], &mut facts);
        step(&mut state, &mut facts, |call| {
            echo(call, vec![chained(OTHER_PROGRAM, selectors.clone()); count])
        });
        loop {
            match state.prepare_next_call(&mut facts) {
                Ok(Some(call)) => {
                    let effects = echo(call, Vec::new());
                    state.complete_call(effects, |_| {}).unwrap();
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    };
    assert!(chain(MAX_NUMBER_CHAINED_CALLS).is_ok());
    assert!(matches!(
        chain(MAX_NUMBER_CHAINED_CALLS + 1),
        Err(ExecutionError::MaxChainedCallsExceeded)
    ));
}

#[test]
fn finishing_with_a_scheduled_call_is_rejected() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance_only(ALICE)];
    let mut state = start(root(selectors.clone()), &[], &mut facts);
    step(&mut state, &mut facts, |call| {
        echo(call, vec![chained(OTHER_PROGRAM, selectors.clone())])
    });

    assert!(matches!(
        state.finish(),
        Err(ExecutionError::IncompleteExecution)
    ));
}

#[test]
fn validation_and_window_failures_name_the_program() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance_only(ALICE)];
    let mut state = start(root(selectors.clone()), &[], &mut facts);
    state.prepare_next_call(&mut facts).unwrap().unwrap();
    assert!(matches!(
        state.complete_call(
            effects(
                vec![AccountChange {
                    balance_diff: BalanceDiff::Sub(1),
                    data: None
                }],
                Vec::new()
            ),
            |_| {}
        ),
        Err(ExecutionError::ExecutionValidation {
            program_account_id: PROGRAM,
            source: ExecutionValidationError::UnauthorizedBalanceDecrease { account_id: ALICE }
        })
    ));

    let mut state = start(root(selectors.clone()), &[], &mut facts);
    step(&mut state, &mut facts, |call| CallEffects {
        block_validity_window: (1..3).try_into().unwrap(),
        ..echo(call, vec![chained(OTHER_PROGRAM, selectors.clone())])
    });
    state.prepare_next_call(&mut facts).unwrap().unwrap();
    assert!(matches!(
        state.complete_call(
            CallEffects {
                block_validity_window: (3..).into(),
                ..effects(unchanged(1), Vec::new())
            },
            |_| {}
        ),
        Err(ExecutionError::EmptyBlockWindowIntersection)
    ));
}

#[test]
fn the_final_windows_are_the_intersection_of_every_call() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance_only(ALICE)];
    let mut state = start(root(selectors.clone()), &[], &mut facts);
    step(&mut state, &mut facts, |call| CallEffects {
        block_validity_window: (1..5).try_into().unwrap(),
        timestamp_validity_window: (..9).into(),
        ..echo(call, vec![chained(OTHER_PROGRAM, selectors.clone())])
    });
    step(&mut state, &mut facts, |call| CallEffects {
        block_validity_window: (2..).into(),
        timestamp_validity_window: (4..7).try_into().unwrap(),
        ..echo(call, Vec::new())
    });

    let FinalState {
        block_validity_window,
        timestamp_validity_window,
        ..
    } = state.finish().unwrap();
    assert_eq!(block_validity_window, (2..5).try_into().unwrap());
    assert_eq!(timestamp_validity_window, (4..7).try_into().unwrap());
}

#[test]
fn a_duplicated_root_account_is_rejected_by_the_transition_rules() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance_only(ALICE),
            ProgramShardSelector::balance_only(ALICE),
        ]),
        &[],
        &mut facts,
    );
    state.prepare_next_call(&mut facts).unwrap().unwrap();

    assert!(matches!(
        state.complete_call(effects(unchanged(2), Vec::new()), |_| {}),
        Err(ExecutionError::ExecutionValidation {
            source: ExecutionValidationError::PreStateAccountIdsNotUnique,
            ..
        })
    ));
}

#[test]
fn public_actions_follow_root_order_and_private_accounts_keep_untouched_shards() {
    let keys = Keys::new(4);
    let private_account = Account {
        nonce: Nonce(3),
        ..Account::default()
    }
    .with_shard(OTHER_PROGRAM, data(b"kept"));
    let witnesses = [keys.regular(true, private_account)];
    let mut facts = facts([
        (
            ALICE,
            false,
            funded(1).with_shard(CAROL, data(b"untouched")),
        ),
        (BOB, true, funded(2)),
    ]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance_only(BOB),
            ProgramShardSelector::new(keys.regular_id(), PROGRAM),
            ProgramShardSelector::balance_only(ALICE),
        ]),
        &witnesses,
        &mut facts,
    );
    step(&mut state, &mut facts, |_| {
        effects(
            vec![
                AccountChange {
                    balance_diff: BalanceDiff::Add(0),
                    data: None,
                },
                AccountChange {
                    balance_diff: BalanceDiff::Add(0),
                    data: Some(data(b"written")),
                },
                AccountChange {
                    balance_diff: BalanceDiff::Add(0),
                    data: None,
                },
            ],
            Vec::new(),
        )
    });

    let FinalState {
        public_actions,
        private_accounts,
        ..
    } = state.finish().unwrap();
    assert_eq!(
        public_actions
            .iter()
            .map(|action| action.account_id)
            .collect::<Vec<_>>(),
        vec![BOB, ALICE]
    );
    assert!(public_actions[1].pre.shards.is_empty());
    assert!(public_actions[1].post.shards.is_empty());
    assert_eq!(
        private_accounts[&keys.regular_id()],
        AccountData::default()
            .with_shard(OTHER_PROGRAM, data(b"kept"))
            .with_shard(PROGRAM, data(b"written"))
    );
}

#[test]
fn a_failed_preparation_aborts_the_execution() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let mut state = start(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        &[],
        &mut facts,
    );
    step(&mut state, &mut facts, |call| {
        echo(
            call,
            vec![chained(
                PROGRAM,
                vec![ProgramShardSelector::balance_only(BOB)],
            )],
        )
    });
    assert!(matches!(
        state.prepare_next_call(&mut facts),
        Err(ExecutionError::UnknownAccount { account_id: BOB })
    ));

    assert!(matches!(
        state.prepare_next_call(&mut facts),
        Err(ExecutionError::Aborted)
    ));
    assert!(matches!(state.finish(), Err(ExecutionError::Aborted)));
}

#[test]
fn a_failed_completion_aborts_the_execution() {
    let mut facts = facts([(ALICE, false, funded(1))]);
    let mut state = start(
        root(vec![ProgramShardSelector::balance_only(ALICE)]),
        &[],
        &mut facts,
    );
    state.prepare_next_call(&mut facts).unwrap().unwrap();
    assert!(matches!(
        state.complete_call(effects(Vec::new(), Vec::new()), |_| {}),
        Err(ExecutionError::RowCountMismatch { .. })
    ));

    assert!(matches!(
        state.prepare_next_call(&mut facts),
        Err(ExecutionError::Aborted)
    ));
    assert!(matches!(state.finish(), Err(ExecutionError::Aborted)));
}
