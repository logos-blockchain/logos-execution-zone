#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use std::collections::BTreeMap;

use super::*;
use crate::{
    AuthorizationSecretKey,
    account::{Account, Balance, Nonce},
    encryption::ViewingPublicKey,
    native_token::{NATIVE_TOKEN_PROGRAM_ID, encode_balance},
};

const PROGRAM: AccountId = AccountId::new([4; 32]);
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

impl Recording {
    fn new(entries: impl IntoIterator<Item = (AccountId, AccountData)>) -> Self {
        Self {
            facts: facts(entries),
            asked: Vec::new(),
        }
    }
}

/// Facts fixed up front, so a shard a test never exposed fails instead of reading back empty.
type PublicFacts = BTreeMap<AccountId, AccountData>;

impl PublicSource for PublicFacts {
    type Error = ExecutionError;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, ExecutionError> {
        self.get(&account_id)
            .and_then(|data| data.shards.get(&program_account_id))
            .cloned()
            .ok_or_else(|| ExecutionError::MissingPublicFact {
                shard_selector: ProgramShardSelector::new(account_id, program_account_id),
            })
    }
}

impl PublicSource for Recording {
    type Error = ExecutionError;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, ExecutionError> {
        self.asked
            .push(ProgramShardSelector::new(account_id, program_account_id));
        self.facts.shard(account_id, program_account_id)
    }
}

fn data(bytes: &[u8]) -> ShardData {
    bytes.to_vec().try_into().unwrap()
}

fn funded(balance: Balance) -> AccountData {
    AccountData {
        shards: [(NATIVE_TOKEN_PROGRAM_ID, encode_balance(balance))].into(),
    }
}

fn facts(entries: impl IntoIterator<Item = (AccountId, AccountData)>) -> PublicFacts {
    entries.into_iter().collect()
}

fn root(shard_selectors: Vec<ProgramShardSelector>) -> RootCall {
    signed_root(shard_selectors, Vec::new())
}

fn signed_root(
    shard_selectors: Vec<ProgramShardSelector>,
    authorized_accounts: Vec<AccountId>,
) -> RootCall {
    RootCall {
        program_account_id: PROGRAM,
        shard_selectors,
        instruction_data: vec![1, 2, 3],
        authorized_accounts,
    }
}

fn chained(
    program_account_id: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
) -> ChainedCall {
    ChainedCall::new(program_account_id, shard_selectors, &())
}

fn effect(account: &AccountMeta, bytes: &[u8]) -> ShardEffect {
    ShardEffect {
        selector: account.into(),
        data: bytes.to_vec(),
    }
}

fn plan(call: &ProgramInput<InstructionData>) -> ProgramOutput {
    ProgramOutput::new(
        call.self_account_id,
        call.caller_account_id,
        call.instruction.clone(),
        call.accounts.clone(),
    )
}

fn start(root: RootCall, witnesses: &[PrivateWitness]) -> ExecutionState<'_> {
    ExecutionState::initialize(root, witnesses, PublicEffects::Resolve)
        .unwrap_or_else(|_| panic!("initialization must succeed"))
}

fn start_deferring(root: RootCall, witnesses: &[PrivateWitness]) -> ExecutionState<'_> {
    ExecutionState::initialize(root, witnesses, PublicEffects::Defer)
        .unwrap_or_else(|_| panic!("initialization must succeed"))
}

fn resolved(public: PublicOutcome) -> Vec<(AccountId, AccountData)> {
    match public {
        PublicOutcome::Resolved(accounts) => accounts,
        PublicOutcome::Deferred(_) => panic!("the resolving mode must produce resolved accounts"),
    }
}

fn journal(public: PublicOutcome) -> Vec<PublicAction> {
    match public {
        PublicOutcome::Deferred(rows) => rows,
        PublicOutcome::Resolved(_) => panic!("the deferring mode must produce journal rows"),
    }
}

fn obligation<S: PublicSource<Error = ExecutionError>>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
) -> ResolveInput {
    state
        .next_obligation(source)
        .unwrap()
        .expect("an obligation must be pending")
        .clone()
}

fn drain<S: PublicSource<Error = ExecutionError>>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
    resolve: &mut impl FnMut(&ResolveInput) -> Option<ShardData>,
) -> Vec<ResolveInput> {
    let mut local = Vec::new();
    loop {
        let Some(input) = state.next_obligation(source).unwrap().cloned() else {
            return local;
        };
        let output = ResolveOutput {
            post_data: resolve(&input),
            input,
        };
        state.accept_resolution(&output).unwrap();
        local.push(output.input);
    }
}

fn step_resolving<S: PublicSource<Error = ExecutionError>>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
    respond: impl FnOnce(&ProgramInput<InstructionData>) -> ProgramOutput,
    resolve: &mut impl FnMut(&ResolveInput) -> Option<ShardData>,
) -> Vec<ProgramEvent> {
    let call = state
        .prepare_next_call()
        .unwrap_or_else(|_| panic!("preparation must succeed"))
        .expect("a call must be pending");
    let output = respond(call);
    state.bind_plan(output).unwrap();
    drain(state, source, resolve);
    state.complete_call().unwrap()
}

fn step<S: PublicSource<Error = ExecutionError>>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
    respond: impl FnOnce(&ProgramInput<InstructionData>) -> ProgramOutput,
) -> Vec<ProgramEvent> {
    step_resolving(state, source, respond, &mut |_| None)
}

fn run_to_end<S: PublicSource<Error = ExecutionError>>(
    state: &mut ExecutionState<'_>,
    source: &mut S,
) -> Vec<AccountId> {
    let mut visited = Vec::new();
    loop {
        let Some(call) = state
            .prepare_next_call()
            .unwrap_or_else(|_| panic!("preparation must succeed"))
        else {
            return visited;
        };
        visited.push(call.self_account_id);
        let output = plan(call);
        state.bind_plan(output).unwrap();
        drain(state, source, &mut |_| None);
        state.complete_call().unwrap();
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
fn root_handles_follow_the_selector_order() {
    let mut state = start(
        signed_root(
            vec![
                ProgramShardSelector::new(BOB, PROGRAM),
                ProgramShardSelector::balance(ALICE),
            ],
            vec![ALICE],
        ),
        &[],
    );

    let call = state.prepare_next_call().unwrap().unwrap();

    assert_eq!(call.self_account_id, PROGRAM);
    assert_eq!(call.caller_account_id, None);
    assert_eq!(call.instruction, vec![1, 2, 3]);
    assert_eq!(
        call.accounts,
        vec![
            AccountMeta::new(BOB, false, PROGRAM),
            AccountMeta::balance(ALICE, true),
        ]
    );
}

#[test]
fn a_selected_shard_without_an_explicit_fact_is_rejected_while_an_empty_one_is_read() {
    let selectors = vec![ProgramShardSelector::new(ALICE, PROGRAM)];
    let mut missing = facts([(ALICE, funded(1))]);
    let mut state = start(root(selectors.clone()), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
    state.bind_plan(output).unwrap();
    assert!(matches!(
        state.next_obligation(&mut missing).err(),
        Some(ExecutionError::MissingPublicFact { shard_selector })
            if shard_selector == ProgramShardSelector::new(ALICE, PROGRAM)
    ));

    let mut explicit = facts([(ALICE, funded(1))]);
    explicit
        .get_mut(&ALICE)
        .unwrap()
        .shards
        .insert(PROGRAM, ShardData::empty());
    let mut state = start(root(selectors), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
    state.bind_plan(output).unwrap();

    assert_eq!(
        obligation(&mut state, &mut explicit).pre_data,
        ShardData::empty()
    );
}

#[test]
fn a_journal_must_repeat_the_prepared_inputs_exactly() {
    let selectors = vec![
        ProgramShardSelector::new(ALICE, PROGRAM),
        ProgramShardSelector::balance(BOB),
    ];
    let bind = |mutate: &dyn Fn(&mut ProgramOutput)| {
        let mut state = start(signed_root(selectors.clone(), vec![ALICE]), &[]);
        let call = state.prepare_next_call().unwrap().unwrap();
        let mut output = plan(call);
        mutate(&mut output);
        state.bind_plan(output)
    };

    assert!(matches!(
        bind(&|output| {
            output.accounts.pop();
        }),
        Err(ExecutionError::RowCountMismatch {
            program_account_id: PROGRAM,
            expected: 2,
            actual: 1
        })
    ));
    assert!(matches!(
        bind(&|output| output.accounts.reverse()),
        Err(ExecutionError::InputEchoMismatch { expected, .. }) if expected.account_id == ALICE
    ));
    assert!(matches!(
        bind(&|output| output.accounts[0].program_account_id = OTHER_PROGRAM),
        Err(ExecutionError::InputEchoMismatch { .. })
    ));
    assert!(matches!(
        bind(&|output| output.accounts[1].is_authorized = true),
        Err(ExecutionError::InputEchoMismatch { .. })
    ));
    assert!(matches!(
        bind(&|output| output.self_account_id = OTHER_PROGRAM),
        Err(ExecutionError::MismatchedProgramId { .. })
    ));
    assert!(matches!(
        bind(&|output| output.caller_account_id = Some(OTHER_PROGRAM)),
        Err(ExecutionError::MismatchedCallerProgramId { .. })
    ));
    assert!(matches!(
        bind(&|output| output.instruction_data = vec![9]),
        Err(ExecutionError::MismatchedInstruction { .. })
    ));
    assert!(bind(&|_| {}).is_ok());
}

#[test]
fn a_handle_that_produces_no_effect_is_still_bound() {
    let mut state = start(
        signed_root(
            vec![
                ProgramShardSelector::balance(ALICE),
                ProgramShardSelector::balance(BOB),
            ],
            vec![BOB],
        ),
        &[],
    );
    let call = state.prepare_next_call().unwrap().unwrap();
    let mut output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
    output.accounts[1].is_authorized = false;

    assert!(matches!(
        state.bind_plan(output),
        Err(ExecutionError::InputEchoMismatch { expected, .. }) if expected.account_id == BOB
    ));
}

#[test]
fn an_effect_outside_the_call_inputs_is_rejected() {
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance(ALICE),
            ProgramShardSelector::balance(BOB),
        ]),
        &[],
    );
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![ShardEffect {
        selector: ProgramShardSelector::new(BOB, PROGRAM),
        data: b"go".to_vec(),
    }]);

    assert!(matches!(
        state.bind_plan(output),
        Err(ExecutionError::ExecutionValidation {
            program_account_id: PROGRAM,
            source: ExecutionValidationError::EffectOutsideInputs { .. }
        })
    ));
}

#[test]
fn the_engine_computes_every_resolver_input() {
    let mut source = Recording::new([(ALICE, funded(1).with_shard(PROGRAM, data(b"a")))]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance(ALICE),
        ]),
        &[],
    );
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![
        effect(&call.accounts[0], b"first"),
        effect(&call.accounts[1], b"guard"),
        effect(&call.accounts[0], b"second"),
    ]);
    state.bind_plan(output).unwrap();

    let first = obligation(&mut state, &mut source);
    assert_eq!(
        first,
        ResolveInput {
            self_account_id: PROGRAM,
            selector: ProgramShardSelector::new(ALICE, PROGRAM),
            pre_data: data(b"a"),
            effect_data: b"first".to_vec(),
        }
    );
    state
        .accept_resolution(&ResolveOutput {
            input: first,
            post_data: Some(data(b"b")),
        })
        .unwrap();

    let guard = obligation(&mut state, &mut source);
    assert_eq!(
        guard,
        ResolveInput {
            self_account_id: PROGRAM,
            selector: ProgramShardSelector::balance(ALICE),
            pre_data: encode_balance(1),
            effect_data: b"guard".to_vec(),
        }
    );
    state
        .accept_resolution(&ResolveOutput {
            input: guard,
            post_data: None,
        })
        .unwrap();

    let second = obligation(&mut state, &mut source);
    assert_eq!(second.pre_data, data(b"b"));
    assert_eq!(second.effect_data, b"second".to_vec());

    assert_eq!(
        source.asked,
        vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance(ALICE),
        ]
    );
}

#[test]
fn a_resolution_must_echo_the_input_the_engine_computed() {
    let tamper = |mutate: &dyn Fn(&mut ResolveInput)| {
        let mut source = facts([(ALICE, funded(4).with_shard(PROGRAM, data(b"a")))]);
        let mut state = start(root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]), &[]);
        let call = state.prepare_next_call().unwrap().unwrap();
        let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
        state.bind_plan(output).unwrap();
        let mut input = obligation(&mut state, &mut source);
        mutate(&mut input);
        state.accept_resolution(&ResolveOutput {
            input,
            post_data: None,
        })
    };

    let mutations: Vec<&dyn Fn(&mut ResolveInput)> = vec![
        &|input| input.self_account_id = OTHER_PROGRAM,
        &|input| input.selector = ProgramShardSelector::balance(ALICE),
        &|input| input.pre_data = data(b"z"),
        &|input| input.effect_data = b"other".to_vec(),
    ];
    for mutate in mutations {
        assert!(matches!(
            tamper(mutate),
            Err(ExecutionError::ExecutionValidation {
                program_account_id: PROGRAM,
                source: ExecutionValidationError::ResolveInputMismatch { .. },
            })
        ));
    }
    assert!(tamper(&|_| {}).is_ok());
}

#[test]
fn an_accepted_resolution_lands_only_on_its_selected_shard() {
    let mut source = facts([(ALICE, funded(4).with_shard(PROGRAM, data(b"a")))]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance(ALICE),
        ]),
        &[],
    );
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![
        effect(&call.accounts[0], b"write"),
        effect(&call.accounts[1], b"guard"),
    ]);
    state.bind_plan(output).unwrap();

    let input = obligation(&mut state, &mut source);
    state
        .accept_resolution(&ResolveOutput {
            input,
            post_data: Some(data(b"b")),
        })
        .unwrap();

    let guard = obligation(&mut state, &mut source);
    assert_eq!(guard.pre_data, encode_balance(4));
    state
        .accept_resolution(&ResolveOutput {
            input: guard,
            post_data: None,
        })
        .unwrap();
    state.complete_call().unwrap();

    let public = resolved(state.finish().unwrap().public);
    assert_eq!(public[0].1, funded(4).with_shard(PROGRAM, data(b"b")));
}

#[test]
fn every_emitted_effect_must_be_resolved() {
    let mut source = facts([(ALICE, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance(ALICE)];
    let emit = |call: &ProgramInput<InstructionData>| {
        plan(call).with_effects(vec![
            effect(&call.accounts[0], b"one"),
            effect(&call.accounts[0], b"two"),
        ])
    };

    let mut state = start(root(selectors.clone()), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = emit(call);
    state.bind_plan(output).unwrap();
    assert!(matches!(
        state.complete_call(),
        Err(ExecutionError::UnresolvedEffects {
            program_account_id: PROGRAM,
            remaining: 2
        })
    ));

    let mut state = start(root(selectors.clone()), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = emit(call);
    state.bind_plan(output).unwrap();
    let first = obligation(&mut state, &mut source);
    state
        .accept_resolution(&ResolveOutput {
            input: first,
            post_data: None,
        })
        .unwrap();
    obligation(&mut state, &mut source);
    assert!(matches!(
        state.complete_call(),
        Err(ExecutionError::UnresolvedEffects { remaining: 1, .. })
    ));

    let mut state = start(root(selectors), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = emit(call);
    state.bind_plan(output).unwrap();
    drain(&mut state, &mut source, &mut |_| None);
    assert!(state.complete_call().unwrap().is_empty());
}

#[test]
fn a_calls_effects_all_resolve_before_its_children_are_scheduled() {
    let mut source = Recording::new([(ALICE, funded(1)), (BOB, funded(1))]);
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance(ALICE),
            ProgramShardSelector::balance(BOB),
        ]),
        &[],
    );
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
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call)
        .with_effects(vec![
            effect(&call.accounts[1], b"first"),
            effect(&call.accounts[0], b"second"),
            effect(&call.accounts[1], b"third"),
        ])
        .with_chained_calls(vec![chained(
            OTHER_PROGRAM,
            vec![ProgramShardSelector::balance(ALICE)],
        )])
        .with_events(events.clone());
    state.bind_plan(output).unwrap();

    let local = drain(&mut state, &mut source, &mut |_| None);
    assert_eq!(
        local
            .iter()
            .map(|input| (input.selector.account_id, input.effect_data.clone()))
            .collect::<Vec<_>>(),
        vec![
            (BOB, b"first".to_vec()),
            (ALICE, b"second".to_vec()),
            (BOB, b"third".to_vec()),
        ]
    );
    assert_eq!(state.complete_call().unwrap(), events);

    let child = state.prepare_next_call().unwrap().unwrap();
    assert_eq!(child.self_account_id, OTHER_PROGRAM);
    assert_eq!(child.caller_account_id, Some(PROGRAM));
}

#[test]
fn a_deferred_public_target_is_never_materialized() {
    let keys = Keys::new(4);
    let private_id = keys.regular_id();
    let witnesses = [keys.regular(true, Account::default())];
    let mut source = Recording::new([(ALICE, funded(10)), (BOB, funded(2))]);
    let mut state = ExecutionState::initialize(
        RootCall {
            program_account_id: PROGRAM,
            shard_selectors: vec![
                ProgramShardSelector::balance(ALICE),
                ProgramShardSelector::new(private_id, PROGRAM),
                ProgramShardSelector::balance(BOB),
            ],
            instruction_data: vec![1, 2, 3],
            authorized_accounts: vec![ALICE],
        },
        &witnesses,
        PublicEffects::Defer,
    )
    .unwrap();

    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![
        effect(&call.accounts[2], b"credit"),
        effect(&call.accounts[1], b"write"),
        effect(&call.accounts[0], b"debit"),
        effect(&call.accounts[2], b"note"),
    ]);
    state.bind_plan(output).unwrap();
    let local = drain(&mut state, &mut source, &mut |_| Some(data(b"w")));
    state.complete_call().unwrap();

    let public_effect = |bytes: &[u8]| PublicResolution::Apply {
        program_account_id: PROGRAM,
        shard_program_account_id: NATIVE_TOKEN_PROGRAM_ID,
        data: bytes.to_vec(),
    };
    assert!(source.asked.is_empty());
    assert_eq!(state.pending_shard(ALICE, NATIVE_TOKEN_PROGRAM_ID), None);
    assert_eq!(state.pending_shard(BOB, NATIVE_TOKEN_PROGRAM_ID), None);
    assert_eq!(local.len(), 1);
    assert_eq!(
        local[0].selector,
        ProgramShardSelector::new(private_id, PROGRAM)
    );

    let FinalState {
        public,
        private_accounts,
        ..
    } = state.finish().unwrap();
    assert_eq!(
        journal(public),
        vec![
            PublicAction {
                account_id: ALICE,
                is_authorized: true,
                resolutions: vec![public_effect(b"debit")],
            },
            PublicAction {
                account_id: BOB,
                is_authorized: false,
                resolutions: vec![public_effect(b"credit"), public_effect(b"note")],
            },
        ]
    );
    assert_eq!(
        private_accounts[&private_id],
        AccountData::default().with_shard(PROGRAM, data(b"w"))
    );
}

#[test]
fn resolving_public_effects_yields_no_deferred_obligations() {
    let mut source = Recording::new([(ALICE, funded(10))]);
    let mut state = start(root(vec![ProgramShardSelector::balance(ALICE)]), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"guard")]);
    state.bind_plan(output).unwrap();

    let local = drain(&mut state, &mut source, &mut |_| None);
    state.complete_call().unwrap();

    assert_eq!(local.len(), 1);
    assert_eq!(source.asked, vec![ProgramShardSelector::balance(ALICE)]);
    let public = resolved(state.finish().unwrap().public);
    assert_eq!(public.len(), 1);
    assert_eq!(public[0].0, ALICE);
}

#[test]
fn a_chained_call_may_select_another_shard_of_a_root_account() {
    let mut source = Recording::new([
        (
            ALICE,
            funded(10)
                .with_shard(PROGRAM, data(b"p"))
                .with_shard(OTHER_PROGRAM, data(b"s")),
        ),
        (BOB, funded(0)),
    ]);
    let mut state = start(
        signed_root(
            vec![
                ProgramShardSelector::new(ALICE, PROGRAM),
                ProgramShardSelector::balance(BOB),
            ],
            vec![ALICE],
        ),
        &[],
    );

    step(&mut state, &mut source, |call| {
        assert_eq!(
            call.accounts,
            vec![
                AccountMeta::new(ALICE, true, PROGRAM),
                AccountMeta::balance(BOB, false),
            ]
        );
        plan(call)
            .with_effects(vec![
                effect(&call.accounts[0], b"keep"),
                effect(&call.accounts[1], b"keep"),
            ])
            .with_chained_calls(vec![
                chained(
                    OTHER_PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
                ),
                chained(
                    OTHER_PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
                ),
            ])
    });
    for written in [b"s2", b"s3"] {
        step_resolving(
            &mut state,
            &mut source,
            |call| {
                assert_eq!(
                    call.accounts,
                    vec![AccountMeta::new(ALICE, true, OTHER_PROGRAM)]
                );
                plan(call).with_effects(vec![effect(&call.accounts[0], b"write")])
            },
            &mut |_| Some(data(written)),
        );
    }

    assert_eq!(
        source.asked,
        vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::balance(BOB),
            ProgramShardSelector::new(ALICE, OTHER_PROGRAM)
        ]
    );
    let public = resolved(state.finish().unwrap().public);
    assert_eq!(
        public[0],
        (
            ALICE,
            AccountData::default()
                .with_shard(PROGRAM, data(b"p"))
                .with_shard(OTHER_PROGRAM, data(b"s3")),
        )
    );
    assert_eq!(public[1].1, funded(0));
}

#[test]
fn a_balance_only_root_then_a_shard_read_after_a_balance_change_keeps_the_write() {
    let mut source = Recording::new([
        (ALICE, funded(10).with_shard(OTHER_PROGRAM, data(b"s"))),
        (BOB, funded(0)),
    ]);
    let mut state = start(
        RootCall {
            program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            shard_selectors: vec![
                ProgramShardSelector::balance(ALICE),
                ProgramShardSelector::balance(BOB),
            ],
            instruction_data: vec![1, 2, 3],
            authorized_accounts: vec![ALICE],
        },
        &[],
    );

    let mut balances = [encode_balance(7), encode_balance(3)].into_iter();
    step_resolving(
        &mut state,
        &mut source,
        |call| {
            assert_eq!(
                call.accounts,
                vec![
                    AccountMeta::balance(ALICE, true),
                    AccountMeta::balance(BOB, false),
                ]
            );
            plan(call)
                .with_effects(vec![
                    effect(&call.accounts[0], b"debit"),
                    effect(&call.accounts[1], b"credit"),
                ])
                .with_chained_calls(vec![chained(
                    OTHER_PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, OTHER_PROGRAM)],
                )])
        },
        &mut |_| balances.next(),
    );
    step_resolving(
        &mut state,
        &mut source,
        |call| plan(call).with_effects(vec![effect(&call.accounts[0], b"read")]),
        &mut |input| {
            assert_eq!(input.pre_data, data(b"s"));
            None
        },
    );

    let public = resolved(state.finish().unwrap().public);
    assert_eq!(public[0].1, funded(7).with_shard(OTHER_PROGRAM, data(b"s")));
}

#[test]
fn a_cleared_shard_reads_back_empty_and_stays_in_the_resolved_projection() {
    let mut source = Recording::new([(ALICE, funded(1).with_shard(PROGRAM, data(b"a")))]);
    let mut state = start(root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]), &[]);

    step_resolving(
        &mut state,
        &mut source,
        |call| {
            plan(call)
                .with_effects(vec![effect(&call.accounts[0], b"clear")])
                .with_chained_calls(vec![chained(
                    PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, PROGRAM)],
                )])
        },
        &mut |_| Some(ShardData::empty()),
    );
    step_resolving(
        &mut state,
        &mut source,
        |call| plan(call).with_effects(vec![effect(&call.accounts[0], b"read")]),
        &mut |input| {
            assert_eq!(input.pre_data, ShardData::empty());
            None
        },
    );

    assert_eq!(
        source.asked,
        vec![ProgramShardSelector::new(ALICE, PROGRAM)]
    );
    let public = resolved(state.finish().unwrap().public);
    assert_eq!(public[0].1.shards[&PROGRAM], ShardData::empty());
}

#[test]
fn a_chained_call_cannot_name_an_account_the_root_did_not() {
    let mut source = facts([(ALICE, funded(1)), (BOB, funded(1))]);
    let mut state = start(root(vec![ProgramShardSelector::balance(ALICE)]), &[]);
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![chained(
            PROGRAM,
            vec![ProgramShardSelector::balance(BOB)],
        )])
    });

    assert!(matches!(
        state.prepare_next_call(),
        Err(ExecutionError::UnknownAccount { account_id: BOB })
    ));
}

#[test]
fn a_witness_outside_the_root_inputs_is_rejected() {
    let keys = Keys::new(4);
    let witnesses = [keys.regular(true, Account::default())];

    let result = ExecutionState::initialize(
        root(vec![ProgramShardSelector::balance(ALICE)]),
        &witnesses,
        PublicEffects::Resolve,
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
    let selectors = vec![ProgramShardSelector::balance(keys.regular_id())];

    let duplicate = [
        keys.regular(true, Account::default()),
        keys.regular(true, Account::default()),
    ];
    assert!(matches!(
        ExecutionState::initialize(root(selectors.clone()), &duplicate, PublicEffects::Resolve).err(),
        Some(ExecutionError::DuplicateWitness { account_id }) if account_id == keys.regular_id()
    ));

    let mut unlinked = keys.regular(true, Account::default());
    unlinked.kind = WitnessKind::Regular {
        ask: Some(other.ask),
    };
    let unlinked = [unlinked];
    assert!(matches!(
        ExecutionState::initialize(root(selectors), &unlinked, PublicEffects::Resolve).err(),
        Some(ExecutionError::InvalidAuthorizationKey { account_id }) if account_id == keys.regular_id()
    ));
}

#[test]
fn two_private_pdas_under_one_seed_conflict() {
    let keys = Keys::new(4);
    let other = Keys::new(5);
    let witnesses = [keys.pda(PROGRAM, SEED), other.pda(PROGRAM, SEED)];

    let result = ExecutionState::initialize(
        root(vec![
            ProgramShardSelector::balance(keys.pda_id(PROGRAM, SEED)),
            ProgramShardSelector::balance(other.pda_id(PROGRAM, SEED)),
        ]),
        &witnesses,
        PublicEffects::Resolve,
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
    let mut source = facts([(public_pda, funded(1))]);
    let selectors = vec![
        ProgramShardSelector::balance(signer.regular_id()),
        ProgramShardSelector::balance(holder.regular_id()),
        ProgramShardSelector::balance(public_pda),
    ];
    let authorization = |call: &ProgramInput<InstructionData>| -> Vec<bool> {
        call.accounts
            .iter()
            .map(|account| account.is_authorized)
            .collect()
    };
    let mut state = start_deferring(root(selectors.clone()), &witnesses);

    step(&mut state, &mut source, |call| {
        assert_eq!(authorization(call), vec![true, false, false]);
        plan(call).with_chained_calls(vec![
            chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
            chained(OTHER_PROGRAM, selectors.clone()),
        ])
    });
    step(&mut state, &mut source, |call| {
        assert_eq!(authorization(call), vec![true, false, true]);
        plan(call).with_chained_calls(vec![chained(PROGRAM, selectors.clone())])
    });
    step(&mut state, &mut source, |call| {
        assert_eq!(authorization(call), vec![true, false, true]);
        plan(call)
    });
    step(&mut state, &mut source, |call| {
        assert_eq!(authorization(call), vec![true, false, false]);
        plan(call)
    });

    let FinalState { public, .. } = state.finish().unwrap();
    assert!(!journal(public)[0].is_authorized);
}

#[test]
fn a_private_pda_is_granted_only_by_its_own_seed_from_its_own_program() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let pda = keys.pda_id(PROGRAM, SEED);
    let mut source = facts([]);
    let selectors = vec![ProgramShardSelector::balance(pda)];
    let mut state = start(root(selectors.clone()), &witnesses);

    step(&mut state, &mut source, |call| {
        assert!(!call.accounts[0].is_authorized);
        plan(call).with_chained_calls(vec![
            chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![OTHER_SEED]),
            chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
            chained(OTHER_PROGRAM, selectors.clone()),
        ])
    });
    step(&mut state, &mut source, |call| {
        assert!(!call.accounts[0].is_authorized);
        plan(call).with_chained_calls(vec![
            chained(PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
        ])
    });
    step(&mut state, &mut source, |call| {
        assert!(!call.accounts[0].is_authorized);
        plan(call)
    });
    step(&mut state, &mut source, |call| {
        assert!(call.accounts[0].is_authorized);
        plan(call)
    });
    step(&mut state, &mut source, |call| {
        assert!(!call.accounts[0].is_authorized);
        plan(call)
    });

    let FinalState {
        public,
        private_accounts,
        ..
    } = state.finish().unwrap();
    assert!(resolved(public).is_empty());
    assert_eq!(private_accounts.len(), 1);
}

#[test]
fn a_public_pda_grant_under_a_privately_bound_seed_conflicts() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let public_pda = AccountId::for_public_pda(&PROGRAM, &SEED);
    let mut source = facts([(public_pda, funded(1))]);
    let selectors = vec![
        ProgramShardSelector::balance(keys.pda_id(PROGRAM, SEED)),
        ProgramShardSelector::balance(public_pda),
    ];
    let mut state = start(root(selectors.clone()), &witnesses);
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![
            chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
        ])
    });

    assert!(matches!(
        state.prepare_next_call(),
        Err(ExecutionError::FamilyBindingConflict { account_id, .. }) if account_id == public_pda
    ));
}

#[test]
fn calls_run_depth_first_in_sibling_order_up_to_the_limit() {
    let mut source = facts([(ALICE, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance(ALICE)];
    let mut state = start(root(selectors.clone()), &[]);
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![
            chained(AccountId::new([1; 32]), selectors.clone()),
            chained(AccountId::new([3; 32]), selectors.clone()),
        ])
    });
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![chained(AccountId::new([2; 32]), selectors.clone())])
    });
    assert_eq!(
        run_to_end(&mut state, &mut source),
        vec![AccountId::new([2; 32]), AccountId::new([3; 32])]
    );
    assert!(state.prepare_next_call().unwrap().is_none());
    state.finish().unwrap();

    let chain = |count: usize| {
        let mut source = facts([(ALICE, funded(1))]);
        let mut state = start(root(selectors.clone()), &[]);
        step(&mut state, &mut source, |call| {
            plan(call).with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone()); count])
        });
        loop {
            match state.prepare_next_call() {
                Ok(Some(call)) => {
                    let output = plan(call);
                    state.bind_plan(output).unwrap();
                    state.complete_call().unwrap();
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
    let mut source = facts([(ALICE, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance(ALICE)];
    let mut state = start(root(selectors.clone()), &[]);
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
    });

    assert!(matches!(
        state.finish(),
        Err(ExecutionError::IncompleteExecution)
    ));
}

#[test]
fn validation_and_window_failures_name_the_program() {
    let mut source = facts([(ALICE, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance(ALICE)];
    let mut state = start(root(selectors.clone()), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"pay")]);
    state.bind_plan(output).unwrap();
    let input = obligation(&mut state, &mut source);
    assert!(matches!(
        state.accept_resolution(&ResolveOutput {
            input,
            post_data: Some(encode_balance(1)),
        }),
        Err(ExecutionError::ExecutionValidation {
            program_account_id: PROGRAM,
            source: ExecutionValidationError::ForeignShardWrite {
                account_id: ALICE,
                executing_account_id: PROGRAM
            }
        })
    ));

    let mut state = start(root(selectors.clone()), &[]);
    step(&mut state, &mut source, |call| {
        plan(call)
            .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
            .try_with_block_validity_window(1..3)
            .unwrap()
    });
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_block_validity_window(3..);
    assert!(matches!(
        state.bind_plan(output),
        Err(ExecutionError::EmptyBlockWindowIntersection)
    ));
}

#[test]
fn the_final_windows_are_the_intersection_of_every_call() {
    let mut source = facts([(ALICE, funded(1))]);
    let selectors = vec![ProgramShardSelector::balance(ALICE)];
    let mut state = start(root(selectors.clone()), &[]);
    step(&mut state, &mut source, |call| {
        plan(call)
            .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
            .try_with_block_validity_window(1..5)
            .unwrap()
            .with_timestamp_validity_window(..9)
    });
    step(&mut state, &mut source, |call| {
        plan(call)
            .with_block_validity_window(2..)
            .try_with_timestamp_validity_window(4..7)
            .unwrap()
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
    let mut state = start(
        root(vec![
            ProgramShardSelector::balance(ALICE),
            ProgramShardSelector::balance(ALICE),
        ]),
        &[],
    );
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call);

    assert!(matches!(
        state.bind_plan(output),
        Err(ExecutionError::ExecutionValidation {
            source: ExecutionValidationError::AccountShardSelectorsNotUnique,
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
    let mut source = Recording::new([
        (ALICE, funded(1).with_shard(CAROL, data(b"untouched"))),
        (BOB, funded(2)),
    ]);
    let mut state = start(
        signed_root(
            vec![
                ProgramShardSelector::balance(BOB),
                ProgramShardSelector::new(keys.regular_id(), PROGRAM),
                ProgramShardSelector::balance(ALICE),
            ],
            vec![BOB],
        ),
        &witnesses,
    );
    step_resolving(
        &mut state,
        &mut source,
        |call| {
            plan(call).with_effects(vec![
                effect(&call.accounts[0], b"keep"),
                effect(&call.accounts[1], b"write"),
                effect(&call.accounts[2], b"keep"),
            ])
        },
        &mut |input| (input.selector.account_id == keys.regular_id()).then(|| data(b"written")),
    );

    let FinalState {
        public,
        private_accounts,
        ..
    } = state.finish().unwrap();
    let public = resolved(public);
    assert_eq!(
        public.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![BOB, ALICE]
    );
    assert_eq!(public[1].1, funded(1));
    assert_eq!(
        private_accounts[&keys.regular_id()],
        AccountData::default()
            .with_shard(OTHER_PROGRAM, data(b"kept"))
            .with_shard(PROGRAM, data(b"written"))
    );
}

#[test]
fn a_failed_preparation_aborts_the_execution() {
    let mut source = facts([(ALICE, funded(1))]);
    let mut state = start(root(vec![ProgramShardSelector::balance(ALICE)]), &[]);
    step(&mut state, &mut source, |call| {
        plan(call).with_chained_calls(vec![chained(
            PROGRAM,
            vec![ProgramShardSelector::balance(BOB)],
        )])
    });
    assert!(matches!(
        state.prepare_next_call(),
        Err(ExecutionError::UnknownAccount { account_id: BOB })
    ));

    assert!(matches!(
        state.prepare_next_call(),
        Err(ExecutionError::Aborted)
    ));
    assert!(matches!(state.finish(), Err(ExecutionError::Aborted)));
}

#[test]
fn a_failed_completion_aborts_the_execution() {
    let mut state = start(root(vec![ProgramShardSelector::balance(ALICE)]), &[]);
    let call = state.prepare_next_call().unwrap().unwrap();
    let output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
    state.bind_plan(output).unwrap();
    assert!(matches!(
        state.complete_call(),
        Err(ExecutionError::UnresolvedEffects { remaining: 1, .. })
    ));

    assert!(matches!(
        state.prepare_next_call(),
        Err(ExecutionError::Aborted)
    ));
    assert!(matches!(state.finish(), Err(ExecutionError::Aborted)));
}

#[test]
fn a_pending_shard_is_known_only_once_observed_and_a_cleared_one_stays_known() {
    let mut source = Recording::new([(
        ALICE,
        funded(1)
            .with_shard(PROGRAM, data(b"a"))
            .with_shard(OTHER_PROGRAM, data(b"b")),
    )]);
    let mut state = start(root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]), &[]);
    assert_eq!(state.pending_shard(ALICE, PROGRAM), None);
    assert_eq!(state.pending_shard(BOB, PROGRAM), None);

    step_resolving(
        &mut state,
        &mut source,
        |call| plan(call).with_effects(vec![effect(&call.accounts[0], b"clear")]),
        &mut |_| Some(ShardData::empty()),
    );

    assert_eq!(
        state.pending_shard(ALICE, PROGRAM),
        Some(&ShardData::empty())
    );
    assert_eq!(state.pending_shard(ALICE, OTHER_PROGRAM), None);
}
