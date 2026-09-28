#![allow(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
};

use super::*;
use crate::{
    AuthorizationSecretKey, Identifier,
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
        AccountId::for_regular_private_account(&self.npk(), &self.vpk, Identifier::ZERO)
    }

    fn pda_id(&self, program: AccountId, seed: PdaSeed) -> AccountId {
        AccountId::for_private_pda(&program, &seed, &self.npk(), &self.vpk, Identifier::ZERO)
    }

    fn witness(&self, kind: WitnessKind) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: [0; 32],
            identifier: Identifier::ZERO,
            kind,
            nullifier: NullifierWitness::Init {
                npk: self.npk(),
                commitment_root: [8; 32],
            },
        }
    }

    fn regular(&self, ask: bool) -> PrivateWitness {
        self.witness(WitnessKind::Regular {
            ask: ask.then_some(self.ask),
        })
    }

    fn update(&self, account: Account) -> PrivateWitness {
        PrivateWitness {
            nullifier: NullifierWitness::Update {
                account,
                view_tag: 0,
                nsk: self.nsk(),
                membership_proof: (0, Vec::new()),
            },
            ..self.regular(true)
        }
    }

    fn pda(&self, program: AccountId, seed: PdaSeed) -> PrivateWitness {
        self.witness(WitnessKind::Pda {
            binding: (program, seed),
        })
    }
}

/// Shards fixed up front, so a shard a test never exposed fails instead of reading back empty.
type PublicShards = BTreeMap<AccountId, AccountData>;

type Planner<'script> = Box<dyn FnOnce(&PlanInput, &ExecutionState<'_>) -> PlanOutput + 'script>;
type Answer<'script> = Box<dyn FnMut(&ApplyInput) -> Result<ApplyOutput, ExecutionError> + 'script>;

enum Trace {
    Plan(PlanInput),
    Apply(ApplyInput),
    Complete(AccountId, Vec<ProgramEvent>),
}

struct Script<'script, P> {
    plans: VecDeque<Planner<'script>>,
    answer: Answer<'script>,
    rejection: Option<ExecutionError>,
    trace: Vec<Trace>,
    shards: PublicShards,
    asked: Vec<ProgramShardSelector>,
    mode: PhantomData<P>,
}

impl<'script> Script<'script, ApplyPublicEffects> {
    fn new(plans: impl IntoIterator<Item = Planner<'script>>) -> Self {
        Self::scripted(plans)
    }
}

impl<'script> Script<'script, DeferPublicEffects> {
    fn deferring(plans: impl IntoIterator<Item = Planner<'script>>) -> Self {
        Self::scripted(plans)
    }
}

impl<'script, P> Script<'script, P> {
    fn scripted(plans: impl IntoIterator<Item = Planner<'script>>) -> Self {
        Self {
            plans: plans.into_iter().collect(),
            answer: Box::new(|input: &ApplyInput| {
                Ok(ApplyOutput {
                    input: input.clone(),
                    post_data: None,
                })
            }),
            rejection: None,
            trace: Vec::new(),
            shards: PublicShards::new(),
            asked: Vec::new(),
            mode: PhantomData,
        }
    }

    fn reading(mut self, entries: impl IntoIterator<Item = (AccountId, AccountData)>) -> Self {
        self.shards = shards(entries);
        self
    }

    fn applying(self, mut apply: impl FnMut(&ApplyInput) -> Option<ShardData> + 'script) -> Self {
        self.answering(move |input| {
            Ok(ApplyOutput {
                input: input.clone(),
                post_data: apply(input),
            })
        })
    }

    fn answering(
        mut self,
        answer: impl FnMut(&ApplyInput) -> Result<ApplyOutput, ExecutionError> + 'script,
    ) -> Self {
        self.answer = Box::new(answer);
        self
    }

    fn rejecting_completion(mut self, error: ExecutionError) -> Self {
        self.rejection = Some(error);
        self
    }

    fn planned(&self) -> Vec<&PlanInput> {
        self.trace
            .iter()
            .filter_map(|entry| match entry {
                Trace::Plan(input) => Some(input),
                Trace::Apply(_) | Trace::Complete(..) => None,
            })
            .collect()
    }

    fn applied(&self) -> Vec<&ApplyInput> {
        self.trace
            .iter()
            .filter_map(|entry| match entry {
                Trace::Apply(input) => Some(input),
                Trace::Plan(_) | Trace::Complete(..) => None,
            })
            .collect()
    }
}

impl<P: PublicEffectMode> Backend for Script<'_, P> {
    type Call = AccountId;
    type Error = ExecutionError;
    type PublicEffects = P;

    fn plan(
        &mut self,
        input: &PlanInput,
        execution: &ExecutionState<'_>,
    ) -> Result<(PlanOutput, AccountId), ExecutionError> {
        self.trace.push(Trace::Plan(input.clone()));
        let output = self
            .plans
            .pop_front()
            .map_or_else(|| plan(input), |planner| planner(input, execution));
        Ok((output, input.self_account_id))
    }

    fn apply(
        &mut self,
        _call: &mut AccountId,
        input: &ApplyInput,
    ) -> Result<ApplyOutput, ExecutionError> {
        self.trace.push(Trace::Apply(input.clone()));
        (self.answer)(input)
    }

    fn complete(
        &mut self,
        call: AccountId,
        events: Vec<ProgramEvent>,
        _execution: &ExecutionState<'_>,
    ) -> Result<(), ExecutionError> {
        self.trace.push(Trace::Complete(call, events));
        self.rejection.take().map_or(Ok(()), Err)
    }

    fn public_shard(
        &mut self,
        shard_selector: ProgramShardSelector,
    ) -> Result<ShardData, ExecutionError> {
        self.asked.push(shard_selector);
        self.shards
            .get(&shard_selector.account_id)
            .and_then(|data| data.shards.get(&shard_selector.program_account_id))
            .cloned()
            .ok_or(ExecutionError::PublicShardUnavailable { shard_selector })
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

fn shards(entries: impl IntoIterator<Item = (AccountId, AccountData)>) -> PublicShards {
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

fn plan(call: &PlanInput) -> PlanOutput {
    PlanOutput::new(call.clone())
}

fn start(root: RootCall, witnesses: &[PrivateWitness]) -> ExecutionState<'_> {
    ExecutionState::initialize(root, witnesses)
        .unwrap_or_else(|_| panic!("initialization must succeed"))
}

fn planning<'script>(plan: impl FnOnce(&PlanInput) -> PlanOutput + 'script) -> Planner<'script> {
    Box::new(move |call: &PlanInput, _: &ExecutionState<'_>| plan(call))
}

fn seeing<'script>(
    plan: impl FnOnce(&PlanInput, &ExecutionState<'_>) -> PlanOutput + 'script,
) -> Planner<'script> {
    Box::new(plan)
}

fn execute<P: PublicEffectMode>(
    state: ExecutionState<'_>,
    script: &mut Script<'_, P>,
) -> Result<ExecutionOutcome<P>, ExecutionError> {
    state.run(script)
}

fn authorization(call: &PlanInput) -> Vec<bool> {
    call.accounts
        .iter()
        .map(|account| account.is_authorized)
        .collect()
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
        private_seed_grant(Some(PROGRAM), &[SEED], &keys.regular(false)),
        None
    );
}

#[test]
fn root_handles_follow_the_selector_order() {
    let mut script = Script::new([]);
    execute(
        start(
            signed_root(
                vec![
                    ProgramShardSelector::new(BOB, PROGRAM),
                    ProgramShardSelector::native_balance(ALICE),
                ],
                vec![ALICE],
            ),
            &[],
        ),
        &mut script,
    )
    .unwrap();

    let call = script.planned()[0];
    assert_eq!(call.self_account_id, PROGRAM);
    assert_eq!(call.caller_account_id, None);
    assert_eq!(call.instruction_data, vec![1, 2, 3]);
    assert_eq!(
        call.accounts,
        vec![
            AccountMeta::new(BOB, false, PROGRAM),
            AccountMeta::native_balance(ALICE, true),
        ]
    );
}

#[test]
fn a_shard_the_public_source_lacks_is_rejected_while_an_empty_one_is_read() {
    let selectors = vec![ProgramShardSelector::new(ALICE, PROGRAM)];
    let go = || planning(|call| plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]));
    assert!(matches!(
        execute(
            start(root(selectors.clone()), &[]),
            &mut Script::new([go()]).reading([(ALICE, funded(1))]),
        ),
        Err(ExecutionError::PublicShardUnavailable { shard_selector })
            if shard_selector == ProgramShardSelector::new(ALICE, PROGRAM)
    ));

    let mut explicit = shards([(ALICE, funded(1))]);
    explicit
        .get_mut(&ALICE)
        .unwrap()
        .shards
        .insert(PROGRAM, ShardData::empty());
    let mut script = Script::new([go()]).reading(explicit);
    execute(start(root(selectors), &[]), &mut script).unwrap();

    assert_eq!(script.applied()[0].pre_data, ShardData::empty());
}

#[test]
fn a_plan_must_repeat_the_prepared_inputs_exactly() {
    let selectors = vec![
        ProgramShardSelector::new(ALICE, PROGRAM),
        ProgramShardSelector::native_balance(BOB),
    ];
    let bind = |mutate: &dyn Fn(&mut PlanOutput)| {
        execute(
            start(signed_root(selectors.clone(), vec![ALICE]), &[]),
            &mut Script::new([planning(|call| {
                let mut output = plan(call);
                mutate(&mut output);
                output
            })]),
        )
    };

    let mutations: Vec<&dyn Fn(&mut PlanOutput)> = vec![
        &|output| {
            output.input.accounts.pop();
        },
        &|output| output.input.accounts.reverse(),
        &|output| output.input.accounts[0].program_account_id = OTHER_PROGRAM,
        &|output| output.input.accounts[1].is_authorized = true,
        &|output| output.input.self_account_id = OTHER_PROGRAM,
        &|output| output.input.caller_account_id = Some(OTHER_PROGRAM),
        &|output| output.input.instruction_data = vec![9],
    ];
    for mutate in mutations {
        assert!(matches!(
            bind(mutate),
            Err(ExecutionError::ExecutionValidation {
                program_account_id: PROGRAM,
                source: ExecutionValidationError::PlanInputMismatch { .. },
            })
        ));
    }
    assert!(bind(&|_| {}).is_ok());
}

#[test]
fn a_handle_that_produces_no_effect_is_still_bound() {
    let result = execute(
        start(
            signed_root(
                vec![
                    ProgramShardSelector::native_balance(ALICE),
                    ProgramShardSelector::native_balance(BOB),
                ],
                vec![BOB],
            ),
            &[],
        ),
        &mut Script::new([planning(|call| {
            let mut output = plan(call).with_effects(vec![effect(&call.accounts[0], b"go")]);
            output.input.accounts[1].is_authorized = false;
            output
        })]),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::ExecutionValidation {
            source: ExecutionValidationError::PlanInputMismatch { expected, actual },
            ..
        }) if expected.accounts[1] == AccountMeta::native_balance(BOB, true)
            && actual.accounts[1] == AccountMeta::native_balance(BOB, false)
    ));
}

#[test]
fn an_effect_outside_the_call_inputs_is_rejected() {
    let result = execute(
        start(
            root(vec![
                ProgramShardSelector::native_balance(ALICE),
                ProgramShardSelector::native_balance(BOB),
            ]),
            &[],
        ),
        &mut Script::new([planning(|call| {
            plan(call).with_effects(vec![ShardEffect {
                selector: ProgramShardSelector::new(BOB, PROGRAM),
                data: b"go".to_vec(),
            }])
        })]),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::ExecutionValidation {
            program_account_id: PROGRAM,
            source: ExecutionValidationError::EffectOutsideInputs { .. }
        })
    ));
}

#[test]
fn the_engine_computes_every_apply_input() {
    let mut script = Script::new([planning(|call| {
        plan(call).with_effects(vec![
            effect(&call.accounts[0], b"first"),
            effect(&call.accounts[1], b"guard"),
            effect(&call.accounts[0], b"second"),
        ])
    })])
    .applying(|input| (input.effect_data == b"first").then(|| data(b"b")))
    .reading([(ALICE, funded(1).with_shard(PROGRAM, data(b"a")))]);
    execute(
        start(
            root(vec![
                ProgramShardSelector::new(ALICE, PROGRAM),
                ProgramShardSelector::native_balance(ALICE),
            ]),
            &[],
        ),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        script.applied(),
        [
            &ApplyInput {
                self_account_id: PROGRAM,
                selector: ProgramShardSelector::new(ALICE, PROGRAM),
                pre_data: data(b"a"),
                effect_data: b"first".to_vec(),
            },
            &ApplyInput {
                self_account_id: PROGRAM,
                selector: ProgramShardSelector::native_balance(ALICE),
                pre_data: encode_balance(1),
                effect_data: b"guard".to_vec(),
            },
            &ApplyInput {
                self_account_id: PROGRAM,
                selector: ProgramShardSelector::new(ALICE, PROGRAM),
                pre_data: data(b"b"),
                effect_data: b"second".to_vec(),
            },
        ]
    );
    assert_eq!(
        script.asked,
        vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::native_balance(ALICE),
        ]
    );
}

#[test]
fn an_apply_output_must_echo_the_input_the_engine_computed() {
    let tamper = |mutate: &dyn Fn(&mut ApplyInput)| {
        execute(
            start(root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]), &[]),
            &mut Script::new([planning(|call| {
                plan(call).with_effects(vec![effect(&call.accounts[0], b"go")])
            })])
            .answering(|input| {
                let mut input = input.clone();
                mutate(&mut input);
                Ok(ApplyOutput {
                    input,
                    post_data: None,
                })
            })
            .reading([(ALICE, funded(4).with_shard(PROGRAM, data(b"a")))]),
        )
    };

    let mutations: Vec<&dyn Fn(&mut ApplyInput)> = vec![
        &|input| input.self_account_id = OTHER_PROGRAM,
        &|input| input.selector = ProgramShardSelector::native_balance(ALICE),
        &|input| input.pre_data = data(b"z"),
        &|input| input.effect_data = b"other".to_vec(),
    ];
    for mutate in mutations {
        assert!(matches!(
            tamper(mutate),
            Err(ExecutionError::ExecutionValidation {
                program_account_id: PROGRAM,
                source: ExecutionValidationError::ApplyInputMismatch { .. },
            })
        ));
    }
    assert!(tamper(&|_| {}).is_ok());
}

#[test]
fn an_accepted_apply_output_lands_only_on_its_selected_shard() {
    let mut script = Script::new([planning(|call| {
        plan(call).with_effects(vec![
            effect(&call.accounts[0], b"write"),
            effect(&call.accounts[1], b"guard"),
        ])
    })])
    .applying(|input| (input.effect_data == b"write").then(|| data(b"b")))
    .reading([(ALICE, funded(4).with_shard(PROGRAM, data(b"a")))]);
    let public = execute(
        start(
            root(vec![
                ProgramShardSelector::new(ALICE, PROGRAM),
                ProgramShardSelector::native_balance(ALICE),
            ]),
            &[],
        ),
        &mut script,
    )
    .unwrap()
    .public;

    assert_eq!(script.applied()[1].pre_data, encode_balance(4));
    assert_eq!(public[0].1, funded(4).with_shard(PROGRAM, data(b"b")));
}

#[test]
fn every_emitted_effect_is_applied_before_its_call_completes() {
    let selectors = vec![ProgramShardSelector::native_balance(ALICE)];
    let emit = || {
        planning(|call| {
            plan(call)
                .with_effects(vec![
                    effect(&call.accounts[0], b"one"),
                    effect(&call.accounts[0], b"two"),
                ])
                .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
        })
    };

    let mut script = Script::new([emit()]).reading([(ALICE, funded(1))]);
    execute(start(root(selectors.clone()), &[]), &mut script).unwrap();
    assert!(matches!(
        script.trace.as_slice(),
        [
            Trace::Plan(_),
            Trace::Apply(one),
            Trace::Apply(two),
            Trace::Complete(PROGRAM, _),
            Trace::Plan(_),
            Trace::Complete(OTHER_PROGRAM, _),
        ] if one.effect_data == b"one" && two.effect_data == b"two"
    ));

    let mut script = Script::new([emit()])
        .applying(|_| Some(encode_balance(0)))
        .reading([(ALICE, funded(1))]);
    let result = execute(start(root(selectors.clone()), &[]), &mut script);
    assert!(matches!(
        result,
        Err(ExecutionError::ExecutionValidation {
            source: ExecutionValidationError::ForeignShardWrite { .. },
            ..
        })
    ));
    assert!(matches!(
        script.trace.as_slice(),
        [Trace::Plan(_), Trace::Apply(_)]
    ));
}

#[test]
fn a_calls_effects_are_all_applied_before_its_children_run() {
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
    let mut script = Script::new([planning(|call| {
        plan(call)
            .with_effects(vec![
                effect(&call.accounts[1], b"first"),
                effect(&call.accounts[0], b"second"),
                effect(&call.accounts[1], b"third"),
            ])
            .with_chained_calls(vec![chained(
                OTHER_PROGRAM,
                vec![ProgramShardSelector::native_balance(ALICE)],
            )])
            .with_events(events.clone())
    })])
    .reading([(ALICE, funded(1)), (BOB, funded(1))]);
    execute(
        start(
            root(vec![
                ProgramShardSelector::native_balance(ALICE),
                ProgramShardSelector::native_balance(BOB),
            ]),
            &[],
        ),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        script
            .applied()
            .into_iter()
            .map(|input| (input.selector.account_id, input.effect_data.clone()))
            .collect::<Vec<_>>(),
        vec![
            (BOB, b"first".to_vec()),
            (ALICE, b"second".to_vec()),
            (BOB, b"third".to_vec()),
        ]
    );
    assert!(matches!(
        script.trace.as_slice(),
        [
            Trace::Plan(_),
            Trace::Apply(_),
            Trace::Apply(_),
            Trace::Apply(_),
            Trace::Complete(PROGRAM, completed),
            Trace::Plan(child),
            Trace::Complete(OTHER_PROGRAM, _),
        ] if *completed == events
            && child.self_account_id == OTHER_PROGRAM
            && child.caller_account_id == Some(PROGRAM)
    ));
}

#[test]
fn a_deferred_public_target_is_never_materialized() {
    let keys = Keys::new(4);
    let private_id = keys.regular_id();
    let witnesses = [keys.regular(true)];
    let state = ExecutionState::initialize(
        RootCall {
            program_account_id: PROGRAM,
            shard_selectors: vec![
                ProgramShardSelector::native_balance(ALICE),
                ProgramShardSelector::new(private_id, PROGRAM),
                ProgramShardSelector::native_balance(BOB),
            ],
            instruction_data: vec![1, 2, 3],
            authorized_accounts: vec![ALICE],
        },
        &witnesses,
    )
    .unwrap();
    let mut script = Script::deferring([planning(|call| {
        plan(call).with_effects(vec![
            effect(&call.accounts[2], b"credit"),
            effect(&call.accounts[1], b"write"),
            effect(&call.accounts[0], b"debit"),
            effect(&call.accounts[2], b"note"),
        ])
    })])
    .applying(|_| Some(data(b"w")))
    .reading([(ALICE, funded(10)), (BOB, funded(2))]);
    let ExecutionOutcome {
        public,
        private_accounts,
        ..
    } = execute(state, &mut script).unwrap();

    let public_effect = |bytes: &[u8]| DeferredPublicEffect {
        program_account_id: PROGRAM,
        shard_program_account_id: NATIVE_TOKEN_PROGRAM_ID,
        data: bytes.to_vec(),
    };
    assert!(script.asked.is_empty());
    let applied = script.applied();
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0].selector,
        ProgramShardSelector::new(private_id, PROGRAM)
    );
    assert_eq!(
        public,
        vec![
            PublicAction {
                account_id: ALICE,
                is_authorized: true,
                effects: vec![public_effect(b"debit")],
            },
            PublicAction {
                account_id: BOB,
                is_authorized: false,
                effects: vec![public_effect(b"credit"), public_effect(b"note")],
            },
        ]
    );
    assert_eq!(
        private_accounts[&private_id],
        AccountData::default().with_shard(PROGRAM, data(b"w"))
    );
}

#[test]
fn applying_public_effects_defers_nothing() {
    let mut script = Script::new([planning(|call| {
        plan(call).with_effects(vec![effect(&call.accounts[0], b"guard")])
    })])
    .reading([(ALICE, funded(10))]);
    let public = execute(
        start(root(vec![ProgramShardSelector::native_balance(ALICE)]), &[]),
        &mut script,
    )
    .unwrap()
    .public;

    assert_eq!(script.applied().len(), 1);
    assert_eq!(
        script.asked,
        vec![ProgramShardSelector::native_balance(ALICE)]
    );
    assert_eq!(public.len(), 1);
    assert_eq!(public[0].0, ALICE);
}

#[test]
fn a_chained_call_may_select_another_shard_of_a_root_account() {
    let write = || {
        planning(|call| {
            assert_eq!(
                call.accounts,
                vec![AccountMeta::new(ALICE, true, OTHER_PROGRAM)]
            );
            plan(call).with_effects(vec![effect(&call.accounts[0], b"write")])
        })
    };
    let mut written = [b"s2", b"s3"].into_iter();
    let mut script = Script::new([
        planning(|call| {
            assert_eq!(
                call.accounts,
                vec![
                    AccountMeta::new(ALICE, true, PROGRAM),
                    AccountMeta::native_balance(BOB, false),
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
        }),
        write(),
        write(),
    ])
    .applying(|input| (input.effect_data == b"write").then(|| data(written.next().unwrap())))
    .reading([
        (
            ALICE,
            funded(10)
                .with_shard(PROGRAM, data(b"p"))
                .with_shard(OTHER_PROGRAM, data(b"s")),
        ),
        (BOB, funded(0)),
    ]);
    let public = execute(
        start(
            signed_root(
                vec![
                    ProgramShardSelector::new(ALICE, PROGRAM),
                    ProgramShardSelector::native_balance(BOB),
                ],
                vec![ALICE],
            ),
            &[],
        ),
        &mut script,
    )
    .unwrap()
    .public;

    assert_eq!(
        script.asked,
        vec![
            ProgramShardSelector::new(ALICE, PROGRAM),
            ProgramShardSelector::native_balance(BOB),
            ProgramShardSelector::new(ALICE, OTHER_PROGRAM)
        ]
    );
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
    let mut balances = [encode_balance(7), encode_balance(3)].into_iter();
    let mut script = Script::new([
        planning(|call| {
            assert_eq!(
                call.accounts,
                vec![
                    AccountMeta::native_balance(ALICE, true),
                    AccountMeta::native_balance(BOB, false),
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
        }),
        planning(|call| plan(call).with_effects(vec![effect(&call.accounts[0], b"read")])),
    ])
    .applying(|input| {
        (input.self_account_id == NATIVE_TOKEN_PROGRAM_ID).then(|| balances.next().unwrap())
    })
    .reading([
        (ALICE, funded(10).with_shard(OTHER_PROGRAM, data(b"s"))),
        (BOB, funded(0)),
    ]);
    let public = execute(
        start(
            RootCall {
                program_account_id: NATIVE_TOKEN_PROGRAM_ID,
                shard_selectors: vec![
                    ProgramShardSelector::native_balance(ALICE),
                    ProgramShardSelector::native_balance(BOB),
                ],
                instruction_data: vec![1, 2, 3],
                authorized_accounts: vec![ALICE],
            },
            &[],
        ),
        &mut script,
    )
    .unwrap()
    .public;

    assert_eq!(script.applied()[2].pre_data, data(b"s"));
    assert_eq!(public[0].1, funded(7).with_shard(OTHER_PROGRAM, data(b"s")));
}

#[test]
fn a_cleared_shard_reads_back_empty_and_stays_in_the_applied_projection() {
    let mut script = Script::new([
        planning(|call| {
            plan(call)
                .with_effects(vec![effect(&call.accounts[0], b"clear")])
                .with_chained_calls(vec![chained(
                    PROGRAM,
                    vec![ProgramShardSelector::new(ALICE, PROGRAM)],
                )])
        }),
        planning(|call| plan(call).with_effects(vec![effect(&call.accounts[0], b"read")])),
    ])
    .applying(|input| (input.effect_data == b"clear").then(ShardData::empty))
    .reading([(ALICE, funded(1).with_shard(PROGRAM, data(b"a")))]);
    let public = execute(
        start(root(vec![ProgramShardSelector::new(ALICE, PROGRAM)]), &[]),
        &mut script,
    )
    .unwrap()
    .public;

    assert_eq!(script.applied()[1].pre_data, ShardData::empty());
    assert_eq!(
        script.asked,
        vec![ProgramShardSelector::new(ALICE, PROGRAM)]
    );
    assert_eq!(public[0].1.shards[&PROGRAM], ShardData::empty());
}

#[test]
fn a_chained_call_cannot_name_an_account_the_root_did_not() {
    let result = execute(
        start(root(vec![ProgramShardSelector::native_balance(ALICE)]), &[]),
        &mut Script::new([planning(|call| {
            plan(call).with_chained_calls(vec![chained(
                PROGRAM,
                vec![ProgramShardSelector::native_balance(BOB)],
            )])
        })])
        .reading([(ALICE, funded(1)), (BOB, funded(1))]),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnknownAccount { account_id: BOB })
    ));
}

#[test]
fn a_witness_outside_the_root_inputs_is_rejected() {
    let keys = Keys::new(4);
    let witnesses = [keys.regular(true)];

    let result = ExecutionState::initialize(
        root(vec![ProgramShardSelector::native_balance(ALICE)]),
        &witnesses,
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
    let selectors = vec![ProgramShardSelector::native_balance(keys.regular_id())];

    let duplicate = [keys.regular(true), keys.regular(true)];
    assert!(matches!(
        ExecutionState::initialize(root(selectors.clone()), &duplicate).err(),
        Some(ExecutionError::DuplicateWitness { account_id }) if account_id == keys.regular_id()
    ));

    let mut unlinked = keys.regular(true);
    unlinked.kind = WitnessKind::Regular {
        ask: Some(other.ask),
    };
    let unlinked = [unlinked];
    assert!(matches!(
        ExecutionState::initialize(root(selectors), &unlinked).err(),
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
            ProgramShardSelector::native_balance(keys.pda_id(PROGRAM, SEED)),
            ProgramShardSelector::native_balance(other.pda_id(PROGRAM, SEED)),
        ]),
        &witnesses,
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
    let witnesses = [signer.regular(true), holder.regular(false)];
    let selectors = vec![
        ProgramShardSelector::native_balance(signer.regular_id()),
        ProgramShardSelector::native_balance(holder.regular_id()),
        ProgramShardSelector::native_balance(public_pda),
    ];
    let mut script = Script::deferring([
        planning(|call| {
            plan(call).with_chained_calls(vec![
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
                chained(OTHER_PROGRAM, selectors.clone()),
            ])
        }),
        planning(|call| plan(call).with_chained_calls(vec![chained(PROGRAM, selectors.clone())])),
    ])
    .reading([(public_pda, funded(1))]);
    let ExecutionOutcome { public, .. } =
        execute(start(root(selectors.clone()), &witnesses), &mut script).unwrap();

    assert_eq!(
        script
            .planned()
            .into_iter()
            .map(authorization)
            .collect::<Vec<_>>(),
        vec![
            vec![true, false, false],
            vec![true, false, true],
            vec![true, false, true],
            vec![true, false, false],
        ]
    );
    assert!(!public[0].is_authorized);
}

#[test]
fn a_private_pda_is_granted_only_by_its_own_seed_from_its_own_program() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let pda = keys.pda_id(PROGRAM, SEED);
    let selectors = vec![ProgramShardSelector::native_balance(pda)];
    let mut script = Script::new([
        planning(|call| {
            plan(call).with_chained_calls(vec![
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![OTHER_SEED]),
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
                chained(OTHER_PROGRAM, selectors.clone()),
            ])
        }),
        planning(|call| {
            plan(call).with_chained_calls(vec![
                chained(PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
            ])
        }),
    ]);
    let ExecutionOutcome {
        public,
        private_accounts,
        ..
    } = execute(start(root(selectors.clone()), &witnesses), &mut script).unwrap();

    assert_eq!(
        script
            .planned()
            .into_iter()
            .map(authorization)
            .collect::<Vec<_>>(),
        vec![
            vec![false],
            vec![false],
            vec![false],
            vec![true],
            vec![false]
        ]
    );
    assert!(public.is_empty());
    assert_eq!(private_accounts.len(), 1);
}

#[test]
fn a_public_pda_grant_under_a_privately_bound_seed_conflicts() {
    let keys = Keys::new(4);
    let witnesses = [keys.pda(PROGRAM, SEED)];
    let public_pda = AccountId::for_public_pda(&PROGRAM, &SEED);
    let selectors = vec![
        ProgramShardSelector::native_balance(keys.pda_id(PROGRAM, SEED)),
        ProgramShardSelector::native_balance(public_pda),
    ];
    let result = execute(
        start(root(selectors.clone()), &witnesses),
        &mut Script::new([planning(|call| {
            plan(call).with_chained_calls(vec![
                chained(OTHER_PROGRAM, selectors.clone()).with_pda_seeds(vec![SEED]),
            ])
        })])
        .reading([(public_pda, funded(1))]),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::FamilyBindingConflict { account_id, .. }) if account_id == public_pda
    ));
}

#[test]
fn calls_run_depth_first_in_sibling_order_up_to_the_limit() {
    let selectors = vec![ProgramShardSelector::native_balance(ALICE)];
    let mut script = Script::new([
        planning(|call| {
            plan(call).with_chained_calls(vec![
                chained(AccountId::new([1; 32]), selectors.clone()),
                chained(AccountId::new([3; 32]), selectors.clone()),
            ])
        }),
        planning(|call| {
            plan(call).with_chained_calls(vec![chained(AccountId::new([2; 32]), selectors.clone())])
        }),
    ])
    .reading([(ALICE, funded(1))]);
    execute(start(root(selectors.clone()), &[]), &mut script).unwrap();
    assert_eq!(
        script
            .planned()
            .into_iter()
            .map(|call| call.self_account_id)
            .collect::<Vec<_>>(),
        vec![
            PROGRAM,
            AccountId::new([1; 32]),
            AccountId::new([2; 32]),
            AccountId::new([3; 32])
        ]
    );

    let chain = |count: usize| {
        execute(
            start(root(selectors.clone()), &[]),
            &mut Script::new([planning(|call| {
                plan(call)
                    .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone()); count])
            })])
            .reading([(ALICE, funded(1))]),
        )
    };
    assert!(chain(MAX_NUMBER_CHAINED_CALLS).is_ok());
    assert!(matches!(
        chain(MAX_NUMBER_CHAINED_CALLS + 1),
        Err(ExecutionError::MaxChainedCallsExceeded)
    ));
}

#[test]
fn validation_and_window_failures_name_the_program() {
    let selectors = vec![ProgramShardSelector::native_balance(ALICE)];
    let result = execute(
        start(root(selectors.clone()), &[]),
        &mut Script::new([planning(|call| {
            plan(call).with_effects(vec![effect(&call.accounts[0], b"pay")])
        })])
        .applying(|_| Some(encode_balance(1)))
        .reading([(ALICE, funded(1))]),
    );
    assert!(matches!(
        result,
        Err(ExecutionError::ExecutionValidation {
            program_account_id: PROGRAM,
            source: ExecutionValidationError::ForeignShardWrite {
                account_id: ALICE,
                executing_account_id: PROGRAM
            }
        })
    ));

    let result = execute(
        start(root(selectors.clone()), &[]),
        &mut Script::new([
            planning(|call| {
                plan(call)
                    .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
                    .try_with_block_validity_window(1..3)
                    .unwrap()
            }),
            planning(|call| plan(call).with_block_validity_window(3..)),
        ])
        .reading([(ALICE, funded(1))]),
    );
    assert!(matches!(
        result,
        Err(ExecutionError::EmptyBlockWindowIntersection)
    ));
}

#[test]
fn the_final_windows_are_the_intersection_of_every_call() {
    let selectors = vec![ProgramShardSelector::native_balance(ALICE)];
    let ExecutionOutcome {
        block_validity_window,
        timestamp_validity_window,
        ..
    } = execute(
        start(root(selectors.clone()), &[]),
        &mut Script::new([
            planning(|call| {
                plan(call)
                    .with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
                    .try_with_block_validity_window(1..5)
                    .unwrap()
                    .with_timestamp_validity_window(..9)
            }),
            planning(|call| {
                plan(call)
                    .with_block_validity_window(2..)
                    .try_with_timestamp_validity_window(4..7)
                    .unwrap()
            }),
        ])
        .reading([(ALICE, funded(1))]),
    )
    .unwrap();

    assert_eq!(block_validity_window, (2..5).try_into().unwrap());
    assert_eq!(timestamp_validity_window, (4..7).try_into().unwrap());
}

#[test]
fn a_duplicated_root_account_is_rejected_by_the_transition_rules() {
    let result = execute(
        start(
            root(vec![
                ProgramShardSelector::native_balance(ALICE),
                ProgramShardSelector::native_balance(ALICE),
            ]),
            &[],
        ),
        &mut Script::new([]),
    );

    assert!(matches!(
        result,
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
    let witnesses = [keys.update(private_account)];
    let ExecutionOutcome {
        public,
        private_accounts,
        ..
    } = execute(
        start(
            signed_root(
                vec![
                    ProgramShardSelector::native_balance(BOB),
                    ProgramShardSelector::new(keys.regular_id(), PROGRAM),
                    ProgramShardSelector::native_balance(ALICE),
                ],
                vec![BOB],
            ),
            &witnesses,
        ),
        &mut Script::new([planning(|call| {
            plan(call).with_effects(vec![
                effect(&call.accounts[0], b"keep"),
                effect(&call.accounts[1], b"write"),
                effect(&call.accounts[2], b"keep"),
            ])
        })])
        .applying(|input| {
            (input.selector.account_id == keys.regular_id()).then(|| data(b"written"))
        })
        .reading([
            (ALICE, funded(1).with_shard(CAROL, data(b"untouched"))),
            (BOB, funded(2)),
        ]),
    )
    .unwrap();

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
fn a_failed_completion_stops_the_execution() {
    let selectors = vec![ProgramShardSelector::native_balance(ALICE)];
    let mut script = Script::new([planning(|call| {
        plan(call).with_chained_calls(vec![chained(OTHER_PROGRAM, selectors.clone())])
    })])
    .rejecting_completion(ExecutionError::EmptyBlockWindowIntersection)
    .reading([(ALICE, funded(1))]);
    let result = execute(start(root(selectors.clone()), &[]), &mut script);

    assert!(matches!(
        result,
        Err(ExecutionError::EmptyBlockWindowIntersection)
    ));
    assert!(matches!(
        script.trace.as_slice(),
        [Trace::Plan(_), Trace::Complete(PROGRAM, _)]
    ));
}

#[test]
fn a_pending_shard_is_known_only_once_observed_and_a_cleared_one_stays_known() {
    let selectors = vec![ProgramShardSelector::new(ALICE, PROGRAM)];
    let mut script = Script::new([
        seeing(|call, state| {
            assert_eq!(state.pending_shard(ALICE, PROGRAM), None);
            assert_eq!(state.pending_shard(BOB, PROGRAM), None);
            plan(call)
                .with_effects(vec![effect(&call.accounts[0], b"clear")])
                .with_chained_calls(vec![chained(PROGRAM, selectors.clone())])
        }),
        seeing(|call, state| {
            assert_eq!(
                state.pending_shard(ALICE, PROGRAM),
                Some(&ShardData::empty())
            );
            assert_eq!(state.pending_shard(ALICE, OTHER_PROGRAM), None);
            plan(call)
        }),
    ])
    .applying(|_| Some(ShardData::empty()))
    .reading([(
        ALICE,
        funded(1)
            .with_shard(PROGRAM, data(b"a"))
            .with_shard(OTHER_PROGRAM, data(b"b")),
    )]);

    execute(start(root(selectors.clone()), &[]), &mut script).unwrap();
    assert_eq!(script.planned().len(), 2);
}
