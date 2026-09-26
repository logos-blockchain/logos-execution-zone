use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{
        AccountMeta, ApplyInput, ApplyOutput, CallKind, GuestOutput, InstructionData, PlanInput,
    },
    to_borsh_frame, to_frame,
};
use risc0_zkvm::{ExecutorEnv, default_executor};

use crate::{
    error::LeeError,
    program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program, apply_journal, plan_journal},
};

fn write_fixture() -> (Program, Vec<AccountMeta>, Vec<u8>, Vec<u8>) {
    let program = crate::test_methods::data_changer();
    let written = vec![7_u8; 4];
    let instruction_data = Program::serialize_instruction(written.clone()).unwrap();
    let target = AccountMeta::new(
        AccountId::new([0; 32]),
        true,
        AccountId::from_builtin_program(program.id()),
    );
    (program, vec![target], instruction_data, written)
}

fn top_level_input(
    program: &Program,
    accounts: Vec<AccountMeta>,
    instruction: InstructionData,
) -> PlanInput {
    PlanInput {
        self_account_id: AccountId::from_builtin_program(program.id()),
        caller_account_id: None,
        accounts,
        instruction_data: instruction,
    }
}

fn apply_input(program: &Program, effect: &[u8], pre_data: ShardData) -> ApplyInput {
    ApplyInput {
        self_account_id: AccountId::from_builtin_program(program.id()),
        selector: ProgramShardSelector::new(
            AccountId::new([0; 32]),
            AccountId::from_builtin_program(program.id()),
        ),
        pre_data,
        effect_data: borsh::to_vec(&effect.to_vec()).unwrap(),
    }
}

#[test]
fn program_execution() {
    let (program, accounts, instruction_data, written) = write_fixture();

    let (plan, _cycles) = program
        .plan(
            &top_level_input(&program, accounts.clone(), instruction_data),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap();

    // The plan names the shard it intends to change and the bytes it proposes, and nothing else:
    // no shard contents went in and none came out.
    assert_eq!(plan.input.accounts, accounts);
    let [effect] = <[_; 1]>::try_from(plan.effects).unwrap();
    assert_eq!(effect.selector, ProgramShardSelector::from(&accounts[0]));
    assert_eq!(effect.data, borsh::to_vec(&written).unwrap());
}

#[test]
fn an_apply_writes_the_effect_the_plan_emitted() {
    let (program, accounts, instruction_data, written) = write_fixture();
    let (plan, _cycles) = program
        .plan(
            &top_level_input(&program, accounts, instruction_data),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap();
    let [effect] = <[_; 1]>::try_from(plan.effects).unwrap();
    let input = ApplyInput {
        self_account_id: AccountId::from_builtin_program(program.id()),
        selector: effect.selector,
        pre_data: ShardData::empty(),
        effect_data: effect.data,
    };

    let (output, _) = program
        .apply(&input, DEFAULT_PUBLIC_CYCLE_BUDGET)
        .expect("apply runs");

    // `apply` echoes the exact input it was handed — that echo is what the engine matches
    // against the apply input it scheduled.
    assert_eq!(output.input, input);
    assert_eq!(
        output.post_data,
        Some(written.try_into().unwrap()),
        "apply writes the bytes its own plan proposed"
    );
}

#[test]
fn journal_is_the_borsh_frame_of_the_output_and_echoes_instruction_data() {
    let (program, accounts, instruction_data, _) = write_fixture();

    let mut env_builder = ExecutorEnv::builder();
    Program::write_plan_inputs(
        &top_level_input(&program, accounts, instruction_data.clone()),
        &mut env_builder,
    )
    .unwrap();
    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .unwrap();

    let payload = lee_core::from_frame(&session_info.journal.bytes).unwrap();
    let output: GuestOutput = borsh::from_slice(payload).unwrap();

    // The journal must be byte-identical to `to_frame(borsh(output))`: the privacy circuit
    // reconstructs exactly these bytes for `env::verify`, so any drift breaks recursion.
    assert_eq!(
        session_info.journal.bytes,
        lee_core::to_frame(&borsh::to_vec(&output).unwrap())
    );
    let GuestOutput::Plan(plan) = output else {
        panic!("the Execute entrypoint must commit a plan journal")
    };
    // The guest must echo the instruction bytes verbatim: chained-call binding compares them.
    assert_eq!(plan.input.instruction_data, instruction_data);
}

#[test]
fn each_entrypoint_commits_its_own_journal_tag() {
    let (program, _accounts, _instruction_data, written) = write_fixture();

    let mut env_builder = ExecutorEnv::builder();
    Program::write_apply_inputs(
        &apply_input(&program, &written, ShardData::empty()),
        &mut env_builder,
    )
    .unwrap();
    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .unwrap();

    // Same image, same program: only the tag distinguishes what this receipt attests to.
    assert!(matches!(
        apply_journal(&session_info.journal.bytes),
        Ok(ApplyOutput { .. })
    ));
}

#[test]
fn a_plan_journal_is_not_accepted_where_an_apply_was_scheduled() {
    let plan = GuestOutput::Plan(lee_core::program::PlanOutput::new(
        lee_core::program::PlanInput {
            self_account_id: AccountId::new([1; 32]),
            caller_account_id: None,
            accounts: Vec::new(),
            instruction_data: Vec::new(),
        },
    ));

    let err = apply_journal(&to_borsh_frame(&plan)).unwrap_err();

    assert!(
        matches!(&err, LeeError::ProgramExecutionFailed(msg)
            if msg.contains("a scheduled apply returned a plan journal")),
        "expected an entrypoint mismatch, got: {err:?}"
    );
}

#[test]
fn an_apply_journal_is_not_accepted_where_a_plan_was_scheduled() {
    let output = GuestOutput::Apply(ApplyOutput {
        input: ApplyInput {
            self_account_id: AccountId::new([1; 32]),
            selector: ProgramShardSelector::native_balance(AccountId::new([2; 32])),
            pre_data: ShardData::empty(),
            effect_data: Vec::new(),
        },
        post_data: None,
    });

    let err = plan_journal(&to_borsh_frame(&output)).unwrap_err();

    assert!(
        matches!(&err, LeeError::ProgramExecutionFailed(msg)
            if msg.contains("a scheduled plan returned an apply journal")),
        "expected an entrypoint mismatch, got: {err:?}"
    );
}

#[test]
fn malformed_journal_frame_is_an_error_not_a_panic() {
    let program = crate::test_methods::malformed_journal();
    let err = program
        .plan(
            &top_level_input(&program, Vec::new(), Vec::new()),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap_err();
    assert!(
        matches!(
            &err,
            crate::error::LeeError::ProgramExecutionFailed(msg)
                if msg.contains("malformed program journal frame")
        ),
        "expected malformed-frame ProgramExecutionFailed, got: {err:?}"
    );
}

#[test]
fn execute_reports_cycles_within_budget() {
    let (program, accounts, instruction_data, _) = write_fixture();
    let (_, cycles) = program
        .plan(
            &top_level_input(&program, accounts, instruction_data),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .expect("executes");
    assert!(cycles > 0);
    // Holds because this write costs far less than the budget; not a general
    // invariant — a session can overshoot its limit by up to one instruction.
    assert!(cycles <= DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn tiny_budget_is_out_of_gas() {
    let (program, accounts, instruction_data, _) = write_fixture();
    let result = program.plan(
        &top_level_input(&program, accounts, instruction_data),
        1_024,
    );
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

/// There is no capability probe in this model: a guest handed a call kind it cannot decode must
/// fail rather than answer with a no-op that would count as success.
#[test]
fn an_unrecognized_call_kind_fails_the_guest() {
    let (program, accounts, instruction_data, _) = write_fixture();

    let mut env_builder = ExecutorEnv::builder();
    // Stands in for a call kind a future protocol upgrade defines; 77 is not a defined
    // discriminant.
    env_builder.write_slice(&to_frame(&[77_u8]));
    let input = top_level_input(&program, accounts, instruction_data);
    env_builder.write_slice(&to_frame(&borsh::to_vec(&input).unwrap()));

    let err = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .expect_err("an unrecognized call kind must fail guest execution");

    assert!(
        format!("{err:#}").contains("call kind must decode from borsh"),
        "expected a call-kind decode failure, got: {err:#}"
    );
}

#[test]
fn the_call_kind_frame_is_a_bare_discriminant_byte() {
    assert_eq!(to_borsh_frame(&CallKind::Plan), to_frame(&[0]));
    assert_eq!(to_borsh_frame(&CallKind::Apply), to_frame(&[1]));
}

/// A guest that halts with a non-zero code is rejected, but unlike a panic the session survives:
/// the error carries the metered cycles so the caller can charge them.
#[test]
fn nonzero_exit_is_rejected_with_its_cycles() {
    let program = crate::test_methods::exits_nonzero();
    let err = program
        .plan(
            &top_level_input(&program, Vec::new(), Vec::new()),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeeError::ProgramExitedWithCode { code: 3, cycles } if cycles > 0),
        "expected ProgramExitedWithCode {{ code: 3, cycles > 0 }}, got: {err:?}"
    );
}
