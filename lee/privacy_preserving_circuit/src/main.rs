use std::{convert::Infallible, fmt};

use lee_core::{
    PrivacyPreservingCircuitInput,
    account::AccountWithMetadata,
    execution_state::{ExecutionState, index_by_account_id},
    program::{CallContext, ChainedCall, ProgramEffects, ProgramOutput, read_input_frame},
};
use risc0_zkvm::guest::env;

mod output;

/// The prover supplied fewer `ProgramEffects` than the walk has calls to serve.
struct InsufficientEffects;

impl fmt::Display for InsufficientEffects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Insufficient program effects for chained calls")
    }
}

impl fmt::Debug for InsufficientEffects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn main() {
    let PrivacyPreservingCircuitInput {
        program_effects,
        top_level_program_id,
        top_level_instruction_data,
        top_level_accounts,
        input_accounts,
        dummy_inputs,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let input_accounts = index_by_account_id(input_accounts).unwrap_or_else(|e| panic!("{e}"));

    let mut effects = program_effects.into_iter();
    let execution_state = ExecutionState::derive(
        &input_accounts,
        ChainedCall {
            program_id: top_level_program_id,
            instruction_data: top_level_instruction_data,
            accounts: top_level_accounts,
            pda_seeds: Vec::new(),
        },
        |call, pre_states| verify_call(&mut effects, call, pre_states),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        effects.next().is_none(),
        "Inner call without a chained call found"
    );

    let output = output::compute_circuit_output(execution_state, &input_accounts, dummy_inputs);

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}

/// Bind one call's effects to the call the walk derived. A receipt binds a program's image and
/// its journal, never its inputs, so the journal is assembled here from the walk's own
/// `CallContext` and `pre_states`: a program run on other accounts, at other values, or under
/// other authorizations than the ones derived here discharges nothing and the proof fails.
fn verify_call(
    effects: &mut impl Iterator<Item = ProgramEffects>,
    call: CallContext,
    pre_states: Vec<AccountWithMetadata>,
) -> Result<ProgramOutput, InsufficientEffects> {
    let effects = effects.next().ok_or(InsufficientEffects)?;
    let program_id = call.self_program_id;
    let program_output = ProgramOutput {
        call,
        pre_states,
        effects,
    };
    env::verify(program_id, &lee_core::to_borsh_frame(&program_output))
        .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
    Ok(program_output)
}
