use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs},
};

/// Echoes its real `pre_states` unchanged, then appends one fabricated, untouched account never
/// present in its own input — to test whether reporting it in `ProgramOutput.pre_states` alone
/// is enough to get it resolved, independent of `ChainedCall.pre_state_ids`.
type Instruction = AccountId;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: fabricated_account_id,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let mut output_pre_states = pre_states.clone();
    let mut output_post_states: Vec<AccountPostState> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    output_pre_states.push(AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: fabricated_account_id,
    });
    output_post_states.push(AccountPostState::new(Account::default()));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        output_pre_states,
        output_post_states,
    )
    .write();
}
