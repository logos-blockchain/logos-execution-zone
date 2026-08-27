use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it.
fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (data_opt, should_claim),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut diff = AccountDiff::unchanged(pre.account_id);

    // Update data if provided
    if let Some(data) = data_opt {
        diff.diff_data = Some(
            data.try_into()
                .expect("provided data should fit into data limit"),
        );
    }

    // Claim or not based on the boolean flag
    let post_state = if should_claim {
        AccountDiffOutput::new_claimed(diff, Claim::Authorized)
    } else {
        AccountDiffOutput::new(diff)
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![post_state],
    )
    .write();
}
