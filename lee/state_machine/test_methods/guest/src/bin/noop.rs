use lee_core::program::{AccountDiffOutput, ProgramCall, read_lee_call};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let post_states = input
        .pre_states
        .iter()
        .map(|account| AccountDiffOutput::unchanged(account.account_id))
        .collect();
    input.into_output(post_states).write();
}
