use lee_core::program::{AccountDiffOutput, ProgramCall, read_lee_call};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let [pre1, _pre2] = input.pre_states.as_slice() else {
        return;
    };

    let account_id_pre1 = pre1.account_id;

    input
        .into_output(vec![AccountDiffOutput::unchanged(account_id_pre1)])
        .write();
}
