use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
    respond_unsupported_call,
};

type Instruction = Vec<u8>;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([target, other]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let target_diff = ShardStateDiff::new(
        target,
        data.try_into()
            .expect("provided data should fit into data limit"),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![target_diff, ShardStateDiff::unchanged(other)],
    )
    .write();
}
