use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};
use referral_program::core::Instruction;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    assert!(
        caller_account_id.is_none(),
        "referral instructions are only invoked as top-level user transactions"
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        referral_program::execute(self_account_id, pre_states, instruction),
    )
    .write();
}
