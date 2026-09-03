use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post = AccountStateDiff::new_claimed(
        pre.clone(),
        BalanceDiff::Add(0),
        pre.account.data,
        Claim::Authorized,
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![account_post],
    )
    .write();
}
