use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, Claim, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = PdaSeed;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: seed,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post_data = pre.account.data.clone();
    let account_post =
        AccountStateDiff::new_claimed(pre, BalanceDiff::Add(0), post_data, Claim::Pda(seed));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![account_post],
    )
    .write();
}
