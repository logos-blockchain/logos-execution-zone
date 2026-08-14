use lee_core::program::{
    AccountPostState, Claim, PdaSeed, ProgramInput, ProgramOutput, read_lee_inputs,
};

type Instruction = PdaSeed;

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: seed,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post = AccountPostState::new_claimed(pre.account.clone(), Claim::Pda(seed));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![pre],
        vec![account_post],
    )
    .write();
}
