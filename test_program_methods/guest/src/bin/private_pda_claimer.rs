use nssa_core::{
    NullifierPublicKey,
    program::{AccountPostState, Claim, PdaSeed, ProgramInput, ProgramOutput, read_nssa_inputs},
};

type Instruction = (PdaSeed, NullifierPublicKey);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (seed, npk),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post =
        AccountPostState::new_claimed(pre.account.clone(), Claim::PrivatePda { seed, npk });

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![account_post],
    )
    .write();
}
