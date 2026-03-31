use nssa_core::program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_post = AccountPostState::new_claimed(pre.account.clone(), Claim::Authorized);

    ProgramOutput::new(instruction_words, vec![pre], vec![account_post]).write();
}
