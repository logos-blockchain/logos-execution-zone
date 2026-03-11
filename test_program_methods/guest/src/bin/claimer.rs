#![expect(clippy::manual_let_else, reason = "Looks much better")]

use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let [pre] = match pre_states.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_post = AccountPostState::new_claimed(pre.account.clone());

    write_nssa_outputs(instruction_words, vec![pre], vec![account_post]);
}
