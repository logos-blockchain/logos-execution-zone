use nssa_core::program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it.
fn main() {
    let (
        ProgramInput { self_program_id,
            pre_states,
            instruction: (data_opt, should_claim),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();

    // Update data if provided
    if let Some(data) = data_opt {
        account_post.data = data
            .try_into()
            .expect("provided data should fit into data limit");
    }

    // Claim or not based on the boolean flag
    let post_state = if should_claim {
        AccountPostState::new_claimed(account_post, Claim::Authorized)
    } else {
        AccountPostState::new(account_post)
    };

    ProgramOutput::new(self_program_id, instruction_words, vec![pre], vec![post_state]).write();
}
