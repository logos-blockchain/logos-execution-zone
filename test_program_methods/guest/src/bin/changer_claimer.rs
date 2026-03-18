use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it.
fn main() {
    let (
        ProgramInput {
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
        AccountPostState::new_claimed(account_post)
    } else {
        AccountPostState::new(account_post)
    };

    write_nssa_outputs(instruction_words, vec![pre], vec![post_state]);
}
