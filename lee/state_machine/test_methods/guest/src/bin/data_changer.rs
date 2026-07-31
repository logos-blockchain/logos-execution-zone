use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, data::Data, data::DataTooBigError},
    program::{AccountDiffOutput, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: data,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Sanity check only — the authoritative check happens wherever `raw_diff` actually gets
    // applied (`update_from_diff`, not yet wired up on the orchestrator side); this just gives an
    // early, in-guest failure for the same case, same as the program did before.
    let _: Data = data
        .clone()
        .try_into()
        .expect("provided data should fit into data limit");

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        raw_diff: Some(data),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new_claimed(diff, Claim::Authorized)],
    )
    .write();
}


#[expect(
    dead_code,
    reason = "placeholder: not called by main() yet — the orchestrator's raw_diff dispatch \
              mechanism isn't wired up. Kept as a tested building block for once it is."
)]
fn update_from_diff(pre_state: Account, diff: AccountDiff) -> Result<Account, DataTooBigError> {
    let mut post_state = pre_state;

    if let Some(raw_diff) = diff.raw_diff {
        post_state.data = raw_diff.try_into()?;
    }

    Ok(post_state)
}