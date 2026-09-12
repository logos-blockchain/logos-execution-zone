use lee_core::{
    account::ShardData,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Writes its own shard on both accounts, but reports its two diffs in the opposite order from
/// `pre_states` — proves order is irrelevant now that each diff embeds its own pre-state, unlike
/// the old two-array `pre_states`/`post_diffs` shape where a reordered report was rejected.
type Instruction = Vec<u8>;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first_pre, second_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let written = data.try_into().expect("written data fits the data limit");
    let first_diff = AccountStateDiff::new(first_pre, written);
    let second_diff = AccountStateDiff::new(second_pre, ShardData::empty());

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        // Swapped: the second account's diff first, the first account's second.
        vec![second_diff, first_diff],
    )
    .write();
}
