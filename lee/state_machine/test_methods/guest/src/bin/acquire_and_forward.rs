use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ChainedCall, InstructionData, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

/// Data to write into the account (`None` echoes it instead), the callee to forward it
/// to, and the callee's instruction.
type Instruction = (Option<Vec<u8>>, ProgramId, InstructionData);

/// Acquires the account by writing data to it or echoes, then forwards it to the callee.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (data, callee, callee_instruction),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([target]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let chained_call = ChainedCall {
        program_account_id: callee.into(),
        instruction_data: callee_instruction,
        pre_state_ids: vec![target.account_id],
        pda_seeds: vec![],
    };

    let target_diff = match data {
        Some(data) => AccountStateDiff::new(
            target,
            BalanceDiff::Add(0),
            data.try_into()
                .expect("provided data should fit into data limit"),
        ),
        None => AccountStateDiff::unchanged(target),
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![target_diff],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
