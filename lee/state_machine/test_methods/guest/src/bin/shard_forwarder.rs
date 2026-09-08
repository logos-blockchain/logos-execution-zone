use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data, ProgramShardSelector},
    program::{
        AccountStateDiff, ChainedCall, InstructionData, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (
    Option<(AccountId, Vec<u8>)>,
    Vec<(AccountId, ProgramShardSelector, InstructionData)>,
);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (own_write, callees),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([own]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut state_diffs = vec![AccountStateDiff::unchanged(own)];
    if let Some((target, data)) = own_write {
        state_diffs.push(AccountStateDiff::new(
            AccountInput::with_shard(target, false, 0, self_account_id, Data::empty()),
            BalanceDiff::Add(0),
            data.try_into()
                .expect("provided data should fit into data limit"),
        ));
    }

    let chained_calls = callees
        .into_iter()
        .map(|(callee, shard_selector, callee_instruction)| ChainedCall {
            program_account_id: callee,
            instruction_data: callee_instruction,
            shard_selectors: vec![shard_selector],
            pda_seeds: vec![],
        })
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
