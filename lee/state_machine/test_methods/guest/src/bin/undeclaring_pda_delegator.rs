use borsh::to_vec;
use lee_core::{
    account::AccountId,
    program::{
        ChainedCall, InstructionData, PdaSeed, ProgramInput, ProgramOutput, read_lee_inputs,
    },
};

type Instruction = (
    Option<PdaSeed>,
    bool,
    AccountId,
    InstructionData,
    Option<AccountId>,
);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            mut pre_states,
            instruction: (seed, declare_authorized, callee_account_id, callee_instruction, sibling),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Some(first) = pre_states.first_mut() else {
        return;
    };
    first.is_authorized = declare_authorized;

    let sibling_call = sibling.map(|sibling_account_id| {
        let mut sibling_pre = pre_states[0].clone();
        sibling_pre.is_authorized = true;
        ChainedCall {
            program_account_id: sibling_account_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_states: vec![sibling_pre],
            pda_seeds: vec![],
        }
    });

    let mut chained_calls = vec![ChainedCall {
        program_account_id: callee_account_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: seed.into_iter().collect(),
    }];
    chained_calls.extend(sibling_call);

    // Emit an output with only chained calls and no pre or post-states.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        Vec::new(),
        Vec::new(),
    )
    .with_chained_calls(chained_calls)
    .write();
}
