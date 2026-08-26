use borsh::to_vec;
use lee_core::{
    account::Input,
    program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

type Instruction = (ProgramId, u128);
// (faucet_program_id, amount)

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (faucet_program_id, amount),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states: Vec<_> = pre_states.iter().map(Input::unchanged).collect();

    assert_eq!(pre_states.len(), 2);
    let [faucet_pre, recipient_pre] = [pre_states[0].clone(), pre_states[1].clone()];

    let chained_calls = vec![ChainedCall {
        program_id: faucet_program_id,
        instruction_data: to_vec(&faucet_core::Instruction::GenesisTransferDirect { amount })
            .unwrap(),
        pre_states: vec![faucet_pre, recipient_pre],
        pda_seeds: vec![],
    }];

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
