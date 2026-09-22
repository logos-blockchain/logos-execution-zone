use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, InstructionData, LeeCall, PdaSeed, Plan, ProgramId, read_lee_call},
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds`, which is how a program-held
/// authority acts on a callee.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("authority_proxy emits no effect to resolve")
    };
    let (target_program_id, target_instruction_data, pda_seed) = input.instruction.clone();

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall {
        program_account_id: target_program_id.into(),
        instruction_data: target_instruction_data,
        shard_selectors: input
            .accounts
            .iter()
            .map(ProgramShardSelector::from)
            .collect(),
        pda_seeds: pda_seed.into_iter().collect(),
    });
    plan.write()
}
