use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, InstructionData, PdaSeed, Plan, ProgramCall, ProgramId, read_program_call,
    },
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds`, which is how a program-held
/// authority acts on a callee.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("authority_proxy emits no effect to apply")
    };
    let (target_program_id, target_instruction_data, pda_seed) = instruction;

    let mut plan = Plan::new(&input);
    plan.call(ChainedCall {
        program_account_id: AccountId::from_builtin_program(target_program_id),
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
