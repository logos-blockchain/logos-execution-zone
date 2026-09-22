use associated_token_account_core::Instruction;
use lee_core::program::{LeeCall, read_lee_call, resolve_keep};

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            associated_token_account_program::execute(&input, instruction_data).write()
        }
        // This program owns no shard: every effect it emits inspects a Token Program shard,
        // so none of them can write.
        LeeCall::Resolve(input) => {
            associated_token_account_program::resolve(&input);
            resolve_keep(input)
        }
    }
}
