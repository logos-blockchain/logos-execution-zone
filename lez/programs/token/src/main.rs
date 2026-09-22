//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use lee_core::program::{LeeCall, read_lee_call, resolve_keep, resolve_write};
use token_program::core::Instruction;

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            token_program::execute(input, instruction_data).write()
        }
        LeeCall::Resolve(input) => match token_program::resolve(&input) {
            Some(data) => resolve_write(input, data),
            None => resolve_keep(input),
        },
    }
}
