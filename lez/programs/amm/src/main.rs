//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use amm_program::core::Instruction;
use lee_core::program::{LeeCall, read_lee_call, resolve_keep, resolve_write};

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            amm_program::execute(input, instruction_data).write()
        }
        LeeCall::Resolve(input) => match amm_program::resolve(&input) {
            Some(data) => resolve_write(input, data),
            None => resolve_keep(input),
        },
    }
}
