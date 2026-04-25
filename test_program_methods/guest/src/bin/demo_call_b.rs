#![no_main]

use lez_sdk::prelude::*;
use nssa_core::program::AccountPostState;

// Register the dispatcher for ZKVM
lez_dispatcher! {
    public: [ process_funds ],
    internal: [] // Program B in this demo does not have any internal continuation
}

/// Public function that will be called by Program A via tail-call
#[public]
fn process_funds(ctx: ExecCtx, amount: u64) -> Vec<AccountPostState> {
    // 1. Extract the return route entrusted by Program A
    // The general call instruction will be parsed automatically by the dispatcher
    let instruction: GeneralCallInstruction = risc0_zkvm::serde::from_slice(&ctx.raw_instruction_data)
        .expect("Failed to parse instruction in B");
    let route = instruction.route.expect("Program B needs a ReturnRoute to answer the call!");

    // 2. Perform computation (example: calculation succeeds if amount > 0)
    let is_success = amount > 0;

    // 3. Return the result to Program A (This will end B's execution)
    return_to_caller!(ctx: ctx, route: route, result: is_success);
}