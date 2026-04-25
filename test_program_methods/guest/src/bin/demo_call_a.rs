#![no_main]

use lez_sdk::prelude::*;
use nssa_core::program::{AccountPostState, ProgramId};
use serde::{Deserialize, Serialize};

// Local state that we want to preserve while Program A is temporarily "paused"
#[derive(Serialize, Deserialize)]
struct MyContext {
    user_id: u64,
    initial_balance: u64,
}

lez_dispatcher! {
    public: [ start_chain ],
    internal: [ continue_chain ]
}

/// Public entrypoint called by the user at the start of the tx
#[public]
fn start_chain(ctx: ExecCtx, (user_id, amount, target_b_id): (u64, u64, ProgramId)) -> Vec<AccountPostState> {
    // Save the data that will be needed later
    let local_state = MyContext { user_id, initial_balance: 1000 };
    
    // Call B asynchronously (CPS).
    // This macro generates a Capability Ticket and immediately stops the VM.
    call_program!(
        ctx: ctx,
        target: target_b_id,
        func: process_funds(amount) => then continue_chain(local_state)
    );
}

/// Continuation function (can only be called if it has a valid Capability Ticket from the Sequencer)
#[internal]
fn continue_chain(_ctx: ExecCtx, local_state: MyContext, b_success: bool) -> Vec<AccountPostState> {
    // If B fails, we explicitly abort.
    // The Sequencer will discard the state_diff (O(1) rollback) because we return a panic.
    if !b_success {
        panic!("Transaction aborted by Program B. Rollback A's state!");
    }

    // If successful, complete the state mutation using the preserved local_state
    // In the original ecosystem, would return an AccountPostState that changes the balance.
    let _final_balance = local_state.initial_balance + 500;
    
    // (Simulated success without modifying the Merkle tree for this demo)
    vec![]
}