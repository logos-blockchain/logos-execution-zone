use lee_core::{
    account::{AccountId, Actor},
    program::{Envelope, PdaSeed, ReceiveInput, Response, run_actor},
};

// Tail Call with PDA example program.
//
// Expects to receive at an account whose Account ID is derived from this program's deployed
// address and the fixed PDA seed below (`AccountId::for_public_pda`). Keeps its own shard
// unchanged, then sends a fixed greeting to that account's actor under the callee program named
// in its message, granting the PDA seed so the protocol authorizes the account for the callee.
//
// The callee's `AccountId` is caller-supplied: a deployed program's address isn't known until
// deploy time, so it can't be a compile-time constant.

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, callee_account_id: AccountId) -> Response {
    let greeting: Vec<u8> = b"Hello from tail call with Program Derived Account ID".to_vec();

    Response::keep().send(
        Envelope::new(
            Actor::new(input.receiver.account_id, callee_account_id),
            &greeting,
        )
        .with_pda_seeds(vec![PDA_SEED]),
    )
}
