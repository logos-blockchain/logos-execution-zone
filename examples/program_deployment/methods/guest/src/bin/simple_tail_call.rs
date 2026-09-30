use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, Plan, ProgramCall, read_program_call},
};

// Tail Call example program.
//
// Reads a single account, emits it unchanged, and performs a tail call to the callee program
// named in its own instruction data, with a fixed greeting.
//
// The callee's `AccountId` is caller-supplied: a deployed program's address isn't known until
// deploy time, so it can't be a compile-time constant.

type Instruction = AccountId;

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("simple_tail_call emits no effect to apply")
    };
    let callee_account_id = instruction;

    // Unpack the single input account handle.
    let [account] = <[_; 1]>::try_from(input.accounts.clone())
        .unwrap_or_else(|_| panic!("Input accounts should consist of a single account"));

    let greeting: Vec<u8> = b"Hello from tail call".to_vec();

    // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to commit
    // it.
    let mut plan = Plan::new(&input);
    plan.call(ChainedCall::new(
        callee_account_id,
        vec![ProgramShardSelector::new(
            account.account_id,
            callee_account_id,
        )],
        &greeting,
    ));
    plan.write()
}
