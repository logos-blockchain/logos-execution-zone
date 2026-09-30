use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, PdaSeed, Plan, ProgramCall, read_program_call},
};

// Tail Call with PDA example program.
//
// Expects a single input account whose Account ID is derived from this program's deployed
// address and the fixed PDA seed below (`AccountId::for_public_pda`). Emits it unchanged, then
// tail-calls the callee program named in its own instruction data, delegating the PDA seed so
// the protocol authorizes the account for the callee.
//
// The callee's `AccountId` is caller-supplied: a deployed program's address isn't known until
// deploy time, so it can't be a compile-time constant.

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

type Instruction = AccountId;

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("tail_call_with_pda emits no effect to apply")
    };
    let callee_account_id = instruction;

    // Unpack the single input account handle.
    let [account] = <[_; 1]>::try_from(input.accounts.clone())
        .unwrap_or_else(|_| panic!("Input accounts should consist of a single account"));

    let greeting: Vec<u8> = b"Hello from tail call with Program Derived Account ID".to_vec();

    // WARNING: building a `Plan` has no effect on its own. `.write()` must be called to commit
    // it.
    let mut plan = Plan::new(&input);
    plan.call(
        ChainedCall::new(
            callee_account_id,
            vec![ProgramShardSelector::new(
                account.account_id,
                callee_account_id,
            )],
            &greeting,
        )
        .with_pda_seeds(vec![PDA_SEED]),
    );
    plan.write()
}
