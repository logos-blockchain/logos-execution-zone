use lee_core::program::{
    ApplyOutput, ChainedCall, GuestOutput, Plan, ProgramCall, read_program_call,
};

fn main() {
    match read_program_call::<()>() {
        ProgramCall::Plan(input, ()) => {
            let mut plan = Plan::new(&input);
            let own = input
                .accounts
                .first()
                .expect("the first handle is the program's own shard");
            plan.effect(own, &());
            plan.write()
        }
        ProgramCall::Apply(input) => {
            let call = ChainedCall::new(input.self_account_id, Vec::new(), &());
            GuestOutput::Apply(ApplyOutput {
                chained_calls: vec![call],
                ..ApplyOutput::new(input, None)
            })
            .write();
        }
    }
}
