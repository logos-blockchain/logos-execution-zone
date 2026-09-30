use associated_token_account_program::{apply, plan};
use lee_core::program::run_program;

fn main() {
    run_program(plan, apply)
}
