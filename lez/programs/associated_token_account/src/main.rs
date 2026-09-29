use associated_token_account_program::receive;
use lee_core::program::run_actor;

fn main() {
    run_actor(receive)
}
