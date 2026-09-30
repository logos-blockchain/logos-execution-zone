//! Panics with the exact phrase the host matches on to detect a session-limit bail, so the
//! "Guest panicked" exclusion in `Program::execute_session` has something real to defend against.
fn main() {
    // Keeps the zkVM runtime linked in; without a reference to it the guest has no entry point.
    let _ = risc0_zkvm::guest::env::cycle_count();
    panic!("Session limit exceeded: 1 >= 0");
}
