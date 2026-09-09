use risc0_zkvm::guest::env;

// FIXME: Remove this program once other guests are rewritten
// to use and handle non-zero exit codes.

fn main() {
    // Commits, then halts with a non-zero code: the host must reject the run but keep the
    // metered cycle count, unlike a panic which drops the session.
    env::commit_slice(b"partial");
    env::exit(3);
}
