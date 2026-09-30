//! Burns enough cycles to span several continuation segments, so the two execution paths can be
//! compared on a session where per-segment and whole-session cycle accounting could disagree.
fn main() {
    let mut acc: u32 = 1;
    for i in 0..2_000_000_u32 {
        acc = acc.wrapping_mul(2_654_435_761).wrapping_add(i);
    }
    risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
}
