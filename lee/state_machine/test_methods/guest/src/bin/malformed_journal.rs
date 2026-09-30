use risc0_zkvm::guest::env;

fn main() {
    // A journal that is not a valid frame: the length prefix claims 0x7FFF_FFFF payload bytes
    // but only one follows. Program deployment is permissionless, so the host must reject this
    // as an error rather than panic.
    env::commit_slice(&[0xFF_u8, 0xFF, 0xFF, 0x7F, 0x00]);
}
