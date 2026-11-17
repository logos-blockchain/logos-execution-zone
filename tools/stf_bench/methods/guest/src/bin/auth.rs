//! Authorizes a message for the public key `SHA-256(secret)` by knowing the secret.

use lee_core::program::read_input_frame;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256 as _},
};

fn main() {
    let secret = read_input_frame();
    let message_hash: [u8; 32] = read_input_frame().try_into().expect("a 32-byte message hash");
    let public_key: [u8; 32] = Impl::hash_bytes(&secret).as_bytes().try_into().expect("32 bytes");
    env::commit_slice(&lee_core::to_borsh_frame(&(public_key, message_hash)));
}
