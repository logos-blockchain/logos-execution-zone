//! A public account's id from its secret, as `lee::signature::public_account_id` derives it. `lee`
//! is host-only, so the guest derives it itself; known-answer tests pin both to the same id.

use lee_core::{
    account::AccountId,
    signing_key::{KeyType, SigningKeyState},
};
use sha2::{Digest as _, Sha256};

#[path = "../../../../lee/state_machine/src/signature/wots/tree.rs"]
#[allow(
    dead_code,
    reason = "the guest only builds trees; it never signs or verifies"
)]
mod tree;

const DS_KEY_SEED: &[u8; 32] =
    b"/LEE/v0.3/KeySeed/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// The seed of the initial key: WOTS+, nonce 0, counter 0.
fn initial_key_seed(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DS_KEY_SEED);
    hasher.update(secret);
    hasher.update(
        borsh::to_vec(&KeyType::Wots).expect("a key type encodes to its discriminant byte"),
    );
    hasher.update(0_u128.to_le_bytes());
    hasher.update(0_u32.to_le_bytes());
    hasher.finalize().into()
}

pub fn public_account_id(secret: &[u8; 32]) -> AccountId {
    let tree = tree::Tree::from_seed(&initial_key_seed(secret));
    let initial = SigningKeyState {
        key_type: KeyType::Wots,
        key_commitment: tree.public_key(),
    };
    AccountId::for_initial_key(&initial).expect("WOTS+ is an initial key type")
}
