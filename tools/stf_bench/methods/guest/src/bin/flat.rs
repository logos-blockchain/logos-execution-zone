//! STF prototype guest: applies one block to the full `V03State` and commits the state hash
//! before and after. Program sessions are replayed from receipts the host proved separately.

use chain_state::apply::{Tip, apply_block};
use common::{HashType, block::Block};
use lee::{V03State, program::stf_oracle};

#[path = "../auth.rs"]
mod auth;
use lee_core::program::read_input_frame;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256 as _},
};

fn main() {
    let start = env::cycle_count();
    let state_bytes = read_input_frame();
    let block_bytes = read_input_frame();
    let calls_bytes = read_input_frame();
    let settings: auth::Settings =
        borsh::from_slice(&read_input_frame()).expect("settings decode");
    // Stand-in for authorization proofs carried in the block: read and hashed, nothing else.
    let before_proofs = env::cycle_count();
    let proof_bytes = read_input_frame();
    let proofs_read = env::cycle_count() - before_proofs;
    let proofs_hash = {
        let before = env::cycle_count();
        let _ = Impl::hash_bytes(&proof_bytes);
        env::cycle_count() - before
    };
    drop(proof_bytes);
    let read = env::cycle_count();
    auth::begin(&settings);

    let pre_hash: [u8; 32] = Impl::hash_bytes(&state_bytes).as_bytes().try_into().unwrap();
    let hashed_pre = env::cycle_count();
    let mut state: V03State = borsh::from_slice(&state_bytes).expect("state decodes");
    drop(state_bytes);
    let block: Block = borsh::from_slice(&block_bytes).expect("block decodes");
    stf_oracle::install(borsh::from_slice(&calls_bytes).expect("calls decode"));
    let decoded = env::cycle_count();

    // Probe: one user transaction's signature check, measured on its own.
    let sig_probe = match block.body.transactions.first() {
        Some(common::transaction::LeeTransaction::Public(tx)) if block.body.transactions.len() > 2 => {
            let before = env::cycle_count();
            assert!(tx.witness_set().is_valid_for(tx.message()));
            env::cycle_count() - before
        }
        _ => 0,
    };
    let probed = env::cycle_count();

    let tip = Tip {
        block_id: settings.tip_id,
        hash: HashType(settings.tip_hash),
    };
    apply_block(Some(&tip), &block, &mut state).expect("block applies");
    let deferred = auth::finish(&settings);
    assert_eq!(stf_oracle::remaining(), 0, "every recorded session replayed");
    let applied = env::cycle_count();

    let post_bytes = borsh::to_vec(&state).expect("state encodes");
    let post_hash: [u8; 32] = Impl::hash_bytes(&post_bytes).as_bytes().try_into().unwrap();
    let hashed_post = env::cycle_count();

    let breakdown = vec![
        read - start,
        hashed_pre - read,
        decoded - hashed_pre,
        applied - probed,
        hashed_post - applied,
        sig_probe,
        proofs_read,
        proofs_hash,
    ];
    env::commit_slice(&lee_core::to_borsh_frame(&(
        pre_hash,
        settings.tip_hash,
        block.header.hash.0,
        post_hash,
        breakdown,
        deferred,
        settings.auth_image,
    )));
}
