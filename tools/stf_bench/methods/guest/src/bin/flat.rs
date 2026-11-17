//! STF prototype guest: applies one block to the full `V03State` and commits the state hash
//! before and after. Program sessions are replayed from receipts the host proved separately.

use chain_state::apply::{Tip, apply_block};
use common::{HashType, block::Block};
use lee::{V03State, program::stf_oracle};
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
    let (tip_id, tip_hash): (u64, [u8; 32]) =
        borsh::from_slice(&read_input_frame()).expect("tip decodes");
    let read = env::cycle_count();

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
        block_id: tip_id,
        hash: HashType(tip_hash),
    };
    apply_block(Some(&tip), &block, &mut state).expect("block applies");
    assert_eq!(stf_oracle::remaining(), 0, "every recorded session replayed");
    let applied = env::cycle_count();

    let post_bytes = borsh::to_vec(&state).expect("state encodes");
    let post_hash: [u8; 32] = Impl::hash_bytes(&post_bytes).as_bytes().try_into().unwrap();
    let hashed_post = env::cycle_count();

    let breakdown: [u64; 6] = [
        read - start,
        hashed_pre - read,
        decoded - hashed_pre,
        applied - probed,
        hashed_post - applied,
        sig_probe,
    ];
    env::commit_slice(&lee_core::to_borsh_frame(&(
        pre_hash,
        tip_hash,
        block.header.hash.0,
        post_hash,
        breakdown,
    )));
}
