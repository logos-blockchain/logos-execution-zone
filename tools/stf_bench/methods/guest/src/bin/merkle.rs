//! STF prototype guest, Merkle variant. Public accounts are committed by a compact sparse Merkle
//! tree and the guest holds only the ones the block touches; everything else in the state is
//! committed by SHA-256 of its borsh encoding. Program sessions are replayed from receipts the
//! host proved separately.
//!
//! The state fingerprint is `SHA-256(account_root || SHA-256(borsh(state without accounts)))`.

use std::collections::{BTreeMap, BTreeSet};

use chain_state::apply::{Tip, apply_block};
use common::{HashType, block::Block};
use lee::{Account, AccountId, V03State, program::stf_oracle, stf_partial};
use lee_core::program::read_input_frame;
use risc0_zkvm::guest::env;
use stf_smt::{Hash, Lookup, Node, value_hash};

fn fingerprint(account_root: &Hash, rest: &Hash) -> Hash {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(account_root);
    bytes[32..].copy_from_slice(rest);
    value_hash(&bytes)
}

fn account_hash(account: &Account) -> Hash {
    value_hash(&borsh::to_vec(account).expect("account encodes"))
}

fn main() {
    let start = env::cycle_count();
    let tree_bytes = read_input_frame();
    let accounts_bytes = read_input_frame();
    let rest_bytes = read_input_frame();
    let block_bytes = read_input_frame();
    let calls_bytes = read_input_frame();
    let (tip_id, tip_hash): (u64, [u8; 32]) =
        borsh::from_slice(&read_input_frame()).expect("tip decodes");
    let read = env::cycle_count();

    let mut tree: Node = borsh::from_slice(&tree_bytes).expect("tree decodes");
    let accounts: Vec<(AccountId, Account)> =
        borsh::from_slice(&accounts_bytes).expect("accounts decode");
    let rest_hash = value_hash(&rest_bytes);
    let rest: V03State = borsh::from_slice(&rest_bytes).expect("state decodes");
    drop(rest_bytes);
    let block: Block = borsh::from_slice(&block_bytes).expect("block decodes");
    stf_oracle::install(borsh::from_slice(&calls_bytes).expect("calls decode"));
    let decoded = env::cycle_count();

    // Every account handed in must be in the old tree, with exactly this content.
    let pre_root = tree.hash();
    let mut pre_values: BTreeMap<AccountId, Hash> = BTreeMap::new();
    for (account_id, account) in &accounts {
        let value = account_hash(account);
        assert_eq!(
            tree.get(account_id.value()),
            Lookup::Found(value),
            "account {account_id} is not in the old state"
        );
        assert!(
            pre_values.insert(*account_id, value).is_none(),
            "account handed in twice"
        );
    }
    let mut state = rest.with_public_accounts(accounts);
    let verified = env::cycle_count();

    stf_partial::start_tracking();
    let tip = Tip {
        block_id: tip_id,
        hash: HashType(tip_hash),
    };
    apply_block(Some(&tip), &block, &mut state).expect("block applies");
    let touched = stf_partial::take_tracked();
    assert_eq!(stf_oracle::remaining(), 0, "every recorded session replayed");
    let applied = env::cycle_count();

    // An account the block read but was not handed must be absent from the old tree.
    for account_id in &touched {
        if !pre_values.contains_key(account_id) {
            assert_eq!(
                tree.get(account_id.value()),
                Lookup::Absent,
                "account {account_id} was read but not handed in"
            );
        }
    }
    let mut changed = 0_u32;
    let keys: BTreeSet<AccountId> = touched.into_iter().chain(pre_values.keys().copied()).collect();
    for account_id in &keys {
        if let Some(account) = state.stf_peek(*account_id) {
            let value = account_hash(account);
            if pre_values.get(account_id) != Some(&value) {
                tree.upsert(*account_id.value(), value);
                changed += 1;
            }
        }
    }
    let post_root = tree.hash();
    let post_rest_hash = value_hash(&borsh::to_vec(&state.stf_without_public()).expect("encodes"));
    let committed = env::cycle_count();

    let breakdown: [u64; 6] = [
        read - start,
        decoded - read,
        verified - decoded,
        applied - verified,
        committed - applied,
        u64::from(changed),
    ];
    env::commit_slice(&lee_core::to_borsh_frame(&(
        fingerprint(&pre_root, &rest_hash),
        tip_hash,
        block.header.hash.0,
        fingerprint(&post_root, &post_rest_hash),
        breakdown,
    )));
}
