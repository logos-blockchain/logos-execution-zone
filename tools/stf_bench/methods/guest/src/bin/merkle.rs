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
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256 as _},
};
use stf_smt::{Hash, Update, value_hash};

#[path = "../auth.rs"]
mod auth;

fn fingerprint(account_root: &Hash, rest: &Hash) -> Hash {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(account_root);
    bytes[32..].copy_from_slice(rest);
    value_hash(&bytes)
}

fn account_hash(account: &Account) -> Hash {
    value_hash(&borsh::to_vec(account).expect("account encodes"))
}

/// Reads an input frame of little-endian words.
fn read_word_frame() -> Vec<u32> {
    let mut len_bytes = [0_u8; 4];
    env::read_slice(&mut len_bytes);
    let len = usize::try_from(u32::from_le_bytes(len_bytes)).expect("frame length fits in usize");
    assert_eq!(len % 4, 0, "a word frame holds whole words");
    let mut words = vec![0_u32; len / 4];
    env::read_slice(&mut words);
    words
}

fn main() {
    let start = env::cycle_count();
    let tree_words = read_word_frame();
    let accounts_bytes = read_input_frame();
    let rest_bytes = read_input_frame();
    let block_bytes = read_input_frame();
    let calls_bytes = read_input_frame();
    let settings: auth::Settings = borsh::from_slice(&read_input_frame()).expect("settings decode");
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

    let accounts: Vec<(AccountId, Account)> =
        borsh::from_slice(&accounts_bytes).expect("accounts decode");
    let rest_hash = value_hash(&rest_bytes);
    let rest: V03State = borsh::from_slice(&rest_bytes).expect("state decodes");
    drop(rest_bytes);
    let block: Block = borsh::from_slice(&block_bytes).expect("block decodes");
    stf_oracle::install(borsh::from_slice(&calls_bytes).expect("calls decode"));
    let decoded = env::cycle_count();

    // The accounts handed in are checked against the old tree after the block runs; a wrong one
    // panics there, so no proof exists.
    let mut pre_values: BTreeMap<AccountId, Hash> = BTreeMap::new();
    for (account_id, account) in &accounts {
        assert!(
            pre_values
                .insert(*account_id, account_hash(account))
                .is_none(),
            "account handed in twice"
        );
    }
    let mut state = rest.with_public_accounts(accounts);
    let verified = env::cycle_count();

    stf_partial::start_tracking();
    let tip = Tip {
        block_id: settings.tip_id,
        hash: HashType(settings.tip_hash),
    };
    apply_block(Some(&tip), &block, &mut state).expect("block applies");
    let deferred = auth::finish(&settings);
    let touched = stf_partial::take_tracked();
    assert_eq!(
        stf_oracle::remaining(),
        0,
        "every recorded session replayed"
    );
    let applied = env::cycle_count();

    // Every account handed in or touched, before and after the block; one the block read but was
    // not handed is absent before.
    let keys: BTreeSet<AccountId> = touched
        .into_iter()
        .chain(pre_values.keys().copied())
        .collect();
    let updates: Vec<Update> = keys
        .iter()
        .map(|account_id| Update {
            key: *account_id.value(),
            old: pre_values.get(account_id).copied(),
            new: state.stf_peek(*account_id).map(account_hash),
        })
        .collect();
    let changed = u32::try_from(
        updates
            .iter()
            .filter(|update| update.new.is_some() && update.new != update.old)
            .count(),
    )
    .expect("fits");
    let (pre_root, post_root) = stf_smt::verify_and_update(&tree_words, &updates);
    let post_rest_hash = value_hash(&borsh::to_vec(&state.stf_without_public()).expect("encodes"));
    let committed = env::cycle_count();

    let breakdown = vec![
        read - start,
        decoded - read,
        verified - decoded,
        applied - verified,
        committed - applied,
        u64::from(changed),
        proofs_read,
        proofs_hash,
    ];
    env::commit_slice(&lee_core::to_borsh_frame(&(
        fingerprint(&pre_root, &rest_hash),
        settings.tip_hash,
        block.header.hash.0,
        fingerprint(&post_root, &post_rest_hash),
        breakdown,
        deferred,
        settings.auth_image,
    )));
}
