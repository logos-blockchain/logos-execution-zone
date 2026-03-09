use nssa::AccountId;

use crate::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::NSSATransaction,
};

// Helpers

#[must_use]
pub fn sequencer_sign_key_for_testing() -> nssa::PrivateKey {
    nssa::PrivateKey::try_new([37; 32]).unwrap()
}

// Dummy producers

/// Produce dummy block with.
///
/// `id` - block id, provide zero for genesis.
///
/// `prev_hash` - hash of previous block, provide None for genesis.
///
/// `transactions` - vector of `EncodedTransaction` objects.
#[must_use]
pub fn produce_dummy_block(
    id: u64,
    prev_hash: Option<HashType>,
    transactions: Vec<NSSATransaction>,
) -> Block {
    let block_data = HashableBlockData {
        block_id: id,
        prev_block_hash: prev_hash.unwrap_or_default(),
        timestamp: id.saturating_mul(100),
        transactions,
    };

    block_data.into_pending_block(&sequencer_sign_key_for_testing(), [0; 32])
}

#[must_use]
pub fn produce_dummy_empty_transaction() -> NSSATransaction {
    let program_id = nssa::program::Program::authenticated_transfer_program().id();
    let account_ids = vec![];
    let nonces = vec![];
    let instruction_data: u128 = 0;
    let message = nssa::public_transaction::Message::try_new(
        program_id,
        account_ids,
        nonces,
        instruction_data,
    )
    .unwrap();
    let private_key = nssa::PrivateKey::try_new([1; 32]).unwrap();
    let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[&private_key]);

    let nssa_tx = nssa::PublicTransaction::new(message, witness_set);

    NSSATransaction::Public(nssa_tx)
}

#[must_use]
pub fn create_transaction_native_token_transfer(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signing_key: &nssa::PrivateKey,
) -> NSSATransaction {
    let account_ids = vec![from, to];
    let nonces = vec![nonce];
    let program_id = nssa::program::Program::authenticated_transfer_program().id();
    let message = nssa::public_transaction::Message::try_new(
        program_id,
        account_ids,
        nonces,
        balance_to_move,
    )
    .unwrap();
    let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

    let nssa_tx = nssa::PublicTransaction::new(message, witness_set);

    NSSATransaction::Public(nssa_tx)
}
