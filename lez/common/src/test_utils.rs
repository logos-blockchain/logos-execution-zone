use lee::AccountId;

use crate::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::{LeeTransaction, clock_invocation},
};

// Helpers

#[must_use]
pub fn sequencer_sign_key_for_testing() -> lee::PrivateKey {
    lee::PrivateKey::try_new([37; 32]).unwrap()
}

// Dummy producers

/// Produce dummy block with provided transactions + clock transaction an the end.
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
    mut transactions: Vec<LeeTransaction>,
) -> Block {
    transactions.push(LeeTransaction::Public(clock_invocation(
        id.saturating_mul(100),
    )));

    let block_data = HashableBlockData {
        block_id: id,
        prev_block_hash: prev_hash.unwrap_or_default(),
        timestamp: id.saturating_mul(100),
        transactions,
    };

    block_data.into_pending_block(&sequencer_sign_key_for_testing())
}

#[must_use]
pub fn produce_dummy_empty_transaction() -> LeeTransaction {
    let program_id = programs::authenticated_transfer().id();
    let account_ids = vec![];
    let nonces = vec![];
    let message = lee::public_transaction::Message::try_new(
        program_id,
        account_ids,
        nonces,
        authenticated_transfer_core::Instruction::Transfer { amount: 0 },
    )
    .unwrap();
    let private_key = lee::PrivateKey::try_new([1; 32]).unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&private_key]);

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}

#[must_use]
pub fn create_transaction_native_token_transfer(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signing_key: &lee::PrivateKey,
) -> LeeTransaction {
    let account_ids = vec![from, to];
    let nonces = vec![nonce.into()];
    let program_id = programs::authenticated_transfer().id();
    let message = lee::public_transaction::Message::try_new(
        program_id,
        account_ids,
        nonces,
        authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}
