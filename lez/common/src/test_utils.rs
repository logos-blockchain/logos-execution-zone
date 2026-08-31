// Backs the hand-built state/diff helpers below, which are compiled only for `common`'s own
// unit tests. They rely on `lee::test_utils`, gated behind `lee`'s `test-utils` feature and
// enabled here via dev-dependencies, so it never reaches a production build.
#[cfg(test)]
use std::collections::HashMap;

use lee::AccountId;
#[cfg(test)]
use lee::{Account, PrivateKey, PublicKey, V03State, ValidatedStateDiff};

use crate::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::{LeeTransaction, clock_invocation, fee_invocation},
};

// Helpers

#[must_use]
pub fn sequencer_sign_key_for_testing() -> lee::PrivateKey {
    lee::PrivateKey::try_new([37; 32]).unwrap()
}

/// A syntactically valid `Public` transaction. Its contents are irrelevant to the
/// bridge guard, which only branches on the transaction *variant* and the diff.
#[cfg(test)]
#[must_use]
pub fn any_public_transaction() -> LeeTransaction {
    let sender_key = PrivateKey::try_new([9_u8; 32]).expect("valid key");
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let recipient_key = PrivateKey::try_new([8_u8; 32]).expect("valid key");
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
    create_transaction_native_token_transfer(sender_id, 0, recipient_id, 1, &sender_key)
}

/// Builds a state whose only entry is `account_id` (set to `pre`) and a single-entry diff
/// that maps `account_id` to `post`, so the validation guards can be exercised in isolation.
#[cfg(test)]
#[must_use]
pub fn state_and_diff(
    account_id: AccountId,
    pre: Account,
    post: Account,
) -> (V03State, ValidatedStateDiff) {
    let state = V03State::new().with_public_accounts([(account_id, pre)]);
    let diff =
        lee::test_utils::validated_state_diff_from_public_diff(HashMap::from([(account_id, post)]));
    (state, diff)
}

// Dummy producers

/// Produce dummy block from the provided transactions, appending the fee and
/// clock tail transactions at the end (in that order).
///
/// The fee tail carries `BlockFeeSummary::default()`, so this helper is only
/// valid for blocks whose `transactions` settle to the default summary — i.e.
/// fee-exempt txs. Passing charged transactions builds a block that fails the
/// byte-for-byte fee-summary check in `apply_block_to_state`.
///
/// - `id`: block id, provide zero for genesis.
/// - `prev_hash`: hash of previous block, provide None for genesis.
/// - `transactions`: vector of `EncodedTransaction` objects.
#[must_use]
pub fn produce_dummy_block(
    id: u64,
    prev_hash: Option<HashType>,
    mut transactions: Vec<LeeTransaction>,
) -> Block {
    transactions.push(LeeTransaction::Public(fee_invocation(
        fee_core::BlockFeeSummary::default(),
        lee::AccountId::from(&lee::PublicKey::new_from_private_key(
            &sequencer_sign_key_for_testing(),
        )),
    )));
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
        authenticated_transfer_core::Instruction::Initialize,
    )
    .unwrap();
    let private_key = lee::PrivateKey::try_new([1; 32]).unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&private_key]);

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}

/// Generous fee fields for test transactions: the sender pays, with a default
/// gas limit and an effectively unbounded fee cap.
#[must_use]
pub const fn test_fee_declaration(payer: AccountId) -> lee::FeeDeclaration {
    lee::FeeDeclaration::new(payer, 2_000_000, 0, u128::MAX >> 1)
}

#[must_use]
pub fn create_transaction_native_token_transfer(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signing_key: &lee::PrivateKey,
) -> LeeTransaction {
    create_transaction_native_token_transfer_with_fees(
        from,
        nonce,
        to,
        balance_to_move,
        signing_key,
        test_fee_declaration(from),
    )
}

#[must_use]
pub fn create_transaction_native_token_transfer_with_fees(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signing_key: &lee::PrivateKey,
    fee_declaration: lee::FeeDeclaration,
) -> LeeTransaction {
    let account_ids = vec![from, to];
    let nonces = vec![nonce.into()];
    let program_id = programs::authenticated_transfer().id();
    let message = lee::public_transaction::Message::try_new_with_fees(
        program_id,
        account_ids,
        nonces,
        authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        },
        fee_declaration,
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}

/// A correctly-signed native-token transfer that omits its fee declaration.
///
/// Classification rejects this: a user public transaction that is not an exempt
/// shape must declare a fee, or it would be executed and included for free.
#[must_use]
pub fn create_transaction_native_token_transfer_without_fee(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signing_key: &lee::PrivateKey,
) -> LeeTransaction {
    let message = lee::public_transaction::Message::try_new(
        programs::authenticated_transfer().id(),
        vec![from, to],
        vec![nonce.into()],
        authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

    LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
}
