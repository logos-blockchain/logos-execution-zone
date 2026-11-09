// Backs the hand-built state/diff helpers below, which are compiled only for `common`'s own
// unit tests. They rely on `lee::test_utils`, gated behind `lee`'s `test-utils` feature and
// enabled here via dev-dependencies, so it never reaches a production build.
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::HashMap;

#[cfg(any(test, feature = "test-utils"))]
use lee::test_utils::{TestSigner, signer_nonces, witness_for};
#[cfg(test)]
use lee::{Account, V03State, ValidatedStateDiff};
use lee::{
    AccountId, Actor,
    signature::{INITIAL_KEY_TYPE, PublicAccountSecret, Signer, public_account_id},
};
use lee_core::{account::Nonce, signing_key::KeyType};

use crate::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::{FeePayee, LeeTransaction, clock_invocation, fee_invocation},
};

// Helpers

/// The test block-producer's reward account.
#[must_use]
pub fn producer_account_for_testing() -> AccountId {
    public_account_id(&PublicAccountSecret::new([37; 32]))
}

/// The test block producer's reward account and its initial state.
#[must_use]
pub fn producer_seed() -> (AccountId, lee::Account) {
    (producer_account_for_testing(), lee::Account::default())
}

/// A syntactically valid `Public` transaction. Its contents are irrelevant to the
/// bridge guard, which only branches on the transaction *variant* and the diff.
#[cfg(test)]
#[must_use]
pub fn any_public_transaction() -> LeeTransaction {
    let sender = TestSigner::new(9);
    let recipient = TestSigner::new(8);
    create_transaction_native_token_transfer(
        sender.account_id(),
        0,
        recipient.account_id(),
        1,
        &sender,
    )
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
        0,
        FeePayee::Present(producer_account_for_testing()),
    )));
    transactions.push(LeeTransaction::Public(clock_invocation(
        id,
        id.saturating_mul(100),
    )));

    let block_data = HashableBlockData {
        block_id: id,
        prev_block_hash: prev_hash.unwrap_or_default(),
        timestamp: id.saturating_mul(100),
        transactions,
        reverted: Vec::new(),
    };

    block_data.into_pending_block()
}

#[must_use]
pub fn produce_dummy_empty_transaction() -> LeeTransaction {
    let nowhere = Actor::native_balance(AccountId::default());
    let secret = PublicAccountSecret::new([1; 32]);
    let account_id = public_account_id(&secret);
    let message = lee::public_transaction::Message::try_new(
        nowhere,
        Vec::new(),
        BTreeMap::from([(account_id, Nonce(0))]),
        native_transfer(nowhere.account_id, 0),
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::sign(
        &message,
        &[Signer::new(
            &secret,
            Nonce(0),
            INITIAL_KEY_TYPE,
            KeyType::Wots,
        )],
    );

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}

/// Generous fee fields for test transactions: the sender pays, with a default
/// gas limit and an effectively unbounded fee cap.
#[must_use]
pub const fn test_fee_declaration(payer: AccountId) -> lee::FeeDeclaration {
    lee::FeeDeclaration::new(payer, 2_000_000, 0, u128::MAX >> 1)
}

#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn create_transaction_native_token_transfer(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signer: &TestSigner,
) -> LeeTransaction {
    create_transaction_native_token_transfer_with_fees(
        from,
        nonce,
        to,
        balance_to_move,
        signer,
        test_fee_declaration(from),
    )
}

#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn create_transaction_native_token_transfer_with_fees(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signer: &TestSigner,
    fee_declaration: lee::FeeDeclaration,
) -> LeeTransaction {
    let public_actors = vec![Actor::native_balance(from), Actor::native_balance(to)];
    let message = lee::public_transaction::Message::try_new_with_fees(
        Actor::native_balance(from),
        public_actors,
        signer_nonces(&[signer], vec![lee_core::account::Nonce(nonce)]),
        native_transfer(to, balance_to_move),
        fee_declaration,
    )
    .unwrap();
    let witness_set = witness_for(&message, &[signer]);

    let lee_tx = lee::PublicTransaction::new(message, witness_set);

    LeeTransaction::Public(lee_tx)
}

/// A correctly-signed native-token transfer that omits its fee declaration.
///
/// Classification rejects this: a user public transaction that is not an exempt
/// shape must declare a fee, or it would be executed and included for free.
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn create_transaction_native_token_transfer_without_fee(
    from: AccountId,
    nonce: u128,
    to: AccountId,
    balance_to_move: u128,
    signer: &TestSigner,
) -> LeeTransaction {
    let message = lee::public_transaction::Message::try_new(
        Actor::native_balance(from),
        vec![Actor::native_balance(from), Actor::native_balance(to)],
        signer_nonces(&[signer], vec![lee_core::account::Nonce(nonce)]),
        native_transfer(to, balance_to_move),
    )
    .unwrap();
    let witness_set = witness_for(&message, &[signer]);

    LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
}

const fn native_transfer(to: AccountId, amount: u128) -> lee_core::native_token::Message {
    lee_core::native_token::Message::Transfer { to, amount }
}
