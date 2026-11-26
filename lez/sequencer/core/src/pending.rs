//! Admission against the mempool's pending slots, one transaction per `(account, nonce)`.
//!
//! Each slot's holder commits its signer to a key at the next nonce. First seen wins.
//!
//! The mempool is this node's own view, so nothing refused here is definitively invalid.

use common::transaction::LeeTransaction;
use lee::{AccountId, public_transaction::WitnessEntry};
use lee_core::{account::Nonce, signing_key::SigningKeyState};

use crate::SequencerMemPool;

/// Why the pending slots turn a transaction away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PendingRefusal {
    #[error("Account {account}'s nonce {} is already pending", nonce.0)]
    NoncePending { account: AccountId, nonce: Nonce },
    #[error("Account {account} already has {limit} pending transactions")]
    AccountLimit { account: AccountId, limit: usize },
}

/// Whether a transaction the slots admit is new, or the very transaction already pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    New,
    Duplicate,
}

/// The key a pending transaction commits `account` to at `nonce`: the next key of the one holding
/// the slot just before it.
#[must_use]
pub fn key_at(
    pool: &SequencerMemPool,
    account: AccountId,
    nonce: Nonce,
) -> Option<SigningKeyState> {
    let previous = nonce.0.checked_sub(1)?;
    let (_, holder) = pool.get(&account, &previous)?;
    signer_slots(holder)
        .into_iter()
        .find_map(|(signer, _, next)| (signer == account).then_some(next))
}

/// Whether `tx` may enter: each slot it claims is free or already its own, and no signer's account
/// holds `max_per_account` slots from its nonce in `state` on.
pub fn check(
    pool: &SequencerMemPool,
    tx: &LeeTransaction,
    state: &lee::V03State,
    max_per_account: usize,
) -> Result<Admission, PendingRefusal> {
    let tx_hash = tx.hash();
    let claimed = signer_slots(tx);
    let mut own = 0_usize;
    for (account, nonce, _) in &claimed {
        match pool.get(account, &nonce.0) {
            Some((_, held)) if held.hash() == tx_hash => own = own.saturating_add(1),
            Some(_) => {
                return Err(PendingRefusal::NoncePending {
                    account: *account,
                    nonce: *nonce,
                });
            }
            None => {}
        }
    }
    if !claimed.is_empty() && own == claimed.len() {
        return Ok(Admission::Duplicate);
    }
    for (account, _, _) in &claimed {
        if pool.lane_len(account, &account_nonce(state, *account).0) >= max_per_account {
            return Err(PendingRefusal::AccountLimit {
                account: *account,
                limit: max_per_account,
            });
        }
    }
    Ok(Admission::New)
}

fn account_nonce(state: &lee::V03State, account: AccountId) -> Nonce {
    state
        .get_account_by_id_ref(account)
        .map_or_else(Nonce::default, |account| account.nonce)
}

/// Each signer's slot, and the key its witness entry rotates it to. Entries pair with `nonces` in
/// order; a transaction whose witness does not match claims nothing (it fails admission anyway).
fn signer_slots(tx: &LeeTransaction) -> Vec<(AccountId, Nonce, SigningKeyState)> {
    let (nonces, entries): (_, &[WitnessEntry]) = match tx {
        LeeTransaction::Public(tx) => (&tx.message().nonces, tx.witness_set().entries()),
        LeeTransaction::PrivacyPreserving(tx) => (&tx.message().nonces, tx.witness_set().entries()),
    };
    if nonces.len() != entries.len() {
        return Vec::new();
    }
    nonces
        .iter()
        .zip(entries)
        .map(|((&account, &nonce), entry)| (account, nonce, entry.next))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee::{
        Actor, PublicTransaction, V03State,
        public_transaction::Message,
        test_utils::{TestSigner, witness_for},
    };

    use super::*;
    use crate::TransactionOrigin;

    fn transfer(signer: &TestSigner, nonce: u128, amount: u128) -> LeeTransaction {
        let sender = Actor::native_balance(signer.account_id());
        let recipient = Actor::native_balance(AccountId::new([9; 32]));
        let message = Message::try_new(
            sender,
            vec![sender, recipient],
            BTreeMap::from([(signer.account_id(), Nonce(nonce))]),
            lee_core::native_token::Message::Transfer {
                to: recipient.account_id,
                amount,
            },
        )
        .unwrap();
        let witness_set = witness_for(&message, &[signer]);
        PublicTransaction::new(message, witness_set).into()
    }

    fn pool_of(txs: &[&LeeTransaction]) -> SequencerMemPool {
        let mut pool = crate::new_mempool(16);
        for tx in txs {
            pool.insert((TransactionOrigin::User, (*tx).clone()))
                .unwrap();
        }
        pool
    }

    #[test]
    fn a_pending_transaction_commits_its_signer_to_the_next_key() {
        let signer = TestSigner::new(1);
        assert_eq!(key_at(&pool_of(&[]), signer.account_id(), Nonce(1)), None);

        let pool = pool_of(&[&transfer(&signer, 0, 1)]);
        assert_eq!(
            key_at(&pool, signer.account_id(), Nonce(1)),
            Some(signer.key_state(Nonce(1)))
        );
        assert_eq!(key_at(&pool, signer.account_id(), Nonce(2)), None);
    }

    #[test]
    fn the_first_transaction_seen_holds_its_slot() {
        let signer = TestSigner::new(1);
        let first = transfer(&signer, 0, 1);
        let pool = pool_of(&[&first]);
        let state = V03State::new();

        assert_eq!(check(&pool, &first, &state, 16), Ok(Admission::Duplicate));
        assert_eq!(
            check(&pool, &transfer(&signer, 0, 2), &state, 16),
            Err(PendingRefusal::NoncePending {
                account: signer.account_id(),
                nonce: Nonce(0),
            })
        );
        assert_eq!(
            check(&pool, &transfer(&signer, 1, 2), &state, 16),
            Ok(Admission::New)
        );
    }

    #[test]
    fn an_account_holds_at_most_its_limit_of_pending_transactions_from_its_nonce_on() {
        let signer = TestSigner::new(1);
        let first = transfer(&signer, 0, 1);
        let pool = pool_of(&[&first, &transfer(&signer, 1, 1)]);

        assert_eq!(
            check(&pool, &transfer(&signer, 2, 1), &V03State::new(), 2),
            Err(PendingRefusal::AccountLimit {
                account: signer.account_id(),
                limit: 2,
            })
        );

        // once `first` is included, its stale slot no longer counts
        let mut state = V03State::new().with_public_account_balances([
            (signer.account_id(), 100),
            (AccountId::new([9; 32]), 0),
        ]);
        let LeeTransaction::Public(first) = first else {
            unreachable!("a transfer is public");
        };
        state
            .transition_from_public_transaction(&first, 1, 0)
            .unwrap();
        assert_eq!(
            check(&pool, &transfer(&signer, 2, 1), &state, 2),
            Ok(Admission::New)
        );
    }
}
