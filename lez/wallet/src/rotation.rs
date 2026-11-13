//! The rotation counter behind a public account's stored key. Ordinary keys use counter 0; a
//! manual rotation moves to the next counter at the same nonce.

use anyhow::{Context as _, Result};
use indexer_service_protocol as protocol;
use indexer_service_rpc::RpcClient as _;
use lee::{
    AccountId,
    signature::{PublicAccountSecret, key_state_with_counter},
};
use lee_core::{
    account::Nonce,
    signing_key::{SignatureMessage, SigningKeyState, signature_program_id},
};
use sequencer_service_rpc::{SequencerClient, SequencerClientBuilder};
use url::Url;

/// Transactions read from the indexer per request.
const PAGE: u64 = 100;

/// What one transaction in an account's history did to its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// The account signed it, so its nonce advanced.
    Signed,
    /// It sent the account this many `SetKey`s from the signature guest.
    ManualRotations(u32),
}

/// The first of `candidates` whose key is `stored`.
pub fn matching_counter(
    secret: &PublicAccountSecret,
    stored: SigningKeyState,
    nonce: Nonce,
    candidates: impl IntoIterator<Item = u32>,
) -> Option<u32> {
    candidates
        .into_iter()
        .find(|&counter| key_state_with_counter(secret, stored.key_type, nonce, counter) == stored)
}

/// The manual rotations of `account` since the last transaction it signed, in its history oldest
/// first: a signed transaction advances its nonce, which starts the count over.
pub fn manual_rotations_since_last_signed<'history>(
    account: AccountId,
    history: impl IntoIterator<Item = &'history protocol::Transaction>,
) -> u32 {
    count(history.into_iter().map(|tx| entry(account, tx)))
}

fn count(entries: impl IntoIterator<Item = Entry>) -> u32 {
    entries.into_iter().fold(0, |count, entry| match entry {
        Entry::Signed => 0,
        Entry::ManualRotations(rotations) => count.saturating_add(rotations),
    })
}

fn entry(account: AccountId, tx: &protocol::Transaction) -> Entry {
    let account = protocol::AccountId {
        value: *account.value(),
    };
    let (nonces, boundary): (&[_], &[_]) = match tx {
        protocol::Transaction::Public(tx) => (&tx.message.nonces, &[]),
        protocol::Transaction::PrivacyPreserving(tx) => (&tx.message.nonces, &tx.message.boundary),
    };
    if nonces.iter().any(|(signer, _)| *signer == account) {
        Entry::Signed
    } else {
        Entry::ManualRotations(set_keys(boundary, account))
    }
}

/// The `SetKey`s `boundary` sends to `account`'s signature actor.
fn set_keys(boundary: &[protocol::BoundaryStep], account: protocol::AccountId) -> u32 {
    let target = protocol::Actor {
        account_id: account,
        program_account_id: protocol::AccountId {
            value: *signature_program_id().value(),
        },
    };
    let count = boundary
        .iter()
        .filter(|step| match step {
            protocol::BoundaryStep::PrivateToPublic(delivery) => {
                delivery.envelope.to == target
                    && borsh::from_slice::<SignatureMessage>(&delivery.envelope.message).is_ok()
            }
            protocol::BoundaryStep::PublicToPrivate(_)
            | protocol::BoundaryStep::EndPrivateSubtree
            | protocol::BoundaryStep::EndPublicSubtree => false,
        })
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// `account`'s whole history from the indexer at `url`, oldest first.
pub async fn history(url: &Url, account: AccountId) -> Result<Vec<protocol::Transaction>> {
    // A plain JSON-RPC HTTP client, the same type the sequencer's.
    let client: SequencerClient = SequencerClientBuilder::default()
        .build(url)
        .context("Failed to create indexer client")?;
    let account_id = protocol::AccountId {
        value: *account.value(),
    };
    let mut transactions = Vec::new();
    loop {
        let offset = u64::try_from(transactions.len()).expect("a history fits in u64");
        let page = client
            .get_transactions_by_account(account_id, offset, PAGE)
            .await
            .context("Failed to read the account's history from the indexer")?;
        let complete = u64::try_from(page.len()).expect("a page fits in u64") < PAGE;
        transactions.extend(page);
        if complete {
            return Ok(transactions);
        }
    }
}

#[cfg(test)]
mod tests {
    use lee_core::signing_key::KeyType;

    use super::*;

    const ACCOUNT: AccountId = AccountId::new([1; 32]);

    fn protocol_id(account: AccountId) -> protocol::AccountId {
        protocol::AccountId {
            value: *account.value(),
        }
    }

    fn delivery(
        to_account: AccountId,
        program: AccountId,
        message: Vec<u8>,
    ) -> protocol::BoundaryStep {
        protocol::BoundaryStep::PrivateToPublic(protocol::Delivery {
            envelope: protocol::MessageEnvelope {
                from: protocol::Actor {
                    account_id: protocol_id(AccountId::new([9; 32])),
                    program_account_id: protocol_id(signature_program_id()),
                },
                to: protocol::Actor {
                    account_id: protocol_id(to_account),
                    program_account_id: protocol_id(program),
                },
                message,
            },
            inherited_authorizations: Vec::new(),
            inherits_entry_authorizations: false,
            pda_seeds: Vec::new(),
        })
    }

    fn set_key() -> Vec<u8> {
        borsh::to_vec(&SignatureMessage::SetKey {
            next: SigningKeyState {
                key_type: KeyType::Wots,
                key_commitment: [3; 32],
            },
        })
        .unwrap()
    }

    #[test]
    fn only_set_keys_to_the_account_are_counted() {
        let boundary = vec![
            delivery(ACCOUNT, signature_program_id(), set_key()),
            delivery(ACCOUNT, signature_program_id(), set_key()),
            delivery(AccountId::new([2; 32]), signature_program_id(), set_key()),
            delivery(ACCOUNT, AccountId::new([7; 32]), set_key()),
            delivery(ACCOUNT, signature_program_id(), vec![0xFF]),
        ];
        assert_eq!(set_keys(&boundary, protocol_id(ACCOUNT)), 2);
    }

    #[test]
    fn a_signed_transaction_starts_the_count_over() {
        let entries = [
            Entry::ManualRotations(2),
            Entry::Signed,
            Entry::ManualRotations(1),
            Entry::ManualRotations(0),
            Entry::ManualRotations(1),
        ];
        assert_eq!(count(entries), 2);
        assert_eq!(count([Entry::ManualRotations(3), Entry::Signed]), 0);
        assert_eq!(count([]), 0);
    }

    #[test]
    fn the_matching_counter_is_found_among_the_candidates() {
        let secret = PublicAccountSecret::new([5; 32]);
        let stored = key_state_with_counter(&secret, KeyType::Schnorr, Nonce(4), 2);
        assert_eq!(
            matching_counter(&secret, stored, Nonce(4), (1..=3).rev()),
            Some(2)
        );
        assert_eq!(matching_counter(&secret, stored, Nonce(4), [0, 1]), None);
        assert_eq!(matching_counter(&secret, stored, Nonce(5), 0..=3), None);
    }

    #[test]
    fn a_foreign_key_matches_no_counter() {
        let secret = PublicAccountSecret::new([5; 32]);
        let foreign = key_state_with_counter(
            &PublicAccountSecret::new([6; 32]),
            KeyType::Wots,
            Nonce(4),
            1,
        );
        assert_eq!(matching_counter(&secret, foreign, Nonce(4), 0..=4), None);
    }
}
