use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::signing_key::SigningKeyState;

use crate::{public_transaction::Message, signature::Signer};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessEntry {
    pub auth_data: Vec<u8>,
    pub next: SigningKeyState,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) entries: Vec<WitnessEntry>,
}

impl WitnessSet {
    #[must_use]
    pub fn sign(message: &Message, signers: &[Signer]) -> Self {
        Self {
            entries: sign_entries(signers, |next| message.message_with_keys(next)),
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[WitnessEntry] {
        &self.entries
    }

    #[must_use]
    pub fn into_raw_parts(self) -> Vec<WitnessEntry> {
        self.entries
    }

    #[must_use]
    pub const fn from_raw_parts(entries: Vec<WitnessEntry>) -> Self {
        Self { entries }
    }
}

/// One entry per signer, in `nonces` (account id) order, each signing the message with every
/// signer's next key.
pub fn sign_entries(
    signers: &[Signer],
    message_with_keys: impl FnOnce(&[SigningKeyState]) -> [u8; 32],
) -> Vec<WitnessEntry> {
    let mut signers: Vec<_> = signers.iter().collect();
    signers.sort_by_key(|signer| signer.account_id());
    let next_keys: Vec<_> = signers.iter().map(|signer| signer.next()).collect();
    let message_with_keys = message_with_keys(&next_keys);
    signers
        .into_iter()
        .map(|signer| WitnessEntry {
            auth_data: signer.auth_data(&message_with_keys),
            next: signer.next(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::{
        account::{Actor, Nonce},
        signing_key::KeyType,
    };

    use super::*;
    use crate::{
        AccountId,
        signature::{PublicAccountSecret, authenticate, key_state, public_account_id},
    };

    #[test]
    fn sign_orders_entries_by_account_and_signs_with_every_next_key() {
        let secret1 = PublicAccountSecret::new([1; 32]);
        let secret2 = PublicAccountSecret::new([2; 32]);
        let (addr1, addr2) = (public_account_id(&secret1), public_account_id(&secret2));
        let message = Message::try_new(
            Actor::new(addr1, AccountId::from_builtin_program([0; 8])),
            vec![Actor::native_balance(addr1), Actor::native_balance(addr2)],
            BTreeMap::from([(addr1, Nonce(1)), (addr2, Nonce(2))]),
            vec![1, 2, 3, 4],
        )
        .unwrap();
        // One signer per key type: WOTS+ staying WOTS+, Schnorr rotating back to WOTS+.
        let mut expected = vec![
            (
                addr1,
                key_state(&secret1, KeyType::Wots, Nonce(1)),
                key_state(&secret1, KeyType::Wots, Nonce(2)),
            ),
            (
                addr2,
                key_state(&secret2, KeyType::Schnorr, Nonce(2)),
                key_state(&secret2, KeyType::Wots, Nonce(3)),
            ),
        ];
        expected.sort_by_key(|(account_id, ..)| *account_id);

        let witness_set = WitnessSet::sign(
            &message,
            &[
                Signer::new(&secret2, Nonce(2), KeyType::Schnorr, KeyType::Wots),
                Signer::new(&secret1, Nonce(1), KeyType::Wots, KeyType::Wots),
            ],
        );

        assert_eq!(witness_set.entries.len(), 2);
        let next_keys: Vec<_> = expected.iter().map(|(.., next)| *next).collect();
        let message_with_keys = message.message_with_keys(&next_keys);
        for (entry, (_, current, next)) in witness_set.entries.iter().zip(expected) {
            assert_eq!(entry.next, next);
            assert_eq!(
                authenticate(&current, &message_with_keys, &entry.auth_data, &entry.next),
                Ok(next)
            );
        }
    }
}
