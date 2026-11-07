use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::signing_key::SigningKeyState;

use crate::{
    AccountId, PrivateKey, PublicKey,
    public_transaction::Message,
    signature::{KeyScheme as _, Schnorr, SignatureScheme as _},
};

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
    pub fn sign(message: &Message, signers: &[(AccountId, PrivateKey, SigningKeyState)]) -> Self {
        let mut signers: Vec<_> = signers.iter().collect();
        signers.sort_by_key(|(account_id, ..)| *account_id);
        let next_keys: Vec<_> = signers.iter().map(|(.., next)| *next).collect();
        let message_with_keys = message.message_with_keys(&next_keys);
        let entries = signers
            .into_iter()
            .map(|(_, key, next)| WitnessEntry {
                auth_data: Schnorr::auth_data(
                    &PublicKey::new_from_private_key(key),
                    &Schnorr::sign(key, &message_with_keys),
                )
                .to_vec(),
                next: *next,
            })
            .collect();
        Self { entries }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::account::{Actor, Nonce};

    use super::*;
    use crate::{
        AccountId,
        signature::{PublicAccountSecret, authenticate, signing_key},
    };

    #[test]
    fn sign_constructor() {
        let secret1 = PublicAccountSecret::new([1; 32]);
        let secret2 = PublicAccountSecret::new([2; 32]);
        let addr1 = AccountId::from(&signing_key::<Schnorr>(&secret1, Nonce(0)).1);
        let addr2 = AccountId::from(&signing_key::<Schnorr>(&secret2, Nonce(0)).1);
        let nonces = BTreeMap::from([(addr1, Nonce(1)), (addr2, Nonce(2))]);
        let instruction = vec![1, 2, 3, 4];
        let message = Message::try_new(
            Actor::new(addr1, AccountId::from_builtin_program([0; 8])),
            vec![Actor::native_balance(addr1), Actor::native_balance(addr2)],
            nonces,
            instruction,
        )
        .unwrap();
        let (key1, public_key1) = signing_key::<Schnorr>(&secret1, Nonce(1));
        let (key2, public_key2) = signing_key::<Schnorr>(&secret2, Nonce(2));
        let next1 = Schnorr::key_state(&signing_key::<Schnorr>(&secret1, Nonce(2)).1);
        let next2 = Schnorr::key_state(&signing_key::<Schnorr>(&secret2, Nonce(3)).1);

        // Given in the reverse of `nonces` order: addr1 sorts before addr2.
        let witness_set = WitnessSet::sign(&message, &[(addr2, key2, next2), (addr1, key1, next1)]);

        assert_eq!(witness_set.entries.len(), 2);
        let message_with_keys = message.message_with_keys(&[next1, next2]);
        for (entry, (public_key, next)) in witness_set
            .entries
            .iter()
            .zip([(public_key1, next1), (public_key2, next2)])
        {
            assert_eq!(entry.next, next);
            assert_eq!(
                authenticate(
                    &Schnorr::key_state(&public_key),
                    &message_with_keys,
                    &entry.auth_data,
                    &entry.next
                ),
                Ok(next)
            );
        }
    }
}
