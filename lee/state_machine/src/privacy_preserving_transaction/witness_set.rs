use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::signing_key::SigningKeyState;

use crate::{
    AccountId, PrivateKey, PublicKey,
    privacy_preserving_transaction::{circuit::Proof, message::Message},
    public_transaction::WitnessEntry,
    signature::{KeyScheme as _, Schnorr, SignatureScheme as _},
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) entries: Vec<WitnessEntry>,
    pub(crate) proof: Proof,
}

impl WitnessSet {
    #[must_use]
    pub fn sign(
        message: &Message,
        proof: Proof,
        signers: &[(AccountId, PrivateKey, SigningKeyState)],
    ) -> Self {
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
        Self { entries, proof }
    }

    #[must_use]
    pub fn entries(&self) -> &[WitnessEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn proof(&self) -> &Proof {
        &self.proof
    }

    #[must_use]
    pub fn into_raw_parts(self) -> (Vec<WitnessEntry>, Proof) {
        (self.entries, self.proof)
    }

    #[must_use]
    pub const fn from_raw_parts(entries: Vec<WitnessEntry>, proof: Proof) -> Self {
        Self { entries, proof }
    }
}
