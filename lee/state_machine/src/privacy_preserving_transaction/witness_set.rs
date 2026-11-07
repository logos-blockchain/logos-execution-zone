use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    privacy_preserving_transaction::{circuit::Proof, message::Message},
    public_transaction::{WitnessEntry, sign_entries},
    signature::Signer,
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WitnessSet {
    pub(crate) entries: Vec<WitnessEntry>,
    pub(crate) proof: Proof,
}

impl WitnessSet {
    #[must_use]
    pub fn sign(message: &Message, proof: Proof, signers: &[Signer]) -> Self {
        Self {
            entries: sign_entries(signers, |next| message.message_with_keys(next)),
            proof,
        }
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
