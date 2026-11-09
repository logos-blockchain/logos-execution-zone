use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Nonce},
    execution_state::PublicExecutionContext,
    program::PdaSeed,
    signing_key::SigningKeyState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::LeeError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAccountEvidence {
    /// The account's initial key.
    Key(SigningKeyState),
    Pda {
        program: AccountId,
        seed: PdaSeed,
    },
}

impl PublicAccountEvidence {
    /// The account the evidence names; `None` for a key of a type that cannot be initial.
    #[must_use]
    pub fn account_id(&self) -> Option<AccountId> {
        match self {
            Self::Key(key) => AccountId::for_initial_key(key),
            Self::Pda { program, seed } => Some(AccountId::for_public_pda(program, seed)),
        }
    }
}

/// Message processed by the sequencer.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionMessage<P> {
    /// The public context of the execution.
    pub public_context: PublicExecutionContext,
    /// Context specific to the execution.
    pub execution: P,
    /// Nonces of public accounts used.
    pub nonces: BTreeMap<AccountId, Nonce>,
    /// Evidence to show that claimed public accounts are indeed public.
    pub admission_evidence: Vec<PublicAccountEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum InvalidTransaction {
    #[error("Nonces do not name exactly the signers")]
    Nonces,
    #[error("Authorized accounts do not match the signers")]
    AuthorizedAccounts,
    #[error("A public transaction cannot select promotions")]
    PublicPromotions,
}

impl<P: BorshSerialize> TransactionMessage<P> {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Autoderived borsh serialization failure")
    }

    pub(crate) fn hash_under(&self, domain: &[u8; 32]) -> [u8; 32] {
        Sha256::new()
            .chain_update(domain)
            .chain_update(self.to_bytes())
            .finalize()
            .into()
    }
}

impl<P> TransactionMessage<P> {
    pub(crate) fn check_signers(&self) -> Result<(), InvalidTransaction> {
        if !self
            .nonces
            .keys()
            .eq(&self.public_context.authorized_accounts)
        {
            return Err(InvalidTransaction::AuthorizedAccounts);
        }
        Ok(())
    }
}

impl From<InvalidTransaction> for LeeError {
    fn from(error: InvalidTransaction) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

/// `Sha256(domain || message_hash || next_0 || next_1 || …)`, each next key as
/// `key_type || key_commitment` (33 B), in `nonces` order.
pub fn hash_with_keys(
    domain: &[u8; 32],
    message_hash: &[u8; 32],
    next: &[SigningKeyState],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(message_hash);
    for key in next {
        hasher.update(borsh::to_vec(key).expect("a signing key state encodes to 33 bytes"));
    }
    hasher.finalize().into()
}

pub fn nonce_map(
    entries: impl IntoIterator<Item = (AccountId, Nonce)>,
) -> Result<BTreeMap<AccountId, Nonce>, InvalidTransaction> {
    let mut nonces = BTreeMap::new();
    for (account_id, nonce) in entries {
        if nonces.insert(account_id, nonce).is_some() {
            return Err(InvalidTransaction::Nonces);
        }
    }
    Ok(nonces)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::account::{AccountId, Nonce};

    use super::{InvalidTransaction, nonce_map};

    #[test]
    fn a_nonce_map_rejects_a_repeated_account() {
        let account_id = AccountId::new([1; 32]);
        assert_eq!(
            nonce_map([(account_id, Nonce(2)), (account_id, Nonce(3))]),
            Err(InvalidTransaction::Nonces)
        );
        assert_eq!(
            nonce_map([(account_id, Nonce(2))]),
            Ok(BTreeMap::from([(account_id, Nonce(2))]))
        );
    }
}
