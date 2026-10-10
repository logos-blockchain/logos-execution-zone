use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Nonce},
    execution_state::PublicExecutionContext,
    program::PdaSeed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{PublicKey, error::LeeError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAccountEvidence {
    Key(PublicKey),
    Pda { program: AccountId, seed: PdaSeed },
}

impl PublicAccountEvidence {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        match self {
            Self::Key(key) => AccountId::from(key),
            Self::Pda { program, seed } => AccountId::for_public_pda(program, seed),
        }
    }
}

/// Message processed by the sequencer.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionMessage<P> {
    /// The public context of the execution.
    pub context: PublicExecutionContext,
    /// Context specific to the execution.
    pub execution: P,
    /// Nonces of public accounts used.
    pub nonces: BTreeMap<AccountId, Nonce>,
    /// Evidence to show that claimed public accounts are indeed public.
    pub admission_evidence: Vec<PublicAccountEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum InvalidTransaction {
    #[error("Invalid signature for given message and public key")]
    Signature,
    #[error("Duplicate signers found in witness set")]
    DuplicateSigner,
    #[error("Nonces do not name exactly the signers")]
    Nonces,
    #[error("Authorized accounts do not match the signers")]
    AuthorizedAccounts,
    #[error("A public transaction cannot select Cast promotions")]
    PublicCastPromotions,
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
    pub(crate) fn check_signers(&self, signers: &[AccountId]) -> Result<(), InvalidTransaction> {
        let unique: BTreeSet<AccountId> = signers.iter().copied().collect();
        if unique.len() != signers.len() {
            return Err(InvalidTransaction::DuplicateSigner);
        }
        if !self.nonces.keys().eq(&unique) {
            return Err(InvalidTransaction::Nonces);
        }
        if unique != self.context.authorized_accounts {
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
