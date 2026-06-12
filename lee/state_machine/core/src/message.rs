//! Guest-side mirror of `lee::privacy_preserving_transaction::message::{Message,
//! EncryptedAccountData}`.
//!
//! The aggregator guest cannot depend on the `lee` crate (it pulls in host-only
//! `risc0-zkvm`/`lee_core` features), so the host converts each transaction's `Message` into
//! this `lee_core`-resident mirror before writing it to the guest. The mirror omits `epk`
//! (the 1088-byte ML-KEM-768 ciphertext from `EphemeralPublicKey`): it isn't part of
//! [`PrivacyPreservingCircuitOutput`] and so plays no role in `env::verify`, and reading it
//! as `Vec<u8>` is costly enough to push the guest over a segment boundary.

use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentSetDigest, Nullifier, PrivacyPreservingCircuitOutput,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    encryption::Ciphertext,
    program::{BlockValidityWindow, TimestampValidityWindow},
};

/// Mirror of `lee::privacy_preserving_transaction::message::EncryptedAccountData`.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct EncryptedAccountData {
    pub ciphertext: Ciphertext,
    pub view_tag: u8,
}

/// Mirror of `lee::privacy_preserving_transaction::message::Message`.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, Clone, PartialEq, Eq))]
pub struct Message {
    pub public_account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub public_post_states: Vec<Account>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
}

impl Message {
    /// Reconstructs the `PrivacyPreservingCircuitOutput` this message corresponds to, given
    /// the `public_pre_states` resolved for `public_account_ids` (same order).
    ///
    /// Mirrors `lee`'s `circuit_output_for_message`, minus the `public_pre_states` lookup
    /// itself: the guest has no access to chain state, so the caller resolves pre-states and
    /// passes them in directly.
    #[must_use]
    pub fn into_circuit_output(
        self,
        public_pre_states: Vec<AccountWithMetadata>,
    ) -> PrivacyPreservingCircuitOutput {
        PrivacyPreservingCircuitOutput {
            public_pre_states,
            public_post_states: self.public_post_states,
            ciphertexts: self
                .encrypted_private_post_states
                .into_iter()
                .map(|data| data.ciphertext)
                .collect(),
            new_commitments: self.new_commitments,
            new_nullifiers: self.new_nullifiers,
            block_validity_window: self.block_validity_window,
            timestamp_validity_window: self.timestamp_validity_window,
        }
    }
}
