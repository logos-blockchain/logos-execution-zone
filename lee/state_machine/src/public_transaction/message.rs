use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    RootCall,
    account::{Actor, Nonce},
    execution_state::PublicExecutionContext,
    program::MessageData,
    signing_key::SigningKeyState,
};

use crate::{
    AccountId, PublicAccountEvidence, TransactionMessage, error::LeeError, fees::FeeDeclaration,
    program::Program, transaction_message::hash_with_keys,
};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";
const KEYED_PREFIX: &[u8; 32] = b"/LEE/v0.3/KeyedMessage/Public/\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PublicExecution {
    pub root: RootCall,
    /// The fee declaration, or `None` for a fee-exempt (system) transaction.
    pub fee: Option<FeeDeclaration>,
}

pub type Message = TransactionMessage<PublicExecution>;

impl Message {
    #[must_use]
    pub fn new(
        to: Actor,
        message: MessageData,
        public_actors: impl IntoIterator<Item = Actor>,
        nonces: BTreeMap<AccountId, Nonce>,
        fee: Option<FeeDeclaration>,
        admission_evidence: Vec<PublicAccountEvidence>,
    ) -> Self {
        Self {
            public_context: PublicExecutionContext::new(public_actors, nonces.keys().copied()),
            execution: PublicExecution {
                root: RootCall { to, message },
                fee,
            },
            nonces,
            admission_evidence,
        }
    }

    /// Builds a fee-exempt message (`fee: None`). Correct for system
    /// transactions (clock, deposits, dispatches); charged transactions use
    /// [`Self::try_new_with_fees`].
    pub fn try_new(
        to: Actor,
        public_actors: impl IntoIterator<Item = Actor>,
        nonces: BTreeMap<AccountId, Nonce>,
        message: impl BorshSerialize,
    ) -> Result<Self, LeeError> {
        Ok(Self::new_preserialized(
            to,
            Program::serialize_message(message)?,
            public_actors,
            nonces,
            None,
        ))
    }

    pub fn try_new_with_fees(
        to: Actor,
        public_actors: impl IntoIterator<Item = Actor>,
        nonces: BTreeMap<AccountId, Nonce>,
        message: impl BorshSerialize,
        fee: FeeDeclaration,
    ) -> Result<Self, LeeError> {
        Ok(Self::new_preserialized(
            to,
            Program::serialize_message(message)?,
            public_actors,
            nonces,
            Some(fee),
        ))
    }

    #[must_use]
    pub fn new_preserialized(
        to: Actor,
        message: MessageData,
        public_actors: impl IntoIterator<Item = Actor>,
        nonces: BTreeMap<AccountId, Nonce>,
        fee: Option<FeeDeclaration>,
    ) -> Self {
        Self::new(to, message, public_actors, nonces, fee, Vec::new())
    }

    #[must_use]
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.hash_under(PREFIX)
    }

    /// The 32-byte value each signer signs.
    #[must_use]
    pub fn message_with_keys(&self, next: &[SigningKeyState]) -> [u8; 32] {
        hash_with_keys(KEYED_PREFIX, &self.hash(), next)
    }
}

impl crate::fees::SignedMessage for Message {
    fn payer(&self) -> Option<AccountId> {
        self.execution.fee.map(|fee| fee.payer)
    }

    fn nonces(&self) -> &BTreeMap<AccountId, Nonce> {
        &self.nonces
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use lee_core::{
        account::{AccountId, Actor, Nonce},
        signing_key::{KeyType, SigningKeyState},
    };
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

    fn key(commitment: u8) -> SigningKeyState {
        SigningKeyState {
            key_type: KeyType::Schnorr,
            key_commitment: [commitment; 32],
        }
    }

    fn pinned_message() -> Message {
        let to = Actor::new(AccountId::new([42; 32]), AccountId::new([0; 32]));
        Message::new_preserialized(
            to,
            vec![0],
            [to],
            BTreeMap::from([(to.account_id, Nonce(1))]),
            None,
        )
    }

    #[test]
    fn a_public_message_has_a_pinned_layout_and_hash() {
        let to = Actor::new(AccountId::new([42; 32]), AccountId::new([0; 32]));
        let message = Message::new_preserialized(
            to,
            vec![0],
            [to],
            BTreeMap::from([(to.account_id, Nonce(1))]),
            None,
        );

        let expected: Vec<u8> = [
            &[1, 0, 0, 0][..], // public_context.actors: one actor
            &[42; 32],
            &[0; 32],
            &[1, 0, 0, 0], // public_context.authorized_accounts: the account naming a nonce
            &[42; 32],
            &[0, 0, 0, 0], // public_context.promotions: none
            &[42; 32],     // execution.root.to.account_id
            &[0; 32],      // execution.root.to.program_account_id: the native token program
            &[1, 0, 0, 0], // execution.root.message
            &[0],
            &[0],          // execution.fee: None
            &[1, 0, 0, 0], // nonces: one account's nonce, a little-endian u128
            &[42; 32],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0], // admission_evidence: none
        ]
        .concat();

        assert_eq!(message.to_bytes(), expected);
        let digest: [u8; 32] = Sha256::digest([&PREFIX[..], &expected].concat()).into();
        assert_eq!(message.hash(), digest);
    }

    #[test]
    fn message_with_keys_has_known_answers() {
        let message = pinned_message();
        assert_eq!(
            message.message_with_keys(&[key(7)]),
            hex!("0c7db897f9d813e0fbc8a7be1f850f73801e1cbea65b3b1b8154a319656c8399")
        );
        assert_eq!(
            message.message_with_keys(&[key(1), key(2), key(3)]),
            hex!("4f7bf181a68bffc9df4d2278ef39211314517388b92bc16ece0cde390c6df31f")
        );
    }

    #[test]
    fn message_with_keys_changes_with_the_order_of_the_next_keys() {
        let message = pinned_message();
        assert_ne!(
            message.message_with_keys(&[key(1), key(2), key(3)]),
            message.message_with_keys(&[key(2), key(1), key(3)])
        );
    }

    #[test]
    fn message_with_keys_changes_with_any_byte_of_any_next_key_commitment() {
        let message = pinned_message();
        let next = [key(1), key(2), key(3)];
        let signed = message.message_with_keys(&next);
        for signer in 0..next.len() {
            for byte in 0..32 {
                let mut changed = next;
                changed[signer].key_commitment[byte] ^= 1;
                assert_ne!(message.message_with_keys(&changed), signed);
            }
        }
    }
}
