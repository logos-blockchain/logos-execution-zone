use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    RootCall,
    account::{Actor, Nonce},
    execution_state::PublicExecutionContext,
    program::MessageData,
};

use crate::{
    AccountId, PublicAccountEvidence, TransactionMessage, error::LeeError, fees::FeeDeclaration,
    program::Program,
};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

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
            context: PublicExecutionContext::new(public_actors, nonces.keys().copied()),
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
    pub fn hash(&self) -> [u8; 32] {
        self.hash_under(PREFIX)
    }
}

impl crate::fees::SignedMessage for Message {
    fn signing_hash(&self) -> [u8; 32] {
        self.hash()
    }

    fn payer(&self) -> Option<AccountId> {
        self.execution.fee.map(|fee| fee.payer)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::account::{AccountId, Actor, Nonce};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

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
            &[1, 0, 0, 0][..], // context.actors: one actor
            &[42; 32],
            &[0; 32],
            &[1, 0, 0, 0], // context.authorized_accounts: the account naming a nonce
            &[42; 32],
            &[0, 0, 0, 0], // context.cast_promotions: none
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
}
