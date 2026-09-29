use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{Actor, Nonce},
    program::MessageData,
};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::LeeError, fees::FeeDeclaration, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub to: Actor,
    pub message: MessageData,
    pub public_actors: Vec<Actor>,
    pub nonces: Vec<Nonce>,
    /// The fee declaration, or `None` for a fee-exempt (system) transaction.
    pub fee: Option<FeeDeclaration>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            to,
            message,
            public_actors,
            nonces,
            fee,
        } = self;
        f.debug_struct("Message")
            .field("to", to)
            .field("message", message)
            .field("public_actors", public_actors)
            .field("nonces", nonces)
            .field("fee", fee)
            .finish()
    }
}

impl Message {
    /// Builds a fee-exempt message (`fee: None`). Correct for system
    /// transactions (clock, deposits, dispatches); charged transactions use
    /// [`Self::try_new_with_fees`].
    pub fn try_new(
        to: Actor,
        public_actors: Vec<Actor>,
        nonces: Vec<Nonce>,
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
        public_actors: Vec<Actor>,
        nonces: Vec<Nonce>,
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
    pub const fn new_preserialized(
        to: Actor,
        message: MessageData,
        public_actors: Vec<Actor>,
        nonces: Vec<Nonce>,
        fee: Option<FeeDeclaration>,
    ) -> Self {
        Self {
            to,
            message,
            public_actors,
            nonces,
            fee,
        }
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(
            PREFIX
                .len()
                .checked_add(self.to_bytes().len())
                .expect("length overflow"),
        );
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&self.to_bytes());

        Sha256::digest(bytes).into()
    }
}

impl crate::fees::SignedMessage for Message {
    fn signing_hash(&self) -> [u8; 32] {
        self.hash()
    }

    fn payer(&self) -> Option<AccountId> {
        self.fee.map(|fee| fee.payer)
    }
}

#[cfg(test)]
mod tests {}
