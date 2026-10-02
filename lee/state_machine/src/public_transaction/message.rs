use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{Actor, Nonce},
    execution_state::TransactionEntry,
    program::{MessageData, MessageRef, PdaSeed},
};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, PublicKey, error::LeeError, fees::FeeDeclaration, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PublicIdentity {
    Key(PublicKey),
    Pda { program: AccountId, seed: PdaSeed },
}

impl PublicIdentity {
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        match self {
            Self::Key(key) => AccountId::from(key),
            Self::Pda { program, seed } => AccountId::for_public_pda(program, seed),
        }
    }
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub root: TransactionEntry<MessageRef>,
    pub public_actors: Vec<Actor>,
    pub nonces: Vec<Nonce>,
    /// The fee declaration, or `None` for a fee-exempt (system) transaction.
    pub fee: Option<FeeDeclaration>,
    pub identities: Vec<PublicIdentity>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            root,
            public_actors,
            nonces,
            fee,
            identities,
        } = self;
        f.debug_struct("Message")
            .field("root", root)
            .field("public_actors", public_actors)
            .field("nonces", nonces)
            .field("fee", fee)
            .field("identities", identities)
            .finish()
    }
}

impl Message {
    #[must_use]
    pub const fn new(
        root: TransactionEntry<MessageRef>,
        public_actors: Vec<Actor>,
        nonces: Vec<Nonce>,
        fee: Option<FeeDeclaration>,
        identities: Vec<PublicIdentity>,
    ) -> Self {
        Self {
            root,
            public_actors,
            nonces,
            fee,
            identities,
        }
    }

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
        Self::new(
            TransactionEntry::Call { to, message },
            public_actors,
            nonces,
            fee,
            Vec::new(),
        )
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
mod tests {
    use lee_core::{
        account::{AccountId, Actor, Nonce},
        execution_state::TransactionEntry,
        program::{MessageDigest, MessageRef},
    };
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

    #[test]
    fn a_public_message_has_a_pinned_layout_and_hash() {
        let to = Actor::new(AccountId::new([42; 32]), AccountId::new([0; 32]));
        let message = Message::new_preserialized(to, vec![0], vec![to], vec![Nonce(1)], None);

        let expected: Vec<u8> = [
            &[0][..],      // root: TransactionEntry::Call
            &[42; 32],     // to.account_id
            &[0; 32],      // to.program_account_id: the native token program
            &[1, 0, 0, 0], // message
            &[0],
            &[1, 0, 0, 0], // public_actors: one actor
            &[42; 32],
            &[0; 32],
            &[1, 0, 0, 0], // nonces: one nonce, a little-endian u128
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0],          // fee: None
            &[0, 0, 0, 0], // identities: none
        ]
        .concat();

        assert_eq!(message.to_bytes(), expected);
        let digest: [u8; 32] = Sha256::digest([&PREFIX[..], &expected].concat()).into();
        assert_eq!(message.hash(), digest);
    }

    #[test]
    fn a_public_message_with_a_receipt_root_has_a_pinned_layout() {
        let to = Actor::new(AccountId::new([42; 32]), AccountId::new([0; 32]));
        let message = Message::new(
            TransactionEntry::Cast(MessageRef {
                sequence: 3,
                digest: MessageDigest::new([9; 32]),
            }),
            vec![to],
            Vec::new(),
            None,
            Vec::new(),
        );

        let expected: Vec<u8> = [
            &[1][..],                                          // root: TransactionEntry::Cast
            &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // sequence
            &[9; 32],                                          // digest
            &[1, 0, 0, 0],                                     // public_actors: one actor
            &[42; 32],
            &[0; 32],
            &[0, 0, 0, 0], // nonces: none
            &[0],          // fee: None
            &[0, 0, 0, 0], // identities: none
        ]
        .concat();

        assert_eq!(message.to_bytes(), expected);
    }
}
