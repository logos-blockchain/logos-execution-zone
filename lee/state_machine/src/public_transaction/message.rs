use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::Nonce, program::InstructionData};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::LeeError, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_account_id: AccountId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
    /// An optional large raw byte payload, carried alongside `instruction_data` rather than
    /// packed into it.
    ///
    /// `instruction_data` is word-serialized (`risc0_zkvm::serde`) so it can be read inside a
    /// RISC0 guest; that format encodes a `Vec<u8>` at 4 bytes per word, since it doesn't route
    /// through the serializer's `serialize_bytes`. `Message` itself, in contrast, is
    /// borsh-encoded on the wire, which packs `Vec<u8>` byte-for-byte. So a large payload that
    /// only needs to reach *native* dispatch logic (never a real guest — e.g. `Deploy`'s program
    /// bytecode, which is handled natively, see `RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID`'s doc
    /// comment) belongs here instead of in `instruction_data`, avoiding that ~4x bloat entirely
    /// rather than just packing it more efficiently.
    pub raw_payload: Option<Vec<u8>>,
}

impl Message {
    pub fn try_new<T: Serialize>(
        program_account_id: AccountId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Result<Self, LeeError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self {
            program_account_id,
            account_ids,
            nonces,
            instruction_data,
            raw_payload: None,
        })
    }

    #[must_use]
    pub const fn new_preserialized(
        program_account_id: AccountId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
    ) -> Self {
        Self {
            program_account_id,
            account_ids,
            nonces,
            instruction_data,
            raw_payload: None,
        }
    }

    #[must_use]
    pub fn with_raw_payload(mut self, raw_payload: Vec<u8>) -> Self {
        self.raw_payload = Some(raw_payload);
        self
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

#[cfg(test)]
mod tests {
    use lee_core::account::{AccountId, Nonce};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

    #[test]
    fn hash_public_pinned() {
        let msg = Message::new_preserialized(
            AccountId::from([1_u32; 8]),
            vec![AccountId::new([42_u8; 32])],
            vec![Nonce(5)],
            vec![],
        );

        // program_account_id: AccountId::from([1_u32; 8]) is the LE-word-flattened bytes of the
        // array
        let account_id_bytes: &[u8] = &[
            1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
            0, 0, 0,
        ];
        // account_ids: AccountId([42_u8; 32])
        let account_ids_bytes: &[u8] = &[42_u8; 32];
        // nonces: u32 len=1, then Nonce(5) as LE u128
        let nonces_bytes: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let instruction_data_bytes: &[u8] = &[0_u8; 4];
        // raw_payload: None
        let raw_payload_bytes: &[u8] = &[0_u8];

        let expected_borsh_vec: Vec<u8> = [
            account_id_bytes,
            &[1_u8, 0, 0, 0], // account_ids len=1
            account_ids_bytes,
            nonces_bytes,
            instruction_data_bytes,
            raw_payload_bytes,
        ]
        .concat();
        let expected_borsh: &[u8] = &expected_borsh_vec;

        assert_eq!(
            borsh::to_vec(&msg).unwrap(),
            expected_borsh,
            "`public_transaction::hash()`: expected borsh order has changed"
        );

        let mut preimage = Vec::with_capacity(PREFIX.len() + expected_borsh.len());
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(expected_borsh);
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            msg.hash(),
            expected_hash,
            "`public_transaction::hash()`: serialization has changed"
        );
    }
}
