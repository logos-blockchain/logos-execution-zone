use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::Nonce,
    program::{InstructionData, ProgramId},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::NssaError, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let program_id_hex = hex::encode(
            self.program_id
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        f.debug_struct("Message")
            .field("program_id", &program_id_hex)
            .field("account_ids", &self.account_ids)
            .field("nonces", &self.nonces)
            .field("instruction_data", &self.instruction_data)
            .finish()
    }
}

impl Message {
    pub fn try_new<T: Serialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Result<Self, NssaError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        })
    }

    #[must_use]
    pub const fn new_preserialized(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
    ) -> Self {
        Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        }
    }

    #[must_use]
    pub fn hash_message(&self) -> [u8; 32] {
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
    use nssa_core::account::{AccountId, Nonce};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

    #[test]
    fn hash_message_public_pinned() {
        let msg = Message::new_preserialized(
            [1_u32; 8],
            vec![AccountId::new([42_u8; 32])],
            vec![Nonce(5)],
            vec![],
        );

        // program_id: [1_u32; 8], each word as LE u32
        let program_id_bytes: &[u8] = &[
            1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
            0, 0, 0,
        ];
        // account_ids: AccountId([42_u8; 32])
        let account_ids_bytes: &[u8] = &[42_u8; 32];
        // nonces: u32 len=1, then Nonce(5) as LE u128
        let nonces_bytes: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let instruction_data_bytes: &[u8] = &[0_u8; 4];

        let expected_borsh_vec: Vec<u8> = [
            program_id_bytes,
            &[1_u8, 0, 0, 0], // account_ids len=1
            account_ids_bytes,
            nonces_bytes,
            instruction_data_bytes,
        ]
        .concat();
        let expected_borsh: &[u8] = &expected_borsh_vec;

        assert_eq!(
            borsh::to_vec(&msg).unwrap(),
            expected_borsh,
            "`public_transaction::hash_message()`: expected borsh order has changed"
        );

        let mut preimage = Vec::with_capacity(PREFIX.len() + expected_borsh.len());
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(expected_borsh);
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            msg.hash_message(),
            expected_hash,
            "`public_transaction::hash_message()`: serialization has changed"
        );
    }
}
