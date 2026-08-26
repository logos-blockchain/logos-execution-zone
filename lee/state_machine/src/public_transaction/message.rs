use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{Nonce, SlotRef},
    program::{InstructionData, ProgramId},
};
use sha2::{Digest as _, Sha256};

use crate::{error::LeeError, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub slots: Vec<SlotRef>,
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
            .field("slots", &self.slots)
            .field("nonces", &self.nonces)
            .field("instruction_data", &self.instruction_data)
            .finish()
    }
}

impl Message {
    pub fn try_new<T: BorshSerialize>(
        program_id: ProgramId,
        slots: Vec<SlotRef>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Result<Self, LeeError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self {
            program_id,
            slots,
            nonces,
            instruction_data,
        })
    }

    #[must_use]
    pub const fn new_preserialized(
        program_id: ProgramId,
        slots: Vec<SlotRef>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
    ) -> Self {
        Self {
            program_id,
            slots,
            nonces,
            instruction_data,
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

#[cfg(test)]
mod tests {
    use lee_core::account::{AccountId, Nonce, SlotRef};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};

    // program_id [1_u32; 8], each word as LE u32.
    const PROGRAM_ID_BYTES: [u8; 32] = [
        1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
        0, 0,
    ];

    fn pinned_message(instruction_data: Vec<u8>) -> Message {
        Message::new_preserialized(
            [1_u32; 8],
            vec![SlotRef {
                account_id: AccountId::new([42; 32]),
                program: Some(AccountId::new([7; 32])),
            }],
            vec![Nonce(5)],
            instruction_data,
        )
    }

    fn assert_borsh_and_hash_pinned(msg: &Message, expected_borsh: &[u8]) {
        assert_eq!(
            borsh::to_vec(msg).unwrap(),
            expected_borsh,
            "`public_transaction::hash()`: expected borsh order has changed"
        );

        let preimage = [&PREFIX[..], expected_borsh].concat();
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            msg.hash(),
            expected_hash,
            "`public_transaction::hash()`: serialization has changed"
        );
    }

    #[test]
    fn hash_public_pinned() {
        // slots: u32 len=1 then SlotRef(account_id [42; 32], program Some([7; 32]) as tag 1 plus
        // the id); nonces: u32 len=1 then LE u128; instruction_data: u32 len=0.
        let expected_borsh: Vec<u8> = [
            &PROGRAM_ID_BYTES[..],
            &[1, 0, 0, 0],
            &[42; 32],
            &[1],
            &[7; 32],
            &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0],
        ]
        .concat();

        assert_borsh_and_hash_pinned(&pinned_message(vec![]), &expected_borsh);
    }

    #[test]
    fn hash_public_pinned_nonempty_instruction() {
        // instruction_data is Vec<u8>: u32 len=3 then the raw bytes, one wire byte per element —
        // pins the element width (the pre-borsh wire carried one u32 word per element).
        let expected_borsh: Vec<u8> = [
            &PROGRAM_ID_BYTES[..],
            &[1, 0, 0, 0],
            &[42; 32],
            &[1],
            &[7; 32],
            &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[3, 0, 0, 0, 7, 8, 9],
        ]
        .concat();

        assert_borsh_and_hash_pinned(&pinned_message(vec![7, 8, 9]), &expected_borsh);
    }

    #[test]
    fn hash_public_pinned_address_only_slot() {
        // A position that names no slot encodes the `Option` tag as 0 and nothing after it.
        let message = Message::new_preserialized(
            [1_u32; 8],
            vec![SlotRef {
                account_id: AccountId::new([42; 32]),
                program: None,
            }],
            vec![Nonce(5)],
            vec![],
        );
        let expected_borsh: Vec<u8> = [
            &PROGRAM_ID_BYTES[..],
            &[1, 0, 0, 0],
            &[42; 32],
            &[0],
            &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0],
        ]
        .concat();

        assert_borsh_and_hash_pinned(&message, &expected_borsh);
    }
}
