use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::Nonce, program::InstructionData};
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
    /// bytecode, which is handled natively, see `PROGRAM_LOADER_ACCOUNT_ID`'s doc
    /// comment) belongs here instead of in `instruction_data`, avoiding that ~4x bloat entirely
    /// rather than just packing it more efficiently.
    ///
    /// Unused for now — no constructor sets it and no dispatch logic reads it yet.
    pub raw_payload: Option<Vec<u8>>,
}

impl Message {
    pub fn try_new<T: BorshSerialize>(
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

    // AccountId::from([1_u32; 8]), each word as LE u32 — From<ProgramId> is a direct byte
    // reinterpretation, so this is also that ProgramId's LE bytes.
    const PROGRAM_ACCOUNT_ID_BYTES: [u8; 32] = [
        1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
        0, 0,
    ];

    fn pinned_message(instruction_data: Vec<u8>) -> Message {
        Message::new_preserialized(
            AccountId::new(PROGRAM_ACCOUNT_ID_BYTES),
            vec![AccountId::new([42; 32])],
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
        // account_ids: u32 len=1 then AccountId([42; 32]); nonces: u32 len=1 then LE u128;
        // instruction_data: u32 len=0.
        let expected_borsh: Vec<u8> = [
            &PROGRAM_ACCOUNT_ID_BYTES[..],
            &[1, 0, 0, 0],
            &[42; 32],
            &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0],
            &[0], // raw_payload: None
        ]
        .concat();

        assert_borsh_and_hash_pinned(&pinned_message(vec![]), &expected_borsh);
    }

    #[test]
    fn hash_public_pinned_nonempty_instruction() {
        // instruction_data is Vec<u8>: u32 len=3 then the raw bytes, one wire byte per element —
        // pins the element width (the pre-borsh wire carried one u32 word per element).
        let expected_borsh: Vec<u8> = [
            &PROGRAM_ACCOUNT_ID_BYTES[..],
            &[1, 0, 0, 0],
            &[42; 32],
            &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[3, 0, 0, 0, 7, 8, 9],
            &[0], // raw_payload: None
        ]
        .concat();

        assert_borsh_and_hash_pinned(&pinned_message(vec![7, 8, 9]), &expected_borsh);
    }
}
