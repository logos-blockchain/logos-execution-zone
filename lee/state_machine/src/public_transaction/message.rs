use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::Nonce,
    program::{InstructionData, ProgramId},
};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, error::LeeError, fees::FeeDeclaration, program::Program};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
    /// The fee declaration, or `None` for a fee-exempt (system) transaction.
    pub fee: Option<FeeDeclaration>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
            fee,
        } = self;
        let program_id_hex = hex::encode(
            program_id
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        f.debug_struct("Message")
            .field("program_id", &program_id_hex)
            .field("account_ids", account_ids)
            .field("nonces", nonces)
            .field("instruction_data", instruction_data)
            .field("fee", fee)
            .finish()
    }
}

impl Message {
    /// Builds a fee-exempt message (`fee: None`). Correct for system
    /// transactions (clock, deposits, dispatches); charged transactions use
    /// [`Self::try_new_with_fees`].
    pub fn try_new<T: BorshSerialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Result<Self, LeeError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self::new_preserialized(
            program_id,
            account_ids,
            nonces,
            instruction_data,
            None,
        ))
    }

    pub fn try_new_with_fees<T: BorshSerialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
        fee: FeeDeclaration,
    ) -> Result<Self, LeeError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self::new_preserialized(
            program_id,
            account_ids,
            nonces,
            instruction_data,
            Some(fee),
        ))
    }

    #[must_use]
    pub const fn new_preserialized(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
        fee: Option<FeeDeclaration>,
    ) -> Self {
        Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
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
mod tests {
    use lee_core::account::{AccountId, Nonce};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};
    use crate::fees::FeeDeclaration;

    // program_id: [1_u32; 8], each word as LE u32.
    const PROGRAM_ID_BYTES: &[u8] = &[
        1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
        0, 0,
    ];
    // account_ids: u32 len=1, then AccountId([42_u8; 32])
    const ACCOUNT_IDS_BYTES: &[u8] = &[
        1, 0, 0, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    // nonces: u32 len=1, then Nonce(5) as LE u128
    const NONCES_BYTES: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn pinned_message(instruction_data: Vec<u8>, fee: Option<FeeDeclaration>) -> Message {
        Message::new_preserialized(
            [1_u32; 8],
            vec![AccountId::new([42; 32])],
            vec![Nonce(5)],
            instruction_data,
            fee,
        )
    }

    /// Pins the borsh wire order (program_id ++ account_ids ++ nonces ++
    /// instruction_data ++ fee) and the prefixed hash. Any layout change trips this.
    fn assert_hash_pinned(msg: &Message, instruction_bytes: &[u8], fee_bytes: &[u8]) {
        let expected_borsh: Vec<u8> = [
            PROGRAM_ID_BYTES,
            ACCOUNT_IDS_BYTES,
            NONCES_BYTES,
            instruction_bytes,
            fee_bytes,
        ]
        .concat();
        assert_eq!(
            borsh::to_vec(msg).unwrap(),
            expected_borsh,
            "`public_transaction::hash()`: expected borsh order has changed"
        );

        let preimage = [&PREFIX[..], &expected_borsh].concat();
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(
            msg.hash(),
            expected_hash,
            "`public_transaction::hash()`: serialization has changed"
        );
    }

    #[test]
    fn hash_public_pinned_exempt() {
        // instruction_data: u32 len=0; fee: `Option::None` -> a single 0 tag byte.
        assert_hash_pinned(&pinned_message(vec![], None), &[0, 0, 0, 0], &[0]);
    }

    #[test]
    fn hash_public_pinned_nonempty_instruction() {
        // instruction_data is Vec<u8>: u32 len=3 then the raw bytes, one wire byte per element —
        // pins the element width (the pre-borsh wire carried one u32 word per element).
        assert_hash_pinned(
            &pinned_message(vec![7, 8, 9], None),
            &[3, 0, 0, 0, 7, 8, 9],
            &[0],
        );
    }

    #[test]
    fn hash_public_pinned_charged() {
        // fee: `Option::Some` -> 1 tag byte, then payer (32 bytes), gas_limit
        // (u64 LE), tip (u64 LE), max_fee (u128 LE).
        let fee_bytes: &[u8] = &[
            1, // Some tag
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, // payer
            9, 0, 0, 0, 0, 0, 0, 0, // gas_limit
            3, 0, 0, 0, 0, 0, 0, 0, // tip
            100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // max_fee
        ];
        assert_hash_pinned(
            &pinned_message(
                vec![],
                Some(FeeDeclaration::new(AccountId::new([7_u8; 32]), 9, 3, 100)),
            ),
            &[0, 0, 0, 0],
            fee_bytes,
        );
    }
}
