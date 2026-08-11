use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::Nonce,
    program::{InstructionData, ProgramId},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    AccountId,
    error::LeeError,
    fees::{FeeFields, SignedMessage},
    program::Program,
};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
    /// Fee fields ([`FeeFields`]), inside the hashed content so every signature
    /// over [`Message::hash`] covers them.
    pub payer: AccountId,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: u128,
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
            .field("payer", &self.payer)
            .field("gas_limit", &self.gas_limit)
            .field("tip", &self.tip)
            .field("max_fee", &self.max_fee)
            .finish()
    }
}

impl Message {
    pub fn try_new<T: Serialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
        fees: FeeFields,
    ) -> Result<Self, LeeError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self::new_preserialized(
            program_id,
            account_ids,
            nonces,
            instruction_data,
            fees,
        ))
    }

    #[must_use]
    pub const fn new_preserialized(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
        fees: FeeFields,
    ) -> Self {
        let FeeFields {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = fees;
        Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
            payer,
            gas_limit,
            tip,
            max_fee,
        }
    }

    /// The message's fee fields, regrouped.
    #[must_use]
    pub const fn fees(&self) -> FeeFields {
        FeeFields::new(self.payer, self.gas_limit, self.tip, self.max_fee)
    }

    /// Test-only shorthand for [`Self::try_new`] with zeroed fee fields, unwrapped.
    ///
    /// Gated so production code cannot reach it: a transaction that pays no fee is a protocol
    /// decision, never a default. System transactions spell [`FeeFields::ZERO`] out at their
    /// construction sites for exactly that reason.
    ///
    /// # Panics
    ///
    /// If `instruction` fails to serialize.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn new_feeless<T: Serialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Self {
        Self::try_new(
            program_id,
            account_ids,
            nonces,
            instruction,
            FeeFields::ZERO,
        )
        .expect("instruction should serialize")
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

impl SignedMessage for Message {
    fn signing_hash(&self) -> [u8; 32] {
        self.hash()
    }

    fn payer(&self) -> AccountId {
        self.payer
    }
}

#[cfg(test)]
mod tests {
    use lee_core::account::{AccountId, Nonce};
    use sha2::{Digest as _, Sha256};

    use super::{FeeFields, Message, PREFIX};

    /// Re-pinned when the fee fields were added: the four of them are appended
    /// after `instruction_data`. The domain prefix is unchanged.
    #[test]
    fn hash_public_pinned() {
        let msg = Message::new_preserialized(
            [1_u32; 8],
            vec![AccountId::new([42_u8; 32])],
            vec![Nonce(5)],
            vec![],
            FeeFields::new(AccountId::new([7_u8; 32]), 0x0102_0304, 9, 0x0a0b),
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
        // payer: AccountId([7_u8; 32])
        let payer_bytes: &[u8] = &[7_u8; 32];
        // gas_limit: u64 LE, tip: u64 LE, max_fee: u128 LE
        let gas_limit_bytes: &[u8] = &[4, 3, 2, 1, 0, 0, 0, 0];
        let tip_bytes: &[u8] = &[9, 0, 0, 0, 0, 0, 0, 0];
        let max_fee_bytes: &[u8] = &[0x0b, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let expected_borsh_vec: Vec<u8> = [
            program_id_bytes,
            &[1_u8, 0, 0, 0], // account_ids len=1
            account_ids_bytes,
            nonces_bytes,
            instruction_data_bytes,
            payer_bytes,
            gas_limit_bytes,
            tip_bytes,
            max_fee_bytes,
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
