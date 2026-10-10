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
    use lee_core::account::{AccountId, Nonce, ProgramShardSelector};
    use sha2::{Digest as _, Sha256};

    use super::{Message, PREFIX};
    use crate::fees::FeeDeclaration;

    // program_account_id: AccountId, matching the raw bytes of the old [1_u32; 8] ProgramId
    // (each word as LE u32) so this pinned wire layout is unchanged.
    const PROGRAM_ACCOUNT_ID_BYTES: &[u8] = &[
        1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0,
        0, 0,
    ];
    const POSITIONS_BYTES: &[u8] = &[
        1, 0, 0, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43,
        43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43, 43,
    ];
    // The balance selector names the reserved native token program, not a tagged absence.
    const BALANCE_POSITIONS_BYTES: &[u8] = &[
        1, 0, 0, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    // nonces: u32 len=1, then Nonce(5) as LE u128
    const NONCES_BYTES: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn pinned_message(
        shard_selectors: Vec<ProgramShardSelector>,
        instruction_data: Vec<u8>,
        fee: Option<FeeDeclaration>,
    ) -> Message {
        Message::new_preserialized(
            AccountId::new([
                1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
                1, 0, 0, 0,
            ]),
            shard_selectors,
            vec![Nonce(5)],
            instruction_data,
            fee,
        )
    }

    fn named_shard_selector() -> ProgramShardSelector {
        ProgramShardSelector::new(AccountId::new([42; 32]), AccountId::new([43; 32]))
    }

    /// Pins the borsh wire order (`program_account_id` ++ `shard_selectors` ++ `nonces` ++
    /// `instruction_data` ++ `fee`) and the prefixed hash. Any layout change trips this.
    fn assert_hash_pinned(
        msg: &Message,
        shard_selectors_bytes: &[u8],
        instruction_bytes: &[u8],
        fee_bytes: &[u8],
    ) {
        let expected_borsh: Vec<u8> = [
            PROGRAM_ACCOUNT_ID_BYTES,
            shard_selectors_bytes,
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
        assert_hash_pinned(
            &pinned_message(vec![named_shard_selector()], vec![], None),
            POSITIONS_BYTES,
            &[0, 0, 0, 0],
            &[0],
        );
    }

    #[test]
    fn hash_public_pinned_balance_shard_selector() {
        assert_hash_pinned(
            &pinned_message(
                vec![ProgramShardSelector::native_balance(AccountId::new(
                    [42; 32],
                ))],
                vec![],
                None,
            ),
            BALANCE_POSITIONS_BYTES,
            &[0, 0, 0, 0],
            &[0],
        );
    }

    #[test]
    fn hash_public_pinned_nonempty_instruction() {
        // instruction_data is Vec<u8>: u32 len=3 then the raw bytes, one wire byte per element —
        // pins the element width (the pre-borsh wire carried one u32 word per element).
        assert_hash_pinned(
            &pinned_message(vec![named_shard_selector()], vec![7, 8, 9], None),
            POSITIONS_BYTES,
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
                vec![named_shard_selector()],
                vec![],
                Some(FeeDeclaration::new(AccountId::new([7; 32]), 9, 3, 100)),
            ),
            POSITIONS_BYTES,
            &[0, 0, 0, 0],
            fee_bytes,
        );
    }
}
