use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use sha2::{Digest as _, Sha256};

use crate::fees::{FeeFields, SignedMessage};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Deployment/\x00\x00\x00";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub bytecode: Vec<u8>,
    /// Fee fields ([`FeeFields`]), inside the hashed content so every signature
    /// over [`Message::hash`] covers them. Deployments are priced as public
    /// transactions (tokenomics ruling Q2).
    pub payer: AccountId,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: u128,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("bytecode", &format_args!("<{} bytes>", self.bytecode.len()))
            .field("payer", &self.payer)
            .field("gas_limit", &self.gas_limit)
            .field("tip", &self.tip)
            .field("max_fee", &self.max_fee)
            .finish()
    }
}

impl Message {
    #[must_use]
    pub const fn new(bytecode: Vec<u8>, fees: FeeFields) -> Self {
        let FeeFields {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = fees;
        Self {
            bytecode,
            payer,
            gas_limit,
            tip,
            max_fee,
        }
    }

    #[must_use]
    pub fn into_bytecode(self) -> Vec<u8> {
        self.bytecode
    }

    /// The message's fee fields, regrouped.
    #[must_use]
    pub const fn fees(&self) -> FeeFields {
        FeeFields::new(self.payer, self.gas_limit, self.tip, self.max_fee)
    }

    /// Test-only shorthand for [`Self::new`] with zeroed fee fields. Gated for the same reason
    /// as its public-transaction counterpart: paying no fee is a decision, not a default.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn new_feeless(bytecode: Vec<u8>) -> Self {
        Self::new(bytecode, FeeFields::ZERO)
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(PREFIX);
        hasher.update(&bytes);
        hasher.finalize().into()
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
    use sha2::{Digest as _, Sha256};

    use super::{FeeFields, Message, PREFIX};
    use crate::AccountId;

    #[test]
    fn bytecode_roundtrip() {
        // `Message::new(b).into_bytecode()` must return exactly `b`. Catches
        // mutations of `into_bytecode` returning `vec![]`, `vec![0]`, or `vec![1]`.
        let bytecode = vec![0x7F_u8, 0x45, 0x4C, 0x46]; // ELF magic
        assert_eq!(
            Message::new(bytecode.clone(), FeeFields::ZERO).into_bytecode(),
            bytecode
        );
        assert!(
            Message::new(vec![], FeeFields::ZERO)
                .into_bytecode()
                .is_empty()
        );
        assert_eq!(
            Message::new(vec![0xAB], FeeFields::ZERO).into_bytecode(),
            vec![0xAB_u8]
        );
    }

    /// Pinned when deployment messages gained a hash: prefix
    /// `/LEE/v0.3/Message/Deployment/`, then the four fee fields appended after
    /// the bytecode. The version tag matches the other message domains.
    #[test]
    fn hash_deployment_pinned() {
        let msg = Message::new(
            vec![0x7F_u8, 0x45, 0x4C, 0x46],
            FeeFields::new(AccountId::new([7_u8; 32]), 0x0102_0304, 9, 0x0a0b),
        );

        let expected_borsh: Vec<u8> = [
            &[4_u8, 0, 0, 0][..],                                    // bytecode len = 4
            &[0x7F, 0x45, 0x4C, 0x46],                               // bytecode
            &[7_u8; 32],                                             // payer
            &[4, 3, 2, 1, 0, 0, 0, 0],                               // gas_limit u64 LE
            &[9, 0, 0, 0, 0, 0, 0, 0],                               // tip u64 LE
            &[0x0b, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // max_fee u128 LE
        ]
        .concat();

        assert_eq!(
            borsh::to_vec(&msg).unwrap(),
            expected_borsh,
            "`program_deployment_transaction::hash()`: expected borsh order has changed"
        );

        let mut preimage = Vec::with_capacity(PREFIX.len() + expected_borsh.len());
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(&expected_borsh);
        let expected_hash: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            msg.hash(),
            expected_hash,
            "`program_deployment_transaction::hash()`: serialization has changed"
        );
    }
}
