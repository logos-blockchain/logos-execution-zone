//! Core data structures for the Authenticated Transfer Program.

use borsh::{BorshDeserialize, BorshSerialize};

/// Instruction type for the Authenticated Transfer program.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: u128 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every native transfer on the wire carries this tag, so a variant added
    /// ahead of `Transfer` would silently re-encode all of them.
    #[test]
    fn transfer_is_the_first_instruction_variant() {
        let bytes = borsh::to_vec(&Instruction::Transfer { amount: 7 }).unwrap();

        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &7_u128.to_le_bytes());
    }
}
