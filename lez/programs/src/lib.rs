//! This crate provides [`Program`]s and associated utilities used by LEZ.

#[cfg(feature = "artifacts")]
pub use inner::*;

#[cfg(feature = "artifacts")]
mod inner {

    use std::borrow::Cow;

    use guests::{
        AMM_ELF, AMM_ID, ASSOCIATED_TOKEN_ACCOUNT_ELF, ASSOCIATED_TOKEN_ACCOUNT_ID,
        AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID, BRIDGE_ELF, BRIDGE_ID,
        BRIDGE_LOCK_ELF, BRIDGE_LOCK_ID, CLOCK_ELF, CLOCK_ID, CROSS_ZONE_INBOX_ELF,
        CROSS_ZONE_INBOX_ID, CROSS_ZONE_OUTBOX_ELF, CROSS_ZONE_OUTBOX_ID, FAUCET_ELF, FAUCET_ID,
        FEE_ELF, FEE_ID, PINATA_ELF, PINATA_ID, PINATA_TOKEN_ELF, PINATA_TOKEN_ID,
        PING_RECEIVER_ELF, PING_RECEIVER_ID, PING_SENDER_ELF, PING_SENDER_ID, SEQUENCER_STAKE_ELF,
        SEQUENCER_STAKE_ID, TOKEN_ELF, TOKEN_ID, VAULT_ELF, VAULT_ID, WRAPPED_TOKEN_ELF,
        WRAPPED_TOKEN_ID,
    };
    use lee::program::Program;

    mod guests {
        include!(concat!(env!("OUT_DIR"), "/lez/programs/mod.rs"));
    }

    #[must_use]
    #[inline]
    pub const fn authenticated_transfer() -> Program {
        Program::new_unchecked(
            AUTHENTICATED_TRANSFER_ID,
            Cow::Borrowed(AUTHENTICATED_TRANSFER_ELF),
        )
    }

    #[must_use]
    #[inline]
    pub const fn token() -> Program {
        Program::new_unchecked(TOKEN_ID, Cow::Borrowed(TOKEN_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn pinata() -> Program {
        Program::new_unchecked(PINATA_ID, Cow::Borrowed(PINATA_ELF))
    }

    // TODO: Not used anywhere?
    #[must_use]
    #[inline]
    pub const fn pinata_token() -> Program {
        Program::new_unchecked(PINATA_TOKEN_ID, Cow::Borrowed(PINATA_TOKEN_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn amm() -> Program {
        Program::new_unchecked(AMM_ID, Cow::Borrowed(AMM_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn clock() -> Program {
        Program::new_unchecked(CLOCK_ID, Cow::Borrowed(CLOCK_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn fee() -> Program {
        Program::new_unchecked(FEE_ID, Cow::Borrowed(FEE_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn ata() -> Program {
        Program::new_unchecked(
            ASSOCIATED_TOKEN_ACCOUNT_ID,
            Cow::Borrowed(ASSOCIATED_TOKEN_ACCOUNT_ELF),
        )
    }

    #[must_use]
    #[inline]
    pub const fn vault() -> Program {
        Program::new_unchecked(VAULT_ID, Cow::Borrowed(VAULT_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn faucet() -> Program {
        Program::new_unchecked(FAUCET_ID, Cow::Borrowed(FAUCET_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn bridge() -> Program {
        Program::new_unchecked(BRIDGE_ID, Cow::Borrowed(BRIDGE_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn cross_zone_outbox() -> Program {
        Program::new_unchecked(CROSS_ZONE_OUTBOX_ID, Cow::Borrowed(CROSS_ZONE_OUTBOX_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn cross_zone_inbox() -> Program {
        Program::new_unchecked(CROSS_ZONE_INBOX_ID, Cow::Borrowed(CROSS_ZONE_INBOX_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn ping_sender() -> Program {
        Program::new_unchecked(PING_SENDER_ID, Cow::Borrowed(PING_SENDER_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn ping_receiver() -> Program {
        Program::new_unchecked(PING_RECEIVER_ID, Cow::Borrowed(PING_RECEIVER_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn bridge_lock() -> Program {
        Program::new_unchecked(BRIDGE_LOCK_ID, Cow::Borrowed(BRIDGE_LOCK_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn wrapped_token() -> Program {
        Program::new_unchecked(WRAPPED_TOKEN_ID, Cow::Borrowed(WRAPPED_TOKEN_ELF))
    }

    #[must_use]
    #[inline]
    pub const fn sequencer_stake() -> Program {
        Program::new_unchecked(SEQUENCER_STAKE_ID, Cow::Borrowed(SEQUENCER_STAKE_ELF))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builtin_programs() {
            let auth_transfer_program = authenticated_transfer();
            let token_program = token();
            let vault_program = vault();
            let faucet_program = faucet();
            let bridge_program = bridge();
            let pinata_program = pinata();
            let sequencer_stake_program = sequencer_stake();

            assert_eq!(auth_transfer_program.id(), AUTHENTICATED_TRANSFER_ID);
            assert_eq!(auth_transfer_program.elf(), AUTHENTICATED_TRANSFER_ELF);
            assert_eq!(token_program.id(), TOKEN_ID);
            assert_eq!(token_program.elf(), TOKEN_ELF);
            assert_eq!(vault_program.id(), VAULT_ID);
            assert_eq!(vault_program.elf(), VAULT_ELF);
            assert_eq!(faucet_program.id(), FAUCET_ID);
            assert_eq!(faucet_program.elf(), FAUCET_ELF);
            assert_eq!(bridge_program.id(), BRIDGE_ID);
            assert_eq!(bridge_program.elf(), BRIDGE_ELF);
            assert_eq!(pinata_program.id(), PINATA_ID);
            assert_eq!(pinata_program.elf(), PINATA_ELF);
            assert_eq!(sequencer_stake_program.id(), SEQUENCER_STAKE_ID);
            assert_eq!(sequencer_stake_program.elf(), SEQUENCER_STAKE_ELF);
        }

        #[test]
        fn builtin_program_ids_match_elfs() {
            let cases: &[(&[u8], [u32; 8])] = &[
                (AMM_ELF, AMM_ID),
                (AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID),
                (ASSOCIATED_TOKEN_ACCOUNT_ELF, ASSOCIATED_TOKEN_ACCOUNT_ID),
                (CLOCK_ELF, CLOCK_ID),
                (FAUCET_ELF, FAUCET_ID),
                (FEE_ELF, FEE_ID),
                (BRIDGE_ELF, BRIDGE_ID),
                (PINATA_ELF, PINATA_ID),
                (PINATA_TOKEN_ELF, PINATA_TOKEN_ID),
                (TOKEN_ELF, TOKEN_ID),
                (VAULT_ELF, VAULT_ID),
                (CROSS_ZONE_OUTBOX_ELF, CROSS_ZONE_OUTBOX_ID),
                (CROSS_ZONE_INBOX_ELF, CROSS_ZONE_INBOX_ID),
                (PING_SENDER_ELF, PING_SENDER_ID),
                (PING_RECEIVER_ELF, PING_RECEIVER_ID),
                (BRIDGE_LOCK_ELF, BRIDGE_LOCK_ID),
                (WRAPPED_TOKEN_ELF, WRAPPED_TOKEN_ID),
                (SEQUENCER_STAKE_ELF, SEQUENCER_STAKE_ID),
            ];
            for (elf, expected_id) in cases {
                let program = Program::new((*elf).into()).unwrap();
                assert_eq!(program.id(), *expected_id);
            }
        }
    }
}
