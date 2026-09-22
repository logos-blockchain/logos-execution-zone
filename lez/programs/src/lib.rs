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
        CROSS_ZONE_INBOX_ID, CROSS_ZONE_OUTBOX_ELF, CROSS_ZONE_OUTBOX_ID, FEE_ELF, FEE_ID,
        PING_RECEIVER_ELF, PING_RECEIVER_ID, PING_SENDER_ELF, PING_SENDER_ID, SEQUENCER_STAKE_ELF,
        SEQUENCER_STAKE_ID, TOKEN_ELF, TOKEN_ID, WRAPPED_TOKEN_ELF, WRAPPED_TOKEN_ID,
    };
    use lee::{AccountId, program::Program};

    mod guests {
        include!(concat!(env!("OUT_DIR"), "/lez/programs/mod.rs"));
    }

    // `authenticated_transfer_core` is duplicated here rather than re-exported: unlike the
    // other builtins' `*_core` crates, it isn't a dependency of this `artifacts` build (only
    // of `programs`, which builds its guest binary), so it can't be depended on here.
    // `authenticated_transfer_name_matches_core` below guards the two copies against drift.
    pub const AUTHENTICATED_TRANSFER_NAME: [u8; 22] = *b"authenticated_transfer";

    pub use amm_core::AMM_NAME;
    pub use associated_token_account_core::ASSOCIATED_TOKEN_ACCOUNT_NAME;
    pub use bridge_core::BRIDGE_NAME;
    pub use bridge_lock_core::BRIDGE_LOCK_NAME;
    pub use clock_core::CLOCK_NAME;
    pub use cross_zone_inbox_core::CROSS_ZONE_INBOX_NAME;
    pub use cross_zone_outbox_core::CROSS_ZONE_OUTBOX_NAME;
    pub use fee_core::FEE_NAME;
    pub use ping_core::{PING_RECEIVER_NAME, PING_SENDER_NAME};
    pub use sequencer_stake_core::SEQUENCER_STAKE_NAME;
    pub use token_core::TOKEN_NAME;
    pub use wrapped_token_core::WRAPPED_TOKEN_NAME;

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
    pub fn authenticated_transfer_account_id() -> AccountId {
        AccountId::from_builtin_program_name(&AUTHENTICATED_TRANSFER_NAME)
    }

    #[must_use]
    #[inline]
    pub const fn token() -> Program {
        Program::new_unchecked(TOKEN_ID, Cow::Borrowed(TOKEN_ELF))
    }

    pub use token_core::token_account_id;

    #[must_use]
    #[inline]
    pub const fn amm() -> Program {
        Program::new_unchecked(AMM_ID, Cow::Borrowed(AMM_ELF))
    }

    pub use amm_core::amm_account_id;

    #[must_use]
    #[inline]
    pub const fn clock() -> Program {
        Program::new_unchecked(CLOCK_ID, Cow::Borrowed(CLOCK_ELF))
    }

    pub use clock_core::clock_account_id;

    #[must_use]
    #[inline]
    pub const fn fee() -> Program {
        Program::new_unchecked(FEE_ID, Cow::Borrowed(FEE_ELF))
    }

    pub use fee_core::fee_account_id;

    #[must_use]
    #[inline]
    pub const fn ata() -> Program {
        Program::new_unchecked(
            ASSOCIATED_TOKEN_ACCOUNT_ID,
            Cow::Borrowed(ASSOCIATED_TOKEN_ACCOUNT_ELF),
        )
    }

    pub use associated_token_account_core::ata_account_id;

    #[must_use]
    #[inline]
    pub const fn bridge() -> Program {
        Program::new_unchecked(BRIDGE_ID, Cow::Borrowed(BRIDGE_ELF))
    }

    pub use bridge_core::bridge_account_id;

    #[must_use]
    #[inline]
    pub const fn cross_zone_outbox() -> Program {
        Program::new_unchecked(CROSS_ZONE_OUTBOX_ID, Cow::Borrowed(CROSS_ZONE_OUTBOX_ELF))
    }

    pub use cross_zone_outbox_core::cross_zone_outbox_account_id;

    #[must_use]
    #[inline]
    pub const fn cross_zone_inbox() -> Program {
        Program::new_unchecked(CROSS_ZONE_INBOX_ID, Cow::Borrowed(CROSS_ZONE_INBOX_ELF))
    }

    pub use cross_zone_inbox_core::cross_zone_inbox_account_id;

    #[must_use]
    #[inline]
    pub const fn ping_sender() -> Program {
        Program::new_unchecked(PING_SENDER_ID, Cow::Borrowed(PING_SENDER_ELF))
    }

    pub use ping_core::ping_sender_account_id;

    #[must_use]
    #[inline]
    pub const fn ping_receiver() -> Program {
        Program::new_unchecked(PING_RECEIVER_ID, Cow::Borrowed(PING_RECEIVER_ELF))
    }

    pub use ping_core::ping_receiver_account_id;

    #[must_use]
    #[inline]
    pub const fn bridge_lock() -> Program {
        Program::new_unchecked(BRIDGE_LOCK_ID, Cow::Borrowed(BRIDGE_LOCK_ELF))
    }

    pub use bridge_lock_core::bridge_lock_account_id;

    #[must_use]
    #[inline]
    pub const fn wrapped_token() -> Program {
        Program::new_unchecked(WRAPPED_TOKEN_ID, Cow::Borrowed(WRAPPED_TOKEN_ELF))
    }

    pub use wrapped_token_core::wrapped_token_account_id;

    #[must_use]
    #[inline]
    pub const fn sequencer_stake() -> Program {
        Program::new_unchecked(SEQUENCER_STAKE_ID, Cow::Borrowed(SEQUENCER_STAKE_ELF))
    }

    pub use sequencer_stake_core::sequencer_stake_account_id;

    #[cfg(test)]
    mod tests {
        use lee::{
            Account, AccountId, ProgramShardSelector, PublicTransaction, V03State,
            public_transaction,
        };

        use super::*;

        #[test]
        fn authenticated_transfer_name_matches_core() {
            assert_eq!(
                AUTHENTICATED_TRANSFER_NAME,
                authenticated_transfer_core::AUTHENTICATED_TRANSFER_NAME,
                "this crate's copy must track authenticated_transfer_core's"
            );
        }

        fn deposit_tx(op_id: [u8; 32], recipient_id: AccountId, amount: u64) -> PublicTransaction {
            let message = public_transaction::Message::try_new(
                bridge_account_id(),
                vec![
                    ProgramShardSelector::balance(bridge_core::compute_bridge_account_id(
                        bridge_account_id(),
                    )),
                    ProgramShardSelector::balance(recipient_id),
                    ProgramShardSelector::new(
                        bridge_core::deposit_receipt_account_id(bridge_account_id(), op_id),
                        bridge_account_id(),
                    ),
                ],
                vec![],
                bridge_core::Instruction::Deposit {
                    l1_deposit_op_id: op_id,
                    recipient_id,
                    amount,
                },
            )
            .unwrap();

            PublicTransaction::new(
                message,
                public_transaction::WitnessSet::from_raw_parts(vec![]),
            )
        }

        #[test]
        fn bridge_deposit_emits_one_event_and_its_replay_emits_none() {
            let recipient_id = AccountId::new([5; 32]);
            let op_id = [9; 32];
            let amount = 1_000;
            let mut state = V03State::new()
                .with_public_accounts([(
                    bridge_core::compute_bridge_account_id(bridge_account_id()),
                    Account::funded(u128::from(amount)),
                )])
                .with_named_programs([
                    (bridge_account_id(), bridge()),
                    (
                        authenticated_transfer_account_id(),
                        authenticated_transfer(),
                    ),
                ]);

            let tx = deposit_tx(op_id, recipient_id, amount);
            let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

            assert_eq!(events.len(), 1);
            assert_eq!(events[0].account_id, bridge_account_id());
            assert_eq!(
                events[0].event.selector,
                bridge_core::event::Deposit::SELECTOR
            );
            assert_eq!(
                bridge_core::event::Deposit::from_bytes(&events[0].event.data).unwrap(),
                bridge_core::event::Deposit {
                    l1_deposit_op_id: op_id,
                    recipient_id,
                    amount,
                }
            );

            let replayed = state.transition_from_public_transaction(&tx, 2, 0).unwrap();

            assert_eq!(replayed.len(), 0);
        }

        #[test]
        fn builtin_programs() {
            let auth_transfer_program = authenticated_transfer();
            let token_program = token();
            let bridge_program = bridge();
            let sequencer_stake_program = sequencer_stake();

            assert_eq!(auth_transfer_program.id(), AUTHENTICATED_TRANSFER_ID);
            assert_eq!(auth_transfer_program.elf(), AUTHENTICATED_TRANSFER_ELF);
            assert_eq!(token_program.id(), TOKEN_ID);
            assert_eq!(token_program.elf(), TOKEN_ELF);
            assert_eq!(bridge_program.id(), BRIDGE_ID);
            assert_eq!(bridge_program.elf(), BRIDGE_ELF);
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
                (FEE_ELF, FEE_ID),
                (BRIDGE_ELF, BRIDGE_ID),
                (TOKEN_ELF, TOKEN_ID),
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
