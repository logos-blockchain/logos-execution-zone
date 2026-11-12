//! This crate provides [`Program`]s and associated utilities used by LEZ.

#[cfg(feature = "artifacts")]
pub use inner::*;

#[cfg(feature = "artifacts")]
mod inner {

    use std::borrow::Cow;

    use guests::{
        BRIDGE_ELF, BRIDGE_ID, BRIDGE_LOCK_ELF, BRIDGE_LOCK_ID, CLOCK_ELF, CLOCK_ID,
        CROSS_ZONE_INBOX_ELF, CROSS_ZONE_INBOX_ID, CROSS_ZONE_OUTBOX_ELF, CROSS_ZONE_OUTBOX_ID,
        FEE_ELF, FEE_ID, PING_RECEIVER_ELF, PING_RECEIVER_ID, PING_SENDER_ELF, PING_SENDER_ID,
        SEQUENCER_STAKE_ELF, SEQUENCER_STAKE_ID, WRAPPED_TOKEN_ELF, WRAPPED_TOKEN_ID,
    };
    use lee::{AccountId, program::Program};

    mod guests {
        include!(concat!(env!("OUT_DIR"), "/lez/programs/mod.rs"));
    }

    pub use bridge_core::BRIDGE_NAME;
    pub use bridge_lock_core::BRIDGE_LOCK_NAME;
    pub use clock_core::CLOCK_NAME;
    pub use cross_zone_inbox_core::CROSS_ZONE_INBOX_NAME;
    pub use cross_zone_outbox_core::CROSS_ZONE_OUTBOX_NAME;
    pub use fee_core::FEE_NAME;
    pub use ping_core::{PING_RECEIVER_NAME, PING_SENDER_NAME};
    pub use sequencer_stake_core::SEQUENCER_STAKE_NAME;
    pub use wrapped_token_core::WRAPPED_TOKEN_NAME;

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

    /// Builtins every zone registers at genesis.
    #[must_use]
    pub fn builtin_core_programs() -> [(AccountId, Program); 4] {
        [
            (clock_account_id(), clock()),
            (fee_account_id(), fee()),
            (bridge_account_id(), bridge()),
            (sequencer_stake_account_id(), sequencer_stake()),
        ]
    }

    #[must_use]
    pub fn builtin_cross_zone_programs() -> [(AccountId, Program); 6] {
        [
            (cross_zone_inbox_account_id(), cross_zone_inbox()),
            (cross_zone_outbox_account_id(), cross_zone_outbox()),
            (ping_sender_account_id(), ping_sender()),
            (ping_receiver_account_id(), ping_receiver()),
            (bridge_lock_account_id(), bridge_lock()),
            (wrapped_token_account_id(), wrapped_token()),
        ]
    }

    /// The refusal list and the elf check derive from this, genesis from its two
    /// halves. The fixed lengths are the enforcement: adding to either half
    /// fails to compile until every length here is updated too.
    #[must_use]
    pub fn builtin_programs() -> [(AccountId, Program); 10] {
        let [clock, fee, bridge, stake] = builtin_core_programs();
        let [inbox, outbox, sender, receiver, lock, wrapped] = builtin_cross_zone_programs();
        [
            clock, fee, bridge, stake, inbox, outbox, sender, receiver, lock, wrapped,
        ]
    }

    #[must_use]
    pub fn builtin_program_account_ids() -> [AccountId; 10] {
        builtin_programs().map(|(account_id, _)| account_id)
    }

    #[cfg(test)]
    mod tests {
        use lee::{Account, AccountId, Actor, PublicTransaction, V03State, public_transaction};

        use super::*;

        fn deposit_tx(
            op_id: [u8; 32],
            recipient_id: AccountId,
            amount: bridge_core::BridgeAmount,
        ) -> PublicTransaction {
            let receipt = Actor::new(
                bridge_core::deposit_receipt_account_id(bridge_account_id(), op_id),
                bridge_account_id(),
            );
            let message = public_transaction::Message {
                admission_evidence: vec![lee::PublicAccountEvidence::Pda {
                    program: bridge_account_id(),
                    seed: bridge_core::deposit_receipt_seed(op_id),
                }],
                ..public_transaction::Message::try_new(
                    receipt,
                    vec![
                        receipt,
                        Actor::native_balance(bridge_core::compute_bridge_account_id(
                            bridge_account_id(),
                        )),
                        Actor::native_balance(recipient_id),
                    ],
                    std::collections::BTreeMap::new(),
                    bridge_core::Message::Deposit {
                        l1_deposit_op_id: op_id,
                        recipient_id,
                        amount,
                    },
                )
                .unwrap()
            };

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
                .with_public_accounts([
                    (
                        bridge_core::compute_bridge_account_id(bridge_account_id()),
                        Account::funded(u128::from(amount)),
                    ),
                    (recipient_id, Account::default()),
                ])
                .with_named_programs([(bridge_account_id(), bridge())]);

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

            let replayed = state.transition_from_public_transaction(&tx, 2, 0);

            assert!(matches!(
                &replayed,
                Err(lee::error::LeeError::ProgramExecutionFailed(msg))
                    if msg.contains("Deposit was already processed")
            ));
        }

        #[test]
        fn builtin_constructors_carry_their_ids_and_elfs() {
            let bridge_program = bridge();
            let sequencer_stake_program = sequencer_stake();

            assert_eq!(bridge_program.id(), BRIDGE_ID);
            assert_eq!(bridge_program.elf(), BRIDGE_ELF);
            assert_eq!(sequencer_stake_program.id(), SEQUENCER_STAKE_ID);
            assert_eq!(sequencer_stake_program.elf(), SEQUENCER_STAKE_ELF);
        }

        #[test]
        fn builtin_program_ids_match_elfs() {
            for (_, program) in builtin_programs() {
                let rebuilt = Program::new(program.elf().to_vec().into()).unwrap();
                assert_eq!(rebuilt.id(), program.id());
            }
        }

        #[test]
        fn builtin_account_ids_are_distinct() {
            let ids = builtin_program_account_ids();
            let unique: std::collections::BTreeSet<_> = ids.iter().collect();
            assert_eq!(unique.len(), ids.len());
        }

        /// Genesis registers in this order and each registration takes the next
        /// merkle leaf, so reordering either half moves every later builtin's
        /// leaf and with it the genesis fingerprint.
        #[test]
        fn builtin_registration_order_is_pinned() {
            assert_eq!(
                builtin_program_account_ids(),
                [
                    clock_account_id(),
                    fee_account_id(),
                    bridge_account_id(),
                    sequencer_stake_account_id(),
                    cross_zone_inbox_account_id(),
                    cross_zone_outbox_account_id(),
                    ping_sender_account_id(),
                    ping_receiver_account_id(),
                    bridge_lock_account_id(),
                    wrapped_token_account_id(),
                ]
            );
        }
    }
}
