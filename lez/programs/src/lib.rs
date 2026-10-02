//! This crate provides [`Program`]s and associated utilities used by LEZ.

#[cfg(feature = "artifacts")]
pub use inner::*;

#[cfg(feature = "artifacts")]
mod inner {

    use std::borrow::Cow;

    use guests::{
        AMM_ELF, AMM_ID, ASSOCIATED_TOKEN_ACCOUNT_ELF, ASSOCIATED_TOKEN_ACCOUNT_ID, BRIDGE_ELF,
        BRIDGE_ID, BRIDGE_LOCK_ELF, BRIDGE_LOCK_ID, BUILTIN_LOADER_ELF, BUILTIN_LOADER_ID,
        CLOCK_ELF, CLOCK_ID, CROSS_ZONE_INBOX_ELF, CROSS_ZONE_INBOX_ID, CROSS_ZONE_OUTBOX_ELF,
        CROSS_ZONE_OUTBOX_ID, FEE_ELF, FEE_ID, PING_RECEIVER_ELF, PING_RECEIVER_ID,
        PING_SENDER_ELF, PING_SENDER_ID, SEQUENCER_STAKE_ELF, SEQUENCER_STAKE_ID, TOKEN_ELF,
        TOKEN_ID, WRAPPED_TOKEN_ELF, WRAPPED_TOKEN_ID,
    };
    use lee::program::Program;

    mod guests {
        include!(concat!(env!("OUT_DIR"), "/lez/programs/mod.rs"));
    }

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
    pub const fn builtin_loader() -> Program {
        Program::new_unchecked(BUILTIN_LOADER_ID, Cow::Borrowed(BUILTIN_LOADER_ELF))
    }

    pub use builtin_loader_core::builtin_loader_account_id;

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

        mod builtin_upgrade {
            use builtin_loader_core::{Instruction, ScheduledUpgrade};
            use lee::{
                Account, AccountId, ProgramShardSelector, PublicTransaction, V03State,
                public_transaction,
            };
            use lee_core::program::{BUILTIN_LOADER_ACCOUNT_ID, PROGRAM_LOADER_ACCOUNT_ID};

            use super::super::*;

            const FROM_HEIGHT: u64 = 5;

            fn builtin_loader_tx(
                selectors: Vec<ProgramShardSelector>,
                instruction: Instruction,
            ) -> PublicTransaction {
                let message = public_transaction::Message::try_new(
                    BUILTIN_LOADER_ACCOUNT_ID,
                    selectors,
                    vec![],
                    instruction,
                )
                .unwrap();
                PublicTransaction::new(
                    message,
                    public_transaction::WitnessSet::from_raw_parts(vec![]),
                )
            }

            /// `clock` installed as an upgradable builtin, and `ping_receiver`'s code uploaded
            /// as the new version's segment chain. Returns the chain's account ids.
            fn staged() -> (V03State, Vec<AccountId>) {
                let new_code = ping_receiver();
                let user_elf = risc0_binfmt::ProgramBinary::decode(new_code.elf())
                    .unwrap()
                    .user_elf
                    .to_vec();
                let ids: Vec<AccountId> = (0..program_loader_core::segment_count(&user_elf))
                    .map(|i| AccountId::new([0x40_u8.wrapping_add(u8::try_from(i).unwrap()); 32]))
                    .collect();
                let segments = program_loader_core::build_segments(&user_elf, &ids).unwrap();
                let state = V03State::new()
                    .with_named_programs([(builtin_loader_account_id(), builtin_loader())])
                    .with_upgradable_programs([(clock_account_id(), clock())])
                    .with_public_accounts(ids.iter().zip(segments).map(|(id, segment)| {
                        (
                            *id,
                            Account::default().with_shard(
                                PROGRAM_LOADER_ACCOUNT_ID,
                                segment.to_loader_shard().try_into().unwrap(),
                            ),
                        )
                    }));
                (state, ids)
            }

            fn schedule_tx(first_segment: AccountId) -> PublicTransaction {
                builtin_loader_tx(
                    vec![ProgramShardSelector::new(
                        clock_account_id(),
                        BUILTIN_LOADER_ACCOUNT_ID,
                    )],
                    Instruction::Schedule {
                        name: CLOCK_NAME.to_vec(),
                        first_segment,
                        from_height: FROM_HEIGHT,
                    },
                )
            }

            fn apply_tx(segments: &[AccountId]) -> PublicTransaction {
                let selectors = [
                    ProgramShardSelector::new(clock_account_id(), BUILTIN_LOADER_ACCOUNT_ID),
                    ProgramShardSelector::new(clock_account_id(), PROGRAM_LOADER_ACCOUNT_ID),
                ]
                .into_iter()
                .chain(
                    segments
                        .iter()
                        .map(|id| ProgramShardSelector::new(*id, PROGRAM_LOADER_ACCOUNT_ID)),
                )
                .collect();
                builtin_loader_tx(
                    selectors,
                    Instruction::Apply {
                        name: CLOCK_NAME.to_vec(),
                        from_height: FROM_HEIGHT,
                    },
                )
            }

            fn schedule(state: &V03State) -> Option<ScheduledUpgrade> {
                ScheduledUpgrade::from_bytes(
                    state
                        .get_account_by_id(clock_account_id())
                        .data
                        .shard(BUILTIN_LOADER_ACCOUNT_ID),
                )
            }

            #[test]
            fn a_scheduled_upgrade_applies_from_its_height() {
                let (mut state, ids) = staged();
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );

                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .expect("scheduling succeeds");
                assert_eq!(
                    schedule(&state),
                    Some(ScheduledUpgrade {
                        first_segment: ids[0],
                        from_height: FROM_HEIGHT,
                    })
                );

                state
                    .transition_from_public_transaction(&apply_tx(&ids), FROM_HEIGHT - 1, 0)
                    .expect_err("an upgrade can't apply before its height");

                state
                    .transition_from_public_transaction(&apply_tx(&ids), FROM_HEIGHT, 0)
                    .expect("the upgrade applies at its height");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(ping_receiver().id())
                );
                assert_eq!(schedule(&state), None, "applying clears the schedule");
            }

            #[test]
            fn an_unscheduled_upgrade_is_refused() {
                let (mut state, ids) = staged();

                state
                    .transition_from_public_transaction(&apply_tx(&ids), FROM_HEIGHT, 0)
                    .expect_err("nothing was scheduled");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
            }

            #[test]
            fn an_upgrade_to_another_chain_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let other = AccountId::new([0x77; 32]);
                state
                    .transition_from_public_transaction(&apply_tx(&[other]), FROM_HEIGHT, 0)
                    .expect_err("the chain differs from the scheduled one");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
            }
        }

        fn deposit_tx(op_id: [u8; 32], recipient_id: AccountId, amount: u64) -> PublicTransaction {
            let message = public_transaction::Message::try_new(
                bridge_account_id(),
                vec![
                    ProgramShardSelector::native_balance(bridge_core::compute_bridge_account_id(
                        bridge_account_id(),
                    )),
                    ProgramShardSelector::native_balance(recipient_id),
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
        fn builtin_programs() {
            let token_program = token();
            let bridge_program = bridge();
            let sequencer_stake_program = sequencer_stake();

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
                (ASSOCIATED_TOKEN_ACCOUNT_ELF, ASSOCIATED_TOKEN_ACCOUNT_ID),
                (BUILTIN_LOADER_ELF, BUILTIN_LOADER_ID),
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
