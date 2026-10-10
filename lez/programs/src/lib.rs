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
        SEQUENCER_STAKE_ELF, SEQUENCER_STAKE_ID, SYSTEM_UPGRADER_ELF, SYSTEM_UPGRADER_ID,
        WRAPPED_TOKEN_ELF, WRAPPED_TOKEN_ID,
    };
    use lee::program::Program;

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
    pub const fn system_upgrader() -> Program {
        Program::new_unchecked(SYSTEM_UPGRADER_ID, Cow::Borrowed(SYSTEM_UPGRADER_ELF))
    }

    pub use system_upgrader_core::system_upgrader_account_id;

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

    #[cfg(test)]
    mod tests {
        use lee::{
            Account, AccountId, ProgramShardSelector, PublicTransaction, V03State,
            public_transaction,
        };

        use super::*;

        mod system_upgrade {
            use std::collections::BTreeMap;

            use lee::{
                Account, AccountId, ProgramShardSelector, PublicTransaction, V03State,
                public_transaction,
            };
            use lee_core::program::{
                PROGRAM_LOADER_ACCOUNT_ID, SYSTEM_UPGRADER_ACCOUNT_ID, SystemProgramName,
            };
            use system_upgrader_core::{
                Instruction, Registry, ScheduledUpgrade, registry_account_id,
            };

            use super::super::*;

            const FROM_HEIGHT: u64 = 5;

            fn registry_selector() -> ProgramShardSelector {
                ProgramShardSelector::new(registry_account_id(), SYSTEM_UPGRADER_ACCOUNT_ID)
            }

            /// An unsigned transaction, as the producer builds it.
            fn system_upgrader_tx(
                selectors: Vec<ProgramShardSelector>,
                instruction: Instruction,
            ) -> PublicTransaction {
                let message = public_transaction::Message::try_new(
                    SYSTEM_UPGRADER_ACCOUNT_ID,
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

            /// `clock` deployed upgradable and registered, and `ping_receiver`'s code uploaded
            /// as the new version's segment chain. Returns the chain's account ids.
            fn staged() -> (V03State, Vec<AccountId>) {
                staged_with([(clock_account_id(), clock(), false)])
            }

            /// `programs` deployed, `clock` registered, and the new chain uploaded.
            fn staged_with(
                programs: impl IntoIterator<Item = (AccountId, Program, bool)>,
            ) -> (V03State, Vec<AccountId>) {
                let new_code = ping_receiver();
                let user_elf = risc0_binfmt::ProgramBinary::decode(new_code.elf())
                    .unwrap()
                    .user_elf
                    .to_vec();
                let ids: Vec<AccountId> = (0..program_loader_core::segment_count(&user_elf))
                    .map(|i| AccountId::new([0x40_u8.wrapping_add(u8::try_from(i).unwrap()); 32]))
                    .collect();
                let segments = program_loader_core::build_segments(&user_elf, &ids).unwrap();
                let registry = Registry {
                    programs: BTreeMap::from([(CLOCK_NAME, None)]),
                };
                let state = V03State::new()
                    .with_named_programs(
                        std::iter::once((system_upgrader_account_id(), system_upgrader(), false))
                            .chain(programs),
                    )
                    .with_public_accounts([(
                        registry_account_id(),
                        Account::default().with_shard(
                            SYSTEM_UPGRADER_ACCOUNT_ID,
                            registry.to_bytes().try_into().unwrap(),
                        ),
                    )])
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
                schedule_tx_with(CLOCK_NAME, first_segment)
            }

            fn schedule_tx_with(
                name: SystemProgramName,
                first_segment: AccountId,
            ) -> PublicTransaction {
                system_upgrader_tx(
                    vec![
                        registry_selector(),
                        ProgramShardSelector::new(
                            AccountId::from_system_program_name(&name),
                            PROGRAM_LOADER_ACCOUNT_ID,
                        ),
                    ],
                    Instruction::Schedule {
                        name,
                        first_segment,
                        from_height: FROM_HEIGHT,
                    },
                )
            }

            fn apply_tx(segments: &[AccountId]) -> PublicTransaction {
                let selectors = [
                    registry_selector(),
                    ProgramShardSelector::new(clock_account_id(), PROGRAM_LOADER_ACCOUNT_ID),
                ]
                .into_iter()
                .chain(
                    segments
                        .iter()
                        .map(|id| ProgramShardSelector::new(*id, PROGRAM_LOADER_ACCOUNT_ID)),
                )
                .collect();
                system_upgrader_tx(
                    selectors,
                    Instruction::Apply {
                        name: CLOCK_NAME,
                        from_height: FROM_HEIGHT,
                    },
                )
            }

            fn registry(state: &V03State) -> Registry {
                Registry::from_bytes(
                    state
                        .get_account_by_id(registry_account_id())
                        .data
                        .shard(SYSTEM_UPGRADER_ACCOUNT_ID),
                )
                .unwrap()
            }

            fn schedule(state: &V03State) -> Option<ScheduledUpgrade> {
                registry(state).scheduled(&CLOCK_NAME)
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
            fn scheduling_an_unregistered_system_program_is_refused() {
                // Deployed at its name-derived address, but not in the registry.
                let name = SystemProgramName::new(b"unregistered");
                let (mut state, ids) = staged_with([
                    (clock_account_id(), clock(), false),
                    (AccountId::from_system_program_name(&name), fee(), false),
                ]);
                let err = state
                    .transition_from_public_transaction(&schedule_tx_with(name, ids[0]), 1, 0)
                    .expect_err("only registered system programs can be scheduled");
                assert!(
                    err.to_string().contains("system program is not registered"),
                    "got: {err}"
                );
            }

            #[test]
            fn scheduling_a_system_program_without_a_header_is_refused() {
                let (mut state, ids) = staged_with([]);

                let err = state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .expect_err("there is no clock header to upgrade");
                assert!(
                    err.to_string()
                        .contains("system program has no program header"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), None);
            }

            #[test]
            fn scheduling_an_immutable_system_program_is_refused() {
                let (mut state, ids) = staged_with([(clock_account_id(), clock(), true)]);

                let err = state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .expect_err("an immutable system program can't be upgraded");
                assert!(
                    err.to_string().contains("system program is immutable"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), None);
            }

            /// `system_upgrader`'s header is mutable, but no signer or PDA can authorize its
            /// address, so only a protocol upgrade can repoint it.
            #[test]
            fn system_upgrader_header_cannot_be_updated() {
                let (mut state, ids) = staged();
                let header_before = state.get_account_by_id(system_upgrader_account_id());
                let signer = lee::PrivateKey::try_new([0x44; 32]).unwrap();

                let message = public_transaction::Message::try_new(
                    PROGRAM_LOADER_ACCOUNT_ID,
                    std::iter::once(system_upgrader_account_id())
                        .chain(ids.iter().copied())
                        .map(|id| ProgramShardSelector::new(id, PROGRAM_LOADER_ACCOUNT_ID))
                        .collect(),
                    vec![lee_core::account::Nonce(0)],
                    lee_core::program::LoaderInstruction::UpdateHeader {
                        first_segment: ids[0],
                        immutable: false,
                    },
                )
                .unwrap();
                let witness_set = public_transaction::WitnessSet::for_message(&message, &[&signer]);
                let err = state
                    .transition_from_public_transaction(
                        &PublicTransaction::new(message, witness_set),
                        1,
                        0,
                    )
                    .expect_err("nobody can authorize system_upgrader's header");
                assert!(err.to_string().contains("must be authorized"), "got: {err}");
                assert_eq!(
                    state.get_account_by_id(system_upgrader_account_id()),
                    header_before
                );
            }

            #[test]
            fn a_second_schedule_while_one_is_pending_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &schedule_tx(AccountId::new([0x77; 32])),
                        2,
                        0,
                    )
                    .expect_err("one upgrade may be pending at a time");
                assert!(
                    err.to_string()
                        .contains("system program already has a scheduled upgrade"),
                    "got: {err}"
                );
                assert_eq!(
                    schedule(&state),
                    Some(ScheduledUpgrade {
                        first_segment: ids[0],
                        from_height: FROM_HEIGHT,
                    }),
                    "the pending upgrade is kept"
                );
            }

            #[test]
            fn system_upgrader_refuses_a_chained_call() {
                let (state, ids) = staged();
                let caller = test_programs::chain_caller();
                let caller_id = AccountId::from_builtin_program(caller.id());
                let mut state = state.with_programs([caller]);

                let schedule_data = Program::serialize_instruction(Instruction::Schedule {
                    name: CLOCK_NAME,
                    first_segment: ids[0],
                    from_height: FROM_HEIGHT,
                })
                .unwrap();
                let message = public_transaction::Message::try_new(
                    caller_id,
                    vec![
                        registry_selector(),
                        ProgramShardSelector::new(clock_account_id(), PROGRAM_LOADER_ACCOUNT_ID),
                    ],
                    vec![],
                    test_guest_core::ChainCall::new(SYSTEM_UPGRADER_ACCOUNT_ID, schedule_data),
                )
                .unwrap();
                let tx = PublicTransaction::new(
                    message,
                    public_transaction::WitnessSet::from_raw_parts(vec![]),
                );

                let err = state
                    .transition_from_public_transaction(&tx, 1, 0)
                    .expect_err("system_upgrader runs only at the top level");
                assert!(
                    err.to_string()
                        .contains("system_upgrader may only be invoked at the top level"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), None);
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
                .with_named_programs([(bridge_account_id(), bridge(), true)]);

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
            let bridge_program = bridge();
            let sequencer_stake_program = sequencer_stake();

            assert_eq!(bridge_program.id(), BRIDGE_ID);
            assert_eq!(bridge_program.elf(), BRIDGE_ELF);
            assert_eq!(sequencer_stake_program.id(), SEQUENCER_STAKE_ID);
            assert_eq!(sequencer_stake_program.elf(), SEQUENCER_STAKE_ELF);
        }

        #[test]
        fn builtin_program_ids_match_elfs() {
            let cases: &[(&[u8], [u32; 8])] = &[
                (SYSTEM_UPGRADER_ELF, SYSTEM_UPGRADER_ID),
                (CLOCK_ELF, CLOCK_ID),
                (FEE_ELF, FEE_ID),
                (BRIDGE_ELF, BRIDGE_ID),
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
