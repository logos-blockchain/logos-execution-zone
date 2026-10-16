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
        use lee::{Account, AccountId, Actor, PublicTransaction, V03State, public_transaction};

        use super::*;

        mod system_upgrade {
            use std::collections::BTreeMap;

            use lee::{Account, AccountId, Actor, PublicTransaction, V03State, public_transaction};
            use lee_core::{
                BlockId,
                program::{
                    PROGRAM_LOADER_ACCOUNT_ID, SYSTEM_UPGRADER_ACCOUNT_ID, SystemProgramName,
                },
            };
            use program_loader_core::{LoaderActorState as _, Message as LoaderMessage};
            use system_upgrader_core::{
                Approval, Message, Proposal, Registry, ScheduledUpgrade, approval_message,
                committee_actor, loader_actor, registry_account_id, registry_actor, staging_actor,
            };

            use super::super::*;

            const ACTIVATION_HEIGHT: BlockId = 5;
            const VALID_UNTIL: BlockId = 100;
            const CHANNEL_ID: [u8; 32] = [5; 32];

            /// The committee: three accredited keys, so two approvals meet the threshold.
            fn committee_key(seed: u8) -> sequencer_stake_core::ed25519_dalek::SigningKey {
                sequencer_stake_core::ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            }

            fn committee_config() -> (AccountId, Account) {
                let entries = (1..=3)
                    .map(|seed| {
                        (
                            sequencer_stake_core::SequencerKey::new(
                                committee_key(seed).verifying_key().to_bytes(),
                            )
                            .unwrap(),
                            sequencer_stake_core::SequencerEntry {
                                account_id: AccountId::new([seed; 32]),
                                total_staked: 10,
                                pending_unstake: None,
                            },
                        )
                    })
                    .collect();
                let config = sequencer_stake_core::SequencerStakeConfig {
                    channel_params: Some(sequencer_stake_core::ChannelParams {
                        minimum_sequencer_stake: 1,
                        posting_timeframe: 1,
                        posting_timeout: 2,
                        exit_delay: 1,
                    }),
                    channel_id: Some(CHANNEL_ID),
                    entries,
                };
                (
                    committee_actor().account_id,
                    Account::default()
                        .with_actor_state(sequencer_stake_account_id(), config.to_bytes().into()),
                )
            }

            /// Approvals of `proposal` by the committee keys `seeds`, each through `valid_until`.
            fn approvals_for(proposal: &Proposal, seeds: &[u8], valid_until: u64) -> Vec<Approval> {
                use sequencer_stake_core::ed25519_dalek::Signer as _;

                seeds
                    .iter()
                    .map(|seed| {
                        let key = committee_key(*seed);
                        Approval {
                            signer: sequencer_stake_core::SequencerKey::new(
                                key.verifying_key().to_bytes(),
                            )
                            .unwrap(),
                            valid_until,
                            signature: key
                                .sign(&approval_message(CHANNEL_ID, proposal, valid_until))
                                .to_bytes()
                                .to_vec(),
                        }
                    })
                    .collect()
            }

            fn schedule_proposal(name: SystemProgramName, first_segment: AccountId) -> Proposal {
                Proposal::Schedule {
                    name,
                    first_segment,
                    image_id: ping_receiver().id(),
                    activation_height: ACTIVATION_HEIGHT,
                }
            }

            /// An unsigned transaction to the registry, as the producer builds it.
            fn system_upgrader_tx(actors: &[Actor], message: &Message) -> PublicTransaction {
                let message = public_transaction::Message::try_new(
                    registry_actor(),
                    std::iter::once(registry_actor()).chain(actors.iter().copied()),
                    BTreeMap::new(),
                    message,
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
                    programs: BTreeMap::from([(CLOCK_NAME, None), (FEE_NAME, None)]),
                };
                let state = V03State::new()
                    .with_programs_at(
                        [
                            (system_upgrader_account_id(), system_upgrader(), false),
                            (sequencer_stake_account_id(), sequencer_stake(), false),
                        ]
                        .into_iter()
                        .chain(programs),
                    )
                    .with_public_accounts([
                        committee_config(),
                        (
                            registry_account_id(),
                            Account::default().with_actor_state(
                                SYSTEM_UPGRADER_ACCOUNT_ID,
                                registry.to_bytes().into(),
                            ),
                        ),
                    ])
                    .with_public_accounts(ids.iter().zip(segments).map(|(id, segment)| {
                        (
                            *id,
                            Account::default().with_actor_state(
                                PROGRAM_LOADER_ACCOUNT_ID,
                                segment.to_loader_actor_state().into(),
                            ),
                        )
                    }));
                (state, ids)
            }

            fn schedule_tx(first_segment: AccountId) -> PublicTransaction {
                schedule_tx_with(
                    CLOCK_NAME,
                    first_segment,
                    approvals_for(
                        &schedule_proposal(CLOCK_NAME, first_segment),
                        &[1, 2],
                        VALID_UNTIL,
                    ),
                )
            }

            fn schedule_tx_with(
                name: SystemProgramName,
                first_segment: AccountId,
                approvals: Vec<Approval>,
            ) -> PublicTransaction {
                let upgrade = ScheduledUpgrade {
                    first_segment,
                    image_id: ping_receiver().id(),
                    activation_height: ACTIVATION_HEIGHT,
                };
                system_upgrader_tx(
                    &[committee_actor(), staging_actor(&name, &upgrade)],
                    &Message::Schedule {
                        name,
                        first_segment,
                        image_id: ping_receiver().id(),
                        activation_height: ACTIVATION_HEIGHT,
                        approvals,
                    },
                )
            }

            /// The same `Schedule` as [`schedule_tx`], for another activation height.
            fn schedule_tx_at(
                first_segment: AccountId,
                activation_height: u64,
            ) -> PublicTransaction {
                let upgrade = ScheduledUpgrade {
                    first_segment,
                    image_id: ping_receiver().id(),
                    activation_height,
                };
                let proposal = Proposal::Schedule {
                    name: CLOCK_NAME,
                    first_segment,
                    image_id: ping_receiver().id(),
                    activation_height,
                };
                system_upgrader_tx(
                    &[committee_actor(), staging_actor(&CLOCK_NAME, &upgrade)],
                    &Message::Schedule {
                        name: CLOCK_NAME,
                        first_segment,
                        image_id: ping_receiver().id(),
                        activation_height,
                        approvals: approvals_for(&proposal, &[1, 2], VALID_UNTIL),
                    },
                )
            }

            fn approved_schedule_tx(
                name: SystemProgramName,
                first_segment: AccountId,
            ) -> PublicTransaction {
                schedule_tx_with(
                    name,
                    first_segment,
                    approvals_for(
                        &schedule_proposal(name, first_segment),
                        &[1, 2],
                        VALID_UNTIL,
                    ),
                )
            }

            fn apply_tx(activation_height: u64) -> PublicTransaction {
                system_upgrader_tx(
                    &[loader_actor(&CLOCK_NAME)],
                    &Message::Apply {
                        name: CLOCK_NAME,
                        activation_height,
                    },
                )
            }

            fn cancel_tx(first_segment: AccountId) -> PublicTransaction {
                let proposal = Proposal::Cancel {
                    name: CLOCK_NAME,
                    first_segment,
                    activation_height: ACTIVATION_HEIGHT,
                };
                system_upgrader_tx(
                    &[committee_actor()],
                    &Message::Cancel {
                        name: CLOCK_NAME,
                        first_segment,
                        activation_height: ACTIVATION_HEIGHT,
                        approvals: approvals_for(&proposal, &[1, 2], VALID_UNTIL),
                    },
                )
            }

            fn install_tx(name: SystemProgramName, first_segment: AccountId) -> PublicTransaction {
                let proposal = Proposal::Install {
                    name,
                    first_segment,
                    image_id: ping_receiver().id(),
                };
                system_upgrader_tx(
                    &[committee_actor(), loader_actor(&name)],
                    &Message::Install {
                        name,
                        first_segment,
                        image_id: ping_receiver().id(),
                        approvals: approvals_for(&proposal, &[1, 2], VALID_UNTIL),
                    },
                )
            }

            fn registry(state: &V03State) -> Registry {
                Registry::from_bytes(
                    state
                        .get_account_by_id(registry_account_id())
                        .data
                        .actor_state(SYSTEM_UPGRADER_ACCOUNT_ID),
                )
                .unwrap()
            }

            fn schedule(state: &V03State) -> Option<ScheduledUpgrade> {
                registry(state).scheduled(&CLOCK_NAME)
            }

            fn scheduled_at(ids: &[AccountId]) -> Option<ScheduledUpgrade> {
                Some(ScheduledUpgrade {
                    first_segment: ids[0],
                    image_id: ping_receiver().id(),
                    activation_height: ACTIVATION_HEIGHT,
                })
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
                assert_eq!(schedule(&state), scheduled_at(&ids));

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT - 1,
                        0,
                    )
                    .expect_err("an upgrade can't apply before its height");

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT,
                        0,
                    )
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
                    .transition_from_public_transaction(
                        &schedule_tx_with(
                            name,
                            ids[0],
                            approvals_for(&schedule_proposal(name, ids[0]), &[1, 2], VALID_UNTIL),
                        ),
                        1,
                        0,
                    )
                    .expect_err("only registered system programs can be scheduled");
                assert!(
                    err.to_string().contains("system program is not registered"),
                    "got: {err}"
                );
            }

            #[test]
            fn applying_to_a_system_program_without_a_header_is_refused() {
                let (mut state, ids) = staged_with([]);
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT,
                        0,
                    )
                    .expect_err("there is no clock header to upgrade");
                assert!(
                    err.to_string().contains("must already hold a valid header"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), scheduled_at(&ids), "the schedule is kept");
            }

            #[test]
            fn applying_to_an_immutable_system_program_is_refused() {
                let (mut state, ids) = staged_with([(clock_account_id(), clock(), true)]);
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT,
                        0,
                    )
                    .expect_err("an immutable system program can't be upgraded");
                assert!(
                    err.to_string().contains("immutable and cannot be updated"),
                    "got: {err}"
                );
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
            }

            /// `system_upgrader`'s header is mutable, but no signer or PDA can authorize its
            /// address, so only a protocol upgrade can repoint it.
            #[test]
            fn system_upgrader_header_cannot_be_updated() {
                let (mut state, ids) = staged();
                let header_before = state.get_account_by_id(system_upgrader_account_id());
                let signer = lee::PrivateKey::try_new([0x44; 32]).unwrap();
                let signer_id = AccountId::from(&lee::PublicKey::new_from_private_key(&signer));
                let header = Actor::new(system_upgrader_account_id(), PROGRAM_LOADER_ACCOUNT_ID);

                let message = public_transaction::Message::try_new(
                    header,
                    [header],
                    BTreeMap::from([(signer_id, lee_core::account::Nonce(0))]),
                    LoaderMessage::UpdateHeader {
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
            fn a_cancelled_upgrade_never_applies_and_frees_the_system_program() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                state
                    .transition_from_public_transaction(&cancel_tx(ids[0]), 2, 0)
                    .expect("the pending upgrade is cancelled");
                assert_eq!(schedule(&state), None);

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT,
                        0,
                    )
                    .expect_err("a cancelled upgrade can't apply");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );

                state
                    .transition_from_public_transaction(&schedule_tx_at(ids[0], 9), 3, 0)
                    .expect("the system program can be scheduled again");
            }

            #[test]
            fn an_upgrade_can_be_cancelled_only_before_its_height() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                state
                    .transition_from_public_transaction(&cancel_tx(ids[0]), ACTIVATION_HEIGHT, 0)
                    .expect_err("the upgrade's own block must carry its Apply");
                state
                    .transition_from_public_transaction(
                        &cancel_tx(ids[0]),
                        ACTIVATION_HEIGHT - 1,
                        0,
                    )
                    .expect("cancelling is valid before its height");
                assert_eq!(schedule(&state), None);
            }

            #[test]
            fn an_upgrade_applies_only_at_its_height() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT + 1,
                        0,
                    )
                    .expect_err("an upgrade can't apply after its height");
                assert_eq!(schedule(&state), scheduled_at(&ids));
            }

            #[test]
            fn scheduling_at_or_past_the_activation_height_is_refused() {
                let (mut state, ids) = staged();

                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), ACTIVATION_HEIGHT, 0)
                    .expect_err("a schedule must land before its activation height");
                assert_eq!(schedule(&state), None);
            }

            #[test]
            fn a_second_upgrade_at_the_same_height_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &approved_schedule_tx(FEE_NAME, ids[0]),
                        2,
                        0,
                    )
                    .expect_err("one upgrade per height");
                assert!(
                    err.to_string()
                        .contains("an upgrade is already scheduled at this height"),
                    "got: {err}"
                );
                assert_eq!(registry(&state).scheduled(&FEE_NAME), None);
            }

            /// The loader validates the chain at `Schedule`, so `Apply` can't fail on it.
            #[test]
            fn scheduling_an_invalid_chain_is_refused() {
                let (mut state, _) = staged();

                let err = state
                    .transition_from_public_transaction(
                        &schedule_tx(AccountId::new([0x77; 32])),
                        1,
                        0,
                    )
                    .expect_err("no segment chain starts there");
                assert!(
                    err.to_string()
                        .contains("must decode as a valid ProgramSegment"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), None);
            }

            /// Approvers sign the code, not just where it lives: a chain computing to another image
            /// ID is refused by the loader.
            #[test]
            fn scheduling_a_chain_with_another_image_id_is_refused() {
                let (mut state, ids) = staged();
                let image_id = clock().id();
                let upgrade = ScheduledUpgrade {
                    first_segment: ids[0],
                    image_id,
                    activation_height: ACTIVATION_HEIGHT,
                };
                let proposal = Proposal::Schedule {
                    name: CLOCK_NAME,
                    first_segment: ids[0],
                    image_id,
                    activation_height: ACTIVATION_HEIGHT,
                };
                let tx = system_upgrader_tx(
                    &[committee_actor(), staging_actor(&CLOCK_NAME, &upgrade)],
                    &Message::Schedule {
                        name: CLOCK_NAME,
                        first_segment: ids[0],
                        image_id,
                        activation_height: ACTIVATION_HEIGHT,
                        approvals: approvals_for(&proposal, &[1, 2], VALID_UNTIL),
                    },
                );

                let err = state
                    .transition_from_public_transaction(&tx, 1, 0)
                    .expect_err("the chain is ping_receiver's code, not clock's");
                assert!(
                    err.to_string()
                        .contains("the chain's image ID is not the expected one"),
                    "got: {err}"
                );
                assert_eq!(schedule(&state), None);
            }

            #[test]
            fn installing_a_chain_with_another_image_id_is_refused() {
                let (mut state, ids) = staged();
                let name = SystemProgramName::new(b"new_system_program");
                let image_id = clock().id();
                let proposal = Proposal::Install {
                    name,
                    first_segment: ids[0],
                    image_id,
                };
                let tx = system_upgrader_tx(
                    &[committee_actor(), loader_actor(&name)],
                    &Message::Install {
                        name,
                        first_segment: ids[0],
                        image_id,
                        approvals: approvals_for(&proposal, &[1, 2], VALID_UNTIL),
                    },
                );

                let err = state
                    .transition_from_public_transaction(&tx, 1, 0)
                    .expect_err("the chain is ping_receiver's code, not clock's");
                assert!(
                    err.to_string()
                        .contains("the chain's image ID is not the expected one"),
                    "got: {err}"
                );
                assert_eq!(registry(&state).programs.get(&name), None);
            }

            /// Its staging header already holds the cancelled proposal's chain.
            #[test]
            fn rescheduling_a_cancelled_upgrade_unchanged_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();
                state
                    .transition_from_public_transaction(&cancel_tx(ids[0]), 2, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 3, 0)
                    .expect_err("the staging header is taken");
                assert!(
                    err.to_string().contains("header target already deployed"),
                    "got: {err}"
                );
            }

            #[test]
            fn scheduling_validates_the_chain_into_a_staging_header() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let staging = staging_actor(&CLOCK_NAME, &scheduled_at(&ids).unwrap());
                assert_eq!(
                    state.get_program_image_id(staging.account_id),
                    Some(ping_receiver().id())
                );
            }

            #[test]
            fn cancelling_a_different_upgrade_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &cancel_tx(AccountId::new([0x77; 32])),
                        2,
                        0,
                    )
                    .expect_err("only the pending upgrade can be cancelled");
                assert!(
                    err.to_string()
                        .contains("the upgrade does not match the system program's schedule"),
                    "got: {err}"
                );
                assert!(schedule(&state).is_some(), "the pending upgrade is kept");
            }

            #[test]
            fn cancelling_with_nothing_scheduled_is_refused() {
                let (mut state, ids) = staged();

                state
                    .transition_from_public_transaction(&cancel_tx(ids[0]), 1, 0)
                    .expect_err("there is nothing to cancel");
            }

            #[test]
            fn a_second_schedule_while_one_is_pending_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                let err = state
                    .transition_from_public_transaction(
                        &schedule_tx_at(AccountId::new([0x77; 32]), 9),
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
                    scheduled_at(&ids),
                    "the pending upgrade is kept"
                );
            }

            #[test]
            fn system_upgrader_refuses_a_message_from_another_actor() {
                let (state, ids) = staged();
                let sender = test_programs::scripted();
                let sender_actor = Actor::new(
                    AccountId::new([0x55; 32]),
                    AccountId::from_builtin_program(sender.id()),
                );
                let mut state = state.with_programs([sender]);
                state.force_insert_account(sender_actor.account_id, Account::default());

                let script = test_guest_core::Script::default().send_sync(
                    registry_actor(),
                    &Message::Schedule {
                        name: CLOCK_NAME,
                        first_segment: ids[0],
                        image_id: ping_receiver().id(),
                        activation_height: ACTIVATION_HEIGHT,
                        approvals: approvals_for(
                            &schedule_proposal(CLOCK_NAME, ids[0]),
                            &[1, 2],
                            VALID_UNTIL,
                        ),
                    },
                );
                let message = public_transaction::Message::try_new(
                    sender_actor,
                    [sender_actor, registry_actor()],
                    BTreeMap::new(),
                    script,
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
            fn installing_a_new_system_program_deploys_it_mutable() {
                let (mut state, ids) = staged();
                let name = SystemProgramName::new(b"new_system_program");
                let program = AccountId::from_system_program_name(&name);

                state
                    .transition_from_public_transaction(&install_tx(name, ids[0]), 1, 0)
                    .expect("a new system program installs");
                assert_eq!(
                    state.get_program_image_id(program),
                    Some(ping_receiver().id())
                );
                let header = lee_core::program::ProgramHeader::from_loader_actor_state(
                    state
                        .get_account_by_id(program)
                        .data
                        .actor_state(PROGRAM_LOADER_ACCOUNT_ID),
                )
                .unwrap();
                assert!(
                    !header.immutable,
                    "an installed system program is upgradable"
                );
                assert_eq!(
                    registry(&state).programs.get(&name),
                    Some(&None),
                    "an installed system program is registered, with nothing pending"
                );
            }

            #[test]
            fn installing_over_an_existing_system_program_is_refused() {
                let (mut state, ids) = staged();

                let err = state
                    .transition_from_public_transaction(&install_tx(CLOCK_NAME, ids[0]), 1, 0)
                    .expect_err("clock is already registered");
                assert!(
                    err.to_string()
                        .contains("system program is already registered"),
                    "got: {err}"
                );
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
            }

            fn refused_schedule(approvals: Vec<Approval>, block: u64, expected: &str) {
                let (mut state, ids) = staged();
                let err = state
                    .transition_from_public_transaction(
                        &schedule_tx_with(CLOCK_NAME, ids[0], approvals),
                        block,
                        0,
                    )
                    .expect_err("the approvals don't authorize this schedule");
                assert!(err.to_string().contains(expected), "got: {err}");
                assert_eq!(schedule(&state), None);
            }

            #[test]
            fn a_schedule_below_the_approval_threshold_is_refused() {
                let (_, ids) = staged();
                refused_schedule(
                    approvals_for(&schedule_proposal(CLOCK_NAME, ids[0]), &[1], VALID_UNTIL),
                    1,
                    "fewer approvals than the threshold",
                );
            }

            #[test]
            fn an_approval_from_outside_the_committee_is_refused() {
                let (_, ids) = staged();
                refused_schedule(
                    approvals_for(&schedule_proposal(CLOCK_NAME, ids[0]), &[1, 9], VALID_UNTIL),
                    1,
                    "does not accredit",
                );
            }

            #[test]
            fn a_duplicate_approver_is_refused() {
                let (_, ids) = staged();
                refused_schedule(
                    approvals_for(&schedule_proposal(CLOCK_NAME, ids[0]), &[1, 1], VALID_UNTIL),
                    1,
                    "the same key approved twice",
                );
            }

            #[test]
            fn an_approval_for_another_action_is_refused() {
                let (_, ids) = staged();
                let cancel = Proposal::Cancel {
                    name: CLOCK_NAME,
                    first_segment: ids[0],
                    activation_height: ACTIVATION_HEIGHT,
                };
                refused_schedule(
                    approvals_for(&cancel, &[1, 2], VALID_UNTIL),
                    1,
                    "should verify against its signer",
                );
            }

            #[test]
            fn an_expired_approval_is_refused() {
                let (_, ids) = staged();
                refused_schedule(
                    approvals_for(&schedule_proposal(CLOCK_NAME, ids[0]), &[1, 2], 3),
                    4,
                    "",
                );
            }

            #[test]
            fn an_unscheduled_upgrade_is_refused() {
                let (mut state, _) = staged();

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT),
                        ACTIVATION_HEIGHT,
                        0,
                    )
                    .expect_err("nothing was scheduled");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
            }

            #[test]
            fn an_apply_for_another_height_is_refused() {
                let (mut state, ids) = staged();
                state
                    .transition_from_public_transaction(&schedule_tx(ids[0]), 1, 0)
                    .unwrap();

                state
                    .transition_from_public_transaction(
                        &apply_tx(ACTIVATION_HEIGHT + 1),
                        ACTIVATION_HEIGHT + 1,
                        0,
                    )
                    .expect_err("the height differs from the scheduled one");
                assert_eq!(
                    state.get_program_image_id(clock_account_id()),
                    Some(clock().id())
                );
                assert_eq!(schedule(&state), scheduled_at(&ids));
            }
        }

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
                .with_programs_at([(bridge_account_id(), bridge(), true)]);

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
