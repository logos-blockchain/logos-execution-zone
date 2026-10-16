//! Clock Program.
//!
//! A system program that records the current block ID and timestamp into a single clock account.
//! A message asserting either value names its granularity: the clock rounds the value down to a
//! multiple of it before comparing.
//!
//! Only the sequencer may tick this program, as the last transaction in every block.
//! The clock account uses this program's actor state.

use clock_core::{CLOCK_PROGRAM_ACCOUNT_ID, ClockAccountData, Message};
use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    assert_eq!(
        input.receiver.account_id, CLOCK_PROGRAM_ACCOUNT_ID,
        "The clock program runs only on the clock account"
    );
    let clock = ClockAccountData::from_bytes(&input.pre_state);
    match message {
        Message::Tick {
            timestamp,
            block_id,
        } => {
            assert_eq!(
                clock.block_id.checked_add(1),
                Some(block_id),
                "Clock block id must advance by exactly one from the account's own"
            );
            Response::set_state(
                ClockAccountData {
                    block_id,
                    timestamp,
                }
                .to_bytes(),
            )
        }
        Message::AssertTimestamp {
            granularity,
            at_least,
            at_most,
        } => {
            let rounded = round_down(clock.timestamp, granularity);
            assert!(
                at_least <= rounded && rounded <= at_most,
                "Rounded clock timestamp {rounded} is outside [{at_least}, {at_most}]"
            );
            Response::keep_state()
        }
        Message::AssertBlockId {
            granularity,
            at_least,
            at_most,
        } => {
            let rounded = round_down(clock.block_id, granularity);
            assert!(
                at_least <= rounded && rounded <= at_most,
                "Rounded clock block id {rounded} is outside [{at_least}, {at_most}]"
            );
            Response::keep_state()
        }
    }
}

fn round_down(value: u64, granularity: u64) -> u64 {
    assert!(granularity > 0, "Clock granularity must be positive");
    value - value % granularity
}

#[cfg(test)]
mod tests {
    use lee_core::{
        Timestamp,
        account::{AccountId, Actor, ActorState},
        program::Transition,
    };

    use super::*;

    const CLOCK: AccountId = AccountId::new([1; 32]);

    fn data(block_id: u64) -> ClockAccountData {
        ClockAccountData {
            block_id,
            timestamp: 1_700_000_057,
        }
    }

    fn tick(block_id: u64) -> Message {
        Message::Tick {
            timestamp: 1_700_000_057,
            block_id,
        }
    }

    fn assert_timestamp(
        granularity: Timestamp,
        at_least: Timestamp,
        at_most: Timestamp,
    ) -> Message {
        Message::AssertTimestamp {
            granularity,
            at_least,
            at_most,
        }
    }

    fn run_on(account_id: AccountId, pre: ClockAccountData, message: Message) -> Transition {
        let receiver = Actor::new(account_id, CLOCK);
        let input = ReceiveInput {
            receiver,
            from: None,
            is_authorized: false,
            pre_state: ActorState::from(pre.to_bytes()),
            message: borsh::to_vec(&message).unwrap(),
        };
        handle_message(&input, message).into_transition(input)
    }

    fn run(pre: ClockAccountData, message: Message) -> Transition {
        run_on(CLOCK_PROGRAM_ACCOUNT_ID, pre, message)
    }

    #[test]
    fn a_tick_advances_the_clock_by_one() {
        let transition = run(data(7), tick(8));

        assert_eq!(
            transition.response.post_state,
            Some(ActorState::from(data(8).to_bytes()))
        );
        assert!(
            transition.response.sync_messages.is_empty()
                && transition.response.async_messages.is_empty()
        );
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_skips_ahead_is_refused() {
        let _transition = run(data(7), tick(9));
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_repeats_is_refused() {
        let _transition = run(data(7), tick(7));
    }

    #[test]
    #[should_panic(expected = "The clock program runs only on the clock account")]
    fn another_account_is_refused() {
        let _transition = run_on(AccountId::new([2; 32]), data(9), tick(10));
    }

    #[test]
    fn a_timestamp_rounded_to_the_granularity_within_bounds_is_kept() {
        for (granularity, rounded) in [
            (1, 1_700_000_057),
            (10, 1_700_000_050),
            (1_000, 1_700_000_000),
        ] {
            let transition = run(data(7), assert_timestamp(granularity, rounded, rounded));

            assert_eq!(transition.response.post_state, None);
            assert!(
                transition.response.sync_messages.is_empty()
                    && transition.response.async_messages.is_empty()
            );
        }
    }

    #[test]
    #[should_panic(
        expected = "Rounded clock timestamp 1700000050 is outside [1700000057, 1700000057]"
    )]
    fn a_timestamp_rounded_to_the_granularity_outside_bounds_is_refused() {
        let _transition = run(data(7), assert_timestamp(10, 1_700_000_057, 1_700_000_057));
    }

    #[test]
    #[should_panic(expected = "Clock granularity must be positive")]
    fn a_zero_granularity_is_refused() {
        let _transition = run(data(7), assert_timestamp(0, 0, Timestamp::MAX));
    }

    #[test]
    fn a_block_id_rounded_to_the_granularity_within_bounds_is_kept() {
        for (granularity, rounded) in [(1, 57), (10, 50), (50, 50), (100, 0)] {
            let transition = run(
                data(57),
                Message::AssertBlockId {
                    granularity,
                    at_least: rounded,
                    at_most: rounded,
                },
            );

            assert_eq!(transition.response.post_state, None);
            assert!(
                transition.response.sync_messages.is_empty()
                    && transition.response.async_messages.is_empty()
            );
        }
    }

    #[test]
    #[should_panic(expected = "Rounded clock block id 50 is outside [57, 57]")]
    fn a_block_id_rounded_to_the_granularity_outside_bounds_is_refused() {
        let _transition = run(
            data(57),
            Message::AssertBlockId {
                granularity: 50,
                at_least: 57,
                at_most: 57,
            },
        );
    }
}
