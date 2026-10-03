//! Clock Program.
//!
//! A system program that records the current block ID and timestamp into dedicated clock accounts.
//! Three accounts are maintained, updated at different block intervals (every 1, 10, and 50
//! blocks), allowing programs to read recent timestamps at various granularities.
//!
//! Only the sequencer may tick this program, as the last transaction in every block; the
//! every-block account then sends the record to the coarser accounts it is due at.
//! Each clock account uses this program's actor state.

use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData, Message,
};
use lee_core::{
    account::Actor,
    program::{Call, ReceiveInput, Response, run_actor},
};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Tick {
            timestamp,
            block_id,
        } => {
            assert_eq!(
                input.receiver.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID,
                "Tick is addressed to the every-block clock account"
            );
            let previous = ClockAccountData::from_bytes(&input.pre_state);
            assert_eq!(
                previous.block_id.checked_add(1),
                Some(block_id),
                "Clock block id must advance by exactly one from the account's own"
            );
            let updated_data = ClockAccountData {
                block_id,
                timestamp,
            };
            let record = |account_id| {
                Call::new(
                    Actor::new(account_id, input.receiver.program_account_id),
                    &Message::Record(updated_data),
                )
            };

            // The schedule below is decided from the block ID just checked to be one past the
            // every-block account's own.
            let mut response = Response::set_state(updated_data.to_bytes());
            if block_id.is_multiple_of(10) {
                response = response.send(record(CLOCK_10_PROGRAM_ACCOUNT_ID));
            }
            if block_id.is_multiple_of(50) {
                response = response.send(record(CLOCK_50_PROGRAM_ACCOUNT_ID));
            }
            response
        }
        Message::Record(data) => {
            assert!(
                input.from_own_program(),
                "Clock records are only sent by the every-block clock account"
            );
            Response::set_state(data.to_bytes())
        }
        Message::AssertTimestamp { at_least, at_most } => {
            let ClockAccountData { timestamp, .. } = ClockAccountData::from_bytes(&input.pre_state);
            assert!(
                at_least <= timestamp && timestamp <= at_most,
                "Clock timestamp {timestamp} is outside [{at_least}, {at_most}]"
            );
            Response::keep_state()
        }
    }
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::{AccountId, ActorState},
        program::Transition,
    };

    use super::*;

    const CLOCK: AccountId = AccountId::new([1; 32]);

    fn data(block_id: u64) -> ClockAccountData {
        ClockAccountData {
            block_id,
            timestamp: 1_700_000_000,
        }
    }

    fn tick(block_id: u64) -> Message {
        Message::Tick {
            timestamp: 1_700_000_000,
            block_id,
        }
    }

    fn run(
        account_id: AccountId,
        origin: Option<AccountId>,
        pre: ClockAccountData,
        message: Message,
    ) -> Transition {
        let receiver = Actor::new(account_id, CLOCK);
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized: false,
            pre_state: ActorState::from(pre.to_bytes()),
            message: borsh::to_vec(&message).unwrap(),
        };
        receive(&input, message).into_transition(input)
    }

    fn written(data: ClockAccountData) -> Option<ActorState> {
        Some(ActorState::from(data.to_bytes()))
    }

    fn record_to(account_id: AccountId, data: ClockAccountData) -> Call {
        Call::new(Actor::new(account_id, CLOCK), &Message::Record(data))
    }

    #[test]
    fn the_every_block_account_advances_by_one() {
        let transition = run(CLOCK_01_PROGRAM_ACCOUNT_ID, None, data(7), tick(8));

        assert_eq!(transition.response.post_state, written(data(8)));
        assert!(transition.response.calls.is_empty() && transition.response.casts.is_empty());
    }

    #[test]
    fn a_tick_records_into_the_coarser_accounts_it_is_due_at() {
        let at_ten = run(CLOCK_01_PROGRAM_ACCOUNT_ID, None, data(9), tick(10));
        assert_eq!(
            (at_ten.response.calls, at_ten.response.casts),
            (
                vec![record_to(CLOCK_10_PROGRAM_ACCOUNT_ID, data(10))],
                Vec::new()
            )
        );

        let at_fifty = run(CLOCK_01_PROGRAM_ACCOUNT_ID, None, data(49), tick(50));
        assert_eq!(
            (at_fifty.response.calls, at_fifty.response.casts),
            (
                vec![
                    record_to(CLOCK_10_PROGRAM_ACCOUNT_ID, data(50)),
                    record_to(CLOCK_50_PROGRAM_ACCOUNT_ID, data(50)),
                ],
                Vec::new()
            )
        );
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_skips_ahead_is_refused() {
        // The block ID drives the 10/50 schedule, so a forged one would off schedule.
        let _transition = run(CLOCK_01_PROGRAM_ACCOUNT_ID, None, data(7), tick(9));
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_repeats_is_refused() {
        let _transition = run(CLOCK_01_PROGRAM_ACCOUNT_ID, None, data(7), tick(7));
    }

    #[test]
    #[should_panic(expected = "Tick is addressed to the every-block clock account")]
    fn only_the_every_block_account_takes_a_tick() {
        let _transition = run(CLOCK_10_PROGRAM_ACCOUNT_ID, None, data(9), tick(10));
    }

    #[test]
    fn a_coarser_account_stores_the_same_values() {
        let sender = Some(CLOCK);
        let transition = run(
            CLOCK_50_PROGRAM_ACCOUNT_ID,
            sender,
            data(40),
            Message::Record(data(50)),
        );

        assert_eq!(transition.response.post_state, written(data(50)));
    }

    #[test]
    #[should_panic(expected = "Clock records are only sent by the every-block clock account")]
    fn a_record_from_another_program_is_refused() {
        let sender = Some(AccountId::new([3; 32]));
        let _transition = run(
            CLOCK_50_PROGRAM_ACCOUNT_ID,
            sender,
            data(40),
            Message::Record(data(50)),
        );
    }

    #[test]
    fn a_timestamp_within_bounds_is_kept() {
        let transition = run(
            CLOCK_50_PROGRAM_ACCOUNT_ID,
            None,
            data(40),
            Message::AssertTimestamp {
                at_least: 1_699_999_999,
                at_most: 1_700_000_001,
            },
        );

        assert_eq!(transition.response.post_state, None);
        assert!(transition.response.calls.is_empty() && transition.response.casts.is_empty());
    }

    #[test]
    #[should_panic(expected = "Clock timestamp 1700000000 is outside [1700000001, 1700000002]")]
    fn a_timestamp_outside_bounds_is_refused() {
        let _transition = run(
            CLOCK_50_PROGRAM_ACCOUNT_ID,
            None,
            data(40),
            Message::AssertTimestamp {
                at_least: 1_700_000_001,
                at_most: 1_700_000_002,
            },
        );
    }
}
