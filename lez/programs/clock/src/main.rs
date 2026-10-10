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
    program::{Call, ReceiveInput, Response},
};

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
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
    use super::*;

    fn data(block_id: u64) -> ClockAccountData {
        ClockAccountData {
            block_id,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn the_every_block_account_advances_by_one() {
        assert_eq!(
            apply(Effect::Advance(data(8)), &data(7).to_bytes()),
            Some(data(8).to_bytes())
        );
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_skips_ahead_is_refused() {
        // The block ID drives the 10/50 schedule, so a forged one would off schedule.
        apply(Effect::Advance(data(9)), &data(7).to_bytes());
    }

    #[test]
    #[should_panic(expected = "Clock block id must advance by exactly one")]
    fn a_block_id_that_repeats_is_refused() {
        apply(Effect::Advance(data(7)), &data(7).to_bytes());
    }

    #[test]
    fn a_coarser_account_stores_the_same_values() {
        assert_eq!(
            apply(Effect::Record(data(50)), &data(40).to_bytes()),
            Some(data(50).to_bytes())
        );
    }
}
