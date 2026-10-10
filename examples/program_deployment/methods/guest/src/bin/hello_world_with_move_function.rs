use lee_core::{
    account::{AccountId, Actor},
    program::{ReceiveInput, Response},
};

// Hello-world with write + move_data example program.
//
// This program reads a message and either:
//
// - `Write(data)`: appends `data` to this program's own actor state on the receiving account.
// - `MoveData { data, to }`: moves bytes out of the receiving account's actor state into the actor
//   state of `to`, the destination account under this same program. The source actor state is
//   cleared and the destination actor state receives the appended bytes.
//
// The caller states the source's contents in `data`; the source refuses unless its actor state
// really holds exactly those bytes, which is what makes the value the destination appends a pinned
// one rather than a caller's claim. The destination appends only on a message from this program.

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Message {
    Write(Vec<u8>),
    MoveData { data: Vec<u8>, to: AccountId },
    Append(Vec<u8>),
}

lee_core::define_actor_logic!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Write(data) => append(input, &data),
        Message::MoveData { data, to } => {
            assert_eq!(
                input.pre_state.as_ref(),
                data.as_slice(),
                "the source account does not hold the bytes the instruction moves out of it"
            );
            Response::set_state(Vec::new()).call(
                Actor::new(to, input.receiver.program_account_id),
                &Message::Append(data),
            )
        }
        Message::Append(data) => {
            assert!(
                input.from_own_program(),
                "only a move of this program appends to its destination"
            );
            append(input, &data)
        }
    }
}

fn append(input: &ReceiveInput, data: &[u8]) -> Response {
    Response::set_state([input.pre_state.as_ref(), data].concat())
}
