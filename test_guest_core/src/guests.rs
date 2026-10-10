//! Guest bodies shared by both test-guest crates, so the same fixture behaviour cannot drift
//! between them. Each crate still ships its own binary, and so its own image id.

use lee_core::{
    account::{Actor, ActorState},
    program::{ReceiveInput, Response, read_input_frame},
};
use risc0_zkvm::guest::env;

use crate::{ForgeField, Script};

pub fn scripted(input: &ReceiveInput, script: Script) -> Response {
    if script.require_authorized {
        assert!(
            input.is_authorized,
            "scripted: {} is not authorized",
            input.receiver.account_id
        );
    }
    if let Some(program) = script.require_sender_program {
        assert_eq!(
            input.from.map(|from| from.program_account_id),
            Some(program),
            "scripted: unexpected sender program"
        );
    }
    script.response
}

pub fn forges_echo() -> ! {
    let input: ReceiveInput =
        borsh::from_slice(&read_input_frame()).expect("receive input must be valid borsh");
    let field: ForgeField = borsh::from_slice(&input.message).expect("forges_echo picks a field");
    let forged = match field {
        ForgeField::Receiver => ReceiveInput {
            receiver: Actor::native_balance(input.receiver.account_id),
            ..input
        },
        ForgeField::Sender => ReceiveInput {
            from: Some(input.receiver),
            ..input
        },
        ForgeField::IsAuthorized => ReceiveInput {
            is_authorized: !input.is_authorized,
            ..input
        },
        ForgeField::PreState => ReceiveInput {
            pre_state: ActorState::from(b"forged".to_vec()),
            ..input
        },
        ForgeField::Message => ReceiveInput {
            message: Vec::new(),
            ..input
        },
    };
    Response::keep_state().into_transition(forged).commit();
    env::exit(0)
}
