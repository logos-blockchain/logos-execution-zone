//! Guest bodies shared by both test-guest crates, so the same fixture behaviour cannot drift
//! between them. Each crate still ships its own binary, and so its own image id.

use lee_core::{
    account::{Actor, ActorState},
    program::{ReceiveInput, Response, read_input_frame, run_actor},
};
use risc0_zkvm::guest::env;

use crate::{ForgeField, Script};

pub fn scripted() -> ! {
    run_actor(|input: &ReceiveInput, script: Script| {
        if script.require_authorized {
            assert!(
                input.is_authorized,
                "scripted: {} is not authorized",
                input.receiver.account_id
            );
        }
        if let Some(program) = script.require_origin {
            assert_eq!(input.origin, Some(program), "scripted: unexpected origin");
        }
        let response = Response {
            calls: script.calls,
            casts: script.casts,
            ..script.write.map_or_else(Response::keep, Response::write)
        };
        script
            .events
            .into_iter()
            .fold(response, Response::event)
            .block_window(script.block_window)
            .timestamp_window(script.timestamp_window)
    })
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
        ForgeField::Origin => ReceiveInput {
            origin: Some(input.receiver.program_account_id),
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
    Response::keep().into_transition(forged).write();
    env::exit(0)
}
