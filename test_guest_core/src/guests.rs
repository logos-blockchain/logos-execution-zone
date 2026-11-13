//! Guest bodies shared by both test-guest crates, so the same fixture behaviour cannot drift
//! between them. Each crate still ships its own binary, and so its own image id.

use lee_core::{
    account::{Actor, ActorState, Target},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID, custody_transfer},
    program::{ReceiveInput, Response, StateReply, read_input_frame},
};
use risc0_zkvm::guest::env;

use crate::{ForgeField, LIVE_PAYOUT_SEED, PayoutRequest, Script};

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
            input.from.map(|from| from.actor().program_account_id),
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
            from: Some(input.receiver.into()),
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

// A request reads its custody's native balance as it stands; the balance's reply pays a tenth of it
// to the requester, who refuses anything below its minimum.
pub fn live_payout(input: &ReceiveInput) -> Response {
    let custody = input.receiver.account_id;
    if input
        .from
        .and_then(Target::local)
        .is_some_and(|from| from.program_account_id == NATIVE_TOKEN_PROGRAM_ID)
    {
        let reply: StateReply = borsh::from_slice(&input.message).expect("a native state reply");
        let PayoutRequest { to, min_payout } =
            borsh::from_slice(&input.pre_state).expect("a pending payout request");
        let payout = native_token::decode_balance(&reply.state)
            .expect("a canonical balance")
            .div_euclid(10);
        assert!(
            payout >= min_payout,
            "live_payout: {payout} is below the minimum {min_payout}"
        );
        return Response::set_state(Vec::new()).send(custody_transfer(
            custody,
            LIVE_PAYOUT_SEED,
            to,
            payout,
        ));
    }
    borsh::from_slice::<PayoutRequest>(&input.message).expect("a payout request");
    Response::set_state(input.message.clone()).send_sync(
        Actor::native_balance(custody),
        &native_token::Message::ReadState,
    )
}
