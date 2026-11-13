//! Signature Program.
//!
//! The guest-callable part of the signature program, run privately in a privacy transaction. For
//! each account it checks that the secret owns the account, then sends `SetKey` to the account's
//! signature actor, which the sequencer handles natively. It never reads the rotated accounts.

use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response},
    signing_key::{SignatureMessage, signature_program_id},
};
use signature_core::{AccountRotation, Message};

mod keys;

lee_core::actor_entrypoint!(handle_message);

fn handle_message(_input: &ReceiveInput, message: Message) -> Response {
    let Message::ManualRotation { rotations } = message;
    assert!(
        !rotations.is_empty(),
        "a manual rotation names at least one account"
    );
    let mut response = Response::keep_state();
    for AccountRotation {
        secret,
        account,
        next,
    } in rotations
    {
        assert_eq!(
            keys::public_account_id(&secret),
            account,
            "the secret does not own the account"
        );
        response = response.send_sync(
            Actor::new(account, signature_program_id()),
            &SignatureMessage::SetKey { next },
        );
    }
    response
}
