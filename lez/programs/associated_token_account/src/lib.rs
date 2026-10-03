//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;
use associated_token_account_core::{Message, PdaSeed, ata_of};
use lee_core::{
    account::{AccountId, Actor},
    program::{Call, ReceiveInput, Response, SendMode},
};
use token_core::TokenDescriptor;

#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod tests;

pub fn receive(input: &ReceiveInput, message: Message) -> Response {
    let holding = |token_program_id: AccountId, definition_id: AccountId| -> (Actor, PdaSeed) {
        let (ata, seed) = ata_of(
            input.receiver.program_account_id,
            input.receiver.account_id,
            definition_id,
            token_program_id,
        );
        (Actor::new(ata, token_program_id), seed)
    };
    match message {
        Message::Create {
            token_program_id,
            definition_id,
            kind,
        } => {
            let (ata, seed) = holding(token_program_id, definition_id);
            let ensure = Call::new(
                ata,
                &token_core::Message::EnsureHolding {
                    descriptor: TokenDescriptor {
                        definition_id,
                        kind,
                    },
                },
            );
            Response::keep_state()
                .call(
                    Actor::new(definition_id, token_program_id),
                    &token_core::Message::AssertKind { kind },
                )
                .send(if input.is_authorized {
                    ensure.with_pda_seeds(vec![seed])
                } else {
                    ensure
                })
        }
        Message::Transfer {
            token_program_id,
            to,
            descriptor,
            amount,
        } => {
            assert!(input.is_authorized, "Owner authorization is missing");
            let (ata, seed) = holding(token_program_id, descriptor.definition_id);
            Response::keep_state().send(
                Call::new(
                    ata,
                    &token_core::Message::Transfer {
                        to,
                        descriptor,
                        amount,
                        notify: None,
                        mode: SendMode::Call,
                    },
                )
                .with_pda_seeds(vec![seed]),
            )
        }
        Message::Burn {
            token_program_id,
            descriptor,
            amount,
        } => {
            assert!(input.is_authorized, "Owner authorization is missing");
            let (ata, seed) = holding(token_program_id, descriptor.definition_id);
            Response::keep_state().send(
                Call::new(
                    ata,
                    &token_core::Message::Burn {
                        descriptor,
                        amount,
                        definition: descriptor.definition_id,
                    },
                )
                .with_pda_seeds(vec![seed]),
            )
        }
    }
}
