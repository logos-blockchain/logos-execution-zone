//! The Token Program implementation.

use lee_core::{
    account::{Actor, ActorState},
    program::{ReceiveInput, Response},
};
pub use token_core as core;
use token_core::{
    Message, NewTokenMetadata, Notification, Notify, TokenDescriptor, TokenHolding, TokenMetadata,
};

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

pub fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    let from_token = input.from_own_program();
    let own = |account_id| Actor::new(account_id, input.receiver.program_account_id);
    match message {
        Message::Transfer {
            to,
            descriptor,
            amount,
            notify,
        } => {
            assert!(input.is_authorized, "Sender authorization is missing");
            Response::set_state(transfer::withdraw(&input.pre_state, &descriptor, amount)).cast(
                own(to),
                &Message::Credit {
                    descriptor,
                    amount,
                    notify,
                },
            )
        }
        Message::Credit {
            descriptor,
            amount,
            notify,
        } => {
            assert!(from_token, "A credit must come from the token program");
            let deposited =
                Response::set_state(transfer::deposit(&input.pre_state, &descriptor, amount));
            match notify {
                Some(Notify { to, payload }) => deposited.call(
                    to,
                    &Message::Notification(Notification {
                        descriptor,
                        amount,
                        payload,
                    }),
                ),
                None => deposited,
            }
        }
        Message::EnsureHolding { descriptor } => {
            initialize::ensure_holding(&input.pre_state, &descriptor, input.is_authorized)
                .map_or_else(Response::keep_state, Response::set_state)
        }
        Message::Burn {
            descriptor,
            amount,
            definition,
        } => {
            assert!(input.is_authorized, "Authorization is missing");
            Response::set_state(burn::burn_holding(&input.pre_state, &descriptor, amount)).call(
                own(definition),
                &Message::BurnSupply {
                    definition_id: descriptor.definition_id,
                    kind: descriptor.kind,
                    amount,
                },
            )
        }
        Message::PrintNft {
            printed,
            definition_id,
        } => {
            assert!(input.is_authorized, "Master NFT Account must be authorized");
            Response::set_state(print_nft::print_copy(&input.pre_state, definition_id)).cast(
                own(printed),
                &Message::Create(ActorState::from(&TokenHolding::NftPrintedCopy {
                    definition_id,
                    owned: true,
                })),
            )
        }
        // TODO(cross-zone): nothing here checks the caller, so the cross-zone inbox
        // can deliver into this program on a peer's word, letting the peer drive
        // writes in token's own actor state at addresses it names. That is the same
        // reach any local caller has; a peer just pays no local fee.
        Message::NewDefinition {
            definition,
            holding,
            metadata,
        } => {
            assert!(
                input.pre_state.is_empty(),
                "Target account must not already hold data"
            );
            let definition_id = input.receiver.account_id;
            let (definition, created) = new_definition::definition(
                definition,
                definition_id,
                metadata.as_ref().map(|(metadata_id, _)| *metadata_id),
            );
            let defined = Response::set_state(ActorState::from(&definition))
                .cast(own(holding), &Message::Create(ActorState::from(&created)));
            match metadata {
                Some((
                    metadata_id,
                    NewTokenMetadata {
                        standard,
                        uri,
                        creators,
                    },
                )) => defined.call(
                    own(metadata_id),
                    &Message::Create(ActorState::from(&TokenMetadata {
                        definition_id,
                        standard,
                        uri,
                        creators,
                        primary_sale_date: 0, // TODO #261: future works to implement this
                    })),
                ),
                None => defined,
            }
        }
        Message::Mint { to, amount } => {
            assert!(input.is_authorized, "Definition authorization is missing");
            Response::set_state(mint::mint_supply(&input.pre_state, amount)).cast(
                own(to),
                &Message::Credit {
                    descriptor: TokenDescriptor::fungible(input.receiver.account_id),
                    amount,
                    notify: None,
                },
            )
        }
        Message::BurnSupply {
            definition_id,
            kind,
            amount,
        } => {
            assert!(from_token, "A supply burn must come from the token program");
            assert_eq!(
                input.receiver.account_id, definition_id,
                "A supply burn names another definition"
            );
            Response::set_state(burn::burn_supply(&input.pre_state, kind, amount))
        }
        Message::AssertKind { kind } => {
            initialize::check_holding_kind(&input.pre_state, kind);
            Response::keep_state()
        }
        Message::Create(data) => {
            assert!(from_token, "A creation must come from the token program");
            assert!(
                input.pre_state.is_empty(),
                "Target account must not already hold data"
            );
            Response::set_state(data)
        }
        Message::Notification(_) => panic!("A token actor does not accept notifications"),
    }
}
