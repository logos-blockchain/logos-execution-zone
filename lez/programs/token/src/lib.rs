//! The Token Program implementation.

use lee_core::{
    account::ActorState,
    program::{ReceiveInput, Response},
};
pub use token_core as core;
use token_core::{Message, expected_sends};

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

pub fn receive(input: &ReceiveInput, message: Message) -> Response {
    let from_token = input.from_own_program();
    let (calls, casts) = expected_sends(input.receiver, &message);
    let post = match message {
        Message::Transfer {
            descriptor, amount, ..
        } => {
            assert!(input.is_authorized, "Sender authorization is missing");
            Some(transfer::withdraw(&input.pre_state, &descriptor, amount))
        }
        Message::Credit {
            descriptor, amount, ..
        } => {
            assert!(from_token, "A credit must come from the token program");
            Some(transfer::deposit(&input.pre_state, &descriptor, amount))
        }
        Message::EnsureHolding { descriptor } => {
            initialize::ensure_holding(&input.pre_state, &descriptor, input.is_authorized)
        }
        Message::Burn {
            descriptor, amount, ..
        } => {
            assert!(input.is_authorized, "Authorization is missing");
            Some(burn::burn_holding(&input.pre_state, &descriptor, amount))
        }
        Message::PrintNft { definition_id, .. } => {
            assert!(input.is_authorized, "Master NFT Account must be authorized");
            Some(print_nft::print_copy(&input.pre_state, definition_id))
        }
        // TODO(cross-zone): nothing here checks the caller, so the cross-zone inbox
        // can deliver into this program on a peer's word, letting the peer drive
        // writes in token's own shard at addresses it names. That is the same
        // reach any local caller has; a peer just pays no local fee.
        Message::NewDefinition {
            definition,
            metadata,
            ..
        } => {
            assert!(
                input.pre_state.is_empty(),
                "Target account must not already hold data"
            );
            Some(ActorState::from(&new_definition::definition(
                definition,
                metadata.map(|(metadata_id, _)| metadata_id),
            )))
        }
        Message::Mint { amount, .. } => {
            assert!(input.is_authorized, "Definition authorization is missing");
            Some(mint::mint_supply(&input.pre_state, amount))
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
            Some(burn::burn_supply(&input.pre_state, kind, amount))
        }
        Message::AssertKind { kind } => {
            initialize::check_holding_kind(&input.pre_state, kind);
            None
        }
        Message::Create(data) => {
            assert!(from_token, "A creation must come from the token program");
            assert!(
                input.pre_state.is_empty(),
                "Target account must not already hold data"
            );
            Some(data)
        }
        Message::Notification(_) => panic!("A token actor does not accept notifications"),
    };
    Response {
        calls,
        casts,
        ..post.map_or_else(Response::keep, Response::write)
    }
}
