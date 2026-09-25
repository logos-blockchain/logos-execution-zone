//! The Token Program implementation.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ShardData},
    program::{Plan, PlanInput},
};
pub use token_core as core;
use token_core::{Instruction, TokenDescriptor, TokenKind};

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Withdraw {
        descriptor: TokenDescriptor,
        amount: u128,
    },
    Deposit {
        descriptor: TokenDescriptor,
        amount: u128,
    },
    Create(ShardData),
    CheckHoldingKind(TokenKind),
    InitializeHolding {
        descriptor: TokenDescriptor,
        is_authorized: bool,
    },
    MintSupply {
        amount: u128,
    },
    BurnSupply {
        kind: TokenKind,
        amount: u128,
    },
    BurnHolding {
        descriptor: TokenDescriptor,
        amount: u128,
    },
    PrintCopy {
        definition_id: AccountId,
    },
}

pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Transfer {
            amount_to_transfer,
            descriptor,
        } => {
            let [sender, recipient] = <&[_; 2]>::try_from(input.accounts.as_slice())
                .expect("Transfer instruction requires exactly two accounts");
            transfer::transfer(&mut plan, sender, recipient, descriptor, amount_to_transfer);
        }
        // TODO(cross-zone): nothing here checks the caller, so the cross-zone inbox
        // can deliver into this program on a peer's word, letting the peer drive
        // writes in token's own shard at addresses it names. That is the same
        // reach any local caller has; a peer just pays no local fee.
        Instruction::NewFungibleDefinition { name, total_supply } => {
            let [definition_account, holding_account] =
                <&[_; 2]>::try_from(input.accounts.as_slice())
                    .expect("NewFungibleDefinition instruction requires exactly two accounts");
            new_definition::new_fungible_definition(
                &mut plan,
                definition_account,
                holding_account,
                name,
                total_supply,
            );
        }
        Instruction::NewDefinitionWithMetadata {
            new_definition,
            metadata,
        } => {
            let [definition_account, holding_account, metadata_account] = <&[_; 3]>::try_from(
                input.accounts.as_slice(),
            )
            .expect("NewDefinitionWithMetadata instruction requires exactly three accounts");
            new_definition::new_definition_with_metadata(
                &mut plan,
                definition_account,
                holding_account,
                metadata_account,
                new_definition,
                *metadata,
            );
        }
        Instruction::InitializeAccount { kind } => {
            let [definition_account, account_to_initialize] =
                <&[_; 2]>::try_from(input.accounts.as_slice())
                    .expect("InitializeAccount instruction requires exactly two accounts");
            initialize::initialize_account(
                &mut plan,
                definition_account,
                account_to_initialize,
                kind,
            );
        }
        Instruction::Burn {
            amount_to_burn,
            kind,
        } => {
            let [definition_account, user_holding_account] =
                <&[_; 2]>::try_from(input.accounts.as_slice())
                    .expect("Burn instruction requires exactly two accounts");
            burn::burn(
                &mut plan,
                definition_account,
                user_holding_account,
                kind,
                amount_to_burn,
            );
        }
        Instruction::Mint { amount_to_mint } => {
            let [definition_account, user_holding_account] =
                <&[_; 2]>::try_from(input.accounts.as_slice())
                    .expect("Mint instruction requires exactly two accounts");
            mint::mint(
                &mut plan,
                definition_account,
                user_holding_account,
                amount_to_mint,
            );
        }
        Instruction::PrintNft { definition_id } => {
            let [master_account, printed_account] = <&[_; 2]>::try_from(input.accounts.as_slice())
                .expect("PrintNft instruction requires exactly two accounts");
            print_nft::print_nft(&mut plan, master_account, printed_account, definition_id);
        }
    }

    plan
}

#[must_use]
pub fn apply(effect: Effect, pre_data: &ShardData) -> Option<ShardData> {
    Some(match effect {
        Effect::Withdraw { descriptor, amount } => {
            transfer::withdraw(pre_data, &descriptor, amount)
        }
        Effect::Deposit { descriptor, amount } => transfer::deposit(pre_data, &descriptor, amount),
        Effect::Create(data) => {
            assert!(
                pre_data.is_empty(),
                "Target account must not already hold data"
            );
            data
        }
        Effect::CheckHoldingKind(kind) => {
            initialize::check_holding_kind(pre_data, kind);
            return None;
        }
        Effect::InitializeHolding {
            descriptor,
            is_authorized,
        } => initialize::initialize_holding(pre_data, &descriptor, is_authorized),
        Effect::MintSupply { amount } => mint::mint_supply(pre_data, amount),
        Effect::BurnSupply { kind, amount } => burn::burn_supply(pre_data, kind, amount),
        Effect::BurnHolding { descriptor, amount } => {
            burn::burn_holding(pre_data, &descriptor, amount)
        }
        Effect::PrintCopy { definition_id } => print_nft::print_copy(pre_data, definition_id),
    })
}
