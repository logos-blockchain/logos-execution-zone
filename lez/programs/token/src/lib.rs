//! The Token Program implementation.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ShardData},
    program::{InstructionData, Plan, ProgramInput, ResolveInput},
};
pub use token_core as core;
use token_core::{
    Instruction, TokenDefinition, TokenDescriptor, TokenHolding, TokenKind, TokenMetadata,
};

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Withdraw {
        descriptor: TokenDescriptor,
        amount: u128,
    },
    Deposit {
        descriptor: TokenDescriptor,
        amount: u128,
    },
    CreateDefinition(TokenDefinition),
    CreateHolding(TokenHolding),
    CreateMetadata(TokenMetadata),
    CheckHoldingKind(TokenKind),
    InitializeHolding {
        descriptor: TokenDescriptor,
        is_authorized: bool,
    },
    MintSupply {
        amount: u128,
    },
    MintHolding {
        definition_id: AccountId,
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
    CreatePrintedCopy {
        definition_id: AccountId,
    },
}

pub fn execute(input: ProgramInput<Instruction>, instruction_data: InstructionData) -> Plan {
    let mut plan = Plan::new(&input, instruction_data);
    let ProgramInput {
        self_account_id,
        caller_account_id: _,
        accounts,
        instruction,
    } = input;

    assert!(
        accounts
            .iter()
            .all(|account| account.program_account_id == self_account_id),
        "Every account must select the Token Program's own shard"
    );

    match instruction {
        Instruction::Transfer {
            amount_to_transfer,
            descriptor,
        } => {
            let [sender, recipient] = accounts
                .try_into()
                .expect("Transfer instruction requires exactly two accounts");
            transfer::transfer(
                &mut plan,
                &sender,
                &recipient,
                descriptor,
                amount_to_transfer,
            );
        }
        // TODO(cross-zone): nothing here checks the caller, so the cross-zone inbox
        // can deliver into this program on a peer's word, letting the peer drive
        // writes in token's own shard at addresses it names. That is the same
        // reach any local caller has; a peer just pays no local fee.
        Instruction::NewFungibleDefinition { name, total_supply } => {
            let [definition_account, holding_account] = accounts
                .try_into()
                .expect("NewFungibleDefinition instruction requires exactly two accounts");
            new_definition::new_fungible_definition(
                &mut plan,
                &definition_account,
                &holding_account,
                name,
                total_supply,
            );
        }
        Instruction::NewDefinitionWithMetadata {
            new_definition,
            metadata,
        } => {
            let [definition_account, holding_account, metadata_account] = accounts
                .try_into()
                .expect("NewDefinitionWithMetadata instruction requires exactly three accounts");
            new_definition::new_definition_with_metadata(
                &mut plan,
                &definition_account,
                &holding_account,
                &metadata_account,
                new_definition,
                *metadata,
            );
        }
        Instruction::InitializeAccount { kind } => {
            let [definition_account, account_to_initialize] = accounts
                .try_into()
                .expect("InitializeAccount instruction requires exactly two accounts");
            initialize::initialize_account(
                &mut plan,
                &definition_account,
                &account_to_initialize,
                kind,
            );
        }
        Instruction::Burn {
            amount_to_burn,
            kind,
        } => {
            let [definition_account, user_holding_account] = accounts
                .try_into()
                .expect("Burn instruction requires exactly two accounts");
            burn::burn(
                &mut plan,
                &definition_account,
                &user_holding_account,
                kind,
                amount_to_burn,
            );
        }
        Instruction::Mint { amount_to_mint } => {
            let [definition_account, user_holding_account] = accounts
                .try_into()
                .expect("Mint instruction requires exactly two accounts");
            mint::mint(
                &mut plan,
                &definition_account,
                &user_holding_account,
                amount_to_mint,
            );
        }
        Instruction::PrintNft { definition_id } => {
            let [master_account, printed_account] = accounts
                .try_into()
                .expect("PrintNft instruction requires exactly two accounts");
            print_nft::print_nft(&mut plan, &master_account, &printed_account, definition_id);
        }
    }

    plan
}

#[must_use]
pub fn resolve(input: &ResolveInput) -> Option<ShardData> {
    // A handle's shard program is chosen by the transaction, not derived, and a resolution that
    // ends in `Keep` is never rejected for naming a foreign shard. Without this, the definition
    // handle of `InitializeAccount` could name a shard the caller fills itself and
    // `CheckHoldingKind` would read those bytes.
    assert_eq!(
        input.selector.program_account_id, input.self_account_id,
        "The Token Program only resolves effects on its own shard"
    );

    let effect =
        Effect::try_from_slice(&input.effect_data).expect("The Token Program wrote its own effect");
    let pre_data = &input.pre_data;

    Some(match effect {
        Effect::Withdraw { descriptor, amount } => {
            transfer::withdraw(pre_data, &descriptor, amount)
        }
        Effect::Deposit { descriptor, amount } => transfer::deposit(pre_data, &descriptor, amount),
        Effect::CreateDefinition(definition) => {
            new_definition::create_definition(pre_data, &definition)
        }
        Effect::CreateHolding(holding) => new_definition::create_holding(pre_data, &holding),
        Effect::CreateMetadata(metadata) => new_definition::create_metadata(pre_data, &metadata),
        Effect::CheckHoldingKind(kind) => {
            initialize::check_holding_kind(pre_data, kind);
            return None;
        }
        Effect::InitializeHolding {
            descriptor,
            is_authorized,
        } => initialize::initialize_holding(pre_data, &descriptor, is_authorized),
        Effect::MintSupply { amount } => mint::mint_supply(pre_data, amount),
        Effect::MintHolding {
            definition_id,
            amount,
        } => mint::mint_holding(pre_data, definition_id, amount),
        Effect::BurnSupply { kind, amount } => burn::burn_supply(pre_data, kind, amount),
        Effect::BurnHolding { descriptor, amount } => {
            burn::burn_holding(pre_data, &descriptor, amount)
        }
        Effect::PrintCopy { definition_id } => print_nft::print_copy(pre_data, definition_id),
        Effect::CreatePrintedCopy { definition_id } => {
            print_nft::create_printed_copy(pre_data, definition_id)
        }
    })
}
