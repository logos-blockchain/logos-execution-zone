//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;
use associated_token_account_core::{AtaContents, Instruction};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{InstructionData, Plan, ProgramInput, ResolveInput},
};
use token_core::{TokenDescriptor, TokenKind};

pub mod burn;
pub mod create;
pub mod transfer;

#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    AtaContents {
        token_program_id: AccountId,
        descriptor: TokenDescriptor,
        contents: AtaContents,
    },
    DefinitionKind {
        token_program_id: AccountId,
        kind: TokenKind,
    },
}

impl Effect {
    const fn token_program_id(&self) -> AccountId {
        match self {
            Self::AtaContents {
                token_program_id, ..
            }
            | Self::DefinitionKind {
                token_program_id, ..
            } => *token_program_id,
        }
    }
}

pub fn execute(input: &ProgramInput<Instruction>, instruction_data: InstructionData) -> Plan {
    match &input.instruction {
        Instruction::Create {
            token_program_id,
            kind,
            contents,
        } => create::create_associated_token_account(
            input,
            instruction_data,
            *token_program_id,
            *kind,
            *contents,
        ),
        Instruction::Transfer {
            token_program_id,
            descriptor,
            amount,
        } => transfer::transfer_from_associated_token_account(
            input,
            instruction_data,
            *token_program_id,
            *descriptor,
            *amount,
        ),
        Instruction::Burn {
            token_program_id,
            kind,
            amount,
        } => burn::burn_from_associated_token_account(
            input,
            instruction_data,
            *token_program_id,
            *kind,
            *amount,
        ),
    }
}

pub fn resolve(input: &ResolveInput) {
    let effect = Effect::try_from_slice(&input.effect_data)
        .expect("The Associated Token Account Program wrote its own effect");

    // Both effects parse Token Program data on a shard this program does not own, and a
    // resolution ending in `Keep` is never rejected for naming a foreign shard, so without this
    // a guard could be aimed at a shard whose bytes the caller wrote. The token program named
    // here is the one the ATA's address was derived under, which ties the pair together.
    assert_eq!(
        input.selector.program_account_id,
        effect.token_program_id(),
        "The Associated Token Account Program only guards the Token Program's own shard"
    );

    match effect {
        Effect::AtaContents {
            descriptor,
            contents,
            ..
        } => create::check_contents(&input.pre_data, &descriptor, contents),
        Effect::DefinitionKind { kind, .. } => create::check_definition_kind(&input.pre_data, kind),
    }
}
