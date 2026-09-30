//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;
use associated_token_account_core::{AtaContents, Instruction};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::ShardData,
    program::{Plan, PlanInput},
};
use token_core::{TokenDescriptor, TokenKind};

pub mod burn;
pub mod create;
pub mod transfer;

#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    AtaContents {
        descriptor: TokenDescriptor,
        contents: AtaContents,
    },
    DefinitionKind {
        kind: TokenKind,
    },
}

pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    match instruction {
        Instruction::Create {
            token_program_id,
            kind,
            contents,
        } => create::create_associated_token_account(input, token_program_id, kind, contents),
        Instruction::Transfer {
            token_program_id,
            descriptor,
            amount,
        } => transfer::transfer_from_associated_token_account(
            input,
            token_program_id,
            descriptor,
            amount,
        ),
        Instruction::Burn {
            token_program_id,
            kind,
            amount,
        } => burn::burn_from_associated_token_account(input, token_program_id, kind, amount),
    }
}

// This program owns no shard: every effect it emits inspects a Token Program shard, so none of
// them can write.
#[must_use]
pub fn apply(effect: Effect, pre_data: &ShardData) -> Option<ShardData> {
    match effect {
        Effect::AtaContents {
            descriptor,
            contents,
        } => create::check_contents(pre_data, &descriptor, contents),
        Effect::DefinitionKind { kind } => create::check_definition_kind(pre_data, kind),
    }
    None
}
