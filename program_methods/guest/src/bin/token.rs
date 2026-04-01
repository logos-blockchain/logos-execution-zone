//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use nssa_core::program::{ProgramInput, ProgramOutput, read_nssa_inputs};
use token_program::core::Instruction;

fn main() {
    let (
        ProgramInput {
            self_program_id: _,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();

    let post_states = match instruction {
        Instruction::Transfer {
            amount_to_transfer: balance_to_move,
        } => {
            let [sender, recipient] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly two accounts");
            token_program::transfer::transfer(sender, recipient, balance_to_move)
        }
        Instruction::NewFungibleDefinition { name, total_supply } => {
            let [definition_account, holding_account] = pre_states
                .try_into()
                .expect("NewFungibleDefinition instruction requires exactly two accounts");
            token_program::new_definition::new_fungible_definition(
                definition_account,
                holding_account,
                name,
                total_supply,
            )
        }
        Instruction::NewDefinitionWithMetadata {
            new_definition,
            metadata,
        } => {
            let [definition_account, holding_account, metadata_account] = pre_states
                .try_into()
                .expect("NewDefinitionWithMetadata instruction requires exactly three accounts");
            token_program::new_definition::new_definition_with_metadata(
                definition_account,
                holding_account,
                metadata_account,
                new_definition,
                *metadata,
            )
        }
        Instruction::InitializeAccount => {
            let [definition_account, account_to_initialize] = pre_states
                .try_into()
                .expect("InitializeAccount instruction requires exactly two accounts");
            token_program::initialize::initialize_account(definition_account, account_to_initialize)
        }
        Instruction::Burn { amount_to_burn } => {
            let [definition_account, user_holding_account] = pre_states
                .try_into()
                .expect("Burn instruction requires exactly two accounts");
            token_program::burn::burn(definition_account, user_holding_account, amount_to_burn)
        }
        Instruction::Mint { amount_to_mint } => {
            let [definition_account, user_holding_account] = pre_states
                .try_into()
                .expect("Mint instruction requires exactly two accounts");
            token_program::mint::mint(definition_account, user_holding_account, amount_to_mint)
        }
        Instruction::PrintNft => {
            let [master_account, printed_account] = pre_states
                .try_into()
                .expect("PrintNft instruction requires exactly two accounts");
            token_program::print_nft::print_nft(master_account, printed_account)
        }
    };

    ProgramOutput::new(instruction_words, pre_states_clone, post_states).write();
}
