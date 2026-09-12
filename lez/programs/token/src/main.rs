//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};
use token_program::core::Instruction;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = match instruction {
        Instruction::Transfer {
            sender,
            recipient,
            amount_to_transfer,
        } => token_program::transfer::transfer(
            pre_states,
            &sender,
            &recipient,
            self_account_id,
            amount_to_transfer,
        ),
        // TODO(cross-zone): nothing here checks the caller, so the cross-zone inbox
        // can deliver into this program on a peer's word, letting the peer drive
        // writes in token's own shard at addresses it names. That is the same
        // reach any local caller has; a peer just pays no local fee.
        Instruction::NewFungibleDefinition {
            name,
            total_supply,
            holder,
        } => {
            let [definition_account, holding_account] = pre_states
                .try_into()
                .expect("NewFungibleDefinition instruction requires exactly two accounts");
            token_program::new_definition::new_fungible_definition(
                &definition_account,
                &holding_account,
                &holder,
                self_account_id,
                name,
                total_supply,
            )
        }
        Instruction::NewDefinitionWithMetadata {
            new_definition,
            metadata,
            holder,
        } => {
            let [definition_account, holding_account, metadata_account] = pre_states
                .try_into()
                .expect("NewDefinitionWithMetadata instruction requires exactly three accounts");
            token_program::new_definition::new_definition_with_metadata(
                &definition_account,
                &holding_account,
                &metadata_account,
                &holder,
                self_account_id,
                new_definition,
                *metadata,
            )
        }
        Instruction::InitializeAccount { holder } => {
            let [definition_account, account_to_initialize] = pre_states
                .try_into()
                .expect("InitializeAccount instruction requires exactly two accounts");
            token_program::initialize::initialize_account(
                &definition_account,
                &account_to_initialize,
                &holder,
                self_account_id,
            )
        }
        Instruction::Burn {
            holder,
            amount_to_burn,
        } => token_program::burn::burn(pre_states, &holder, self_account_id, amount_to_burn),
        Instruction::Mint {
            holder,
            amount_to_mint,
        } => {
            let [definition_account, user_holding_account] = pre_states
                .try_into()
                .expect("Mint instruction requires exactly two accounts");
            token_program::mint::mint(
                &definition_account,
                &user_holding_account,
                &holder,
                self_account_id,
                amount_to_mint,
            )
        }
        Instruction::PrintNft {
            master_holder,
            copy_holder,
        } => token_program::print_nft::print_nft(
            pre_states,
            &master_holder,
            &copy_holder,
            self_account_id,
        ),
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
