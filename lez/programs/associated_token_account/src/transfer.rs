use associated_token_account_core::Instruction;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, InstructionData, Plan, ProgramInput},
};
use token_core::TokenDescriptor;

pub fn transfer_from_associated_token_account(
    input: &ProgramInput<Instruction>,
    instruction_data: InstructionData,
    token_program_id: AccountId,
    descriptor: TokenDescriptor,
    amount: u128,
) -> Plan {
    let [owner, sender_ata, recipient] = <&[AccountMeta; 3]>::try_from(input.accounts.as_slice())
        .expect("Transfer instruction requires exactly three accounts");
    assert!(owner.is_authorized, "Owner authorization is missing");

    // `descriptor` is a proposal, and needs no guard here: a wrong definition id derives a
    // different address, which cannot be the sender this call names, and the token program's
    // `Withdraw` effect refuses any descriptor that is not the sender holding's real one.
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        sender_ata,
        owner,
        descriptor.definition_id,
        input.self_account_id,
        token_program_id,
    );

    let mut plan = Plan::new(input, instruction_data);
    plan.call(
        ChainedCall::new(
            token_program_id,
            vec![
                ProgramShardSelector::from(sender_ata),
                ProgramShardSelector::from(recipient),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: amount,
                descriptor,
            },
        )
        .with_pda_seeds(vec![seed]),
    );
    plan
}
