use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, Plan, PlanInput},
};
use token_core::TokenKind;

pub fn burn_from_associated_token_account(
    input: &PlanInput,
    token_program_id: AccountId,
    kind: TokenKind,
    amount: u128,
) -> Plan {
    let [owner, holder_ata, token_definition] =
        <&[AccountMeta; 3]>::try_from(input.accounts.as_slice())
            .expect("Burn instruction requires exactly three accounts");
    assert!(owner.is_authorized, "Owner authorization is missing");

    // No proposal exists to guard: the seed's definition id is the account this burn already
    // names, and token's `BurnHolding` effect requires the holder's real definition id to be
    // exactly that account, which is what the discarded read asserted. `BurnSupply` pins `kind`.
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        holder_ata,
        owner,
        token_definition.account_id,
        input.self_account_id,
        token_program_id,
    );

    let mut plan = Plan::new(input);
    plan.call(
        ChainedCall::new(
            token_program_id,
            vec![
                ProgramShardSelector::from(token_definition),
                ProgramShardSelector::from(holder_ata),
            ],
            &token_core::Instruction::Burn {
                amount_to_burn: amount,
                kind,
            },
        )
        .with_pda_seeds(vec![seed]),
    );
    plan
}
