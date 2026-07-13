use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{
    Instruction, balance_bytes, config_account_id, holding_account_id, holding_seed, read_balance,
    read_minter,
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Instruction::Mint { recipient, amount } = instruction;

    // pre_states: [config PDA, recipient holding PDA].
    let [config, holding] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("Mint requires the config and recipient holding accounts");

    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the caller to it, since the guest cannot import the inbox id.
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "first account must be the wrapped-token config PDA"
    );
    let minter = read_minter(&config.account.data.clone().into_inner())
        .expect("config account holds an authorized minter id");
    assert_eq!(
        caller_program_id,
        Some(minter),
        "Mint is only callable by the authorized minter (the cross-zone inbox)"
    );

    assert_eq!(
        holding.account_id,
        holding_account_id(self_program_id, &recipient),
        "second account must be the recipient holding PDA"
    );

    let new_balance = read_balance(&holding.account.data.clone().into_inner())
        .checked_add(amount)
        .expect("wrapped-token balance overflow");
    let mut holding_account = holding.account.clone();
    holding_account.data = balance_bytes(new_balance)
        .to_vec()
        .try_into()
        .expect("balance fits in account data");
    let holding_post = AccountPostState::new_claimed_if_default(
        holding_account,
        Claim::Pda(holding_seed(&recipient)),
    );
    let config_post = AccountPostState::new(config.account.clone());

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config, holding],
        vec![config_post, holding_post],
    )
    .write();
}
