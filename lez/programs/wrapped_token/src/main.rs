use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, balance_bytes, config_account_id, config_seed,
    holding_account_id, holding_seed, minter_bytes, read_balance, read_minter,
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

    match instruction {
        Instruction::Mint { recipient, amount } => mint(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            recipient,
            amount,
        ),
        Instruction::InitConfig { minter } => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            minter,
        ),
    }
}

fn mint(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    recipient: [u8; 32],
    amount: u128,
) {
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

    assert!(
        amount <= MAX_MINT_AMOUNT,
        "mint amount exceeds the per-mint cap"
    );
    // The backstop against accumulation, which the per-mint cap does not bound.
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

/// Writes the authorized minter into the config PDA exactly once at genesis.
fn init_config(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    minter: lee_core::program::ProgramId,
) {
    assert!(
        caller_program_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "account must be the wrapped-token config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned config must already hold exactly this minter (the
    // genesis block is replayed onto seeded state during multi-sequencer
    // reconstruction), otherwise reject a post-genesis attempt to set a different
    // minter. `new_claimed_if_default` alone would not stop the owning program from
    // rewriting its own config data on a later call.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner, self_program_id,
            "wrapped-token config PDA is owned by another program"
        );
        assert_eq!(
            config.account.data.clone().into_inner(),
            minter_bytes(minter).to_vec(),
            "wrapped-token config already initialized with a different minter"
        );
    }

    let mut config_account = config.account.clone();
    config_account.data = minter_bytes(minter)
        .to_vec()
        .try_into()
        .expect("minter id fits in account data");
    let config_post =
        AccountPostState::new_claimed_if_default(config_account, Claim::Pda(config_seed()));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config],
        vec![config_post],
    )
    .write();
}
