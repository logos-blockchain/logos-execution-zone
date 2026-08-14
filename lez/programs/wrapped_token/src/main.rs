use cross_zone_inbox_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{AccountPostState, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, WrappedTokenConfig, balance_bytes, config_account_id,
    config_seed, holding_account_id, holding_seed, read_balance,
};

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    match instruction {
        Instruction::Mint { recipient, amount } => mint(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            recipient,
            amount,
        ),
        Instruction::InitConfig(config) => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            &config,
        ),
    }
}

fn mint(
    self_account_id: lee_core::account::AccountId,
    caller_account_id: Option<lee_core::account::AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    recipient: [u8; 32],
    amount: u128,
) {
    // Recover the real `ProgramId` (RISC0 image id): on this branch every program account lives
    // at the direct `AccountId::from(program_id)` bijection, so this round-trip is exact. Needed
    // for the PDA-derivation helpers below, which are pinned to the actual image id.
    let self_program_id = lee_core::program::ProgramId::from(self_account_id);

    // pre_states: [source marker, config PDA, recipient holding PDA].
    let [marker, config, holding] = <[AccountWithMetadata; 3]>::try_from(pre_states)
        .expect("Mint requires the source marker, config, and recipient holding accounts");

    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the caller to it, since the guest cannot import the inbox id.
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "second account must be the wrapped-token config PDA"
    );
    let cfg = WrappedTokenConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("config account holds a wrapped-token config");
    assert_eq!(
        caller_account_id,
        Some(cfg.minter.into()),
        "Mint is only callable by the authorized minter (the cross-zone inbox)"
    );
    // The inbox vouches only that the message arrived; which peer sent it is this
    // token's own business, and unbacked value is what gets minted if it takes
    // anyone's word for it. The marker's address is the source, so re-deriving it
    // from an authorized pair is the whole check.
    assert!(
        cfg.sources.iter().any(|(src_zone, src_program_id)| {
            marker.account_id
                == inbox_source_marker_account_id(cfg.minter, src_zone, *src_program_id)
        }),
        "Mint is only callable for a peer source this token authorizes"
    );

    assert_eq!(
        holding.account_id,
        holding_account_id(self_program_id, &recipient),
        "third account must be the recipient holding PDA"
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
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![marker.clone(), config, holding],
        vec![
            AccountPostState::new(marker.account),
            config_post,
            holding_post,
        ],
    )
    .write();
}

/// Writes the minter and the authorized peer sources into the config PDA exactly
/// once at genesis.
fn init_config(
    self_account_id: lee_core::account::AccountId,
    caller_account_id: Option<lee_core::account::AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    config_value: &WrappedTokenConfig,
) {
    assert!(
        caller_account_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_account_id.into()),
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
            config.account.program_owner, self_account_id,
            "wrapped-token config PDA is owned by another program"
        );
        assert_eq!(
            config.account.data.clone().into_inner(),
            config_value.to_bytes(),
            "wrapped-token config already initialized differently"
        );
    }

    let mut config_account = config.account.clone();
    config_account.data = config_value
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");
    let config_post =
        AccountPostState::new_claimed_if_default(config_account, Claim::Pda(config_seed()));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![config],
        vec![config_post],
    )
    .write();
}
