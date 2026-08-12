use cross_zone_marker_core::inbox_source_marker_account_id;
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
        Instruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            &config,
        ),
        Instruction::RenounceAuthority => renounce_authority(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
        ),
        Instruction::UpdateSources { sources } => update_sources(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            sources,
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
        caller_program_id,
        Some(cfg.minter),
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
        self_program_id,
        caller_program_id,
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

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
) {
    assert!(
        caller_program_id.is_none(),
        "RenounceAuthority is only invoked as a top-level transaction"
    );

    // pre_states: [config PDA, authority account].
    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("RenounceAuthority requires the config and authority accounts");
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "first account must be the wrapped-token config PDA"
    );

    let mut cfg = WrappedTokenConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("config account holds a wrapped-token config");
    let Some(expected) = cfg.authority else {
        panic!("wrapped-token authority is already renounced");
    };
    assert_eq!(
        authority.account_id, expected,
        "second account must be the configured authority"
    );
    assert!(
        authority.is_authorized,
        "the configured authority must authorize renouncing it"
    );

    cfg.authority = None;
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config, authority.clone()],
        vec![
            AccountPostState::new(config_account),
            AccountPostState::new(authority.account),
        ],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    sources: Vec<([u8; 32], lee_core::program::ProgramId)>,
) {
    // Top-level only. An account stays authorized for every call below the one
    // that authorized it, so a program the authority signed for could otherwise
    // chain in here and rewrite the list without the holder intending it. A
    // governance PDA holding this needs the caller pinned to that program
    // instead, which is a guest change that work has to make anyway.
    assert!(
        caller_program_id.is_none(),
        "UpdateSources is only invoked as a top-level transaction"
    );

    // pre_states: [config PDA, authority account].
    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("UpdateSources requires the config and authority accounts");
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "first account must be the wrapped-token config PDA"
    );

    let mut cfg = WrappedTokenConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("config account holds a wrapped-token config");
    let Some(expected) = cfg.authority else {
        panic!("wrapped-token sources are fixed at genesis: no authority is configured");
    };
    assert_eq!(
        authority.account_id, expected,
        "second account must be the configured authority"
    );
    // Authorized rather than merely named, so a PDA held by a governance program
    // works through the same delegation any signer would use.
    assert!(
        authority.is_authorized,
        "the configured authority must authorize a source change"
    );

    cfg.sources = sources;
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config, authority.clone()],
        vec![
            AccountPostState::new(config_account),
            AccountPostState::new(authority.account),
        ],
    )
    .write();
}

/// Writes the minter and the authorized peer sources into the config PDA exactly
/// once at genesis.
fn init_config(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    config_value: &WrappedTokenConfig,
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
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config],
        vec![config_post],
    )
    .write();
}
