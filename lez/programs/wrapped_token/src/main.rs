use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall, ProgramId, ProgramInput,
        read_lee_call,
    },
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, WrappedTokenConfig, balance_bytes, config_account_id,
    config_seed, holding_account_id, holding_seed, read_balance,
};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();

    match instruction {
        Instruction::Mint { recipient, amount } => mint(input, recipient, amount),
        Instruction::InitConfig(config) => init_config(input, &config),
        Instruction::RenounceAuthority => renounce_authority(input),
        Instruction::UpdateSources { sources } => update_sources(input, sources),
    }
}

fn mint(input: ProgramInput, recipient: [u8; 32], amount: u128) {
    // pre_states: [source marker, config PDA, recipient holding PDA].
    let [marker, config, holding] = input.pre_states.as_slice() else {
        panic!("Mint requires the source marker, config, and recipient holding accounts");
    };

    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the caller to it, since the guest cannot import the inbox id.
    assert_eq!(
        config.account_id,
        config_account_id(input.call.self_program_id),
        "second account must be the wrapped-token config PDA"
    );
    let cfg = WrappedTokenConfig::from_bytes(&config.account.data)
        .expect("config account holds a wrapped-token config");
    assert_eq!(
        input.call.caller_program_id,
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
        holding_account_id(input.call.self_program_id, &recipient),
        "third account must be the recipient holding PDA"
    );

    assert!(
        amount <= MAX_MINT_AMOUNT,
        "mint amount exceeds the per-mint cap"
    );
    // The backstop against accumulation, which the per-mint cap does not bound.
    let new_balance = read_balance(&holding.account.data)
        .checked_add(amount)
        .expect("wrapped-token balance overflow");
    let holding_diff = AccountDiff {
        id: holding.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            balance_bytes(new_balance)
                .to_vec()
                .try_into()
                .expect("balance fits in account data"),
        ),
    };
    let holding_post = AccountDiffOutput::new_claimed_if_default(
        holding_diff,
        holding.account.program_owner,
        Claim::Pda(holding_seed(&recipient)),
    );
    let post_states = vec![
        AccountDiffOutput::unchanged(marker.account_id),
        AccountDiffOutput::unchanged(config.account_id),
        holding_post,
    ];

    input.into_output(post_states).write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(input: ProgramInput) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let Some(config_meta) = input.pre_states.first() else {
        panic!("RenounceAuthority requires the config account");
    };
    assert_eq!(
        config_meta.account_id,
        config_account_id(input.call.self_program_id),
        "first account must be the wrapped-token config PDA"
    );
    let mut cfg = WrappedTokenConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        input.call.caller_program_id.is_none() || input.call.caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = input.pre_states.as_slice() else {
        panic!("this instruction requires exactly the config and authority accounts");
    };

    let Some(expected) = cfg.authority else {
        panic!("wrapped-token authority is already renounced");
    };
    assert_eq!(
        authority.account_id, expected,
        "second account must be the configured authority"
    );
    // Claims apply after post-state validation, so a first use must find the
    // account untouched; an unowned account with history is refused for good.
    assert!(
        authority.account == Account::default()
            || authority.account.program_owner != DEFAULT_PROGRAM_OWNER,
        "the authority account must be untouched before its first use as one"
    );
    assert!(
        authority.is_authorized,
        "the configured authority must authorize renouncing it"
    );

    cfg.authority = None;
    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            cfg.to_bytes()
                .try_into()
                .expect("wrapped-token config fits in account data"),
        ),
    };

    let post_states = vec![
        AccountDiffOutput::new(config_diff),
        // Claimed on first use: the authority's own signature bumps its
        // nonce, so merely echoing it would work once and never again.
        AccountDiffOutput::new_claimed_if_default(
            AccountDiff::unchanged(authority.account_id),
            authority.account.program_owner,
            Claim::Authorized,
        ),
    ];

    input.into_output(post_states).write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(input: ProgramInput, sources: Vec<([u8; 32], ProgramId)>) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let Some(config_meta) = input.pre_states.first() else {
        panic!("UpdateSources requires the config account");
    };
    assert_eq!(
        config_meta.account_id,
        config_account_id(input.call.self_program_id),
        "first account must be the wrapped-token config PDA"
    );
    let mut cfg = WrappedTokenConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        input.call.caller_program_id.is_none() || input.call.caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = input.pre_states.as_slice() else {
        panic!("this instruction requires exactly the config and authority accounts");
    };

    let Some(expected) = cfg.authority else {
        panic!("wrapped-token sources are fixed at genesis: no authority is configured");
    };
    assert_eq!(
        authority.account_id, expected,
        "second account must be the configured authority"
    );
    // Claims apply after post-state validation, so a first use must find the
    // account untouched; an unowned account with history is refused for good.
    assert!(
        authority.account == Account::default()
            || authority.account.program_owner != DEFAULT_PROGRAM_OWNER,
        "the authority account must be untouched before its first use as one"
    );
    assert!(
        authority.is_authorized,
        "the configured authority must authorize a source change"
    );

    cfg.sources = sources;
    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            cfg.to_bytes()
                .try_into()
                .expect("wrapped-token config fits in account data"),
        ),
    };

    let post_states = vec![
        AccountDiffOutput::new(config_diff),
        // Claimed on first use: the authority's own signature bumps its
        // nonce, so merely echoing it would work once and never again.
        AccountDiffOutput::new_claimed_if_default(
            AccountDiff::unchanged(authority.account_id),
            authority.account.program_owner,
            Claim::Authorized,
        ),
    ];

    input.into_output(post_states).write();
}

/// Writes the minter and the authorized peer sources into the config PDA exactly
/// once at genesis.
fn init_config(input: ProgramInput, config_value: &WrappedTokenConfig) {
    assert!(
        input.call.caller_program_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    // pre_states: [config PDA].
    let [config] = input.pre_states.as_slice() else {
        panic!("InitConfig requires the config account");
    };
    assert_eq!(
        config.account_id,
        config_account_id(input.call.self_program_id),
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
            config.account.program_owner,
            input.call.self_program_id.into(),
            "wrapped-token config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_value.to_bytes(),
            "wrapped-token config already initialized differently"
        );
    }

    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config_value
                .to_bytes()
                .try_into()
                .expect("wrapped-token config fits in account data"),
        ),
    };
    let config_post = AccountDiffOutput::new_claimed_if_default(
        config_diff,
        config.account.program_owner,
        Claim::Pda(config_seed()),
    );

    input.into_output(vec![config_post]).write();
}
