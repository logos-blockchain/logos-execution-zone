use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::Input,
    program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, WrappedTokenConfig, balance_bytes, config_account_id,
    holding_account_id, read_balance,
};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    match instruction {
        Instruction::Mint { recipient, amount } => mint(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            recipient,
            amount,
        ),
        Instruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            &config,
        ),
        Instruction::RenounceAuthority => renounce_authority(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
        ),
        Instruction::UpdateSources { sources } => update_sources(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            sources,
        ),
    }
}

fn mint(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
    recipient: [u8; 32],
    amount: u128,
) {
    // pre_states: [source marker, config PDA, recipient holding PDA].
    let [marker, config, holding] = <[Input; 3]>::try_from(pre_states)
        .expect("Mint requires the source marker, config, and recipient holding accounts");

    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the caller to it, since the guest cannot import the inbox id.
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "second account must be the wrapped-token config PDA"
    );
    let cfg = WrappedTokenConfig::from_bytes(config.data(self_program_id))
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
    let new_balance = read_balance(holding.data(self_program_id))
        .checked_add(amount)
        .expect("wrapped-token balance overflow");
    let mut holding_post = holding.slot_of(self_program_id).clone();
    holding_post.data = balance_bytes(new_balance)
        .to_vec()
        .try_into()
        .expect("balance fits in account data");
    let config_post = config.unchanged();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![marker.clone(), config, holding],
        vec![marker.unchanged(), config_post, Some(holding_post)],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let config_meta = pre_states
        .first()
        .expect("RenounceAuthority requires the config account");
    assert_eq!(
        config_meta.account_id,
        config_account_id(self_program_id),
        "first account must be the wrapped-token config PDA"
    );
    let mut cfg = WrappedTokenConfig::from_bytes(config_meta.data(self_program_id))
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[Input; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

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
    let mut config_post = config.slot_of(self_program_id).clone();
    config_post.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![Some(config_post), authority.unchanged()],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
    sources: Vec<([u8; 32], ProgramId)>,
) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let config_meta = pre_states
        .first()
        .expect("UpdateSources requires the config account");
    assert_eq!(
        config_meta.account_id,
        config_account_id(self_program_id),
        "first account must be the wrapped-token config PDA"
    );
    let mut cfg = WrappedTokenConfig::from_bytes(config_meta.data(self_program_id))
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[Input; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

    let Some(expected) = cfg.authority else {
        panic!("wrapped-token sources are fixed at genesis: no authority is configured");
    };
    assert_eq!(
        authority.account_id, expected,
        "second account must be the configured authority"
    );
    assert!(
        authority.is_authorized,
        "the configured authority must authorize a source change"
    );

    cfg.sources = sources;
    let mut config_post = config.slot_of(self_program_id).clone();
    config_post.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![Some(config_post), authority.unchanged()],
    )
    .write();
}

/// Writes the minter and the authorized peer sources into the config PDA exactly
/// once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
    config_value: &WrappedTokenConfig,
) {
    assert!(
        caller_program_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    // pre_states: [config PDA].
    let [config] =
        <[Input; 1]>::try_from(pre_states).expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "account must be the wrapped-token config PDA"
    );
    // Init-once, idempotent under genesis replay: an account this program has not
    // written is a first init; an already-written one must already hold exactly
    // this config (the genesis block is replayed onto seeded state during
    // multi-sequencer reconstruction), otherwise reject a post-genesis attempt to
    // set a different minter.
    let existing = config.slot_of(self_program_id);
    if !existing.data.is_empty() {
        assert_eq!(
            *existing.data,
            config_value.to_bytes(),
            "wrapped-token config already initialized differently"
        );
    }

    let mut config_post = existing.clone();
    config_post.data = config_value
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![Some(config_post)],
    )
    .write();
}
