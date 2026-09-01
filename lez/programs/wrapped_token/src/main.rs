use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::AccountWithMetadata,
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, SourceEntry, SourcePolicy, WrappedTokenConfig, balance_bytes,
    config_account_id, holding_account_id, read_balance,
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
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
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
    let mut cfg = WrappedTokenConfig::from_bytes(&config.account.data)
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
    let minter = cfg.minter;
    let source = cfg
        .sources
        .iter_mut()
        .find(|entry| {
            marker.account_id
                == inbox_source_marker_account_id(
                    minter,
                    &entry.policy.src_zone,
                    entry.policy.src_program_id,
                )
        })
        .expect("Mint is only callable for a peer source this token authorizes");
    // The source's lifetime allowance. A breach fails the whole delivery, so the
    // message stays undelivered and can be redelivered after a cap raise.
    let minted = source
        .minted
        .checked_add(amount)
        .expect("source mint total overflow");
    if let Some(cap) = source.policy.mint_cap {
        assert!(minted <= cap, "mint exceeds this source's lifetime cap");
    }
    source.minted = minted;

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
    let new_balance = read_balance(&holding.account.data)
        .checked_add(amount)
        .expect("wrapped-token balance overflow");
    let mut holding_account = holding.account.clone();
    holding_account.data = balance_bytes(new_balance)
        .to_vec()
        .try_into()
        .expect("balance fits in account data");
    let holding_post = holding_account;
    // The advanced counter is written back, so the cap survives restarts and
    // re-derivation alike: it is state, not host memory.
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");
    let config_post = config_account;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![marker.clone(), config, holding],
        vec![marker.account, config_post, holding_post],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
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
    let mut cfg = WrappedTokenConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
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
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![config_account, authority.account],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    sources: Vec<SourcePolicy>,
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
    let mut cfg = WrappedTokenConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a wrapped-token config");
    // Top-level, or the governance program the config names; see
    // `WrappedTokenConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
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

    // Mint advances the first matching entry, so a duplicated pair would split
    // one source's policy across entries an auditor reads as two.
    for (index, policy) in sources.iter().enumerate() {
        assert!(
            !sources[..index].iter().any(|other| {
                other.src_zone == policy.src_zone && other.src_program_id == policy.src_program_id
            }),
            "UpdateSources lists the same source twice"
        );
    }
    // The counter is the guest's, never the caller's: a kept source carries its
    // spent allowance over, so an update cannot reset it, and a source removed
    // and later re-added starts at zero.
    let previous = core::mem::take(&mut cfg.sources);
    cfg.sources = sources
        .into_iter()
        .map(|policy| SourceEntry {
            minted: previous
                .iter()
                .find(|entry| {
                    entry.policy.src_zone == policy.src_zone
                        && entry.policy.src_program_id == policy.src_program_id
                })
                .map_or(0, |entry| entry.minted),
            policy,
        })
        .collect();
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![config_account, authority.account],
    )
    .write();
}

/// Writes the minter and the authorized peer sources into the config PDA exactly
/// once at genesis.
fn init_config(
    self_program_id: lee_core::program::ProgramId,
    caller_program_id: Option<lee_core::program::ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
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
    // Init-once, idempotent under genesis replay: an empty config is a first init;
    // a written config must already hold exactly this minter (the genesis block is
    // replayed onto seeded state during multi-sequencer reconstruction), otherwise
    // reject a post-genesis attempt to set a different minter. Implicit ownership
    // alone would not stop the owning program from rewriting its own config data
    // on a later call.
    if !config.account.data.is_empty() {
        assert_eq!(
            config.account.program_owner,
            self_program_id.into(),
            "wrapped-token config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_value.to_bytes(),
            "wrapped-token config already initialized differently"
        );
    }

    let mut config_account = config.account.clone();
    config_account.data = config_value
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");
    let config_post = config_account;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![config_post],
    )
    .write();
}
