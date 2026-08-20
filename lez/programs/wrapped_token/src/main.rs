use std::convert::Infallible;

use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall,
        ProgramInput, ProgramOutput, read_lee_call, write_update_from_diff_output,
    },
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, WrappedTokenConfig, balance_bytes, config_account_id,
    config_seed, holding_account_id, holding_seed, read_balance,
};

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Result<Data, Infallible> {
    Ok(diff_data)
}

fn unchanged(account_id: lee_core::account::AccountId) -> AccountDiffOutput {
    AccountDiffOutput::new(AccountDiff {
        id: account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    })
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
    };

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
    let cfg = WrappedTokenConfig::from_bytes(&config.account.data)
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
    let new_balance = read_balance(&holding.account.data)
        .checked_add(amount)
        .expect("wrapped-token balance overflow");
    let holding_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: holding.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                balance_bytes(new_balance)
                    .to_vec()
                    .try_into()
                    .expect("balance bytes fit in account data"),
            ),
        },
        holding.account.program_owner.into(),
        Claim::Pda(holding_seed(&recipient)),
    );
    let config_post = unchanged(config.account_id);
    let marker_post = unchanged(marker.account_id);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![marker, config, holding],
        vec![marker_post, config_post, holding_post],
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
    let new_config_data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    let authority_program_owner = authority.account.program_owner.into();
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config.clone(), authority.clone()],
        vec![
            AccountDiffOutput::new(AccountDiff {
                id: config.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(new_config_data),
            }),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountDiffOutput::new_claimed_if_default(
                AccountDiff {
                    id: authority.account_id,
                    diff_balance: BalanceDiff::Add(0),
                    diff_data: None,
                },
                authority_program_owner,
                Claim::Authorized,
            ),
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
    let new_config_data = cfg
        .to_bytes()
        .try_into()
        .expect("wrapped-token config fits in account data");

    let authority_program_owner = authority.account.program_owner.into();
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config.clone(), authority.clone()],
        vec![
            AccountDiffOutput::new(AccountDiff {
                id: config.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(new_config_data),
            }),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountDiffOutput::new_claimed_if_default(
                AccountDiff {
                    id: authority.account_id,
                    diff_balance: BalanceDiff::Add(0),
                    diff_data: None,
                },
                authority_program_owner,
                Claim::Authorized,
            ),
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

    let config_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: config.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                config_value
                    .to_bytes()
                    .try_into()
                    .expect("wrapped-token config fits in account data"),
            ),
        },
        config.account.program_owner.into(),
        Claim::Pda(config_seed()),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config],
        vec![config_post],
    )
    .write();
}
