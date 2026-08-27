use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff},
    program::{
        AccountDiffOutput, CallContext, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call,
    },
};
use ping_core::{
    ReceiverConfig, ReceiverInstruction, ping_record_pda, ping_record_seed,
    receiver_config_account_id, receiver_config_seed,
};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<ReceiverInstruction>();
    let ProgramInput {
        call:
            CallContext {
                self_program_id,
                caller_program_id,
                instruction_data,
            },
        pre_states,
    } = input;

    match instruction {
        ReceiverInstruction::Record { payload } => record(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            payload,
        ),
        ReceiverInstruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            &config,
        ),
        ReceiverInstruction::RenounceAuthority => renounce_authority(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
        ),
        ReceiverInstruction::UpdateSources { sources } => update_sources(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            sources,
        ),
    }
}

fn record(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    payload: Vec<u8>,
) {
    // pre_states: [source marker, config PDA, record PDA].
    let [marker, config, record] = <[AccountWithMetadata; 3]>::try_from(pre_states)
        .expect("Record requires the source marker, config, and record accounts");

    assert_eq!(
        config.account_id,
        receiver_config_account_id(self_program_id),
        "second account must be the receiver config PDA"
    );
    let cfg = ReceiverConfig::from_bytes(&config.account.data)
        .expect("config account holds a receiver config");
    assert_eq!(
        caller_program_id,
        Some(cfg.deliverer),
        "Record is only callable by the authorized deliverer (the cross-zone inbox)"
    );
    // Which peer sent it is this program's own business. Without this the record
    // says only that some program on some configured peer wrote it.
    assert!(
        cfg.sources.iter().any(|(src_zone, src_program_id)| {
            marker.account_id
                == inbox_source_marker_account_id(cfg.deliverer, src_zone, *src_program_id)
        }),
        "Record is only callable for a peer source this receiver authorizes"
    );

    assert_eq!(
        record.account_id,
        ping_record_pda(self_program_id),
        "third account must be the ping record PDA"
    );

    let record_diff = AccountDiff {
        id: record.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(payload.try_into().expect("payload fits in account data")),
    };
    let post = AccountDiffOutput::new_claimed_if_default(
        record_diff,
        record.account.program_owner,
        Claim::Pda(ping_record_seed()),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![marker.clone(), config.clone(), record],
        vec![
            AccountDiffOutput::new(AccountDiff::unchanged(marker.account_id)),
            AccountDiffOutput::new(AccountDiff::unchanged(config.account_id)),
            post,
        ],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
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
        receiver_config_account_id(self_program_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

    let Some(expected) = cfg.authority else {
        panic!("receiver authority is already renounced");
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
                .expect("receiver config fits in account data"),
        ),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![
            AccountDiffOutput::new(config_diff),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountDiffOutput::new_claimed_if_default(
                AccountDiff::unchanged(authority.account_id),
                authority.account.program_owner,
                Claim::Authorized,
            ),
        ],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
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
        receiver_config_account_id(self_program_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        caller_program_id.is_none() || caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

    let Some(expected) = cfg.authority else {
        panic!("receiver sources are fixed at genesis: no authority is configured");
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
                .expect("receiver config fits in account data"),
        ),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![
            AccountDiffOutput::new(config_diff),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountDiffOutput::new_claimed_if_default(
                AccountDiff::unchanged(authority.account_id),
                authority.account.program_owner,
                Claim::Authorized,
            ),
        ],
    )
    .write();
}

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    config_value: &ReceiverConfig,
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
        receiver_config_account_id(self_program_id),
        "account must be the receiver config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already hold exactly this, since genesis is
    // replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            self_program_id.into(),
            "receiver config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_value.to_bytes(),
            "receiver config already initialized differently"
        );
    }

    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config_value
                .to_bytes()
                .try_into()
                .expect("receiver config fits in account data"),
        ),
    };
    let config_post = AccountDiffOutput::new_claimed_if_default(
        config_diff,
        config.account.program_owner,
        Claim::Pda(receiver_config_seed()),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![config_post],
    )
    .write();
}
