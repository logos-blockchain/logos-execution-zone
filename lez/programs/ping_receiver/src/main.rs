use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall, ProgramId, ProgramInput,
        read_lee_call,
    },
};
use ping_core::{
    ReceiverConfig, ReceiverInstruction, ping_record_pda, ping_record_seed,
    receiver_config_account_id, receiver_config_seed,
};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<ReceiverInstruction>();

    match instruction {
        ReceiverInstruction::Record { payload } => record(input, payload),
        ReceiverInstruction::InitConfig(config) => init_config(input, &config),
        ReceiverInstruction::RenounceAuthority => renounce_authority(input),
        ReceiverInstruction::UpdateSources { sources } => update_sources(input, sources),
    }
}

fn record(input: ProgramInput, payload: Vec<u8>) {
    // pre_states: [source marker, config PDA, record PDA].
    let [marker, config, record] = input.pre_states.as_slice() else {
        panic!("Record requires the source marker, config, and record accounts");
    };

    assert_eq!(
        config.account_id,
        receiver_config_account_id(input.call.self_program_id),
        "second account must be the receiver config PDA"
    );
    let cfg = ReceiverConfig::from_bytes(&config.account.data)
        .expect("config account holds a receiver config");
    assert_eq!(
        input.call.caller_program_id,
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
        ping_record_pda(input.call.self_program_id),
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

    let post_states = vec![
        AccountDiffOutput::unchanged(marker.account_id),
        AccountDiffOutput::unchanged(config.account_id),
        post,
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
        receiver_config_account_id(input.call.self_program_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        input.call.caller_program_id.is_none() || input.call.caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = input.pre_states.as_slice() else {
        panic!("this instruction requires exactly the config and authority accounts");
    };

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
        receiver_config_account_id(input.call.self_program_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(&config_meta.account.data)
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        input.call.caller_program_id.is_none() || input.call.caller_program_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = input.pre_states.as_slice() else {
        panic!("this instruction requires exactly the config and authority accounts");
    };

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

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(input: ProgramInput, config_value: &ReceiverConfig) {
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
        receiver_config_account_id(input.call.self_program_id),
        "account must be the receiver config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already hold exactly this, since genesis is
    // replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            input.call.self_program_id.into(),
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

    input.into_output(vec![config_post]).write();
}
