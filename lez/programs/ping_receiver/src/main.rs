use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff},
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};
use ping_core::{ReceiverConfig, ReceiverInstruction, ping_record_pda, receiver_config_account_id};

fn main() {
    let call = read_lee_call::<ReceiverInstruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    match instruction {
        ReceiverInstruction::Record { payload } => record(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            payload,
        ),
        ReceiverInstruction::InitConfig(config) => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            &config,
        ),
        ReceiverInstruction::RenounceAuthority => renounce_authority(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
        ),
        ReceiverInstruction::UpdateSources { sources } => update_sources(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            sources,
        ),
    }
}

fn record(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountInput>,
    instruction_data: Vec<u8>,
    payload: Vec<u8>,
) {
    // Only the source marker's account ID is used.
    let [marker, config, record] = <[AccountInput; 3]>::try_from(pre_states)
        .expect("Record requires the source marker, config, and record accounts");

    assert_eq!(
        config.account_id,
        receiver_config_account_id(self_account_id),
        "second account must be the receiver config PDA"
    );
    let cfg = ReceiverConfig::from_bytes(config.shard_of(self_account_id))
        .expect("config account holds a receiver config");
    assert_eq!(
        caller_account_id,
        Some(cfg.deliverer),
        "Record is only callable by the authorized deliverer (the cross-zone inbox)"
    );
    // Which peer sent it is this program's own business. Without this the record
    // says only that some program on some configured peer wrote it.
    assert!(
        cfg.sources.iter().any(|(src_zone, src_account_id)| {
            marker.account_id
                == inbox_source_marker_account_id(cfg.deliverer, src_zone, *src_account_id)
        }),
        "Record is only callable for a peer source this receiver authorizes"
    );

    assert_eq!(
        record.account_id,
        ping_record_pda(self_account_id),
        "third account must be the ping record PDA"
    );

    let record_data = payload.try_into().expect("payload fits in account data");
    let post = AccountStateDiff::new(record, BalanceDiff::Add(0), record_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::unchanged(marker),
            AccountStateDiff::unchanged(config),
            post,
        ],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountInput>,
    instruction_data: Vec<u8>,
) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let config_meta = pre_states
        .first()
        .expect("RenounceAuthority requires the config account");
    assert_eq!(
        config_meta.account_id,
        receiver_config_account_id(self_account_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(config_meta.shard_of(self_account_id))
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        caller_account_id.is_none() || caller_account_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountInput; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

    let Some(expected) = cfg.authority else {
        panic!("receiver authority is already renounced");
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
    let config_data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::new(config, BalanceDiff::Add(0), config_data),
            AccountStateDiff::unchanged(authority),
        ],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountInput>,
    instruction_data: Vec<u8>,
    sources: Vec<([u8; 32], AccountId)>,
) {
    // The config is read before the account list is validated, so who may call
    // is decided first; an inbox-delivered call fails here on its prepended marker.
    let config_meta = pre_states
        .first()
        .expect("UpdateSources requires the config account");
    assert_eq!(
        config_meta.account_id,
        receiver_config_account_id(self_account_id),
        "first account must be the receiver config PDA"
    );
    let mut cfg = ReceiverConfig::from_bytes(config_meta.shard_of(self_account_id))
        .expect("config account holds a receiver config");
    // Top-level, or the governance program the config names; see
    // `ReceiverConfig::governance` for why the escape hatch exists.
    assert!(
        caller_account_id.is_none() || caller_account_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );

    let [config, authority] = <[AccountInput; 2]>::try_from(pre_states)
        .expect("this instruction requires exactly the config and authority accounts");

    let Some(expected) = cfg.authority else {
        panic!("receiver sources are fixed at genesis: no authority is configured");
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
    let config_data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::new(config, BalanceDiff::Add(0), config_data),
            AccountStateDiff::unchanged(authority),
        ],
    )
    .write();
}

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountInput>,
    instruction_data: Vec<u8>,
    config_value: &ReceiverConfig,
) {
    assert!(
        caller_account_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    // pre_states: [config PDA].
    let [config] =
        <[AccountInput; 1]>::try_from(pre_states).expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        receiver_config_account_id(self_account_id),
        "account must be the receiver config PDA"
    );
    // Init-once, idempotent under genesis replay: an empty shard is a first init;
    // a written one must already hold exactly this, since genesis is replayed onto
    // seeded state during multi-sequencer reconstruction.
    let existing = config.shard_of(self_account_id);
    if !existing.is_empty() {
        assert_eq!(
            **existing,
            config_value.to_bytes(),
            "receiver config already initialized differently"
        );
    }

    let config_data = config_value
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");
    let config_post = AccountStateDiff::new(config, BalanceDiff::Add(0), config_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![config_post],
    )
    .write();
}
