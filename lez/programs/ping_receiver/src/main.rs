use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        AccountPostState, Claim, DEFAULT_PROGRAM_OWNER, ProgramId, ProgramInput, ProgramOutput,
        read_lee_inputs,
    },
};
use ping_core::{
    ReceiverConfig, ReceiverInstruction, ping_record_pda, ping_record_seed,
    receiver_config_account_id, receiver_config_seed,
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
    ) = read_lee_inputs::<ReceiverInstruction>();

    match instruction {
        ReceiverInstruction::Record {
            self_program_id,
            payload,
        } => record(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            self_program_id,
            payload,
        ),
        ReceiverInstruction::InitConfig {
            self_program_id,
            config,
        } => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            self_program_id,
            &config,
        ),
        ReceiverInstruction::RenounceAuthority => renounce_authority(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
        ),
        ReceiverInstruction::UpdateSources { sources } => update_sources(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            sources,
        ),
    }
}

fn record(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    self_program_id: ProgramId,
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
        ping_record_pda(self_program_id),
        "third account must be the ping record PDA"
    );

    let mut post_account = record.account.clone();
    post_account.data = payload.try_into().expect("payload fits in account data");
    let post =
        AccountPostState::new_claimed_if_default(post_account, Claim::Pda(ping_record_seed()));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![marker.clone(), config.clone(), record],
        vec![
            AccountPostState::new(marker.account),
            AccountPostState::new(config.account),
            post,
        ],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
) {
    // See `record`'s doc comment: exact round-trip to the actual image id, needed by the
    // PDA-derivation helpers below.
    let self_program_id = ProgramId::from(self_account_id);

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
        caller_account_id.is_none() || caller_account_id == cfg.governance.map(Into::into),
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
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![config, authority.clone()],
        vec![
            AccountPostState::new(config_account),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountPostState::new_claimed_if_default(authority.account, Claim::Authorized),
        ],
    )
    .write();
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    sources: Vec<([u8; 32], ProgramId)>,
) {
    // See `record`'s doc comment: exact round-trip to the actual image id, needed by the
    // PDA-derivation helpers below.
    let self_program_id = ProgramId::from(self_account_id);

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
        caller_account_id.is_none() || caller_account_id == cfg.governance.map(Into::into),
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
    let mut config_account = config.account.clone();
    config_account.data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![config, authority.clone()],
        vec![
            AccountPostState::new(config_account),
            // Claimed on first use: the authority's own signature bumps its
            // nonce, so merely echoing it would work once and never again.
            AccountPostState::new_claimed_if_default(authority.account, Claim::Authorized),
        ],
    )
    .write();
}

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    self_program_id: ProgramId,
    config_value: &ReceiverConfig,
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
        receiver_config_account_id(self_program_id),
        "account must be the receiver config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already hold exactly this, since genesis is
    // replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner, self_account_id,
            "receiver config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_value.to_bytes(),
            "receiver config already initialized differently"
        );
    }

    let mut config_account = config.account.clone();
    config_account.data = config_value
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");
    let config_post = AccountPostState::new_claimed_if_default(
        config_account,
        Claim::Pda(receiver_config_seed()),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        vec![config],
        vec![config_post],
    )
    .write();
}
