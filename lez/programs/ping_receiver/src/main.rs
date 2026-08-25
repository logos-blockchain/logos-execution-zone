use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};
use ping_core::{ReceiverConfig, ReceiverInstruction, ping_record_pda, receiver_config_account_id};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<ReceiverInstruction>();

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
        ReceiverInstruction::RenounceAuthority { authority_seed } => renounce_authority(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            authority_seed,
        ),
        ReceiverInstruction::UpdateSources {
            sources,
            authority_seed,
        } => update_sources(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            sources,
            authority_seed,
        ),
    }
}

fn authority_acts(
    authority: &AccountWithMetadata,
    caller_program_id: Option<ProgramId>,
    authority_seed: Option<PdaSeed>,
) -> bool {
    authority.is_authorized
        || caller_program_id
            .zip(authority_seed)
            .is_some_and(|(caller, seed)| {
                authority.account_id == AccountId::for_public_pda(&caller, &seed)
            })
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
    let cfg = ReceiverConfig::from_bytes(config.account.data(self_program_id))
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

    let mut record_post = record.account.clone();
    record_post.slot_mut(self_program_id).data =
        payload.try_into().expect("payload fits in account data");
    // An empty payload leaves an empty slot, which may not be stored.
    record_post.prune();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![marker.clone(), config.clone(), record],
        vec![marker.account, config.account, record_post],
    )
    .write();
}

/// Gives up the authority, freezing the source list for good.
fn renounce_authority(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    authority_seed: Option<PdaSeed>,
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
    let mut cfg = ReceiverConfig::from_bytes(config_meta.account.data(self_program_id))
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
    assert!(
        authority_acts(&authority, caller_program_id, authority_seed),
        "the configured authority must authorize renouncing it"
    );

    cfg.authority = None;
    let mut config_post = config.account.clone();
    config_post.slot_mut(self_program_id).data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![config_post, authority.account],
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
    authority_seed: Option<PdaSeed>,
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
    let mut cfg = ReceiverConfig::from_bytes(config_meta.account.data(self_program_id))
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
    assert!(
        authority_acts(&authority, caller_program_id, authority_seed),
        "the configured authority must authorize a source change"
    );

    cfg.sources = sources;
    let mut config_post = config.account.clone();
    config_post.slot_mut(self_program_id).data = cfg
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, authority.clone()],
        vec![config_post, authority.account],
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
    // Init-once, idempotent under genesis replay: an account this program has not
    // written is a first init; an already-written one must already hold exactly
    // this, since genesis is replayed onto seeded state during multi-sequencer
    // reconstruction.
    if let Some(slot) = config.account.slot(self_program_id) {
        assert_eq!(
            *slot.data,
            config_value.to_bytes(),
            "receiver config already initialized differently"
        );
    }

    let mut config_post = config.account.clone();
    config_post.slot_mut(self_program_id).data = config_value
        .to_bytes()
        .try_into()
        .expect("receiver config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![config_post],
    )
    .write();
}
