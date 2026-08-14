use cross_zone_inbox_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{AccountPostState, Claim, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
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
        ReceiverInstruction::Record { payload } => record(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            payload,
        ),
        ReceiverInstruction::InitConfig(config) => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_words,
            &config,
        ),
    }
}

fn record(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    payload: Vec<u8>,
) {
    // Recover the real `ProgramId` (RISC0 image id): on this branch every program account lives
    // at the direct `AccountId::from(program_id)` bijection, so this round-trip is exact. Needed
    // for the PDA-derivation helpers below, which are pinned to the actual image id.
    let self_program_id = ProgramId::from(self_account_id);

    // pre_states: [source marker, config PDA, record PDA].
    let [marker, config, record] = <[AccountWithMetadata; 3]>::try_from(pre_states)
        .expect("Record requires the source marker, config, and record accounts");

    assert_eq!(
        config.account_id,
        receiver_config_account_id(self_program_id),
        "Second account must be the receiver config PDA"
    );
    let cfg = ReceiverConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("config account holds a receiver config");
    assert_eq!(
        caller_account_id,
        Some(cfg.deliverer.into()),
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
        "Third account must be the ping record PDA"
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

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
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
        receiver_config_account_id(self_account_id.into()),
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
            config.account.data.clone().into_inner(),
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
