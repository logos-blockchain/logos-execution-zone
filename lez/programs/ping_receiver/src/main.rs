use std::convert::Infallible;

use cross_zone_inbox_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call, write_update_from_diff_output,
    },
};
use ping_core::{
    ReceiverConfig, ReceiverInstruction, ping_record_pda, ping_record_seed,
    receiver_config_account_id, receiver_config_seed,
};

/// Every data write in this program replaces the account's data wholesale with an
/// already-fully-computed encoding, so `diff_data` already *is* the new data verbatim —
/// materializing it is a passthrough.
fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(diff_data
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed"))
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
    ) = match read_lee_call::<ReceiverInstruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
            return;
        }
    };

    match instruction {
        ReceiverInstruction::Record { payload } => record(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            payload,
        ),
        ReceiverInstruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            &config,
        ),
    }
}

fn record(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    payload: Vec<u8>,
) {
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
        "Third account must be the ping record PDA"
    );

    let payload: Data = payload.try_into().expect("payload fits in account data");
    let post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: record.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(payload.as_ref().to_vec()),
        },
        record.account.program_owner,
        Claim::Pda(ping_record_seed()),
    );
    let marker_post = unchanged(marker.account_id);
    let config_post = unchanged(config.account_id);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![marker, config, record],
        vec![marker_post, config_post, post],
    )
    .write();
}

/// Writes the deliverer and the authorized peer sources into the config PDA
/// exactly once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
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
            config.account.program_owner, self_program_id,
            "receiver config PDA is owned by another program"
        );
        assert_eq!(
            config.account.data.clone().into_inner(),
            config_value.to_bytes(),
            "receiver config already initialized differently"
        );
    }

    let config_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: config.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(config_value.to_bytes()),
        },
        config.account.program_owner,
        Claim::Pda(receiver_config_seed()),
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
