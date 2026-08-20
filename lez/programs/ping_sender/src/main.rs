use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountDiff, AccountId, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call, write_update_from_diff_output,
    },
};
use ping_core::{
    SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id, sender_config_seed,
};

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Data {
    diff_data
}

const fn unchanged(account_id: AccountId) -> AccountDiffOutput {
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
    ) = match read_lee_call::<SenderInstruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone());
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
    };

    assert!(
        caller_program_id.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );

    match instruction {
        SenderInstruction::Send {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        } => send(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        ),
        SenderInstruction::InitConfig { outbox_program_id } => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            outbox_program_id,
        ),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn send(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    target_zone: [u8; 32],
    target_program_id: ProgramId,
    target_accounts: Vec<[u8; 32]>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, outbox PDA]. The outbox claims its own slot, so
    // ping_sender forwards it unchanged.
    let [config, outbox] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("Send requires the config and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would let an emission
    // skip the real outbox and leave no record of itself.
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_program_id),
        "first account must be the ping-sender config PDA"
    );
    let outbox_program_id =
        read_outbox(&config.account.data).expect("config account holds an outbox program id");

    let call = ChainedCall::new(
        outbox_program_id,
        vec![outbox.account_id],
        &OutboxInstruction::Emit {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        },
    );

    let config_post = unchanged(config.account_id);
    let outbox_post = unchanged(outbox.account_id);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config, outbox],
        vec![config_post, outbox_post],
    )
    .with_chained_calls(vec![call])
    .write();
}

/// Writes the outbox program id into the config PDA exactly once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    outbox_program_id: ProgramId,
) {
    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_program_id),
        "account must be the ping-sender config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already pin exactly this outbox, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            self_program_id.into(),
            "ping-sender config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            outbox_bytes(outbox_program_id),
            "ping-sender config already pins a different outbox"
        );
    }

    let config_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: config.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                outbox_bytes(outbox_program_id)
                    .to_vec()
                    .try_into()
                    .expect("ping-sender config fits under DATA_MAX_LENGTH"),
            ),
        },
        config.account.program_owner.into(),
        Claim::Pda(sender_config_seed()),
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
