use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Input, SlotRef},
    program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};
use ping_core::{SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<SenderInstruction>();

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
            instruction_data,
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
            instruction_data,
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
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
    target_zone: [u8; 32],
    target_program_id: ProgramId,
    target_accounts: Vec<SlotRef>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, outbox PDA]. The outbox writes its own slot, so
    // ping_sender forwards it unchanged.
    let [config, outbox] =
        <[Input; 2]>::try_from(pre_states).expect("Send requires the config and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would let an emission
    // skip the real outbox and leave no record of itself.
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_program_id),
        "first account must be the ping-sender config PDA"
    );
    let outbox_program_id = read_outbox(config.data(self_program_id))
        .expect("config account holds an outbox program id");

    let call = ChainedCall::new(
        outbox_program_id,
        vec![outbox.clone()],
        &OutboxInstruction::Emit {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        },
    );

    let config_post = config.unchanged();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, outbox.clone()],
        vec![config_post, outbox.unchanged()],
    )
    .with_chained_calls(vec![call])
    .write();
}

/// Writes the outbox program id into the config PDA exactly once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<Input>,
    instruction_data: Vec<u8>,
    outbox_program_id: ProgramId,
) {
    // pre_states: [config PDA].
    let [config] =
        <[Input; 1]>::try_from(pre_states).expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_program_id),
        "account must be the ping-sender config PDA"
    );
    // Init-once, idempotent under genesis replay: an account this program has not
    // written is a first init; an already-written one must already pin exactly
    // this outbox, since genesis is replayed onto seeded state during
    // multi-sequencer reconstruction.
    let existing = config.slot_of(self_program_id);
    if !existing.data.is_empty() {
        assert_eq!(
            *existing.data,
            outbox_bytes(outbox_program_id),
            "ping-sender config already pins a different outbox"
        );
    }

    let mut config_post = existing.clone();
    config_post.data = outbox_bytes(outbox_program_id)
        .to_vec()
        .try_into()
        .expect("outbox id fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![Some(config_post)],
    )
    .write();
}
