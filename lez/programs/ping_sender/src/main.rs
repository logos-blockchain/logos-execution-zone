use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{AccountId, AccountWithMetadata, BalanceDiff},
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};
use ping_core::{SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id};

fn main() {
    let call = read_lee_call::<SenderInstruction>();
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

    assert!(
        caller_account_id.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );

    match instruction {
        SenderInstruction::Send {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => send(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        ),
        SenderInstruction::InitConfig { outbox_account_id } => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            outbox_account_id,
        ),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn send(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    target_zone: [u8; 32],
    target_account_id: AccountId,
    target_accounts: Vec<[u8; 32]>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, outbox PDA]. The outbox acquires its own slot, so
    // ping_sender forwards it unchanged.
    let [config, outbox] = <[AccountWithMetadata; 2]>::try_from(pre_states)
        .expect("Send requires the config and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would let an emission
    // skip the real outbox and leave no record of itself.
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_account_id),
        "first account must be the ping-sender config PDA"
    );
    let outbox_account_id =
        read_outbox(&config.account.data).expect("config account holds an outbox program id");

    let call = ChainedCall::new(
        outbox_account_id,
        vec![outbox.account_id],
        &OutboxInstruction::Emit {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        },
    );

    let config_post = AccountStateDiff::unchanged(config);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![config_post, AccountStateDiff::unchanged(outbox)],
    )
    .with_chained_calls(vec![call])
    .write();
}

/// Writes the outbox program id into the config PDA exactly once at genesis.
fn init_config(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    outbox_account_id: AccountId,
) {
    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_account_id),
        "account must be the ping-sender config PDA"
    );
    // Init-once, idempotent under genesis replay: an empty config is a first init;
    // a written one must already pin exactly this outbox, since genesis is replayed
    // onto seeded state during multi-sequencer reconstruction. Implicit ownership
    // alone would not stop a later self-owned rewrite.
    if !config.account.data.is_empty() {
        assert_eq!(
            config.account.program_owner, self_account_id,
            "ping-sender config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            outbox_bytes(outbox_account_id),
            "ping-sender config already pins a different outbox"
        );
    }

    let config_data = outbox_bytes(outbox_account_id)
        .to_vec()
        .try_into()
        .expect("outbox id fits in account data");
    let config_post = AccountStateDiff::new(config, BalanceDiff::Add(0), config_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![config_post],
    )
    .write();
}
