use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramId, ProgramInput, read_lee_call,
    },
};
use ping_core::{
    SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id, sender_config_seed,
};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<SenderInstruction>();

    assert!(
        input.call.caller_program_id.is_none(),
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
            input,
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        ),
        SenderInstruction::InitConfig { outbox_program_id } => {
            init_config(input, outbox_program_id);
        }
    }
}

fn send(
    input: ProgramInput,
    target_zone: [u8; 32],
    target_program_id: ProgramId,
    target_accounts: Vec<[u8; 32]>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, outbox PDA]. The outbox claims its own slot, so
    // ping_sender forwards it unchanged.
    let [config, outbox] = input.pre_states.as_slice() else {
        panic!("Send requires the config and outbox accounts");
    };

    // Pinned rather than caller-named: chaining elsewhere would let an emission
    // skip the real outbox and leave no record of itself.
    assert_eq!(
        config.account_id,
        sender_config_account_id(input.call.self_program_id),
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

    let post_states = vec![
        AccountDiffOutput::unchanged(config.account_id),
        AccountDiffOutput::unchanged(outbox.account_id),
    ];

    input
        .into_output(post_states)
        .with_chained_calls(vec![call])
        .write();
}

/// Writes the outbox program id into the config PDA exactly once at genesis.
fn init_config(input: ProgramInput, outbox_program_id: ProgramId) {
    // pre_states: [config PDA].
    let [config] = input.pre_states.as_slice() else {
        panic!("InitConfig requires the config account");
    };
    assert_eq!(
        config.account_id,
        sender_config_account_id(input.call.self_program_id),
        "account must be the ping-sender config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already pin exactly this outbox, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            input.call.self_program_id.into(),
            "ping-sender config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            outbox_bytes(outbox_program_id),
            "ping-sender config already pins a different outbox"
        );
    }

    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            outbox_bytes(outbox_program_id)
                .to_vec()
                .try_into()
                .expect("outbox id fits in account data"),
        ),
    };
    let config_post = AccountDiffOutput::new_claimed_if_default(
        config_diff,
        config.account.program_owner,
        Claim::Pda(sender_config_seed()),
    );

    input.into_output(vec![config_post]).write();
}
