use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, config_seed, escrow_account_id, escrow_seed,
    read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramId, ProgramInput, read_lee_call,
    },
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();

    assert!(
        input.call.caller_program_id.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );

    match instruction {
        Instruction::Lock {
            amount,
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        } => lock(
            input,
            amount,
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ordinal,
        ),
        Instruction::InitConfig {
            outbox_program_id,
            target_program_id,
        } => init_config(input, outbox_program_id, target_program_id),
    }
}

fn lock(
    input: ProgramInput,
    amount: u128,
    target_zone: [u8; 32],
    target_program_id: ProgramId,
    target_accounts: Vec<[u8; 32]>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, holder holding (authorized), escrow PDA, outbox PDA].
    let [config, holder, escrow, outbox] = input.pre_states.as_slice() else {
        panic!("Lock requires config, holder, escrow, and outbox accounts");
    };

    // Pinned rather than caller-named: chaining elsewhere would debit the escrow
    // and leave no record of what it was for.
    assert_eq!(
        config.account_id,
        config_account_id(input.call.self_program_id),
        "first account must be the bridge-lock config PDA"
    );
    let (outbox_program_id, pinned_target) = read_config(&config.account.data)
        .expect("config account holds an outbox and a mint target");

    // Value conservation: the forwarded payload must mint exactly what is locked.
    let WrappedInstruction::Mint {
        recipient,
        amount: mint_amount,
    } = decode_mint(&payload)
    else {
        panic!("bridge_lock payload must be a wrapped-token mint");
    };
    assert_eq!(
        mint_amount, amount,
        "locked amount must equal the wrapped mint amount"
    );

    // All before the debit: nothing releases an escrow, so a message the
    // destination refuses is a burn. `target_zone` is not checkable here, so a
    // lock aimed at a zone that will not route it still burns.
    assert_eq!(
        target_program_id, pinned_target,
        "bridge_lock only mints through the wrapped token it is pinned to"
    );
    assert_eq!(
        target_accounts,
        vec![
            wrapped_token_core::config_account_id(pinned_target).into_value(),
            wrapped_token_core::holding_account_id(pinned_target, &recipient).into_value(),
        ],
        "target accounts must be the mint's config and the recipient's holding"
    );
    assert!(
        amount <= MAX_MINT_AMOUNT,
        "locked amount exceeds what the wrapped token will mint"
    );

    assert!(holder.is_authorized, "holder must authorize the lock");
    // The holder holding is bridge_lock-owned, so bridge_lock may debit its native
    // balance directly (state-machine rule 5). This also pins the transfer to a
    // genuine holding: a caller cannot substitute an account owned by some other
    // program to emit the mint without an actual lock.
    assert_eq!(
        holder.account.program_owner,
        input.call.self_program_id.into(),
        "holder account must be a bridge_lock holding"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(input.call.self_program_id),
        "third account must be the escrow PDA"
    );

    // Move the real native balance holder -> escrow. bridge_lock owns both accounts,
    // so it debits the holder and credits the escrow directly; conservation holds
    // because the same amount moves between them.
    let holder_diff = AccountDiff {
        id: holder.account_id,
        diff_balance: BalanceDiff::Sub(amount),
        diff_data: None,
    };
    let holder_post = AccountDiffOutput::new(holder_diff);

    let escrow_diff = AccountDiff {
        id: escrow.account_id,
        diff_balance: BalanceDiff::Add(amount),
        diff_data: None,
    };
    let escrow_post = AccountDiffOutput::new_claimed_if_default(
        escrow_diff,
        escrow.account.program_owner,
        Claim::Pda(escrow_seed()),
    );

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
        holder_post,
        escrow_post,
        AccountDiffOutput::unchanged(outbox.account_id),
    ];

    input
        .into_output(post_states)
        .with_chained_calls(vec![call])
        .write();
}

/// Writes the outbox program and the mint target into the config PDA exactly once
/// at genesis.
fn init_config(input: ProgramInput, outbox_program_id: ProgramId, target_program_id: ProgramId) {
    // pre_states: [config PDA].
    let [config] = input.pre_states.as_slice() else {
        panic!("InitConfig requires the config account");
    };
    assert_eq!(
        config.account_id,
        config_account_id(input.call.self_program_id),
        "account must be the bridge-lock config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already pin exactly these programs, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            input.call.self_program_id.into(),
            "bridge-lock config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_bytes(outbox_program_id, target_program_id),
            "bridge-lock config already pins a different outbox or mint target"
        );
    }

    let config_diff = AccountDiff {
        id: config.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config_bytes(outbox_program_id, target_program_id)
                .to_vec()
                .try_into()
                .expect("pinned ids fit in account data"),
        ),
    };
    let config_post = AccountDiffOutput::new_claimed_if_default(
        config_diff,
        config.account.program_owner,
        Claim::Pda(config_seed()),
    );

    input.into_output(vec![config_post]).write();
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token instruction it carries.
fn decode_mint(payload: &[u8]) -> WrappedInstruction {
    borsh::from_slice(payload).expect("payload decodes to a wrapped-token instruction")
}
