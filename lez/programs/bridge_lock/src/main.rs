use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, escrow_account_id, read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::AccountWithMetadata,
    program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
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
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
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
        } => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            outbox_program_id,
            target_program_id,
        ),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn lock(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    amount: u128,
    target_zone: [u8; 32],
    target_program_id: ProgramId,
    target_accounts: Vec<[u8; 32]>,
    payload: Vec<u8>,
    ordinal: u32,
) {
    // pre_states: [config PDA, holder holding (authorized), escrow PDA, outbox PDA].
    let [config, holder, escrow, outbox] = <[AccountWithMetadata; 4]>::try_from(pre_states)
        .expect("Lock requires config, holder, escrow, and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would debit the escrow
    // and leave no record of what it was for.
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "first account must be the bridge-lock config PDA"
    );
    let (outbox_program_id, pinned_target) = read_config(config.account.data(self_program_id))
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
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_program_id),
        "third account must be the escrow PDA"
    );

    // Move the real native balance holder -> escrow. Both sides are bridge_lock's own
    // slot, so it debits one and credits the other directly; conservation holds because
    // the same amount moves between them.
    let mut holder_post = holder.account.clone();
    let holder_slot = holder_post.slot_mut(self_program_id);
    holder_slot.balance = holder_slot
        .balance
        .checked_sub(amount)
        .expect("insufficient balance to lock");
    holder_post.prune();

    let mut escrow_post = escrow.account.clone();
    let escrow_slot = escrow_post.slot_mut(self_program_id);
    escrow_slot.balance = escrow_slot
        .balance
        .checked_add(amount)
        .expect("escrow balance overflow");
    escrow_post.prune();

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

    let config_post = config.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, holder, escrow, outbox.clone()],
        vec![config_post, holder_post, escrow_post, outbox.account],
    )
    .with_chained_calls(vec![call])
    .write();
}

/// Writes the outbox program and the mint target into the config PDA exactly once
/// at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    outbox_program_id: ProgramId,
    target_program_id: ProgramId,
) {
    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
        "account must be the bridge-lock config PDA"
    );
    // Init-once, idempotent under genesis replay: an absent bridge-lock slot is a
    // first init; an existing one must already pin exactly these programs, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    if let Some(slot) = config.account.slot(self_program_id) {
        assert_eq!(
            *slot.data,
            config_bytes(outbox_program_id, target_program_id),
            "bridge-lock config already pins a different outbox or mint target"
        );
    }

    let mut config_post = config.account.clone();
    config_post.slot_mut(self_program_id).data = config_bytes(outbox_program_id, target_program_id)
        .to_vec()
        .try_into()
        .expect("pinned ids fit in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config],
        vec![config_post],
    )
    .write();
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token instruction it carries.
fn decode_mint(payload: &[u8]) -> WrappedInstruction {
    borsh::from_slice(payload).expect("payload decodes to a wrapped-token instruction")
}
