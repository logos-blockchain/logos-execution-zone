use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, config_seed, escrow_account_id, escrow_seed,
    holding_account_id, holding_seed, read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{
        AccountPostState, ChainedCall, Claim, DEFAULT_PROGRAM_OWNER, ProgramId, ProgramInput,
        ProgramOutput, read_lee_inputs,
    },
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
        Instruction::InitHolding { holder } => init_holding(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            &holder,
        ),
    }
}

/// Idempotent claim: a re-run on a funded holding must be a byte-identical
/// echo, or a stranger's `InitHolding` could reset a balance.
fn init_holding(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    holder: &[u8; 32],
) {
    // pre_states: [holding PDA].
    let [holding] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitHolding requires the holding account");
    assert_eq!(
        holding.account_id,
        holding_account_id(self_program_id, holder),
        "account must be the holder's bridge-lock holding PDA"
    );
    if holding.account.program_owner != DEFAULT_PROGRAM_OWNER {
        assert_eq!(
            holding.account.program_owner,
            self_program_id.into(),
            "bridge-lock holding PDA is owned by another program"
        );
    }
    let holding_post = AccountPostState::new_claimed_if_default(
        holding.account.clone(),
        Claim::Pda(holding_seed(holder)),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![holding],
        vec![holding_post],
    )
    .write();
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
    // pre_states: [config PDA, holder (authorized, echoed), holding PDA,
    // escrow PDA, outbox PDA].
    let [config, holder, holding, escrow, outbox] =
        <[AccountWithMetadata; 5]>::try_from(pre_states)
            .expect("Lock requires config, holder, holding, escrow, and outbox accounts");

    // Pinned rather than caller-named: chaining elsewhere would debit the escrow
    // and leave no record of what it was for.
    assert_eq!(
        config.account_id,
        config_account_id(self_program_id),
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
    // A zero lock would emit a real dispatch and zero-mint into any
    // recipient's wrapped holding.
    assert!(amount > 0, "locked amount must be positive");

    assert!(holder.is_authorized, "holder must authorize the lock");
    // The signature gates the debit; the derivation pins the debit target to a
    // genuine bridge-lock holding.
    assert_eq!(
        holding.account_id,
        holding_account_id(self_program_id, &holder.account_id.into_value()),
        "third account must be the holder's bridge-lock holding PDA"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_program_id),
        "fourth account must be the escrow PDA"
    );

    // bridge_lock owns holding and escrow, so the same amount moves between
    // them and conservation holds. An unclaimed holding reads as balance 0, so
    // a positive lock against one fails here.
    let holding_new = holding
        .account
        .balance
        .checked_sub(amount)
        .expect("insufficient holding balance to lock");
    let escrow_new = escrow
        .account
        .balance
        .checked_add(amount)
        .expect("escrow balance overflow");

    let mut holding_account = holding.account.clone();
    holding_account.balance = holding_new;
    let holding_post = AccountPostState::new_claimed_if_default(
        holding_account,
        Claim::Pda(holding_seed(&holder.account_id.into_value())),
    );

    let mut escrow_account = escrow.account.clone();
    escrow_account.balance = escrow_new;
    let escrow_post =
        AccountPostState::new_claimed_if_default(escrow_account, Claim::Pda(escrow_seed()));

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

    let config_post = AccountPostState::new(config.account.clone());

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config, holder.clone(), holding, escrow, outbox.clone()],
        vec![
            config_post,
            // The holder only signs; its account is echoed untouched.
            AccountPostState::new(holder.account),
            holding_post,
            escrow_post,
            AccountPostState::new(outbox.account),
        ],
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
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already pin exactly these programs, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner,
            self_program_id.into(),
            "bridge-lock config PDA is owned by another program"
        );
        assert_eq!(
            *config.account.data,
            config_bytes(outbox_program_id, target_program_id),
            "bridge-lock config already pins a different outbox or mint target"
        );
    }

    let mut config_account = config.account.clone();
    config_account.data = config_bytes(outbox_program_id, target_program_id)
        .to_vec()
        .try_into()
        .expect("pinned ids fit in account data");
    let config_post =
        AccountPostState::new_claimed_if_default(config_account, Claim::Pda(config_seed()));

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
