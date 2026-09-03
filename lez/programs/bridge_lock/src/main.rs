use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, config_seed, escrow_account_id, escrow_seed,
    holding_account_id, holding_seed, read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, BalanceDiff},
    program::{
        AccountStateDiff, ChainedCall, Claim, DEFAULT_PROGRAM_OWNER, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

fn main() {
    let call = read_lee_call::<Instruction>();
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
            self_account_id,
            caller_account_id,
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
            outbox_account_id,
            target_program_id,
        } => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            outbox_account_id,
            target_program_id,
        ),
        Instruction::InitHolding { holder } => init_holding(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            &holder,
        ),
    }
}

/// Idempotent claim: a re-run on a funded holding must be a byte-identical
/// echo, or a stranger's `InitHolding` could reset a balance.
fn init_holding(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    holder: &[u8; 32],
) {
    // pre_states: [holding PDA].
    let [holding] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitHolding requires the holding account");
    assert_eq!(
        holding.account_id,
        holding_account_id(self_account_id, holder),
        "account must be the holder's bridge-lock holding PDA"
    );
    if holding.account.program_owner != DEFAULT_PROGRAM_OWNER {
        assert_eq!(
            holding.account.program_owner, self_account_id,
            "bridge-lock holding PDA is owned by another program"
        );
    }
    let holding_post = AccountStateDiff::new_claimed_if_default(
        holding.clone(),
        BalanceDiff::Add(0),
        holding.account.data,
        Claim::Pda(holding_seed(holder)),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![holding_post],
    )
    .write();
}

#[expect(
    clippy::too_many_arguments,
    reason = "the emission fields are passed through verbatim"
)]
fn lock(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
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
        config_account_id(self_account_id),
        "first account must be the bridge-lock config PDA"
    );
    let (outbox_account_id, pinned_target) = read_config(&config.account.data)
        .expect("config account holds an outbox and a mint target");

    // Value conservation: the forwarded payload must mint exactly what is locked.
    let WrappedInstruction::Mint {
        recipient,
        amount: mint_amount,
        ..
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
    let pinned_target_account_id = program_loader_core::immutable_deploy_account_id(pinned_target);
    assert_eq!(
        target_accounts,
        vec![
            wrapped_token_core::config_account_id(pinned_target_account_id).into_value(),
            wrapped_token_core::holding_account_id(pinned_target_account_id, &recipient)
                .into_value(),
        ],
        "target accounts must be the mint's config and the recipient's holding"
    );
    assert!(
        amount <= MAX_MINT_AMOUNT,
        "locked amount exceeds what the wrapped token will mint"
    );

    assert!(holder.is_authorized, "holder must authorize the lock");
    // The signature gates the debit; the derivation pins the debit target to a
    // genuine bridge-lock holding.
    assert_eq!(
        holding.account_id,
        holding_account_id(self_account_id, &holder.account_id.into_value()),
        "third account must be the holder's bridge-lock holding PDA"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_account_id),
        "fourth account must be the escrow PDA"
    );

    // bridge_lock owns holding and escrow, so the same amount moves between them and
    // conservation holds; the protocol's own balance-diff application rejects an
    // insufficient holding balance, so no manual checked_sub is needed here.
    let holding_post = AccountStateDiff::new_claimed_if_default(
        holding.clone(),
        BalanceDiff::Sub(amount),
        holding.account.data,
        Claim::Pda(holding_seed(&holder.account_id.into_value())),
    );

    let escrow_post = AccountStateDiff::new_claimed_if_default(
        escrow.clone(),
        BalanceDiff::Add(amount),
        escrow.account.data,
        Claim::Pda(escrow_seed()),
    );

    let call = ChainedCall::new(
        outbox_account_id,
        vec![outbox.account_id],
        &OutboxInstruction::Emit {
            target_zone,
            target_program_id,
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
        vec![
            config_post,
            // The holder only signs; its account is echoed untouched.
            AccountStateDiff::unchanged(holder),
            holding_post,
            escrow_post,
            AccountStateDiff::unchanged(outbox),
        ],
    )
    .with_chained_calls(vec![call])
    .write();
}

/// Writes the outbox program and the mint target into the config PDA exactly once
/// at genesis.
fn init_config(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    outbox_account_id: AccountId,
    target_program_id: ProgramId,
) {
    // pre_states: [config PDA].
    let [config] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(self_account_id),
        "account must be the bridge-lock config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned one must already pin exactly these programs, since
    // genesis is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop a later self-owned rewrite.
    if config.account != Account::default() {
        assert_eq!(
            config.account.program_owner, self_account_id,
            "bridge-lock config PDA is owned by another program"
        );
        assert_eq!(
            config.account.data.clone().into_inner(),
            config_bytes(outbox_account_id, target_program_id).to_vec(),
            "bridge-lock config already pins a different outbox or mint target"
        );
    }

    let config_post = AccountStateDiff::new_claimed_if_default(
        config,
        BalanceDiff::Add(0),
        config_bytes(outbox_account_id, target_program_id)
            .to_vec()
            .try_into()
            .expect("pinned ids fit in account data"),
        Claim::Pda(config_seed()),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![config_post],
    )
    .write();
}

/// Decodes the cross-zone payload (borsh bytes) into the wrapped-token instruction it carries.
fn decode_mint(payload: &[u8]) -> WrappedInstruction {
    borsh::from_slice(payload).expect("payload decodes to a wrapped-token instruction")
}
