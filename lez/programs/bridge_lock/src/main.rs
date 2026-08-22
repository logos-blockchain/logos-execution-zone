use bridge_lock_core::{
    Instruction, config_account_id, config_bytes, config_seed, escrow_account_id, escrow_seed,
    read_config,
};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{Account, AccountDiff, AccountId, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call, write_update_from_diff_output,
    },
};
use wrapped_token_core::{Instruction as WrappedInstruction, MAX_MINT_AMOUNT};

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
    ) = match read_lee_call::<Instruction>() {
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
            instruction_words,
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
            instruction_words,
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
    instruction_words: Vec<u32>,
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
        self_program_id.into(),
        "holder account must be a bridge_lock holding"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_program_id),
        "third account must be the escrow PDA"
    );

    // Move the real native balance holder -> escrow. bridge_lock owns both accounts,
    // so it debits the holder and credits the escrow directly; conservation holds
    // because the same amount moves between them.
    let holder_post = AccountDiffOutput::new(AccountDiff {
        id: holder.account_id,
        diff_balance: BalanceDiff::Sub(amount),
        diff_data: None,
    });

    let escrow_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: escrow.account_id,
            diff_balance: BalanceDiff::Add(amount),
            diff_data: None,
        },
        escrow.account.program_owner.into(),
        Claim::Pda(escrow_seed()),
    );

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

    let config_post = unchanged(config.account_id);
    let outbox_post = unchanged(outbox.account_id);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config, holder, escrow, outbox],
        vec![config_post, holder_post, escrow_post, outbox_post],
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
    instruction_words: Vec<u32>,
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

    let config_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: config.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                config_bytes(outbox_program_id, target_program_id)
                    .to_vec()
                    .try_into()
                    .expect("bridge-lock config fits under DATA_MAX_LENGTH"),
            ),
        },
        config.account.program_owner.into(),
        Claim::Pda(config_seed()),
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

/// Decodes the cross-zone payload (risc0 words, little-endian bytes) into the
/// wrapped-token instruction it carries.
fn decode_mint(payload: &[u8]) -> WrappedInstruction {
    assert!(
        payload.len().is_multiple_of(4),
        "payload must be u32-aligned instruction words"
    );
    let words: Vec<u32> = payload
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap_or_else(|_| unreachable!())))
        .collect();
    risc0_zkvm::serde::from_slice(&words).expect("payload decodes to a wrapped-token instruction")
}
