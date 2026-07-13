use bridge_lock_core::{Instruction, balance_bytes, escrow_account_id, escrow_seed, read_balance};
use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
};
use wrapped_token_core::Instruction as WrappedInstruction;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "bridge_lock is only invoked as a top-level user transaction"
    );

    let Instruction::Lock {
        amount,
        target_zone,
        target_program_id,
        target_accounts,
        payload,
        outbox_program_id,
        ordinal,
    } = instruction;

    // Value conservation: the forwarded payload must mint exactly what is locked.
    let WrappedInstruction::Mint {
        amount: mint_amount,
        ..
    } = decode_mint(&payload);
    assert_eq!(
        mint_amount, amount,
        "locked amount must equal the wrapped mint amount"
    );

    // pre_states: [holder holding (authorized), escrow PDA, outbox PDA].
    let [holder, escrow, outbox] = <[AccountWithMetadata; 3]>::try_from(pre_states)
        .expect("Lock requires holder, escrow, and outbox accounts");

    assert!(holder.is_authorized, "holder must authorize the lock");
    assert_eq!(
        holder.account.program_owner, self_program_id,
        "holder account must be a bridge_lock holding"
    );
    assert_eq!(
        escrow.account_id,
        escrow_account_id(self_program_id),
        "second account must be the escrow PDA"
    );

    let holder_new = read_balance(&holder.account.data.clone().into_inner())
        .checked_sub(amount)
        .expect("insufficient balance to lock");
    let escrow_new = read_balance(&escrow.account.data.clone().into_inner())
        .checked_add(amount)
        .expect("escrow balance overflow");

    let mut holder_account = holder.account.clone();
    holder_account.data = balance_bytes(holder_new)
        .to_vec()
        .try_into()
        .expect("balance fits in account data");
    let holder_post = AccountPostState::new(holder_account);

    let mut escrow_account = escrow.account.clone();
    escrow_account.data = balance_bytes(escrow_new)
        .to_vec()
        .try_into()
        .expect("balance fits in account data");
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

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![holder, escrow, outbox.clone()],
        vec![
            holder_post,
            escrow_post,
            AccountPostState::new(outbox.account),
        ],
    )
    .with_chained_calls(vec![call])
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
