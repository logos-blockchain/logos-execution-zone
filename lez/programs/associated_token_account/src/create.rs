use lee_core::{
    account::{Input, Slot},
    program::{ChainedCall, ProgramId},
};

pub fn create_associated_token_account(
    owner: Input,
    token_definition: Input,
    ata_account: Input,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
) -> (Vec<Option<Slot>>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    // Only the address check is wanted here; the chained call carries no PDA seeds.
    let _ = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.unchanged(),
        token_definition.unchanged(),
        ata_account.unchanged(),
    ];

    // Idempotent: already initialized → no-op
    if !ata_account.data(token_program_id).is_empty() {
        return (post_states, vec![]);
    }

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition, ata_account],
        &token_core::Instruction::InitializeAccount,
    );

    (post_states, vec![chained_call])
}
