use lee::AccountId;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::{WalletCore, program_facades::program_loader::ProgramLoader};

/// Deploys `bytecode` through `program_loader`: claims one fresh header account and as many
/// fresh segment accounts as the bytecode needs, uploads the chain, and returns the header's
/// `AccountId` — the address to dispatch calls to the deployed program at.
///
/// `payer` must be an existing, funded account. A freshly-claimed account cannot pay for its own
/// claim (funding it first would claim it via the transfer guest instead), so deployment is
/// always paid for by a separate, already-funded account.
pub async fn deploy_program(
    wallet_core: &mut WalletCore,
    bytecode: Vec<u8>,
    payer: AccountId,
) -> anyhow::Result<AccountId> {
    let segment_count = bytecode.len().div_ceil(MAX_SEGMENT_DATA_LEN).max(1);
    let header = wallet_core.create_new_account_public(None).0;
    let segments: Vec<AccountId> = (0..segment_count)
        .map(|_| wallet_core.create_new_account_public(None).0)
        .collect();
    wallet_core.store_persistent_data()?;

    ProgramLoader(wallet_core)
        .deploy(header, &segments, bytecode, true, Some(payer))
        .await
}
