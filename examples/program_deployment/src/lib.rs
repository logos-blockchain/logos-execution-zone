use lee::AccountId;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::{WalletCore, program_facades::program_loader::ProgramLoader};

/// Deploys `bytecode` through `program_loader`, returning the header's `AccountId`.
///
/// Claims one fresh header account and as many fresh segment accounts as the bytecode needs, then
/// uploads the chain.
///
/// `payer` must be an existing, funded account. A freshly-claimed account cannot pay for its own
/// claim (funding it first would claim it via the transfer guest instead), so deployment is
/// always paid for by a separate, already-funded account.
pub async fn deploy_program(
    wallet_core: &mut WalletCore,
    bytecode: Vec<u8>,
    payer: AccountId,
) -> anyhow::Result<AccountId> {
    let segment_count = bytecode.len().div_ceil(MAX_SEGMENT_DATA_LEN);
    let header = wallet_core.create_new_account_public(None).0;
    let segments: Vec<AccountId> =
        std::iter::repeat_with(|| wallet_core.create_new_account_public(None).0)
            .take(segment_count)
            .collect();
    wallet_core.store_persistent_data()?;

    ProgramLoader(wallet_core)
        .deploy(header, &segments, bytecode, true, Some(payer))
        .await
}
