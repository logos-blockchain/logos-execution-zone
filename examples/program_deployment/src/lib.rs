use lee::{AccountId, FeeDeclaration, PrivateKey};
use lee_core::account::Nonce;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::{WalletCore, max_fee_for, program_facades::program_loader::ProgramLoader};

/// Deploys `bytecode` through `program_loader`, returning the header's `AccountId`.
///
/// `payer` must be an existing, funded account — a freshly-claimed account can't pay for its own
/// claim.
pub async fn deploy_program(
    wallet_core: &mut WalletCore,
    bytecode: Vec<u8>,
    payer: AccountId,
) -> anyhow::Result<AccountId> {
    // Only the `user_elf` is segmented on-chain (the kernel is the protocol default), so the
    // segment count must come from it rather than the whole `ProgramBinary`.
    let segment_count = risc0_binfmt::ProgramBinary::decode(&bytecode)
        .map_err(|err| anyhow::anyhow!("invalid program binary: {err}"))?
        .user_elf
        .len()
        .div_ceil(MAX_SEGMENT_DATA_LEN);
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

/// Declares `payer` as the fee payer of a hand-built public transaction.
///
/// Returns the fee declaration together with the payer's current nonce and signing key: the
/// transaction must list that nonce and be signed with that key, or the sequencer rejects it with
/// "Incorrect fee".
pub async fn fee_paid_by(
    wallet_core: &WalletCore,
    payer: AccountId,
) -> anyhow::Result<(FeeDeclaration, Nonce, PrivateKey)> {
    let signing_key = wallet_core
        .get_account_public_signing_key(payer)
        .ok_or_else(|| anyhow::anyhow!("fee payer {payer} is not a self owned public account"))?
        .clone();
    let nonce = wallet_core.get_accounts_nonces(&[payer]).await?[0];
    let gas_limit = wallet_core.config().gas_limit;
    let fee = FeeDeclaration::new(payer, gas_limit, 0, max_fee_for(gas_limit));
    Ok((fee, nonce, signing_key))
}
