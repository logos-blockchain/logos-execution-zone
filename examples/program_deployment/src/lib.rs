use lee::AccountId;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::{WalletCore, program_facades::program_loader::ProgramLoader};

/// Deploys `bytecode` through `program_loader`, returning the header's `AccountId`.
///
/// `payer` must be an existing, funded account — a freshly-claimed account can't pay for its own
/// claim.
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

/// Builds a public transaction whose fee is paid by `payer`.
///
/// The sequencer rejects public transactions without a fee declaration, so `payer` co-signs: its
/// nonce and signature are appended after those of `signing_keys`, without adding it to the
/// transaction's inputs.
pub async fn public_tx_paid_by<T: borsh::BorshSerialize>(
    wallet_core: &WalletCore,
    program_account_id: AccountId,
    shard_selectors: Vec<lee::ProgramShardSelector>,
    mut nonces: Vec<lee_core::account::Nonce>,
    signing_keys: &[&lee::PrivateKey],
    instruction: T,
    payer: AccountId,
) -> anyhow::Result<lee::PublicTransaction> {
    let payer_key = wallet_core
        .get_account_public_signing_key(payer)
        .ok_or_else(|| anyhow::anyhow!("fee payer's signing key is not held by this wallet"))?
        .clone();
    nonces.extend(wallet_core.get_accounts_nonces(&[payer]).await?);
    let gas_limit = wallet_core.config().gas_limit;
    let message = lee::public_transaction::Message::try_new_with_fees(
        program_account_id,
        shard_selectors,
        nonces,
        instruction,
        lee::FeeDeclaration::new(payer, gas_limit, 0, wallet::max_fee_for(gas_limit)),
    )?;
    let mut keys = signing_keys.to_vec();
    keys.push(&payer_key);
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);
    Ok(lee::PublicTransaction::new(message, witness_set))
}
