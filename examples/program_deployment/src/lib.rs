use lee::{
    AccountId, FeeDeclaration, PublicAccountEvidence,
    signature::{Signer, initial_key},
};
use lee_core::{account::Nonce, signing_key::KeyType};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::{
    WalletCore, WalletSequencerClient, max_fee_for, program_facades::program_loader::ProgramLoader,
};

/// Deploys `bytecode` through `program_loader`, returning the header's `AccountId`.
///
/// Also prints it as `Deployed Program with {"program_id":"<id>"}`, a line a driving tool can pick
/// out of the wallet's other output (a runner that deploys two programs prints two, in deploy
/// order).
///
/// `payer` must be an existing, funded account — a freshly-claimed account can't pay for its own
/// claim.
#[expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]
pub async fn deploy_program<C: WalletSequencerClient>(
    wallet_core: &mut WalletCore<C>,
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

    let program_id = ProgramLoader(wallet_core)
        .deploy(header, &segments, bytecode, true, Some(payer))
        .await?;
    println!("Deployed Program with {{\"program_id\":\"{program_id}\"}}");
    Ok(program_id)
}

/// Returns the program a runner should call: `existing` if given, else `bytecode` newly deployed.
///
/// Each deployment is a new instance with its own actor states, so a run that continues from an
/// earlier run's state has to name that run's program ID.
pub async fn deploy_or_reuse<C: WalletSequencerClient>(
    wallet_core: &mut WalletCore<C>,
    bytecode: Vec<u8>,
    payer: AccountId,
    existing: Option<AccountId>,
) -> anyhow::Result<AccountId> {
    match existing {
        Some(program_id) => Ok(program_id),
        None => deploy_program(wallet_core, bytecode, payer).await,
    }
}

/// Declares `payer` as the fee payer of a hand-built public transaction.
///
/// Returns the fee declaration together with the payer's current nonce and its signer at that
/// nonce, rotating to a WOTS+ key: the transaction must list that nonce and be signed by that
/// signer, or the sequencer rejects it with "Incorrect fee".
pub async fn fee_paid_by<C: WalletSequencerClient>(
    wallet_core: &WalletCore<C>,
    payer: AccountId,
) -> anyhow::Result<(FeeDeclaration, Nonce, Signer)> {
    let secret = wallet_core
        .storage()
        .key_chain()
        .pub_account_secret(payer)
        .ok_or_else(|| anyhow::anyhow!("fee payer {payer} is not a self owned public account"))?
        .clone();
    let nonce = wallet_core.get_accounts_nonces(&[payer]).await?[0];
    let key_type = wallet_core.current_key_type(payer).await?;
    let gas_limit = wallet_core.config().gas_limit;
    let fee = FeeDeclaration::new(payer, gas_limit, 0, max_fee_for(gas_limit));
    Ok((
        fee,
        nonce,
        Signer::new(&secret, nonce, key_type, KeyType::Wots),
    ))
}

/// Admits `account_id` as a public actor of a hand-built transaction if this wallet holds its key.
///
/// An actor that doesn't sign and may not exist on chain yet is only admitted with evidence;
/// without it the call reverts with `UnadmittedPublicActor`, but is still included and charged.
/// The evidence is the account's initial key, which gives its id.
pub fn admission_evidence<C: WalletSequencerClient>(
    wallet_core: &WalletCore<C>,
    account_id: AccountId,
) -> Option<PublicAccountEvidence> {
    wallet_core
        .storage()
        .key_chain()
        .pub_account_secret(account_id)
        .map(|secret| PublicAccountEvidence::Key(initial_key(secret)))
}
