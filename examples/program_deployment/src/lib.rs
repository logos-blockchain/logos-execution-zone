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
    let segment_count = segment_count(&bytecode)?;
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

/// Number of segment accounts `program_loader` needs for `bytecode`.
///
/// Only the `user_elf` is segmented on-chain (the kernel is the protocol default), so the count
/// must come from it rather than the whole `ProgramBinary`.
fn segment_count(bytecode: &[u8]) -> anyhow::Result<usize> {
    Ok(risc0_binfmt::ProgramBinary::decode(bytecode)
        .map_err(|err| anyhow::anyhow!("invalid program binary: {err}"))?
        .user_elf
        .len()
        .div_ceil(MAX_SEGMENT_DATA_LEN))
}

/// Declares `payer` as the fee payer of a hand-built public transaction.
///
/// Returns the fee declaration together with the payer's current nonce and signing key. The
/// payer must sign the transaction with that key, or the sequencer rejects it with "Incorrect
/// fee"; like every signer, it also lists its nonce in the message.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_count_ignores_the_kernel_elf() {
        // A user ELF that fills exactly one segment; with the kernel appended, the whole binary
        // spills into a second segment's worth of bytes.
        let user_elf = vec![1_u8; MAX_SEGMENT_DATA_LEN];
        let kernel_elf = vec![2_u8; 64];
        let bytecode = risc0_binfmt::ProgramBinary::new(&user_elf, &kernel_elf).encode();
        assert_eq!(bytecode.len().div_ceil(MAX_SEGMENT_DATA_LEN), 2);

        assert_eq!(segment_count(&bytecode).unwrap(), 1);
    }

    #[test]
    fn segment_count_rejects_a_raw_elf() {
        assert!(segment_count(&[0x7f, b'E', b'L', b'F']).is_err());
    }
}
